"""Real cryptographic Django requests held across a host-controlled Redis crash.

Only the host driver can restart Redis; no Docker socket or credentials are
transported through IPC. A new disposable PostgreSQL DB and unique Redis prefix
isolate synthetic identities. Audit posting is mocked, verifiers are not.
Original Unlicense tooling. This file is executed only by explicit qualification.
"""
import base64
import copy
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import signal
import threading
import time
import traceback
from unittest.mock import patch
import uuid

import cbor2
import pyotp
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from django.conf import settings
from django.contrib.auth.signals import user_logged_in
from django.core.management import call_command
from django.db import close_old_connections, connection, connections
from django.test import Client, override_settings
from django.test.runner import DiscoverRunner
from django.urls import reverse
from accounts.models import User, UserTOTP, UserWebAuthn
from zentral.conf import api_base_url, settings as central
from zentral.core.events.base import BaseEvent
from zentral.core.queues import queues
import azd_santa_operator as policy

SCOPE = 'private-real-django-mfa-redis-restart'
LIMITATION = 'Genuine Django/crypto requests and Redis restart; audit delivery mocked, no TCP/browser/TLS/native-Mac/host-power-loss/backup proof'
FIELDS = {'scope', 'namespace', 'compose_sha256', 'policy_sha256', 'harness_sha256', 'image_id', 'redis_run_id_sha256'}


def need(value):
    if not value:
        raise RuntimeError('Private MFA restart assertion failed; inspect private process output')


def validate_context(value):
    need(isinstance(value, dict) and set(value) == FIELDS and value['scope'] == SCOPE)
    need(re.fullmatch(r'azd-mfa-restart-[0-9a-f]{24}', value['namespace']))
    need(all(re.fullmatch(r'[a-f0-9]{64}', value[key]) for key in ('compose_sha256', 'policy_sha256', 'harness_sha256', 'redis_run_id_sha256')))
    need(re.fullmatch(r'sha256:[a-f0-9]{64}', value['image_id']))
    need(value['policy_sha256'] == hashlib.sha256(Path(policy.__file__).read_bytes()).hexdigest())
    need(value['harness_sha256'] == hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    return value


def private_phase(root, name, value):
    raw = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
    need(len(raw) <= 4096)
    temporary = root / (name + '.pending')
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'wb') as output:
        output.write(raw); output.flush(); os.fsync(output.fileno())
    os.link(temporary, root / name)  # Atomic exclusive publication, never partial IPC.
    temporary.unlink()


def wait_resume(root, context):
    deadline = time.monotonic() + 45
    path = root / 'resume.json'
    while not path.exists():
        need(time.monotonic() < deadline)
        time.sleep(0.02)
    need(path.is_file() and not path.is_symlink() and path.stat().st_size <= 4096)
    value = json.loads(path.read_bytes())
    need(value == dict(context, phase='resume'))


def client():
    return Client(enforce_csrf_checks=True, HTTP_HOST='localhost', HTTP_USER_AGENT='Mozilla/5.0 synthetic-mfa-restart')


def post(browser, route, values):
    return browser.post(reverse(route), values, secure=True, HTTP_REFERER='https://localhost/',
                        HTTP_X_CSRFTOKEN=browser.cookies['csrftoken'].value)


def password(browser, user, value):
    need(browser.get(reverse('login'), secure=True).status_code == 200)
    need(post(browser, 'login', dict(username=user.username, password=value)).status_code == 302)


def user(namespace):
    name = namespace + '-' + uuid.uuid4().hex[:8]
    value = secrets.token_urlsafe(30)
    return User.objects.create_user(name, name + '@example.invalid', password=value), value


def encode(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip('=')


def assert_replay_evidence(observed, web, totp, budget_status, successes, expected_users):
    need(web == (403, False) and totp == (403, False))
    need(observed.get('webauthn-replay') == [('challenge', False)])
    need(observed.get('totp-replay') == [('challenge', True), ('totp', False)])
    need(budget_status == 429 and observed.get('budget-after') is False)
    need(sorted(successes) == sorted(expected_users))


def scenario(context, root):
    local = threading.local()
    observed = {}
    successes = []
    held = {name: threading.Event() for name in ('webauthn-replay', 'totp-replay')}
    release = {name: threading.Event() for name in held}
    observation_lock = threading.Lock()
    original_challenge, original_add, original_budget = policy._challenge, policy._cache_add, policy._budget

    def role(name, action):
        local.name = name
        return action()

    def challenge(request):
        result = original_challenge(request)
        name = getattr(local, 'name', '')
        if name in held and request.method == 'POST':
            need(result is None and isinstance(request.session['verification_token'], str))
            held[name].set()  # The real request already loaded its anonymous session.
            need(release[name].wait(timeout=100))
            # Discard this process's pre-crash idle connections. Readiness and
            # the claim wrappers must prove Redis results, not transport errors.
            from django.core.cache import caches
            caches['azd_santa_security'].client.get_client(write=True).connection_pool.disconnect()
            policy.check_security_store()
        return result

    def add(key, value, seconds):
        name = getattr(local, 'name', '')
        kind = 'challenge' if key.startswith('challenge-used:') else 'totp' if key.startswith('totp-used:') else 'other'
        try:
            result = original_add(key, value, seconds)
        except Exception:
            with observation_lock:
                observed.setdefault(name, []).append((kind, 'error'))
            raise
        need(type(result) is bool)
        with observation_lock:
            observed.setdefault(name, []).append((kind, result))
        return result  # Observe the real result; never substitute an outcome.

    def budget(key, maximum, seconds=policy.CHALLENGE_SECONDS):
        result = original_budget(key, maximum, seconds)
        if getattr(local, 'name', '') == 'budget-after':
            observed['budget-after'] = result
        return result

    def logged_in(sender, request, user, **kwargs):
        need(request.session.get('mfa_authenticated') is True)
        successes.append(user.pk)

    def pending(name, browser, route, values):
        close_old_connections()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SET lock_timeout = '8s'")
                cursor.execute("SET statement_timeout = '15s'")
            response = role(name, lambda: post(browser, route, values))
            return response.status_code, policy.PROOF in browser.session
        finally:
            connections.close_all()

    # All password hashing/session creation precedes the short real TOTP window.
    web_user, web_password = user(context['namespace'])
    key = ec.generate_private_key(ec.SECP256R1())
    numbers = key.public_key().public_numbers()
    credential = encode(secrets.token_bytes(32))
    rp = central['api']['fqdn']
    UserWebAuthn.objects.create(user=web_user, name='counterless', key_handle=credential,
        public_key=cbor2.dumps({1: 2, 3: -7, -1: 1, -2: numbers.x.to_bytes(32, 'big'), -3: numbers.y.to_bytes(32, 'big')}),
        rp_id=rp, transports=['internal'], sign_count=0)
    web_first = client(); password(web_first, web_user, web_password)
    need(web_first.get(reverse('accounts:verify_webauthn'), secure=True).status_code == 200)
    challenge_value = web_first.session['webauthn_challenge']['challenge']
    data = json.dumps(dict(type='webauthn.get', challenge=challenge_value, origin=api_base_url(), crossOrigin=False), separators=(',', ':')).encode()
    auth_data = hashlib.sha256(rp.encode()).digest() + b'\x01' + bytes(4)
    signature = key.sign(auth_data + hashlib.sha256(data).digest(), ec.ECDSA(hashes.SHA256()))
    assertion = json.dumps(dict(id=credential, rawId=credential, type='public-key', response=dict(
        clientDataJSON=encode(data), authenticatorData=encode(auth_data), signature=encode(signature)), clientExtensionResults={}))
    web_replay = client(); web_replay.cookies = copy.deepcopy(web_first.cookies)
    totp_user, totp_password = user(context['namespace'])
    seed = pyotp.random_base32()
    UserTOTP.objects.create(user=totp_user, name='replay', secret=seed)
    totp_first, totp_replay = client(), client()
    for browser in (totp_first, totp_replay):
        password(browser, totp_user, totp_password)
        need(browser.get(reverse('accounts:verify_totp'), secure=True).status_code == 200)
    need(totp_first.session['verification_token'] != totp_replay.session['verification_token'])
    budget_user, budget_password = user(context['namespace'])
    UserTOTP.objects.create(user=budget_user, name='budget', secret=pyotp.random_base32())
    limited = client(); password(limited, budget_user, budget_password)
    need(limited.get(reverse('accounts:verify_totp'), secure=True).status_code == 200)
    for _ in range(5):
        need(post(limited, 'accounts:verify_totp', dict(verification_code='nototp')).status_code == 200)

    user_logged_in.connect(logged_in, weak=False)
    try:
        with patch.object(policy, '_challenge', side_effect=challenge), patch.object(policy, '_cache_add', side_effect=add), \
             patch.object(policy, '_budget', side_effect=budget), ThreadPoolExecutor(max_workers=2) as pool:
            web_future = pool.submit(pending, 'webauthn-replay', web_replay, 'accounts:verify_webauthn', dict(token_response=assertion))
            try:
                need(held['webauthn-replay'].wait(timeout=10))
                need(role('webauthn-first', lambda: post(web_first, 'accounts:verify_webauthn', dict(token_response=assertion))).status_code == 302)
                need(policy.PROOF in web_first.session and observed['webauthn-first'] == [('challenge', True)])
                # Use an actual current code, not a mocked clock/verifier. Failure
                # to retain sufficient wall-clock headroom is a failed gate.
                deadline = time.monotonic() + 32
                while time.time() % 30 > 0.75:
                    need(time.monotonic() < deadline)
                    time.sleep(0.02)
                counter = int(time.time()) // 30
                code = pyotp.TOTP(seed).now()
                totp_future = pool.submit(pending, 'totp-replay', totp_replay, 'accounts:verify_totp', dict(verification_code=code))
                need(held['totp-replay'].wait(timeout=10))
                need(role('totp-first', lambda: post(totp_first, 'accounts:verify_totp', dict(verification_code=code))).status_code == 302)
                need(policy.PROOF in totp_first.session and observed['totp-first'] == [('challenge', True), ('totp', True)])
                _, redis_client = policy._security_client()
                before_run = redis_client.info('server')['run_id']
                private_phase(root, 'ready.json', dict(context, phase='ready',
                              redis_run_id_sha256=hashlib.sha256(before_run.encode()).hexdigest()))
                wait_resume(root, context)
                from django.core.cache import caches
                caches['azd_santa_security'].client.get_client(write=True).connection_pool.disconnect()
                policy.check_security_store()  # Recheck real marker/settings BEFORE releasing requests.
                _, redis_client = policy._security_client()
                need(redis_client.info('server')['run_id'] != before_run)
                need(int(time.time()) // 30 == counter and pyotp.TOTP(seed).verify(code))
                release['webauthn-replay'].set()
                web_result = web_future.result(timeout=20)
                need(int(time.time()) // 30 == counter and pyotp.TOTP(seed).verify(code))
                release['totp-replay'].set()
                totp_result = totp_future.result(timeout=20)
                budget_status = role('budget-after', lambda: post(limited, 'accounts:verify_totp', dict(verification_code='nototp'))).status_code
                assert_replay_evidence(observed, web_result, totp_result, budget_status,
                                       successes, [web_user.pk, totp_user.pk])
                need(web_first.get(reverse('accounts:profile'), secure=True).status_code == 200)
                need(totp_first.get(reverse('accounts:profile'), secure=True).status_code == 200)
            finally:
                for event in release.values():
                    event.set()
    finally:
        user_logged_in.disconnect(logged_in)
    return dict(webauthn_nonce_rejected=True, totp_step_rejected=True, budget_exhausted=True,
                accepted_logins=2, marker_settings_ready=True, redis_restarted=True)


def run(context):
    context = validate_context(context)
    root = Path('/var/zentral') / context['namespace']; root.mkdir(mode=0o700)
    policy.check_security_store()
    _, selected_redis = policy._security_client()
    need(hashlib.sha256(selected_redis.info('server')['run_id'].encode()).hexdigest() == context['redis_run_id_sha256'])
    need(set(connections) == {'default'} and connection.vendor == 'postgresql'
         and not connection.settings_dict['TEST'].get('MIRROR') and not settings.DEBUG
         and connection.settings_dict['HOST'] == 'db' and connection.settings_dict['NAME'] == 'zentral')
    name = 'azd_restart_' + uuid.uuid4().hex[:24]
    print('Private isolated test database: ' + name, flush=True)
    with connection.cursor() as cursor:
        cursor.execute('SELECT 1 FROM pg_database WHERE datname = %s', [name]); need(cursor.fetchone() is None)
    original_test = copy.deepcopy(connection.settings_dict['TEST'])
    connection.settings_dict['TEST']['NAME'] = name
    runner = DiscoverRunner(verbosity=0, interactive=False, keepdb=False)
    old = None; result = None
    audit = patch.object(BaseEvent, 'post', return_value=None)
    audit.start()
    try:
        runner.setup_test_environment()
        old = runner.setup_databases()
        call_command('collectstatic', interactive=False, verbosity=0)
        configuration = copy.deepcopy(settings.CACHES)
        configuration['azd_santa_security']['KEY_PREFIX'] = context['namespace']
        with override_settings(CACHES=configuration):
            policy.initialize_security_store('fresh')
            result = scenario(context, root)
            cache, redis_client = policy._security_client()
            prefix = (context['namespace'] + ':').encode()
            for key in redis_client.scan_iter(match=cache.make_key('*'), count=100):
                need(key.startswith(prefix))
                redis_client.delete(key)  # This run's exact unique prefix only; no flush.
    except Exception:
        traceback.print_exc()  # Host captures process output only into a private 0600 file.
        result = None
    finally:
        try:
            if old is not None:
                runner.teardown_databases(old)
            runner.teardown_test_environment()
        except Exception:
            traceback.print_exc(); result = None
        connection.settings_dict['TEST'] = original_test
        try:
            queues.stop()
        except Exception:
            traceback.print_exc(); result = None
        audit.stop()
        private_phase(root, 'result.json', dict(context, phase='passed' if result else 'failed',
                      **(dict(result, limitation=LIMITATION) if result else {})))
    return result is not None


if __name__ == '__main__':
    def interrupted(*args):
        raise TimeoutError('Bounded private request qualification interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGALRM, interrupted)
    signal.alarm(330)
    raise SystemExit(0 if run(json.loads(os.environ['AZD_MFA_RESTART_CONTEXT'])) else 2)
