"""Explicit real-Django recovery checks in a NEW disposable PostgreSQL database.

Run only on the isolated qualification host using the private shared runner.
No main database rows are reset; BaseEvent.post is mocked to avoid publishing
test-database object IDs into the main event pipeline. Audit delivery is unproven.
Original work released under the Unlicense.
"""
import contextlib
import copy
import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
import hashlib
import io
import json
import os
import re
from pathlib import Path
import secrets
import threading
import time
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit
import uuid

import pyotp
from django.conf import settings
from django.contrib.auth.models import Group
from django.contrib.auth.tokens import default_token_generator
from django.core.management import call_command, CommandError
from django.db import close_old_connections, connection, connections
from django.test import Client, TransactionTestCase, override_settings
from django.test.runner import DiscoverRunner
from accounts.models import User, UserTOTP, UserWebAuthn, APIToken, OIDCAPITokenIssuer
from django.urls import reverse
from zentral.core.events.base import BaseEvent
import azd_santa_operator as policy
import azd_santa_operator_recovery as recovery

PREFIX = 'azd-mfa-' + uuid.uuid4().hex[:24]
PRIVATE = Path('/var/zentral') / PREFIX
EVENTS = []


def post_event(event):
    EVENTS.append(event)


class OperatorRequests(TransactionTestCase):
    reset_sequences = True

    def setUp(self):
        EVENTS.clear()
        # Test DB sequence resets reuse user PKs. Keep real shared Redis and its
        # fail-closed options, but never collide with main/other-test budgets.
        caches = copy.deepcopy(settings.CACHES)
        caches['azd_santa_security']['KEY_PREFIX'] = 'azd-recovery-tests:' + PREFIX + ':' + self._testMethodName
        isolated = override_settings(CACHES=caches)
        isolated.enable()
        self.addCleanup(isolated.disable)
        # Each fresh isolated DB/prefix is deliberately provisioned. Never
        # initialize or flush the product namespace from the request path.
        policy.initialize_security_store('fresh')
        cache, client = policy._security_client()
        marker = cache.make_key(policy.STORE_MARKER)
        self.addCleanup(lambda: client.delete(marker))

    def new_client(self):
        return Client(enforce_csrf_checks=True, HTTP_HOST='localhost', HTTP_USER_AGENT='Mozilla/5.0 synthetic-recovery')

    def user(self, *, factors=0, **flags):
        name = PREFIX + '-' + uuid.uuid4().hex[:8]
        password = secrets.token_urlsafe(30)
        user = User.objects.create_user(name, name + '@example.invalid', password=password, **flags)
        for index in range(factors):
            UserTOTP.objects.create(user=user, name='synthetic-' + str(index), secret=pyotp.random_base32())
        return user, password

    def command(self, mode, user=None, **options):
        name = PREFIX + '-' + uuid.uuid4().hex[:8]
        output = PRIVATE / (uuid.uuid4().hex + '.json')
        params = dict(username=user.username if user else name,
                      email=user.email if user else name + '@example.invalid',
                      reason='synthetic lost-all-factor qualification', output=str(output))
        params.update(options)
        stdout = io.StringIO()
        call_command('operator_access', mode, stdout=stdout, **params)
        data = json.loads(Path(params['output']).read_text())
        if 'setup_url' in data:
            self.assertNotIn(data['setup_url'], stdout.getvalue())
        else:
            self.assertEqual(data['scope'], 'azd-santa-sealed-setup')
            self.assertNotIn('accounts/reset/', stdout.getvalue())
        self.assertEqual(Path(params['output']).stat().st_mode & 0o777, 0o600)
        return data

    def post(self, client, path, body):
        return client.post(path, body, secure=True, HTTP_REFERER='https://localhost/',
                           HTTP_X_CSRFTOKEN=client.cookies['csrftoken'].value)

    def assert_login_redirect(self, response):
        self.assertEqual(response.status_code, 302)
        location = urlsplit(response['Location'])
        self.assertEqual((location.scheme, location.netloc, location.path), ('', '', reverse('login')))

    def password(self, client, user, password):
        client.get(reverse('login'), secure=True)
        return self.post(client, reverse('login'), dict(username=user.username, password=password))

    def load_reset(self, client, artifact):
        response = client.get(urlsplit(artifact['setup_url']).path, secure=True)
        self.assertEqual(response.status_code, 302)
        path = response['Location']
        self.assertEqual(client.get(path, secure=True).status_code, 200)
        return path

    def reset(self, artifact):
        client = self.new_client()
        path = self.load_reset(client, artifact)
        password = secrets.token_urlsafe(30)
        self.assertEqual(self.post(client, path, dict(new_password1=password, new_password2=password)).status_code, 302)
        self.assertNotIn('_auth_user_id', client.session)
        return client, password

    def test_bootstrap_then_password_totp_and_normal_mfa(self):
        service, _ = self.user(is_service_account=True)
        token, _ = APIToken.objects.create_for_user(service, name='preserve-bootstrap')
        artifact = self.command('bootstrap')
        self.assertTrue(APIToken.objects.filter(pk=token.pk).exists())
        user = User.objects.get(pk=artifact['target']['pk'])
        self.assertTrue(user.is_superuser)
        client, password = self.reset(artifact)
        self.assertEqual(self.password(client, user, password).status_code, 302)
        response = client.get(reverse('accounts:profile'), secure=True)
        self.assertEqual(response['Location'], reverse('accounts:add_totp'))
        response = client.get(reverse('accounts:add_totp'), secure=True)
        seed = response.context['form'].initial_secret
        response = self.post(client, reverse('accounts:add_totp'), dict(name='synthetic-recovered', secret=seed,
                              verification_code=pyotp.TOTP(seed).now()))
        self.assertEqual(response['Location'], reverse('login'))
        self.assertNotIn(policy.PROOF, client.session)
        response = self.password(client, user, password)
        self.assertEqual(response['Location'], reverse('accounts:verify_totp'))
        client.get(response['Location'], secure=True)
        self.assertEqual(self.post(client, reverse('accounts:verify_totp'), dict(verification_code=pyotp.TOTP(seed).now())).status_code, 302)
        self.assertEqual(client.get(reverse('accounts:profile'), secure=True).status_code, 200)
        # The isolated test DB is still empty of Santa configurations. Exercise
        # its authenticated real template, including the optional Jamf link.
        from zentral.contrib.santa.models import Configuration
        self.assertEqual(Configuration.objects.count(), 0)
        self.assertEqual(client.get(reverse('santa:index'), secure=True).status_code, 200)

    def test_any_existing_human_blocks_bootstrap_including_inactive_and_remote(self):
        for flags in ({'is_active': False}, {'is_remote': True}, {}):
            user, _ = self.user(**flags)
            with self.assertRaises(CommandError):
                self.command('bootstrap')
            User.objects.filter(pk=user.pk).delete()

    def test_recovery_preserves_roles_and_other_accounts_removes_all_human_credentials(self):
        user, old_password = self.user(factors=2, is_superuser=True)
        group = Group.objects.create(name=PREFIX)
        user.groups.add(group)
        UserWebAuthn.objects.create(user=user, name='synthetic-key', key_handle='synthetic-key', public_key=b'synthetic',
                                   rp_id='localhost', transports=['internal'], sign_count=0)
        APIToken.objects.create_for_user(user, name='synthetic-legacy-human')
        OIDCAPITokenIssuer.objects.create(user=user, name=PREFIX, issuer_uri='https://issuer.example.invalid', audience='synthetic', cel_condition='true')
        other, _ = self.user(factors=1)
        service, _ = self.user(is_service_account=True)
        token, _ = APIToken.objects.create_for_user(service, name='preserve')
        previous_other = other.password
        artifact = self.command('recover', user)
        user.refresh_from_db(); other.refresh_from_db()
        self.assertTrue(user.is_superuser)
        self.assertEqual(list(user.groups.values_list('pk', flat=True)), [group.pk])
        self.assertFalse(user.check_password(old_password))
        self.assertEqual(user.usertotp_set.count() + user.userwebauthn_set.count(), 0)
        self.assertFalse(APIToken.objects.filter(user=user).exists())
        self.assertFalse(OIDCAPITokenIssuer.objects.filter(user=user).exists())
        self.assertEqual(other.password, previous_other)
        self.assertEqual(other.usertotp_set.count(), 1)
        self.assertTrue(APIToken.objects.filter(pk=token.pk).exists())
        event = next(event for event in EVENTS if 'operator_access' in event.payload)
        self.assertEqual(event.payload['operator_access']['removed'], dict(totp=2, webauthn=1, human_tokens=1, human_oidc_issuers=1))
        self.assertEqual(event.payload['operator_access']['mode'], 'recover')
        self.assertNotIn(artifact['setup_url'], json.dumps(event.payload, default=str))
        self.assertNotIn(old_password, json.dumps(event.payload, default=str))

    def test_exact_target_and_account_type_checks_precede_security_changes(self):
        user, _ = self.user(factors=1)
        previous = user.password
        with self.assertRaises(CommandError):
            self.command('recover', user, email='wrong@example.invalid')
        user.refresh_from_db()
        self.assertEqual(user.password, previous)
        self.assertEqual(user.usertotp_set.count(), 1)
        for flags in ({'is_remote': True}, {'is_service_account': True}, {'is_active': False}):
            invalid, _ = self.user(**flags)
            with self.assertRaises(CommandError):
                self.command('recover', invalid)

    def test_existing_sessions_challenges_seed_and_reset_link_are_invalidated(self):
        user, password = self.user()
        seed_client = self.new_client()
        self.password(seed_client, user, password)
        seed_client.get(reverse('accounts:add_totp'), secure=True)
        device = UserTOTP.objects.create(user=user, name='synthetic-old', secret=pyotp.random_base32())
        authenticated = self.new_client()
        location = self.password(authenticated, user, password)['Location']
        authenticated.get(location, secure=True)
        self.assertEqual(self.post(authenticated, location, dict(verification_code=pyotp.TOTP(device.secret).now())).status_code, 302)
        pending = self.new_client()
        self.password(pending, user, password)
        old_link = dict(setup_url=recovery_url(user))
        reset_client = self.new_client(); old_reset_path = self.load_reset(reset_client, old_link)
        old_token = default_token_generator.make_token(user)
        self.command('recover', user)
        user.refresh_from_db()
        self.assertFalse(default_token_generator.check_token(user, old_token))
        for client in (seed_client, authenticated, pending):
            response = client.get(reverse('accounts:profile'), secure=True)
            self.assert_login_redirect(response)
        response = self.post(reset_client, old_reset_path, dict(new_password1='new-password-never-applied', new_password2='new-password-never-applied'))
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.context['validlink'])

    def test_expiry_and_sequential_one_use(self):
        user, _ = self.user()
        artifact = self.command('recover', user)
        with patch.object(default_token_generator, '_now', return_value=default_token_generator._now() + timedelta(seconds=601)):
            response = self.new_client().get(urlsplit(artifact['setup_url']).path, secure=True)
            self.assertEqual(response.status_code, 200)
            self.assertFalse(response.context['validlink'])
        self.reset(artifact)
        response = self.new_client().get(urlsplit(artifact['setup_url']).path, secure=True)
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.context['validlink'])

    def test_simultaneous_reset_posts_have_only_one_success(self):
        user, _ = self.user()
        artifact = self.command('recover', user)
        clients = [self.new_client(), self.new_client()]
        paths = [self.load_reset(client, artifact) for client in clients]
        barrier = threading.Barrier(2)
        def reset(index):
            close_old_connections()
            try:
                barrier.wait(timeout=10)
                password = secrets.token_urlsafe(30)
                return self.post(clients[index], paths[index], dict(new_password1=password, new_password2=password)).status_code
            finally:
                connections.close_all()
        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(sorted(pool.map(reset, (0, 1))), [200, 302])

    def test_concurrent_bootstrap_creates_exactly_one_human(self):
        barrier = threading.Barrier(2)
        def bootstrap(index):
            close_old_connections()
            try:
                barrier.wait(timeout=10)
                self.command('bootstrap')
                return True
            except CommandError:
                return False
            finally:
                connections.close_all()
        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(sorted(pool.map(bootstrap, (0, 1))), [False, True])
        self.assertEqual(User.objects.filter(is_service_account=False).count(), 1)

    def test_existing_output_is_unchanged_and_postcommit_failure_is_truthful(self):
        user, _ = self.user(factors=1)
        path = PRIVATE / (uuid.uuid4().hex + '.json')
        path.write_text('preserve'); path.chmod(0o600)
        original = user.password
        with self.assertRaises(CommandError):
            self.command('recover', user, output=str(path))
        user.refresh_from_db()
        self.assertEqual(user.password, original)
        self.assertEqual(path.read_text(), 'preserve')
        with patch.object(recovery.json, 'dump', side_effect=OSError('synthetic output failure')):
            with self.assertRaisesMessage(CommandError, 'committed but setup artifact write failed'):
                self.command('recover', user)
        user.refresh_from_db()
        self.assertNotEqual(user.password, original)
        self.assertEqual(user.usertotp_set.count(), 0)

    def test_audit_failure_after_commit_preserves_private_link_and_reports_phase(self):
        user, _ = self.user(factors=1)
        previous = user.password
        path = PRIVATE / (uuid.uuid4().hex + '.json')
        with patch.object(BaseEvent, 'post', side_effect=RuntimeError('synthetic audit failure')):
            with self.assertRaisesMessage(CommandError, 'committed and private setup artifact written; audit submission failed'):
                self.command('recover', user, output=str(path))
        user.refresh_from_db()
        self.assertNotEqual(user.password, previous)
        self.assertEqual(user.usertotp_set.count(), 0)
        artifact = json.loads(path.read_text())
        self.assertIn('setup_url', artifact)
        self.assertIn('not delivery proof', artifact['audit'])

    def test_sealed_recipient_validation_has_no_user_or_output_side_effects(self):
        user, _ = self.user(factors=1)
        previous = user.password
        path = PRIVATE / (uuid.uuid4().hex + '.json')
        with self.assertRaisesMessage(CommandError, 'before user security changes'):
            self.command('recover', user, output=str(path), recipient_public_key='not-base64', context_sha256='c' * 64)
        user.refresh_from_db()
        self.assertEqual(user.password, previous)
        self.assertEqual(user.usertotp_set.count(), 1)
        self.assertFalse(path.exists())

    def test_sealed_setup_export_and_encrypt_failure_are_private_and_transactional(self):
        from cryptography.hazmat.primitives import serialization, hashes
        from cryptography.hazmat.primitives.asymmetric import rsa, padding
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        import azd_santa_sealed_setup as sealed
        user, _ = self.user(factors=1)
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        public = base64.b64encode(key.public_key().public_bytes(serialization.Encoding.DER,
                                                              serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
        previous = user.password
        with patch.object(sealed.Recipient, 'seal', side_effect=RuntimeError('synthetic encryption failure')):
            with self.assertRaisesMessage(CommandError, 'No confirmed access commit'):
                self.command('recover', user, recipient_public_key=public, context_sha256='c' * 64, sealed_stdout=True)
        user.refresh_from_db()
        self.assertEqual(user.password, previous)
        self.assertEqual(user.usertotp_set.count(), 1)
        envelope = self.command('recover', user, recipient_public_key=public, context_sha256='c' * 64, sealed_stdout=True)
        self.assertLessEqual(len(json.dumps(envelope, separators=(',', ':')).encode()), 2600)
        decode = lambda name: base64.b64decode(envelope[name], validate=True)
        symmetric = key.decrypt(decode('wrapped_key_base64'), padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        payload = json.loads(AESGCM(symmetric).decrypt(decode('nonce_base64'), decode('ciphertext_base64'),
            sealed.aad(envelope['mode'], envelope['kid_sha256'], envelope['context_sha256'], envelope['target_sha256'])))
        self.assertEqual(payload['target_pk'], user.pk)
        self.assertEqual(set(payload), {'setup_url', 'expires_at_unix', 'target_pk'})
        self.reset(payload)
        # A write failure after commit must not export a success marker or a
        # cleartext fallback. The account reset remains a real committed fact.
        user.refresh_from_db()
        previous = user.password
        output = PRIVATE / (uuid.uuid4().hex + '.json')
        stdout = io.StringIO()
        with patch.object(recovery.json, 'dump', side_effect=OSError('synthetic sealed output failure')):
            with self.assertRaisesMessage(CommandError, 'committed but setup artifact write failed'):
                call_command('operator_access', 'recover', username=user.username, email=user.email,
                             reason='Synthetic sealed output failure test', output=str(output),
                             recipient_public_key=public, context_sha256='c' * 64,
                             sealed_stdout=True, stdout=stdout)
        user.refresh_from_db()
        self.assertNotEqual(user.password, previous)
        self.assertNotIn('SANTA_SEALED_SETUP_JSON:', stdout.getvalue())
        self.assertNotIn('accounts/reset/', stdout.getvalue())
        self.assertEqual(output.read_bytes(), b'')

    def test_counterless_webauthn_and_recovery_serialize_in_both_lock_orders(self):
        import cbor2
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from zentral.conf import api_base_url, settings as central

        def encode(raw):
            return base64.urlsafe_b64encode(raw).decode().rstrip('=')

        for first in ('verify', 'recover'):
            with self.subTest(first=first):
                user, password = self.user()
                previous_hash = user.password
                key = ec.generate_private_key(ec.SECP256R1())
                public = key.public_key().public_numbers()
                credential = encode(secrets.token_bytes(32))
                rp = central['api']['fqdn']
                UserWebAuthn.objects.create(user=user, name='synthetic-counterless', key_handle=credential,
                    public_key=cbor2.dumps({1: 2, 3: -7, -1: 1, -2: public.x.to_bytes(32, 'big'), -3: public.y.to_bytes(32, 'big')}),
                    rp_id=rp, transports=['internal'], sign_count=0)
                client = self.new_client()
                response = self.password(client, user, password)
                self.assertEqual(response['Location'], reverse('accounts:verify_webauthn'))
                self.assertEqual(client.get(response['Location'], secure=True).status_code, 200)
                challenge = client.session['webauthn_challenge']['challenge']
                data = json.dumps(dict(type='webauthn.get', challenge=challenge, origin=api_base_url(),
                                       crossOrigin=False), separators=(',', ':')).encode()
                authenticator = hashlib.sha256(rp.encode()).digest() + b'\x01' + bytes(4)
                signature = key.sign(authenticator + hashlib.sha256(data).digest(), ec.ECDSA(hashes.SHA256()))
                assertion = json.dumps(dict(id=credential, rawId=credential, type='public-key', response=dict(
                    clientDataJSON=encode(data), authenticatorData=encode(authenticator), signature=encode(signature)),
                    clientExtensionResults={}))
                locked = threading.Event()
                contending = threading.Event()
                release = threading.Event()
                backend_pids = {}

                def observe(role):
                    def wrapper(execute, sql, params, many, context):
                        statement = sql.upper()
                        target_lock = (statement.lstrip().startswith('SELECT')
                                       and 'FROM "ACCOUNTS_USER"' in statement
                                       and 'FOR UPDATE' in statement
                                       and any(value in (params or ()) for value in (user.pk, user.username)))
                        if target_lock and role != first:
                            contending.set()
                        result = execute(sql, params, many, context)
                        if target_lock and role == first and not locked.is_set():
                            locked.set()
                            if not release.wait(timeout=10):
                                raise RuntimeError('Synthetic lock-order observation timed out')
                        return result
                    return wrapper

                def operation(role):
                    close_old_connections()
                    try:
                        # Bound genuine PostgreSQL waits, not mocked lock/crypto
                        # outcomes. A missing user-first lock is a test failure.
                        with connection.cursor() as cursor:
                            cursor.execute('SELECT pg_backend_pid()')
                            backend_pids[role] = cursor.fetchone()[0]
                            cursor.execute("SET lock_timeout = '8s'")
                            cursor.execute("SET statement_timeout = '15s'")
                        with connection.execute_wrapper(observe(role)):
                            if role == 'recover':
                                return self.command('recover', user)
                            result = self.post(client, reverse('accounts:verify_webauthn'), dict(token_response=assertion))
                            return result.status_code, policy.PROOF in client.session
                    finally:
                        connections.close_all()

                other = 'recover' if first == 'verify' else 'verify'
                with ThreadPoolExecutor(max_workers=2) as pool:
                    leader = pool.submit(operation, first)
                    try:
                        self.assertTrue(locked.wait(timeout=10), 'Leader did not acquire the target user row first')
                        follower = pool.submit(operation, other)
                        self.assertTrue(contending.wait(timeout=10), 'Other operation did not contend for the target user row')
                        # Observe PostgreSQL's actual wait graph rather than
                        # assuming a pre-execute thread event proves blocking.
                        deadline = time.monotonic() + 5
                        blocked = False
                        while time.monotonic() < deadline:
                            with connection.cursor() as cursor:
                                cursor.execute('SELECT pg_blocking_pids(%s)', [backend_pids[other]])
                                blocked = backend_pids[first] in cursor.fetchone()[0]
                            if blocked:
                                break
                            time.sleep(0.02)
                        self.assertTrue(blocked, 'PostgreSQL did not confirm the expected user-row wait')
                    finally:
                        release.set()
                    results = {first: leader.result(timeout=25), other: follower.result(timeout=25)}
                status, proof = results['verify']
                self.assertIn(status, (200, 302, 403))
                if first == 'verify':
                    self.assertEqual((status, proof), (302, True))
                else:
                    self.assertFalse(proof)
                user.refresh_from_db()
                self.assertNotEqual(user.password, previous_hash)
                self.assertFalse(user.check_password(password))
                self.assertEqual(user.usertotp_set.count() + user.userwebauthn_set.count(), 0)
                self.assert_login_redirect(client.get(reverse('accounts:profile'), secure=True))
                _, new_password = self.reset(results['recover'])
                user.refresh_from_db()
                self.assertTrue(user.check_password(new_password))
                self.assertEqual(user.usertotp_set.count() + user.userwebauthn_set.count(), 0)


def recovery_url(user):
    from accounts.password_reset import handler
    # Successful login updates last_login through a freshly loaded user. Reset
    # tokens bind that value; create the baseline link from current DB state.
    user.refresh_from_db()
    return handler.generate_password_reset_url(user)


def case_identity(case):
    # unittest includes subtest parameters in _SubTest.id(). Export only the
    # reviewed parent method name; parameter values belong in private logs.
    identity = getattr(case, 'test_case', case).id()
    if not re.fullmatch(r'__main__\.OperatorRequests\.test_[a-z0-9_]+', identity):
        raise RuntimeError('Unrecognized recovery request test identity')
    return identity


def run():
    PRIVATE.mkdir(mode=0o700)
    capture = io.StringIO()
    name = 'azd_recovery_' + uuid.uuid4().hex[:24]
    if (set(connections) != {'default'} or not re.fullmatch(r'azd_recovery_[0-9a-f]{24}', name)
            or connection.settings_dict['TEST'].get('MIRROR') or connection.vendor != 'postgresql'
            or settings.DEBUG or settings.PASSWORD_RESET_TIMEOUT != 600):
        raise RuntimeError('Expected the reviewed private PostgreSQL/non-debug/reset policy')
    # Never let Django's test runner destroy or reuse a pre-existing database.
    with connection.cursor() as cursor:
        cursor.execute('SELECT 1 FROM pg_database WHERE datname = %s', [name])
        if cursor.fetchone():
            raise RuntimeError('Generated isolated test database already exists')
    original = copy.deepcopy(connection.settings_dict['TEST'])
    connection.settings_dict['TEST']['NAME'] = name
    runner = DiscoverRunner(verbosity=0, interactive=False, keepdb=False)
    def write(filename, value):
        fd = os.open(PRIVATE / filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as output:
            output.write(value)
    with contextlib.redirect_stdout(capture), contextlib.redirect_stderr(capture), patch.object(BaseEvent, 'post', post_event):
        runner.setup_test_environment()
        old = None
        try:
            old = runner.setup_databases()
            call_command('collectstatic', interactive=False, verbosity=0)
            result = unittest.TextTestRunner(stream=capture, verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(OperatorRequests))
        finally:
            try:
                if old is not None:
                    runner.teardown_databases(old)
            finally:
                try:
                    runner.teardown_test_environment()
                finally:
                    connection.settings_dict['TEST'] = original
                    # A cleanup error must not discard the only private record
                    # of earlier request failures. It still prevents acceptance.
                    write('private-tests.log', capture.getvalue())
    receipt = dict(scope='private-real-django-operator-recovery', namespace=PREFIX,
        tests=result.testsRun, passed=result.wasSuccessful(), skipped=len(result.skipped),
        failures=[case_identity(case) for case, _ in result.failures], errors=[case_identity(case) for case, _ in result.errors],
        harness_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        policy_sha256=hashlib.sha256(Path(policy.__file__).read_bytes()).hexdigest(),
        recovery_sha256=hashlib.sha256(Path(recovery.__file__).read_bytes()).hexdigest(),
        database_scope='Disposable isolated PostgreSQL test database; audit posting mocked, delivery unproven',
        limitation='Synthetic operators, direct Django request client; no real-browser/TLS/native-Mac/restore proof')
    write('receipt.json', json.dumps(receipt))
    print(json.dumps(receipt))
    return result.wasSuccessful()


if __name__ == '__main__':
    raise SystemExit(0 if run() else 2)
