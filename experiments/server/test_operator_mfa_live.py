"""Explicit private Django/PostgreSQL/Redis MFA qualification with synthetic users.

Run inside the qualified core web container after setup. This exercises real
middleware, URLs, sessions, forms and cryptographic verifiers, not direct calls
to form_valid or forged positive MFA flags. Logs/credentials stay private.
"""
import base64
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import secrets
import threading
import time
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from unittest.mock import patch
from urllib.parse import urlsplit

import pyotp
from django.conf import settings
from django.contrib.auth.tokens import default_token_generator
from django.core import mail, signing
from django.core.management import call_command
from django.db import close_old_connections
from django.test import Client, override_settings
from django.test.utils import setup_test_environment, teardown_test_environment
from django.urls import reverse
from django.utils import timezone
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

from accounts.models import APIToken, User, UserTOTP, UserWebAuthn
import azd_santa_operator as policy

PREFIX = 'azd-mfa-' + uuid.uuid4().hex[:24]
PRIVATE = Path('/var/zentral') / PREFIX
REDACTIONS = []
FIXTURES = []


def b64(value):
    return base64.urlsafe_b64encode(value).decode().rstrip('=')


class OperatorRequests(unittest.TestCase):
    sequence = 0

    def client(self):
        return Client(enforce_csrf_checks=True, HTTP_HOST='localhost',
                      HTTP_USER_AGENT='Mozilla/5.0 azd-santa-private-qualification')

    def get(self, client, name, args=None):
        return client.get(reverse(name, args=args), secure=True)

    def post(self, client, name, data, args=None):
        return client.post(reverse(name, args=args), data,
            secure=True, HTTP_REFERER='https://localhost/',
            HTTP_X_CSRFTOKEN=client.cookies.get('csrftoken').value)

    def user(self, *, factors=0, admin=False, service=False):
        type(self).sequence += 1
        name = PREFIX + '-' + str(self.sequence)
        password = secrets.token_urlsafe(30)
        user = User.objects.create_user(username=name, email=name + '@example.invalid',
            password=password, is_superuser=admin, is_staff=False, is_service_account=service)
        seeds = [pyotp.random_base32() for _ in range(factors)]
        devices = [UserTOTP.objects.create(user=user, name='synthetic-' + str(i), secret=seed)
                   for i, seed in enumerate(seeds)]
        REDACTIONS.extend([password, *seeds])
        FIXTURES.append(dict(user=user.pk, username=name, password=password, totp_seeds=seeds))
        return user, password, devices

    def password(self, client, user, password):
        self.assertEqual(self.get(client, 'login').status_code, 200)
        response = self.post(client, 'login', {'username': user.username, 'password': password})
        self.assertEqual(response.status_code, 302)
        return response

    def mfa(self, client, user, password, device):
        response = self.password(client, user, password)
        self.assertEqual(response['Location'], reverse('accounts:verify_totp'))
        self.assertEqual(self.get(client, 'accounts:verify_totp').status_code, 200)
        response = self.post(client, 'accounts:verify_totp', {'verification_code': pyotp.TOTP(device.secret).now()})
        self.assertEqual(response.status_code, 302)
        self.assertIn(policy.PROOF, client.session)
        return response

    def seed(self, client):
        response = self.get(client, 'accounts:add_totp')
        self.assertEqual(response.status_code, 200)
        seed = response.context['form'].initial_secret
        REDACTIONS.append(seed)
        return seed

    def enroll(self, client, seed):
        return self.post(client, 'accounts:add_totp', {
            'name': 'synthetic-' + uuid.uuid4().hex[:8],
            'secret': seed, 'verification_code': pyotp.TOTP(seed).now()})

    def test_first_password_scope_real_setup_and_full_mfa_login(self):
        for admin in (False, True):
            user, password, _ = self.user(admin=admin)
            client = self.client()
            self.password(client, user, password)
            for name in ('accounts:profile', 'accounts:nginx_auth_request', 'accounts:users'):
                response = self.get(client, name)
                self.assertEqual(response.status_code, 302)
                self.assertEqual(response['Location'], reverse('accounts:add_totp'))
            response = self.post(client, 'accounts:create_user_api_token', {}, args=[user.pk])
            self.assertEqual(response.status_code, 302)
            self.assertEqual(user.apitoken_set.count(), 0)
            seed = self.seed(client)
            response = self.enroll(client, seed)
            self.assertEqual(response.status_code, 302)
            self.assertEqual(response['Location'], reverse('login'))
            self.assertNotIn(policy.PROOF, client.session)
            device = user.usertotp_set.get()
            self.mfa(client, user, password, device)
            response = self.get(client, 'accounts:profile')
            self.assertEqual(response.status_code, 200)
            self.assertFalse(response.context['can_add_token'])
            response = self.post(client, 'accounts:create_user_api_token', {}, args=[user.pk])
            self.assertEqual(response.status_code, 403)

    def test_changed_and_missing_seed_or_code_do_not_create_factors(self):
        user, password, _ = self.user()
        client = self.client()
        self.password(client, user, password)
        seed = self.seed(client)
        other = pyotp.random_base32()
        REDACTIONS.append(other)
        for payload in (
            {'name': 'changed', 'secret': other, 'verification_code': pyotp.TOTP(other).now()},
            {'name': 'missing-seed', 'verification_code': pyotp.TOTP(seed).now()},
            {'name': 'missing-code', 'secret': seed},
        ):
            self.assertEqual(self.post(client, 'accounts:add_totp', payload).status_code, 200)
            self.assertEqual(user.usertotp_set.count(), 0)

    def test_legacy_boolean_and_missing_bootstrap_do_not_grant_access(self):
        for factors in (0, 1):
            user, _, _ = self.user(factors=factors, admin=True)
            client = self.client()
            client.force_login(user, backend=policy.LOCAL_BACKEND)  # Deliberately model a legacy session.
            session = client.session
            session['mfa_authenticated'] = True
            session.save()
            response = self.get(client, 'accounts:nginx_auth_request')
            self.assertEqual(response.status_code, 302)
            self.assertEqual(response['Location'], reverse('login'))
            self.assertNotIn(policy.PROOF, client.session)

    def test_bootstrap_is_user_password_and_time_bound(self):
        first, password, _ = self.user()
        client = self.client()
        self.password(client, first, password)
        marker = copy.deepcopy(client.session[policy.ENROLL])
        second, _, _ = self.user()
        client.force_login(second, backend=policy.LOCAL_BACKEND)
        session = client.session
        session[policy.ENROLL] = marker
        session.save()
        self.assertEqual(self.get(client, 'accounts:add_totp')['Location'], reverse('login'))
        for change in ('expired', 'changed-password'):
            user, password, _ = self.user()
            client = self.client()
            self.password(client, user, password)
            if change == 'expired':
                session = client.session
                record = dict(session[policy.ENROLL], issued=time.time() - policy.ENROLL_SECONDS - 1)
                session[policy.ENROLL] = record
                session.save()
            else:
                user.set_password(secrets.token_urlsafe(30)); user.save()
            response = self.get(client, 'accounts:add_totp')
            self.assertEqual(response.status_code, 302)
            location = urlsplit(response['Location'])
            self.assertEqual((location.scheme, location.netloc, location.path), ('', '', reverse('login')))

    def test_pending_challenge_expires_and_password_reset_invalidates_it(self):
        for scenario in ('expiry', 'password-change'):
            user, password, _ = self.user(factors=1)
            client = self.client()
            self.password(client, user, password)
            if scenario == 'expiry':
                session = client.session
                data = signing.loads(session['verification_token'], salt='zentral_verify_token', key=settings.SECRET_KEY)
                old = time.time() - policy.CHALLENGE_SECONDS - 1
                with patch('django.core.signing.time.time', return_value=old):
                    session['verification_token'] = signing.dumps(data, salt='zentral_verify_token', key=settings.SECRET_KEY)
                session.save()
            else:
                user.set_password(secrets.token_urlsafe(30)); user.save()
            response = self.get(client, 'accounts:verify_totp')
            self.assertEqual(response.status_code, 302)
            self.assertEqual(response['Location'], reverse('login'))

    def test_shared_attempt_budget_and_unavailable_cache_fail_closed(self):
        user, password, _ = self.user(factors=1)
        client = self.client()
        self.password(client, user, password)
        self.get(client, 'accounts:verify_totp')
        for _ in range(5):
            self.assertEqual(self.post(client, 'accounts:verify_totp', {'verification_code': 'nototp'}).status_code, 200)
        self.assertEqual(self.post(client, 'accounts:verify_totp', {'verification_code': 'nototp'}).status_code, 429)
        self.assertNotIn(policy.PROOF, client.session)
        configuration = settings.CACHES.serialize() if hasattr(settings.CACHES, 'serialize') else copy.deepcopy(settings.CACHES)
        configuration['azd_santa_security']['LOCATION'] = 'redis://redis:1/2'
        with override_settings(CACHES=configuration):
            another, password, _ = self.user()
            client = self.client()
            self.get(client, 'login')
            response = self.post(client, 'login', {'username': another.username, 'password': password})
            self.assertEqual(response.status_code, 503)
            self.assertNotIn(policy.PROOF, client.session)

    def test_totp_replay_does_not_authenticate_second_session(self):
        user, password, devices = self.user(factors=1)
        first, second = self.client(), self.client()
        # Prepare both challenges before using the code; signed nonces must differ.
        self.password(first, user, password); self.password(second, user, password)
        self.assertNotEqual(first.session['verification_token'], second.session['verification_token'])
        self.get(first, 'accounts:verify_totp'); self.get(second, 'accounts:verify_totp')
        code = pyotp.TOTP(devices[0].secret).now()
        self.assertEqual(self.post(first, 'accounts:verify_totp', {'verification_code': code}).status_code, 302)
        self.assertEqual(self.post(second, 'accounts:verify_totp', {'verification_code': code}).status_code, 403)
        self.assertEqual(self.get(first, 'accounts:profile').status_code, 200)
        self.assertNotIn(policy.PROOF, second.session)

    def test_factor_addition_does_not_renew_eight_hour_proof(self):
        user, password, devices = self.user(factors=1)
        client = self.client()
        self.mfa(client, user, password, devices[0])
        issued = client.session[policy.PROOF]['issued']
        with patch('azd_santa_operator.time.time', return_value=issued + 7 * 3600):
            seed = self.seed(client)
            self.assertEqual(self.enroll(client, seed).status_code, 302)
            self.assertEqual(client.session[policy.PROOF]['issued'], issued)
        with patch('azd_santa_operator.time.time', return_value=issued + 8 * 3600 + 1):
            response = self.get(client, 'accounts:profile')
            self.assertEqual(response.status_code, 302)
            self.assertEqual(response['Location'], reverse('login'))

    def test_last_factor_and_concurrent_two_delete_are_safe(self):
        user, password, devices = self.user(factors=2)
        clients = [self.client(), self.client()]
        for client, device in zip(clients, devices):
            self.mfa(client, user, password, device)
        barrier = threading.Barrier(2)
        def remove(index):
            close_old_connections()
            try:
                barrier.wait(timeout=10)
                return self.post(clients[index], 'accounts:delete_totp', {'password': password}, args=[devices[index].pk]).status_code
            finally:
                close_old_connections()
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(remove, (0, 1)))
        self.assertEqual(user.usertotp_set.count(), 1)
        self.assertTrue(all(result in (302, 403) for result in results))
        # The session that authorized the deletion retains the updated proof.
        owner = next(client for client in clients if self.get(client, 'accounts:profile').status_code == 200)
        remaining = user.usertotp_set.get()
        self.assertEqual(self.post(owner, 'accounts:delete_totp', {'password': password}, args=[remaining.pk]).status_code, 403)
        self.assertEqual(user.usertotp_set.count(), 1)

    def test_factor_replacement_removal_and_deactivation_invalidate_sessions(self):
        for change in ('replace', 'remove', 'deactivate'):
            user, password, devices = self.user(factors=1)
            client = self.client()
            self.mfa(client, user, password, devices[0])
            if change == 'replace':
                UserTOTP.objects.filter(pk=devices[0].pk).update(secret=pyotp.random_base32())
            elif change == 'remove':
                devices[0].delete()
            else:
                User.objects.filter(pk=user.pk).update(is_active=False)
            response = self.get(client, 'accounts:profile')
            self.assertEqual(response.status_code, 302)
            self.assertTrue(response['Location'].startswith(reverse('login')))

    def test_human_api_token_fails_service_identity_and_pbac_remain(self):
        for service in (False, True):
            user, _, _ = self.user(service=service)
            _, key = APIToken.objects.create_for_user(user, name=PREFIX, expiry=timezone.now() + timedelta(hours=1))
            REDACTIONS.append(key)
            client = self.client()
            headers = dict(HTTP_AUTHORIZATION='Token ' + key)
            response = client.get(reverse('base_api:task_result', args=[uuid.uuid4()]), secure=True, **headers)
            self.assertEqual(response.status_code, 200 if service else 401)
            if service:
                response = client.get(reverse('santa_api:configurations'), secure=True, **headers)
                self.assertEqual(response.status_code, 403)

    def reset_password(self, client, user, password):
        url = reverse('password_reset_confirm', args=[urlsafe_base64_encode(force_bytes(user.pk)), default_token_generator.make_token(user)])
        response = client.get(url, secure=True)
        self.assertEqual(response.status_code, 302)
        url = response['Location']
        self.assertEqual(client.get(url, secure=True).status_code, 200)
        response = client.post(url, {'new_password1': password, 'new_password2': password}, secure=True,
            HTTP_REFERER='https://localhost/', HTTP_X_CSRFTOKEN=client.cookies['csrftoken'].value)
        self.assertEqual(response.status_code, 302)

    def test_reset_and_invitation_require_normal_mfa_or_first_enrollment(self):
        user, password, devices = self.user(factors=1)
        client = self.client()
        self.password(client, user, password)
        updated = secrets.token_urlsafe(30); REDACTIONS.append(updated)
        self.reset_password(client, user, updated)
        self.assertEqual(user.usertotp_set.count(), 1)
        self.assertNotIn(policy.PROOF, client.session)
        self.assertEqual(self.get(client, 'accounts:verify_totp')['Location'], reverse('login'))
        self.mfa(client, user, updated, devices[0])
        admin, password, devices = self.user(factors=1, admin=True)
        inviter = self.client(); self.mfa(inviter, admin, password, devices[0])
        invited = PREFIX + '-invited'
        response = self.post(inviter, 'accounts:invite_user', {'username': invited, 'email': invited + '@example.invalid'})
        self.assertEqual(response.status_code, 302)
        target = User.objects.get(username=invited)
        recipient = self.client()
        updated = secrets.token_urlsafe(30); REDACTIONS.append(updated)
        self.reset_password(recipient, target, updated)
        self.password(recipient, target, updated)
        self.assertEqual(self.get(recipient, 'accounts:profile')['Location'], reverse('accounts:add_totp'))
        self.assertEqual(target.usertotp_set.count(), 0)

    def test_expired_password_bootstrap_reaches_setup_then_password_change(self):
        chain = list(settings.MIDDLEWARE)
        force = 'accounts.middleware.force_password_change_middleware'
        if force not in chain:
            chain.insert(chain.index('django.contrib.messages.middleware.MessageMiddleware') + 1, force)
        with override_settings(MAX_PASSWORD_AGE_DAYS=1, MIDDLEWARE=chain):
            user, password, _ = self.user()
            User.objects.filter(pk=user.pk).update(password_updated_at=timezone.now() - timedelta(days=2))
            client = self.client(); self.password(client, user, password)
            seed = self.seed(client)
            self.assertEqual(self.enroll(client, seed).status_code, 302)
            self.mfa(client, user, password, user.usertotp_set.get())
            response = self.get(client, 'accounts:profile')
            self.assertEqual(response.status_code, 302)
            self.assertEqual(response['Location'], reverse('password_change'))
            self.assertEqual(self.get(client, 'password_change').status_code, 200)

    def test_counterless_security_key_same_loaded_challenge_authenticates_once(self):
        import cbor2
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from zentral.conf import api_base_url, settings as central
        user, password, _ = self.user()
        key = ec.generate_private_key(ec.SECP256R1())
        public = key.public_key().public_numbers()
        credential = b64(secrets.token_bytes(32))
        rp = central['api']['fqdn']
        UserWebAuthn.objects.create(user=user, name='counterless', key_handle=credential,
            public_key=cbor2.dumps({1: 2, 3: -7, -1: 1, -2: public.x.to_bytes(32, 'big'), -3: public.y.to_bytes(32, 'big')}),
            rp_id=rp, transports=['internal'], sign_count=0)
        base = self.client()
        response = self.password(base, user, password)
        self.assertEqual(response['Location'], reverse('accounts:verify_webauthn'))
        self.assertEqual(self.get(base, 'accounts:verify_webauthn').status_code, 200)
        challenge = base.session['webauthn_challenge']['challenge']
        data = json.dumps(dict(type='webauthn.get', challenge=challenge, origin=api_base_url(), crossOrigin=False), separators=(',', ':')).encode()
        authenticator = hashlib.sha256(rp.encode()).digest() + b'\x01' + bytes(4)
        signature = key.sign(authenticator + hashlib.sha256(data).digest(), ec.ECDSA(hashes.SHA256()))
        assertion = json.dumps(dict(id=credential, rawId=credential, type='public-key',
            response=dict(clientDataJSON=b64(data), authenticatorData=b64(authenticator), signature=b64(signature)), clientExtensionResults={}))
        clients = [self.client(), self.client()]
        for client in clients:
            client.cookies = copy.deepcopy(base.cookies)
        barrier = threading.Barrier(2)
        original = policy._challenge
        def preloaded(request):
            result = original(request)
            if result is None and request.method == 'POST':
                barrier.wait(timeout=10)
            return result
        def authenticate(index):
            close_old_connections()
            try:
                return self.post(clients[index], 'accounts:verify_webauthn', {'token_response': assertion}).status_code
            finally:
                close_old_connections()
        with patch.object(policy, '_challenge', side_effect=preloaded), ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(authenticate, (0, 1)))
        self.assertEqual(sorted(results), [302, 403])
        authorized = [self.get(client, 'accounts:profile').status_code == 200 for client in clients]
        self.assertEqual(authorized.count(True), 1)


def run():
    if 'azd_santa_operator.RequireOperatorMFA' not in settings.MIDDLEWARE or settings.DEBUG:
        raise RuntimeError('Expected the non-debug qualified operator policy')
    PRIVATE.mkdir(mode=0o700)
    # This one-off container bypasses the normal web entrypoint. Prepare the
    # same real manifest before rendering forms; never substitute dummy storage.
    call_command('collectstatic', interactive=False, verbosity=0)
    setup_test_environment()
    capture = io.StringIO()
    import contextlib
    with contextlib.redirect_stdout(capture), contextlib.redirect_stderr(capture), override_settings(EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend'):
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(OperatorRequests)
        result = unittest.TextTestRunner(stream=capture, verbosity=2).run(suite)
    teardown_test_environment()
    def write(name, text):
        fd = os.open(PRIVATE / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as output:
            output.write(text)
    write('private-tests.log', capture.getvalue())
    write('private-fixtures.json', json.dumps(FIXTURES))
    sanitized = capture.getvalue()
    for secret in sorted(REDACTIONS, key=len, reverse=True):
        sanitized = sanitized.replace(secret, '[REDACTED]')
    write('redacted-tests.log', sanitized)
    receipt = dict(scope='private-real-django-operator-mfa', namespace=PREFIX,
        tests=result.testsRun, passed=result.wasSuccessful(),
        skipped=len(result.skipped),
        failures=[case.id() for case, _ in result.failures], errors=[case.id() for case, _ in result.errors],
        harness_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        policy_sha256=hashlib.sha256(Path(policy.__file__).read_bytes()).hexdigest(),
        limitation='Synthetic operators, direct Django request client; no real-browser/TLS/native-Mac/restore proof')
    write('receipt.json', json.dumps(receipt))
    print(json.dumps(receipt))
    print('SANTA_OPERATOR_MFA_REQUESTS_OK' if result.wasSuccessful() else 'SANTA_OPERATOR_MFA_REQUESTS_FAILED')
    return result.wasSuccessful()


if __name__ == '__main__':
    raise SystemExit(0 if run() else 2)
