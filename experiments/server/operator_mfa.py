"""Original local-operator policy for the pinned private Zentral core build.

Human browser access requires a fresh, factor-bound proof. API automation retains
dedicated service identities and upstream PBAC; device sync has its own authority.
Installed by the image builder, never by a customer editing Django settings.
Original work released under the Unlicense.
"""
import json
import os
import re
import secrets
import time
from contextlib import nullcontext

import pyotp
from django.contrib.auth import get_user_model, logout
from django.core import signing
from django.core.cache import caches
from django.core.exceptions import ImproperlyConfigured, PermissionDenied
from django.db import transaction
from django.http import HttpResponse, HttpResponseRedirect
from django.urls import Resolver404, resolve, reverse
from django.utils.crypto import constant_time_compare, salted_hmac

LOCAL_BACKEND = 'accounts.auth_backends.ZentralBackend'
ENROLL = 'azd_santa_enrollment_v1'
PROOF = 'azd_santa_mfa_v1'
SEED = 'azd_santa_factor_seed_v1'
SETUP = 'accounts:add_totp'
VERIFY = {'accounts:verify_totp', 'accounts:verify_webauthn'}
DELETE = {'accounts:delete_totp', 'accounts:delete_webauthn_device'}
ENROLL_SECONDS = 600
CHALLENGE_SECONDS = 300
PROOF_SECONDS = 8 * 3600
STORE_MARKER = 'security-store-instance-v1'
STORE_SETTINGS = {'appendonly': 'yes', 'appendfsync': 'always',
                  'aof-load-truncated': 'no', 'maxmemory-policy': 'noeviction',
                  'no-appendfsync-on-rewrite': 'no'}
STORE_GUARD = '''
local marker = redis.call('GET', KEYS[1])
if not marker then return redis.error_reply('SECURITY_STORE_UNAVAILABLE') end
local id, ready = string.match(marker, '^([0-9a-f]+):(%d+)$')
if id ~= ARGV[1] or not ready or tonumber(ready) > tonumber(redis.call('TIME')[1]) then
    return redis.error_reply('SECURITY_STORE_UNAVAILABLE')
end
'''


def install_policy(namespace):
    """Run while settings are loading; do not import any Django models here."""
    from urllib.parse import urlsplit, urlunsplit
    store_id = os.environ.get('AZD_SANTA_SECURITY_STORE_ID', '')
    if not re.fullmatch(r'[0-9a-f]{64}', store_id):
        raise ImproperlyConfigured('Configure the private security-store identity before startup')
    namespace['AZD_SANTA_SECURITY_STORE_ID'] = store_id
    cache = namespace.get('CACHES', {}).get('default', {})
    location = cache.get('LOCATION')
    if not isinstance(location, str) or urlsplit(location).scheme not in ('redis', 'rediss'):
        raise ImproperlyConfigured('Operator MFA requires the shared Redis cache')
    url = urlsplit(location)
    namespace['CACHES']['azd_santa_security'] = {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': urlunsplit((url.scheme, url.netloc, '/2', url.query, url.fragment)),
        'KEY_PREFIX': 'azd-santa-security-v1',
        'OPTIONS': {'CLIENT_CLASS': 'django_redis.client.DefaultClient', 'IGNORE_EXCEPTIONS': False,
                    'SOCKET_CONNECT_TIMEOUT': 2, 'SOCKET_TIMEOUT': 2},
    }
    chain = namespace['MIDDLEWARE']
    chain.insert(chain.index('realms.middlewares.realm_session_middleware') + 1,
                 'azd_santa_operator.RequireOperatorMFA')
    chain.insert(0, 'azd_santa_admission.Admission')


def _digest(value):
    return salted_hmac('azd-santa.operator-mfa-v1', json.dumps(value, sort_keys=True)).hexdigest()


def _material(device):
    if device.TYPE == 'TOTP':
        value = [device.TYPE, device.pk, device.secret]
    else:
        value = [device.TYPE, device.pk, device.key_handle, bytes(device.public_key).hex(), device.rp_id]
    return _digest(value)


def _factors(user):
    devices = list(user.usertotp_set.all()) + list(user.userwebauthn_set.all())
    return sorted(_material(device) for device in devices)


def _local(user, request=None):
    return (user.is_authenticated and user.is_active and not user.is_remote
            and not user.is_service_account and user.has_usable_password()
            and (request is None or request.session.get('_auth_user_backend') == LOCAL_BACKEND))


def _stamp(user):
    return {'user': str(user.pk), 'auth': user.get_session_auth_hash()}


def _fresh(record, user, ttl):
    if not isinstance(record, dict) or any(record.get(k) != v for k, v in _stamp(user).items()):
        return False
    issued = record.get('issued')
    return type(issued) in (int, float) and 0 <= time.time() - issued <= ttl


def _proof(request, user, factors):
    proof = request.session.get(PROOF)
    return (bool(factors) and _fresh(proof, user, PROOF_SECONDS)
            and request.session.get('mfa_authenticated') is True
            and constant_time_compare(str(proof.get('factors')), _digest(factors)))


def begin_enrollment(request, user):
    if not _local(user, request) or _factors(user):
        logout(request)
        raise PermissionDenied('Fresh local password authentication is required')
    for key in (PROOF, SEED, 'mfa_authenticated', 'verification_token', 'webauthn_challenge'):
        request.session.pop(key, None)
    request.session[ENROLL] = dict(_stamp(user), issued=time.time())


def enrollment_seed(session, user):
    factors = _factors(user)
    proof = session.get(PROOF)
    valid_proof = (factors and _fresh(proof, user, PROOF_SECONDS)
                   and constant_time_compare(str(proof.get('factors')), _digest(factors)))
    if not _local(user) or not (valid_proof or (not factors and _fresh(session.get(ENROLL), user, ENROLL_SECONDS))):
        raise PermissionDenied('Restart verification setup after signing in')
    seed = session.get(SEED)
    if not _fresh(seed, user, ENROLL_SECONDS):
        seed = dict(_stamp(user), issued=time.time(), value=pyotp.random_base32())
        session[SEED] = seed
    return seed['value']


def check_seed(session, user, submitted):
    return isinstance(submitted, str) and constant_time_compare(enrollment_seed(session, user), submitted)


def _security_client():
    cache = caches['azd_santa_security']
    client = cache.client.get_client(write=True)
    config = client.config_get(*STORE_SETTINGS)
    config = {(k.decode() if isinstance(k, bytes) else k):
              (v.decode() if isinstance(v, bytes) else v) for k, v in config.items()}
    state = client.info('persistence')
    if any(config.get(key) != value for key, value in STORE_SETTINGS.items()) or state.get('aof_last_write_status') != 'ok':
        raise ImproperlyConfigured('Security-store persistence is not ready')
    return cache, client


def _expected_store_id():
    from django.conf import settings
    return settings.AZD_SANTA_SECURITY_STORE_ID


def _store_operation(script, key=None, *arguments):
    cache, client = _security_client()
    keys = [cache.make_key(STORE_MARKER)]
    if key is not None:
        keys.append(cache.make_key(key))
    # Marker check and mutation share one Redis operation: replacement between
    # a separate GET and SET must never admit a claim into an empty store.
    return client.eval(STORE_GUARD + script, len(keys), *keys,
                       _expected_store_id(), *arguments)


def check_security_store():
    _store_operation('return 1')


def _cache_add(key, value, seconds):
    if value is not True:
        raise ValueError('Security claims must be boolean')
    return bool(_store_operation(
        "if redis.call('SET', KEYS[2], '1', 'NX', 'EX', ARGV[2]) then return 1 else return 0 end", key, seconds))


def _budget(key, maximum, seconds=CHALLENGE_SECONDS):
    count = _store_operation('''
local count = redis.call('GET', KEYS[2])
if not count then redis.call('SET', KEYS[2], '1', 'EX', ARGV[2]); return 1 end
if not string.match(count, '^%d+$') or tonumber(count) < 1 then
    return redis.error_reply('SECURITY_STORE_UNAVAILABLE')
end
if tonumber(count) >= tonumber(ARGV[3]) then return tonumber(ARGV[3]) + 1 end
return redis.call('INCR', KEYS[2])
''', key, seconds, maximum)
    return count <= maximum


def _fresh_authority_empty():
    from zentral.contrib.inventory.models import EnrollmentSecret
    return not get_user_model().objects.exists() and not EnrollmentSecret.objects.exists()


def initialize_security_store(mode, *, confirm_quiesced=False):
    """Privileged explicit setup; never called by middleware or normal startup."""
    if mode == 'fresh':
        if not _fresh_authority_empty():
            raise ImproperlyConfigured('Fresh initialization requires a new database without accounts or enrollment credentials')
    elif mode != 'migrate' or not confirm_quiesced:
        raise ImproperlyConfigured('Migration requires explicit quiescence confirmation')
    cache, client = _security_client()
    delay = CHALLENGE_SECONDS + 60 if mode == 'migrate' else 0
    if mode == 'fresh':
        from azd_santa_admission import initialize_fresh
        result = initialize_fresh(cache, client, _expected_store_id(), delay, STORE_MARKER)
    else:
        result = client.eval('''
if redis.call('EXISTS', KEYS[1]) ~= 0 then return 0 end
local ready = tonumber(redis.call('TIME')[1]) + tonumber(ARGV[2])
redis.call('SET', KEYS[1], ARGV[1] .. ':' .. tostring(ready))
return 1
''', 1, cache.make_key(STORE_MARKER), _expected_store_id(), delay)
    if result != 1:
        raise ImproperlyConfigured('Security-store marker already exists; inspect configuration and state instead of reinitializing')


def security_store_command_class():
    from django.core.management.base import BaseCommand, CommandError

    class Command(BaseCommand):
        help = 'Explicit private security-store initialization/check; never runs automatically.'

        def add_arguments(self, parser):
            parser.add_argument('mode', choices=('fresh', 'migrate', 'check'))
            parser.add_argument('--confirm-quiesced', action='store_true',
                                help='Confirm old application processes are stopped; migration enforces an additional six-minute admission hold')

        def handle(self, *args, **options):
            try:
                if options['mode'] == 'check':
                    check_security_store()
                else:
                    initialize_security_store(options['mode'], confirm_quiesced=options['confirm_quiesced'])
            except Exception:
                raise CommandError('Security store is not admitted; inspect private persistence/configuration state. No marker was silently repaired.') from None
            self.stdout.write('Security-store operation completed; migration hold may still block authentication.')

    return Command


def challenge_nonce():
    return secrets.token_urlsafe(32)


def prepare_mfa(request, user, device, code=None, *, verification_token):
    """Accept the factor before Django emits its successful-login signal."""
    fresh_user = get_user_model().objects.get(pk=user.pk)
    if (not _local(fresh_user) or device is None
            or getattr(user, 'backend', None) != LOCAL_BACKEND):
        logout(request)
        raise PermissionDenied('Sign in again')
    factors = _factors(fresh_user)
    material = _material(device)
    if material not in factors:
        logout(request)
        raise PermissionDenied('Verification method changed; sign in again')
    # The pre-authentication session may already have been loaded by another
    # request. Claim a signed random challenge, not the rotated session key or a
    # WebAuthn signature counter (some authenticators always report zero).
    try:
        from django.conf import settings
        data = signing.loads(verification_token, salt='zentral_verify_token',
                             key=settings.SECRET_KEY, max_age=CHALLENGE_SECONDS)
        nonce = data.get('azd_nonce')
        valid = (data.get('user_id') == user.pk and data.get('auth_backend') == LOCAL_BACKEND
                 and data.get('azd_auth_hash') == fresh_user.get_session_auth_hash()
                 and isinstance(nonce, str) and re.fullmatch(r'[A-Za-z0-9_-]{43}', nonce))
        claimed = valid and _cache_add('challenge-used:' + _digest(verification_token), True, CHALLENGE_SECONDS + 60)
    except Exception:
        claimed = False
    if not claimed:
        logout(request)
        raise PermissionDenied('Verification expired or was already used; sign in again')
    if device.TYPE == 'TOTP':
        # Original verification already succeeded. Find that exact timestep,
        # allowing a boundary crossing during form processing, then claim once.
        counter = int(time.time()) // 30
        matched = next((c for c in (counter, counter - 1)
                        if isinstance(code, str) and constant_time_compare(pyotp.TOTP(device.secret).at(c * 30), code)), None)
        try:
            accepted = matched is not None and _cache_add('totp-used:' + material + ':' + str(matched), True, 120)
        except Exception:
            logout(request)
            raise PermissionDenied('Verification is temporarily unavailable') from None
        if not accepted:
            logout(request)
            raise PermissionDenied('Use a new verification code and sign in again')
    return fresh_user, dict(_stamp(fresh_user), issued=time.time(), factors=_digest(factors))


def complete_mfa(request, proof):
    """Attach the accepted request-local proof after Django rotates the session."""
    request.session[PROOF] = proof
    request.session['mfa_authenticated'] = True
    for key in (ENROLL, SEED, 'verification_token', 'webauthn_challenge'):
        request.session.pop(key, None)


def _login(request):
    logout(request)
    return HttpResponseRedirect(reverse('login'))


def _challenge(request):
    try:
        from django.conf import settings
        data = signing.loads(request.session['verification_token'], salt='zentral_verify_token',
                             key=settings.SECRET_KEY, max_age=CHALLENGE_SECONDS)
        user = get_user_model().objects.get(pk=data['user_id'])
        if (not _local(user) or data.get('auth_backend') != LOCAL_BACKEND
                or not isinstance(data.get('azd_nonce'), str)
                or not re.fullmatch(r'[A-Za-z0-9_-]{43}', data['azd_nonce'])
                or not constant_time_compare(data.get('azd_auth_hash', ''), user.get_session_auth_hash()) or not _factors(user)):
            return _login(request)
    except (KeyError, TypeError, ValueError, signing.BadSignature, get_user_model().DoesNotExist):
        return _login(request)
    if request.method == 'POST':
        try:
            allowed = _budget('verify:' + str(user.pk), 5)
        except Exception:
            return HttpResponse('Verification is temporarily unavailable. Try again later.', status=503)
        if not allowed:
            return HttpResponse('Too many verification attempts. Try again later.', status=429)
    return None


class RequireOperatorMFA:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        try:
            match = resolve(request.path_info, urlconf=getattr(request, 'urlconf', None))
            name = match.view_name
        except Resolver404:
            name = None
        if name != 'logout' and (request.user.is_authenticated or (name == 'login' and request.method == 'POST') or name in VERIFY):
            try:
                check_security_store()
            except Exception:
                return HttpResponse('Sign-in is temporarily unavailable. Try again later.', status=503)
        if name and name.startswith('realms_public:'):
            return HttpResponse('Use the local operator sign-in for this deployment.', status=403)
        if not request.user.is_authenticated:
            if name in VERIFY:
                rejected = _challenge(request)
                if rejected is not None:
                    return rejected
            elif name == 'login' and request.method == 'POST':
                identity = str(request.POST.get('username', '')).strip().lower()[:256]
                try:
                    allowed = _budget('password:' + _digest(identity), 10)
                except Exception:
                    return HttpResponse('Sign-in is temporarily unavailable. Try again later.', status=503)
                if not allowed:
                    return HttpResponse('Too many sign-in attempts. Try again later.', status=429)
            return self.get_response(request)
        if not _local(request.user, request):
            logout(request)
            return HttpResponse('A local MFA-enabled operator account is required.', status=403)
        if name == 'logout':
            return self.get_response(request)
        locked = name in DELETE | {SETUP, 'accounts:register_webauthn_device'} and request.method == 'POST'
        with transaction.atomic() if locked else nullcontext():
            if locked:
                request.user = get_user_model().objects.select_for_update().get(pk=request.user.pk)
            user = request.user
            factors = _factors(user)
            verified = _proof(request, user, factors)
            enrolling = not factors and _fresh(request.session.get(ENROLL), user, ENROLL_SECONDS)
            if not verified:
                if not enrolling:
                    return _login(request)
                if name != SETUP:
                    return HttpResponseRedirect(reverse(SETUP))
            if name in DELETE and request.method == 'POST' and len(factors) <= 1:
                return HttpResponse('Add another verification method before removing this one.', status=403)
            if name in {'accounts:create_user_api_token', 'accounts:update_user_api_token',
                        'accounts:create_oidc_api_token_issuer', 'accounts:update_oidc_api_token_issuer'}:
                target = get_user_model().objects.filter(pk=match.kwargs.get('user_pk')).first()
                if target is not None and not target.is_service_account:
                    return HttpResponse('Use an automation service account for API access.', status=403)
            response = self.get_response(request)
            if name == SETUP or (name in DELETE | {'accounts:register_webauthn_device'} and request.method == 'POST'):
                after = _factors(user)
                if response.status_code in (200, 201, 302) and after != factors:
                    request.session.pop(SEED, None)
                if enrolling and after:
                    return _login(request)
                if verified and after != factors:
                    # This session authorized the change. Other sessions keep
                    # their old fingerprint and must authenticate again.
                    request.session[PROOF] = dict(request.session[PROOF], factors=_digest(after))
            return response

    def process_template_response(self, request, response):
        if getattr(response, 'template_name', None) == 'registration/login.html':
            response.context_data['login_realms'] = []
        context = getattr(response, 'context_data', None)
        if context and 'tokens' in context:
            target = context.get('object', request.user)
            if isinstance(target, get_user_model()) and not target.is_service_account:
                context['can_add_token'] = False
                context['can_manage_oidc_api_token_issuers'] = False
        return response
