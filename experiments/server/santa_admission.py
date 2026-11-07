"""Original Unlicense shared Santa admission. No implicit initialization/reclamation.

No model imports. The only mutable keys have fixed size or bounded TTL/cardinality.
Persistent permits never expire while old application work might still execute.
"""
from dataclasses import dataclass
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import secrets

STATE = 'santa-admission-v1'
PREFIXES = ('/public/santa/sync/', '/santa/sync/')
FORWARD = ('HTTP_FORWARDED', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP',
           'HTTP_X_SSL_CLIENT_S_DN', 'HTTP_X_SSL_CLIENT_VERIFY', 'HTTP_X_FORWARDED_PROTO',
           'HTTP_X_FORWARDED_CLIENT_CERT', 'HTTP_X_SSL_CLIENT_CERT', 'HTTP_X_CLIENT_CERT')


@dataclass(frozen=True)
class Config:
    window: int = 60
    global_max: int = 120
    source_max: int = 60
    credential_max: int = 30
    capacity: int = 1
    mode: str = 'direct'
    peers: tuple = ()

    @property
    def fingerprint(self):
        return hashlib.sha256(json.dumps(self.__dict__, sort_keys=True).encode()).hexdigest()


def configured(environ):
    values = {}
    for key, default, ceiling in (('window', 60, 300), ('global_max', 120, 1200),
                                ('source_max', 60, 1200), ('credential_max', 30, 1200)):
        raw = environ.get('AZD_SANTA_ADMISSION_' + key.upper(), str(default))
        if not re.fullmatch(r'[0-9]{1,4}', raw) or not 1 <= int(raw) <= ceiling:
            raise ValueError('Invalid Santa admission limit')
        values[key] = int(raw)
    mode = environ.get('AZD_SANTA_ADMISSION_MODE', 'direct')
    peers = tuple(environ.get('AZD_SANTA_ADMISSION_PEERS', '').split(',')) if environ.get('AZD_SANTA_ADMISSION_PEERS') else ()
    if mode not in ('direct', 'proxy') or (mode == 'direct' and peers) or (mode == 'proxy' and not peers):
        raise ValueError('Explicit Santa proxy trust required')
    if len(peers) > 8: raise ValueError('Too many trusted proxy peers')
    for peer in peers:
        network = ipaddress.ip_network(peer, strict=True)
        if network.prefixlen == 0: raise ValueError('Unbounded proxy trust')
    return Config(**values, mode=mode, peers=peers)


CONFIG = configured(os.environ)
# State and numeric validation precede mutation. Never repair corrupt counters.
VALIDATE = '''
if redis.call('TYPE', KEYS[2]).ok ~= 'hash' or redis.call('TTL',KEYS[2]) ~= -1 then return redis.error_reply('ADMISSION_UNAVAILABLE') end
if redis.call('HGET', KEYS[2], 'config') ~= ARGV[2] then return redis.error_reply('ADMISSION_UNAVAILABLE') end
local generation=redis.call('HGET',KEYS[2],'generation')
if not generation or #generation ~= 32 or not string.match(generation,'^[0-9a-f]+$') then return redis.error_reply('ADMISSION_UNAVAILABLE') end
if redis.call('HLEN',KEYS[2]) > 2+tonumber(ARGV[3]) then return redis.error_reply('ADMISSION_UNAVAILABLE') end
for _,field in ipairs(redis.call('HKEYS',KEYS[2])) do
 if field ~= 'config' and field ~= 'generation' then
  local i=tonumber(field); local token=redis.call('HGET',KEYS[2],field)
  if not string.match(field,'^[0-9]$') or not i or i<0 or i>=tonumber(ARGV[3]) or tostring(i)~=field or #token~=43 or not string.match(token,'^[A-Za-z0-9_-]+$') then return redis.error_reply('ADMISSION_UNAVAILABLE') end
 end
end
'''
ACQUIRE = VALIDATE + '''
local counts={}
for i=3,5 do
 local v=redis.call('GET',KEYS[i]); local ttl=redis.call('TTL',KEYS[i])
 if v and (not string.match(v,'^%d+$') or #v>5 or tonumber(v)<1 or tostring(tonumber(v))~=v or tonumber(v)>tonumber(ARGV[i+2]) or ttl<0 or ttl>tonumber(ARGV[4])) then return redis.error_reply('ADMISSION_UNAVAILABLE') end
 counts[i]=tonumber(v) or 0
end
local limits={tonumber(ARGV[5]),tonumber(ARGV[6]),tonumber(ARGV[7])}
-- Global rejected attempts saturate; never allocate identity keys after its cap.
if counts[3]>=limits[1] then return {0,math.max(1,redis.call('TTL',KEYS[3]))} end
if counts[3]==0 then redis.call('SET',KEYS[3],'1','EX',ARGV[4]) else redis.call('INCR',KEYS[3]) end
for i=4,5 do
 if counts[i]>=limits[i-2] then return {0,math.max(1,redis.call('TTL',KEYS[i]))} end
end
local slot=nil
for i=0,tonumber(ARGV[3])-1 do if redis.call('HEXISTS',KEYS[2],tostring(i))==0 then slot=tostring(i);break end end
if not slot then return {0,1} end
for i=4,5 do
 if counts[i]==0 then redis.call('SET',KEYS[i],'1','EX',ARGV[4]) else redis.call('INCR',KEYS[i]) end
end
redis.call('HSET',KEYS[2],slot,ARGV[8])
return {1,slot}
'''
RELEASE = VALIDATE + '''
if redis.call('HGET',KEYS[2],ARGV[4]) ~= ARGV[5] then return 0 end
redis.call('HDEL',KEYS[2],ARGV[4]); return 1
'''
GLOBAL_COUNTER = '''
local counter_type=redis.call('TYPE',KEYS[3]).ok
if counter_type~='none' and counter_type~='string' then return redis.error_reply('ADMISSION_UNAVAILABLE') end
local v=redis.call('GET',KEYS[3]); local ttl=redis.call('TTL',KEYS[3])
if v and (not string.match(v,'^%d+$') or #v>5 or tonumber(v)<1 or tostring(tonumber(v))~=v or tonumber(v)>tonumber(ARGV[5]) or ttl<0 or ttl>tonumber(ARGV[4])) then return redis.error_reply('ADMISSION_UNAVAILABLE') end
'''
CHECK = VALIDATE + GLOBAL_COUNTER + 'return 1'
EMPTY = VALIDATE + GLOBAL_COUNTER + "if redis.call('HLEN',KEYS[2])~=2 then return redis.error_reply('ADMISSION_QUIESCENCE_REQUIRED') end; return 1"
RECONCILE = VALIDATE + '''
for i=0,tonumber(ARGV[3])-1 do redis.call('HDEL',KEYS[2],tostring(i)) end
redis.call('HSET',KEYS[2],'generation',ARGV[4]); return 1
'''


def _eval(script, extra_keys=(), arguments=()):
    from azd_santa_operator import _security_client, STORE_GUARD, STORE_MARKER, _expected_store_id
    cache, client = _security_client()
    keys = [cache.make_key(STORE_MARKER), cache.make_key(STATE), *(cache.make_key(k) for k in extra_keys)]
    return client.eval(STORE_GUARD + script, len(keys), *keys,
                       _expected_store_id(), CONFIG.fingerprint, CONFIG.capacity, *arguments)


def initialize_fresh(cache, client, expected_id, delay, marker):
    # One atomic privileged operation initializes marker AND admission state.
    script = '''
if redis.call('EXISTS',KEYS[1])~=0 or redis.call('EXISTS',KEYS[2])~=0 then return 0 end
local ready=tonumber(redis.call('TIME')[1])+tonumber(ARGV[2])
redis.call('SET',KEYS[1],ARGV[1]..':'..tostring(ready))
redis.call('HSET',KEYS[2],'config',ARGV[3],'generation',ARGV[4]);return 1
'''
    return client.eval(script, 2, cache.make_key(marker), cache.make_key(STATE),
                       expected_id, delay, CONFIG.fingerprint, secrets.token_hex(16))


def reconcile(*, initialize_missing=False):
    # Host controller must establish quiescence BEFORE this explicit job.
    if initialize_missing:
        script = '''
if redis.call('EXISTS',KEYS[2])~=0 then return redis.error_reply('ADMISSION_ALREADY_EXISTS') end
redis.call('HSET',KEYS[2],'config',ARGV[2],'generation',ARGV[4]);return 1
'''
    else:
        script = RECONCILE
    if _eval(script, arguments=(secrets.token_hex(16),)) != 1:
        raise ValueError('Admission reconciliation failed')


def check(*, require_empty=False):
    if type(require_empty) is not bool: raise ValueError('Explicit admission readiness mode required')
    if _eval(EMPTY if require_empty else CHECK, ('sync-global',), (CONFIG.window, CONFIG.global_max)) != 1: raise ValueError('Admission state unavailable')


def identity(meta, credential, key):
    address = ipaddress.ip_address(meta.get('REMOTE_ADDR', ''))
    if CONFIG.mode == 'proxy':
        if not any(address in ipaddress.ip_network(peer) for peer in CONFIG.peers):
            raise ValueError('Untrusted proxy peer')
        address = ipaddress.ip_address(meta.get('HTTP_X_AZD_SANTA_CLIENT_IP', ''))
    # IPv6 rotation within one /64 does not evade the source budget.
    source = str(ipaddress.ip_network(str(address) + '/64', strict=False)) if address.version == 6 else str(address)
    for header in (*FORWARD, 'HTTP_X_AZD_SANTA_CLIENT_IP'):
        meta.pop(header, None)
    meta['HTTP_X_REAL_IP'] = str(address)  # Existing upstream audit helper sees only canonical identity.
    def mac(domain, value):
        return hmac.new(key.encode(), (domain + '\0' + value).encode(), hashlib.sha256).hexdigest()
    return 'sync-source:' + mac('source', source), 'sync-credential:' + mac('credential', credential)


def credential_from(request):
    header = request.META.get('HTTP_ZENTRAL_AUTHORIZATION')
    if header is not None:
        if not isinstance(header, str) or len(header) > 1024: return '!invalid'
        parts = header.split()
        return parts[1] if len(parts) == 2 and parts[0] == 'Bearer' else '!invalid'
    # Preserve the pinned deprecated transport, without putting the path in logs.
    for prefix in PREFIXES:
        if request.path_info.startswith(prefix):
            parts = request.path_info[len(prefix):].split('/')
            if len(parts) == 3 and len(parts[0]) <= 1024: return parts[0]
    return '!missing'


def require_admission(request):
    from django.core.exceptions import PermissionDenied
    if not isinstance(getattr(request, '_azd_santa_admission', None), Permit):
        raise PermissionDenied('Sync admission required')


@dataclass(frozen=True)
class Permit:
    slot: str
    token: str


class SecretPathFilter(logging.Filter):
    """Never log credential-bearing sync paths or authorization-header errors."""
    def filter(self, record):
        request = getattr(record, 'request', None)
        if request is not None and str(getattr(request, 'path_info', '')).startswith(PREFIXES):
            return False
        text = record.getMessage().lower()
        return not any(value in text for value in (*PREFIXES, 'zentral-authorization'))


class Admission:
    def __init__(self, get_response):
        self.get_response = get_response
        for name in ('django.request', 'gunicorn.error', 'gunicorn.access'):
            logger = logging.getLogger(name)
            if not any(isinstance(f, SecretPathFilter) for f in logger.filters):
                logger.addFilter(SecretPathFilter())

    def __call__(self, request):
        if not request.path_info.startswith(PREFIXES): return self.get_response(request)
        from django.conf import settings
        from django.http import JsonResponse
        def rejected(status, retry=1):
            response = JsonResponse({'detail': 'Sync admission unavailable' if status == 503 else 'Sync request limit exceeded'}, status=status)
            response['Retry-After'] = str(max(1, min(CONFIG.window, int(retry))))
            return response
        try:
            source, credential = identity(request.META, credential_from(request), settings.SECRET_KEY)
            token = secrets.token_urlsafe(32)
            result = _eval(ACQUIRE, ('sync-global', source, credential),
                           (CONFIG.window, CONFIG.global_max, CONFIG.source_max, CONFIG.credential_max, token))
            if result[0] == 0: return rejected(429, result[1])
            slot = result[1].decode() if isinstance(result[1], bytes) else str(result[1])
            if result[0] != 1 or slot != '0': raise ValueError('Invalid permit')
        except Exception:
            return rejected(503)
        permit = Permit(slot, token)
        request._azd_santa_admission = permit
        try:
            response = self.get_response(request)
            if getattr(response, 'streaming', False):
                # Santa responses are materialized JSON. Keep the slot on an
                # unsupported streaming path; never release capacity prematurely.
                return rejected(503)
        except BaseException:
            # The handler stack has unwound, so its synchronous work is over.
            try: _eval(RELEASE, arguments=(slot, token))
            except Exception: pass  # Leaked slots require privileged quiescence.
            raise
        else:
            try:
                if _eval(RELEASE, arguments=(slot, token)) != 1: return rejected(503)
            except Exception:
                return rejected(503)
            return response
        finally:
            request.__dict__.pop('_azd_santa_admission', None)
