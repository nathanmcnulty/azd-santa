"""Original Unlicense. Explicit disposable-container Lua qualification only.

No container creation, lifecycle, FLUSH, app Redis discovery or host network use.
Failure retains namespaced keys and an owner-private bounded failure receipt.
"""
import argparse
import ast
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import time
import types

PINS = {'santa_admission.py': 'ebe2abef0cb9786f677a08dacf96b27acd944fcdd4e1465afa5c74701249629b',
        'operator_mfa.py': '0d5eb3b850b58c4f6092206734114fdbf931e965cb6b448feb60a4068aee4b8d'}
LABEL = 'santa-admission-lua-v1'
SNAPSHOT = '''
local keys=redis.call('KEYS',ARGV[1]);table.sort(keys);local result={}
for _,key in ipairs(keys) do
 local kind=redis.call('TYPE',key).ok;local body
 if kind=='string' then body=redis.call('GET',key)
 elseif kind=='hash' then
  local fields=redis.call('HKEYS',key);table.sort(fields);body={}
  for _,field in ipairs(fields) do table.insert(body,{field,redis.call('HGET',key,field)}) end
 elseif kind=='list' then body=redis.call('LRANGE',key,0,-1)
 else return redis.error_reply('UNSUPPORTED_QUALIFICATION_KEY_TYPE') end
 table.insert(result,{key,kind,body,redis.call('PEXPIRETIME',key)})
end
return cjson.encode(result)
'''


def need(value):
    if not value:
        raise ValueError('Admission Redis qualification failed; inspect private receipt')


def sources():
    root = Path(__file__).resolve().parent
    raw = {}
    for name, digest in PINS.items():
        path = root / name
        info = path.lstat()
        need(stat.S_ISREG(info.st_mode) and not path.is_symlink())
        need(info.st_uid == 0 and not info.st_mode & 0o022)
        raw[name] = path.read_bytes()
        need(hashlib.sha256(raw[name]).hexdigest() == digest)
    # The Django policy is never imported. Extract its literal guard/marker only.
    tree = ast.parse(raw['operator_mfa.py'])
    constants = {node.targets[0].id: ast.literal_eval(node.value)
                 for node in tree.body if isinstance(node, ast.Assign)
                 and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                 and node.targets[0].id in ('STORE_GUARD', 'STORE_MARKER')}
    need(set(constants) == {'STORE_GUARD', 'STORE_MARKER'})
    module = types.ModuleType('qualification_santa_admission')
    module.__file__ = str(root / 'santa_admission.py')
    sys.modules[module.__name__] = module
    # Configuration is explicit for every case; inherited environment is ignored.
    saved = {k: os.environ.pop(k) for k in tuple(os.environ) if k.startswith('AZD_SANTA_ADMISSION_')}
    try:
        exec(compile(raw['santa_admission.py'], module.__file__, 'exec'), module.__dict__)
    finally:
        os.environ.update(saved)
    return module, constants


class RedisError(Exception):
    pass


def parse_reply(result):
    need(len(result.stdout) <= 65536 and len(result.stderr) <= 4096)
    text = result.stdout.strip()
    if text.startswith('error:'):
        # redis-cli --json encodes Redis error replies with this explicit prefix.
        json.loads(text[6:])
        raise RedisError('Redis rejected script')
    need(result.returncode == 0 and not result.stderr.strip())
    return json.loads(text)


class Target:
    def __init__(self, cid, image):
        need(re.fullmatch('[a-f0-9]{64}', cid) and re.fullmatch('sha256:[a-f0-9]{64}', image))
        self.cid, self.image = cid, image
        self.environment = {k: v for k, v in os.environ.items() if not k.startswith(('DOCKER_', 'COMPOSE_'))}
        self.docker = ['docker', '--host', 'unix:///var/run/docker.sock']

    def inspect(self):
        template = ('{"id":{{json .Id}},"image":{{json .Image}},"running":{{json .State.Running}},'
                    '"network":{{json .HostConfig.NetworkMode}},"mounts":{{json .Mounts}},'
                    '"ports":{{json .HostConfig.PortBindings}},"labels":{{json .Config.Labels}}}')
        result = subprocess.run(self.docker + ['inspect', '--format', template, self.cid],
                                capture_output=True, text=True, timeout=15, env=self.environment)
        need(result.returncode == 0 and len(result.stdout) <= 65536)
        value = json.loads(result.stdout)
        need(value['id'] == self.cid and value['image'] == self.image and value['running'] is True)
        need(value['network'] == 'none' and not value['ports'])
        need((value['labels'] or {}).get('io.azd-santa.qualification') == LABEL)
        need(all(m['Type'] == 'tmpfs' and m['Destination'] == '/data' for m in value['mounts'])
             and len(value['mounts']) <= 1)
        return value

    def command(self, *arguments):
        need(all(isinstance(arg, (str, int)) for arg in arguments))
        result = subprocess.run(self.docker + ['exec', self.cid, 'redis-cli', '--json',
                               *map(str, arguments)], capture_output=True, text=True,
                                timeout=15, env=self.environment)
        return parse_reply(result)

    def eval(self, script, count, *arguments):
        return self.command('EVAL', script, count, *arguments)


class Case:
    def __init__(self, target, module, constants, *, window=30, global_max=100, source_max=60, credential_max=30, fresh=True):
        self.target, self.module, self.constants = target, module, constants
        self.config = module.Config(window=window, global_max=global_max,
                                    source_max=source_max, credential_max=credential_max)
        self.prefix = 'qualification:' + secrets.token_hex(16) + ':'
        self.store = secrets.token_hex(32)
        self.marker = self.make_key(constants['STORE_MARKER'])
        self.state = self.make_key(module.STATE)
        self.global_key = self.make_key('sync-global')
        need(target.command('EXISTS', self.marker, self.state, self.global_key) == 0)
        if not fresh:
            return
        previous = module.CONFIG
        try:
            module.CONFIG = self.config
            need(module.initialize_fresh(self, target, self.store, 0, constants['STORE_MARKER']) == 1)
            need(module.initialize_fresh(self, target, self.store, 0, constants['STORE_MARKER']) == 0)
        finally:
            module.CONFIG = previous

    def make_key(self, key):
        return self.prefix + key

    def script(self, script, extra=(), arguments=()):
        keys = (self.marker, self.state, *(self.make_key(k) for k in extra))
        return self.target.eval(self.constants['STORE_GUARD'] + script, len(keys), *keys,
                                self.store, self.config.fingerprint, self.config.capacity, *arguments)

    def check(self, empty=False):
        return self.script(self.module.EMPTY if empty else self.module.CHECK, ('sync-global',),
                           (self.config.window, self.config.global_max))

    def acquire(self, source='source', credential='credential', token=None):
        token = token or secrets.token_urlsafe(32)
        return self.script(self.module.ACQUIRE, ('sync-global', source, credential),
            (self.config.window, self.config.global_max, self.config.source_max, self.config.credential_max, token)), token

    def release(self, token):
        return self.script(self.module.RELEASE, arguments=('0', token))

    def read_state(self, allow_missing=False):
        return self.script(self.module.READ_OR_MISSING if allow_missing else self.module.READ_STATE,
                           ('sync-global',), (self.config.window, self.config.global_max))

    def reconcile(self, expected, generation, initialize_missing=False):
        # Direct production Lua also tests invalid fence arguments, independently
        # of the product Python API's parameter validation.
        return self.script(self.module.INITIALIZE_QUIESCED if initialize_missing else self.module.RECONCILE,
                           ('sync-global',), (self.config.window, self.config.global_max, expected, generation))

    def snapshot(self):
        # One atomic readonly snapshot: sorted exact fields/values and absolute
        # millisecond expiration timestamps, not naturally decreasing TTLs.
        return json.loads(self.target.eval(SNAPSHOT, 0, self.prefix + '*'))

    def counters(self):
        return [row for row in self.snapshot() if row[0] not in (self.marker, self.state)]


def rejected(callback):
    try:
        callback()
    except RedisError:
        return
    raise ValueError('Corrupt state was accepted')


def unchanged(case, callback, *, reject=False, expected=None):
    before = case.snapshot()
    if reject:
        rejected(callback)
    else:
        need(callback() == expected)
    need(case.snapshot() == before)


def exercise(target, module, constants, record):
    unknown = Case(target, module, constants, fresh=False)
    for callback in (unknown.check, unknown.acquire, unknown.read_state,
                     lambda: unknown.read_state(allow_missing=True),
                     lambda: unknown.reconcile(secrets.token_hex(16), secrets.token_hex(16)),
                     lambda: unknown.reconcile('', secrets.token_hex(16), initialize_missing=True)):
        unchanged(unknown, callback, reject=True)
    need(target.command('EXISTS', unknown.marker, unknown.state, unknown.global_key) == 0)
    record.append('unknown_store_never_initialized_implicitly')
    case = Case(target, module, constants)
    need(case.check(empty=True) == 1)
    first, token = case.acquire(); need(first == [1, '0'])
    need(target.command('TTL', case.state) == -1)
    need(case.check() == 1); rejected(lambda: case.check(empty=True))
    need(case.acquire()[0][0] == 0)
    need(case.release(secrets.token_urlsafe(32)) == 0)
    need(case.release(token) == 1 and case.release(token) == 0 and case.check(empty=True) == 1)
    record.append('fixed_capacity_matching_release_and_empty')

    # These are disposable namespaces, never production key repair.
    mutations = [
        ('missing_marker', lambda c: target.command('DEL', c.marker)),
        ('wrong_marker', lambda c: target.command('SET', c.marker, '0' * 64 + ':0')),
        ('malformed_marker', lambda c: target.command('SET', c.marker, 'invalid')),
        ('held_marker', lambda c: target.command('SET', c.marker, c.store + ':' + str(int(target.command('TIME')[0]) + 300))),
        ('marker_type', lambda c: (target.command('DEL', c.marker), target.command('LPUSH', c.marker, 'bad'))),
        ('missing_state', lambda c: target.command('DEL', c.state)),
        ('state_type', lambda c: (target.command('DEL', c.state), target.command('SET', c.state, 'bad'))),
        ('state_ttl', lambda c: target.command('EXPIRE', c.state, 30)),
        ('config', lambda c: target.command('HSET', c.state, 'config', 'bad')),
        ('generation', lambda c: target.command('HSET', c.state, 'generation', 'bad')),
        ('foreign_field', lambda c: target.command('HSET', c.state, 'foreign', 'bad')),
        ('slot_token', lambda c: target.command('HSET', c.state, '0', 'bad')),
        ('global_type', lambda c: target.command('LPUSH', c.global_key, 'bad')),
        ('global_zero', lambda c: target.command('SET', c.global_key, '0', 'EX', 30)),
        ('global_noncanonical', lambda c: target.command('SET', c.global_key, '01', 'EX', 30)),
        ('global_nonnumeric', lambda c: target.command('SET', c.global_key, 'bad', 'EX', 30)),
        ('global_overlimit', lambda c: target.command('SET', c.global_key, '101', 'EX', 30)),
        ('global_no_ttl', lambda c: target.command('SET', c.global_key, '1')),
        ('global_long_ttl', lambda c: target.command('SET', c.global_key, '1', 'EX', 300)),
    ]
    for name, mutation in mutations:
        case = Case(target, module, constants); mutation(case)
        for callback in (case.check, lambda: case.check(empty=True), case.acquire, case.read_state,
                         lambda: case.reconcile(secrets.token_hex(16), secrets.token_hex(16))):
            unchanged(case, callback, reject=True)
        if name == 'missing_state':
            unchanged(case, lambda: case.read_state(allow_missing=True), expected=['missing', 0])
        else:
            unchanged(case, lambda: case.read_state(allow_missing=True), reject=True)
        if not name.startswith('global_'):
            unchanged(case, lambda: case.release(secrets.token_urlsafe(32)), reject=True)
        record.append(name + '_fail_closed')
        if name.startswith('global_'):
            missing = Case(target, module, constants)
            target.command('DEL', missing.state); mutation(missing)
            unchanged(missing, lambda: missing.read_state(allow_missing=True), reject=True)
            unchanged(missing, lambda: missing.reconcile('', secrets.token_hex(16), initialize_missing=True), reject=True)
    record.append('missing_initialization_corrupt_global_rejected_without_mutation')

    for kind in ('source', 'credential', 'global'):
        limits = dict(global_max=20, source_max=20, credential_max=20)
        limits[kind + '_max'] = 2
        case = Case(target, module, constants, **limits)
        for _ in range(2):
            result, token = case.acquire(); need(result == [1, '0']); need(case.release(token) == 1)
        need(case.acquire()[0][0] == 0 and case.check(empty=True) == 1)
        record.append(kind + '_cap_valid_readiness')

    case = Case(target, module, constants, global_max=3)
    for i in range(12):
        result, token = case.acquire('source:' + str(i), 'credential:' + str(i))
        if i < 3: need(result == [1, '0'] and case.release(token) == 1)
        else: need(result[0] == 0)
    keys = target.command('KEYS', case.prefix + '*')
    need(len(keys) == 9 and target.command('GET', case.global_key) == '3')
    record.append('global_first_cardinality_bound')

    case = Case(target, module, constants)
    tokens = [secrets.token_urlsafe(32) for _ in range(8)]
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda token: case.acquire(token=token)[0], tokens))
    winners = [i for i, result in enumerate(results) if result == [1, '0']]
    need(len(winners) == 1 and sum(result[0] == 0 for result in results) == 7)
    need(case.release(tokens[winners[0]]) == 1)
    record.append('eight_concurrent_acquires_one_permit')

    case = Case(target, module, constants, window=1)
    result, token = case.acquire(); need(result == [1, '0'])
    deadline = time.monotonic() + 5
    while target.command('EXISTS', case.global_key):
        need(time.monotonic() < deadline); time.sleep(.1)
    need(case.acquire()[0][0] == 0 and target.command('TTL', case.state) == -1)
    rejected(lambda: case.check(empty=True))
    generation = target.command('HGET', case.state, 'generation')
    new_generation = secrets.token_hex(16)
    need(case.reconcile(generation, new_generation) == [1, new_generation])
    need(new_generation != generation and target.command('HGET', case.state, 'generation') == new_generation)
    need(case.release(token) == 0 and case.check(empty=True) == 1)
    result, next_token = case.acquire(); need(result == [1, '0']); need(case.release(next_token) == 1)
    record.append('rate_expiry_never_reclaims_live_permit_explicit_reconcile_only')
    exercise_fences(target, module, constants, record)


def exercise_fences(target, module, constants, record):
    case = Case(target, module, constants, window=300)
    initial = target.command('HGET', case.state, 'generation')
    unchanged(case, case.read_state, expected=[initial, 0])
    result, old_token = case.acquire(); need(result == [1, '0'])
    unchanged(case, case.read_state, expected=[initial, 1])
    record.append('readonly_state_preserves_exact_keys_values_and_expirations')

    counters = case.counters()
    target_generation = secrets.token_hex(16)
    need(case.reconcile(initial, target_generation) == [1, target_generation])
    need(case.read_state() == [target_generation, 0] and case.counters() == counters)
    need(target.command('HGET', case.state, 'config') == case.config.fingerprint)
    need(case.release(old_token) == 0)
    record.append('expected_to_target_cas_clears_only_old_permit_preserves_exact_budgets')

    # Model a lost transport reply by deliberately not interpreting the actual
    # first CAS reply. Observe current generation readonly, then retry the same
    # reserved transition only. No fake success result is substituted.
    next_generation = secrets.token_hex(16)
    case.reconcile(target_generation, next_generation)
    unchanged(case, case.read_state, expected=[next_generation, 0])
    unchanged(case, lambda: case.reconcile(target_generation, next_generation),
              expected=[0, next_generation])
    need(case.counters() == counters)
    record.append('discarded_cas_reply_readonly_observation_and_same_transition_retry')

    result, new_token = case.acquire(); need(result == [1, '0'])
    unchanged(case, lambda: case.reconcile(target_generation, next_generation),
              expected=[0, next_generation])
    unchanged(case, case.read_state, expected=[next_generation, 1])
    record.append('same_target_replay_preserves_new_live_permit_and_exact_budgets')

    for expected, target_fence in ((initial, target_generation), (initial, secrets.token_hex(16)),
                                    (target_generation, secrets.token_hex(16))):
        unchanged(case, lambda: case.reconcile(expected, target_fence), reject=True)
    need(case.read_state() == [next_generation, 1])
    record.append('stale_expected_and_target_rejected_without_touching_new_permit')

    invalid = ('', 'a' * 31, 'a' * 33, 'A' * 32, 'g' * 32, 'a' * 31 + '\n')
    for fence in invalid:
        unchanged(case, lambda: case.reconcile(fence, secrets.token_hex(16)), reject=True)
        unchanged(case, lambda: case.reconcile(next_generation, fence), reject=True)
    unchanged(case, lambda: case.reconcile(next_generation, next_generation), reject=True)
    need(case.release(new_token) == 1)
    record.append('invalid_and_equal_fences_rejected_without_mutation')

    # A valid empty state must still advance its fence, not skip CAS because
    # occupancy happens to be zero. Counters retain their original expiration.
    final_generation = secrets.token_hex(16)
    counters = case.counters()
    need(case.reconcile(next_generation, final_generation) == [1, final_generation])
    need(case.read_state() == [final_generation, 0] and case.counters() == counters)
    record.append('empty_state_cas_advances_generation_without_resetting_budgets')

    missing = Case(target, module, constants, window=300)
    result, old_token = missing.acquire(); need(result == [1, '0']); need(missing.release(old_token) == 1)
    target.command('DEL', missing.state)  # Explicit disposable fixture corruption.
    counters = missing.counters()
    unchanged(missing, missing.read_state, reject=True)
    unchanged(missing, lambda: missing.read_state(allow_missing=True), expected=['missing', 0])
    new_generation = secrets.token_hex(16)
    for expected in ('a' * 32, 'bad'):
        unchanged(missing, lambda: missing.reconcile(expected, new_generation, initialize_missing=True), reject=True)
    for generation in invalid:
        unchanged(missing, lambda: missing.reconcile('', generation, initialize_missing=True), reject=True)
    need(missing.reconcile('', new_generation, initialize_missing=True) == [1, new_generation])
    need(missing.read_state() == [new_generation, 0] and missing.counters() == counters)
    record.append('explicit_missing_initialization_requires_empty_expected_and_valid_target')
    result, token = missing.acquire(); need(result == [1, '0'])
    unchanged(missing, lambda: missing.reconcile('', new_generation, initialize_missing=True), reject=True)
    need(missing.release(token) == 1)
    record.append('missing_initializer_never_adopts_existing_hash_or_clears_live_permit')


def write(path, document):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as output:
        json.dump(document, output, sort_keys=True); output.flush(); os.fsync(output.fileno())


def run(args):
    need(sys.platform == 'linux' and os.geteuid() == 0 and sys.flags.isolated)
    destination = Path(args.destination)
    need(destination.is_absolute() and destination.parent == destination.parent.resolve(strict=True))
    for parent in (destination.parent, *destination.parent.parents):
        info = parent.stat(); need(info.st_uid == 0 and not info.st_mode & 0o022)
    need(not destination.exists() and not destination.is_symlink())
    module, constants = sources()
    target = Target(args.container_id, args.expected_image)
    target.inspect()
    destination.mkdir(mode=0o700)
    base = dict(scope='disposable-redis-admission-fenced-lua-v2', container_id=args.container_id,
                image_id=args.expected_image, sources=PINS,
                harness_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    write(destination / 'attempt.json', base)
    observations = []
    try:
        need(target.command('PING') == 'PONG')
        exercise(target, module, constants, observations)
        target.inspect()
        write(destination / 'receipt.json', dict(base, passed=True, observations=observations,
            limitation='Disposable Redis Lua only; no HTTP, Django security-client persistence, timeout-held request, restart, native or host reconciliation proof'))
    except BaseException:
        write(destination / 'failed.json', dict(base, passed=False, completed=observations,
              action='Preserve selected disposable container and receipt; no automatic replay'))
        raise
    print('SANTA_ADMISSION_REDIS_LUA_OK')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--container-id', required=True)
    parser.add_argument('--expected-image', required=True)
    parser.add_argument('--destination', required=True)
    try:
        run(parser.parse_args())
    except BaseException:
        raise SystemExit('Admission Redis Lua qualification failed; inspect retained private evidence') from None
