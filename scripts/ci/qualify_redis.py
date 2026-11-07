"""Original Unlicense. Disposable hosted-runner orchestration, not app Redis.

Root/isolated Linux only. Private logs stay on the discarded runner. Stdout is
one whitelisted success receipt only after exact-container cleanup succeeds.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
import secrets
import signal

ROOT = Path('/var/lib/azd-santa-lua-ci')
FILES = ('test_admission_redis_live.py', 'santa_admission.py', 'operator_mfa.py')
LABEL = 'santa-admission-lua-v1'
RECEIPT_SCOPES = {'disposable-redis-admission-lua-v1': 27,
                  'disposable-redis-admission-fenced-lua-v2': 37}
MEMORY = 64 * 1024 * 1024
TMPFS = 'rw,nosuid,nodev,noexec,size=67108864,uid=999,gid=999,mode=0700'
DOCKER = ['/usr/bin/docker', '--host', 'unix:///var/run/docker.sock']
INSPECT = ('{"id":{{json .Id}},"image":{{json .Image}},"labels":{{json .Config.Labels}},'
           '"user":{{json .Config.User}},"host":{{json .HostConfig}},"mounts":{{json .Mounts}},'
           '"running":{{json .State.Running}},"ports":{{json .NetworkSettings.Ports}}}')
PHASES = {'preflight', 'source_staging', 'docker_pull', 'image_readback', 'docker_create',
          'created_inspection', 'docker_start', 'started_inspection', 'redis_readiness',
          'harness', 'harness_marker', 'receipt_validation', 'cleanup_owner', 'cleanup_stop',
          'cleanup_stopped', 'internal'}
_PHASE = 'preflight'


def select_phase(value):
    global _PHASE
    aliases = {'pull': 'docker_pull', 'image': 'image_readback', 'create': 'docker_create',
               'created': 'created_inspection', 'start': 'docker_start', 'started': 'started_inspection',
               'cleanup-owner': 'cleanup_owner', 'stop-owned': 'cleanup_stop', 'cleanup-stopped': 'cleanup_stopped'}
    value = 'redis_readiness' if re.fullmatch(r'ready-[0-9]{1,2}', value) else aliases.get(value, value)
    _PHASE = value if value in PHASES else 'internal'


class CiFailure(Exception):
    def __init__(self, phase, kind, exit_code=None, completed=None):
        self.phase = phase if phase in PHASES else 'internal'
        self.kind = kind if kind in {'validation', 'command_exit', 'timeout', 'output_limit',
                                    'interrupted', 'io_error', 'internal_error'} else 'internal_error'
        self.exit_code = exit_code if type(exit_code) is int and -64 <= exit_code <= 255 else None
        self.completed = completed if type(completed) is int and 0 <= completed <= 37 else None
        super().__init__('Disposable Redis CI failed')

    def diagnostic(self):
        return dict(scope='disposable-redis-ci-failure-v1', phase=self.phase, kind=self.kind,
                    exit_code=self.exit_code, completed_observations=self.completed, automatic_replay=False)


def failure(error):
    if isinstance(error, CiFailure): return error
    kind = ('timeout' if isinstance(error, (TimeoutError, subprocess.TimeoutExpired)) else
            'interrupted' if isinstance(error, (KeyboardInterrupt, SystemExit)) else
            'io_error' if isinstance(error, OSError) else
            'validation' if isinstance(error, ValueError) else 'internal_error')
    return CiFailure(_PHASE, kind)


def need(value):
    if not value: raise ValueError('Disposable Redis CI qualification failed')


def read_source(path):
    need(path == path.resolve(strict=True) and path.is_file() and not path.is_symlink())
    with path.open('rb') as stream:
        before = os.fstat(stream.fileno())
        raw = stream.read(1024 * 1024 + 1)
        need(stat.S_ISREG(before.st_mode) and len(raw) <= 1024 * 1024
             and identity(os.fstat(stream.fileno())) == identity(before)
             and identity(path.stat()) == identity(before))
    return raw


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def write(path, value):
    raw = value if isinstance(value, bytes) else json.dumps(value, sort_keys=True).encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())


def redis_reference(lock):
    value = json.loads(lock)
    need(type(value) is dict and type(value.get('redis')) is str
         and re.fullmatch(r'redis@sha256:[a-f0-9]{64}', value['redis']))
    return value['redis']


def image_identity(value, reference):
    need(type(value) is list and len(value) == 1)
    image = value[0]
    need(type(image['Id']) is str and re.fullmatch(r'sha256:[a-f0-9]{64}', image['Id'])
         and image['Os'] == 'linux' and image['Architecture'] == 'amd64')
    digests = image['RepoDigests']
    need(type(digests) is list and 0 < len(digests) <= 16
         and any(item in (reference, 'docker.io/library/' + reference) for item in digests))
    return image['Id']


def owned(row, cid, image, token):
    need(row['id'] == cid and row['image'] == image
         and row['labels'].get('io.azd-santa.qualification') == LABEL
         and row['labels'].get('io.azd-santa.ci-owner') == token)


def isolated(row, cid, image, token):
    owned(row, cid, image, token)
    host = row['host']
    need(row['user'] == '999:999' and host['ReadonlyRootfs'] is True
         and host['NetworkMode'] == 'none' and not host['PortBindings'] and not host['PublishAllPorts']
         and host['Memory'] == MEMORY and host['MemorySwap'] == MEMORY
         and host['NanoCpus'] == 500000000 and host['PidsLimit'] == 32
         and host['RestartPolicy']['Name'] == 'no' and host['CapDrop'] == ['ALL']
         and not host['CapAdd'] and not host['Privileged'] and not host['PidMode']
         and not host['Devices'] and host['SecurityOpt'] == ['no-new-privileges:true']
         and host['LogConfig']['Type'] == 'none' and host['Tmpfs'] == {'/data': TMPFS}
         and all(value is None for value in (row['ports'] or {}).values()))
    # Docker stores --tmpfs in HostConfig.Tmpfs; some versions omit it from
    # Mounts entirely. The exact bounded host map above is mandatory either way.
    mounts = row['mounts']
    need(type(mounts) is list and (not mounts or len(mounts) == 1
         and mounts[0]['Type'] == 'tmpfs' and mounts[0]['Destination'] == '/data'
         and mounts[0]['RW'] is True))


def public_receipt(value, cid, image, hashes, source_commit, reference):
    need(set(hashes) == set(FILES) and all(type(item) is str and re.fullmatch(r'[a-f0-9]{64}', item)
         for item in hashes.values()))
    keys = {'scope', 'container_id', 'image_id', 'sources', 'harness_sha256', 'passed', 'observations', 'limitation'}
    need(type(value) is dict and set(value) == keys
         and value['scope'] in RECEIPT_SCOPES and value['passed'] is True
         and value['container_id'] == cid and value['image_id'] == image
         and value['harness_sha256'] == hashes[FILES[0]]
         and value['sources'] == {name: hashes[name] for name in FILES[1:]})
    observations = value['observations']
    need(type(observations) is list and len(observations) == RECEIPT_SCOPES[value['scope']]
         and all(type(item) is str and re.fullmatch(r'[a-z0-9_]{1,96}', item) for item in observations)
         and len(set(observations)) == len(observations))
    # Do not copy even the harness limitation text: only explicitly selected
    # nonsecret fields cross the artifact boundary, never arbitrary diagnostics.
    return dict(scope='hosted-disposable-redis-lua-v1', harness_scope=value['scope'], passed=True, source_commit=source_commit,
                redis_reference=reference, image_id=image, container_id=cid,
                sources=hashes, observations=observations,
                limitation='Disposable Redis Lua only; no Azure, HTTP, Django, durability, native or application acceptance')


def completed_count(value, cid, image, hashes):
    need(type(value) is dict and set(value) == {'scope', 'container_id', 'image_id', 'sources',
        'harness_sha256', 'passed', 'completed', 'action'} and value['scope'] in RECEIPT_SCOPES
        and value['passed'] is False and value['container_id'] == cid and value['image_id'] == image
        and value['harness_sha256'] == hashes[FILES[0]]
        and value['sources'] == {name: hashes[name] for name in FILES[1:]})
    rows = value['completed']
    need(type(rows) is list and len(rows) <= RECEIPT_SCOPES[value['scope']]
         and all(type(item) is str and re.fullmatch(r'[a-z0-9_]{1,96}', item) for item in rows)
         and len(set(rows)) == len(rows))
    return len(rows)


def failed_count(path, cid, image, hashes):
    try:
        info = path.lstat()
        need(info.st_uid == 0 and not info.st_mode & 0o077 and info.st_nlink == 1)
        return completed_count(json.loads(read_source(path)), cid, image, hashes)
    except BaseException:
        return None  # Missing/untrusted diagnostic is never success or count zero.


class Runner:
    def __init__(self, root):
        self.root = root
        self.environment = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'DOCKER_CONFIG': str(root / 'docker-config')}
        (root / 'docker-config').mkdir(mode=0o700)

    def call(self, phase, args, timeout=30, allowed_failure=False):
        select_phase(phase)
        try:
            result = subprocess.run(args, capture_output=True, timeout=timeout, env=self.environment)
        except subprocess.TimeoutExpired:
            write(self.root / (phase + '.json'), dict(timed_out=True, automatic_retry=False))
            raise CiFailure(_PHASE, 'timeout') from None
        write(self.root / (phase + '.json'), dict(returncode=result.returncode,
            stdout=result.stdout[:1024*1024].decode(errors='replace'), stderr=result.stderr[:1024*1024].decode(errors='replace')))
        if len(result.stdout) > 1024*1024 or len(result.stderr) > 1024*1024:
            raise CiFailure(_PHASE, 'output_limit')
        if result.returncode != 0 and not allowed_failure:
            raise CiFailure(_PHASE, 'command_exit', result.returncode)
        return result.stdout.decode() if result.returncode == 0 else None

    def inspect(self, phase, cid):
        return json.loads(self.call(phase, DOCKER + ['inspect', '--format', INSPECT, cid]))


def run(source_root, source_commit):
    select_phase('preflight')
    need(sys.platform == 'linux' and os.geteuid() == 0 and sys.flags.isolated
         and re.fullmatch(r'[a-f0-9]{40}', source_commit))
    source_root = Path(source_root)
    need(source_root == source_root.resolve(strict=True))
    select_phase('source_staging')
    # Absent-only fixed hosted-runner namespace. Never reuse an earlier attempt.
    ROOT.mkdir(mode=0o700)
    need(ROOT.stat().st_uid == 0 and stat.S_IMODE(ROOT.stat().st_mode) == 0o700)
    staged = ROOT / 'sources'; staged.mkdir(mode=0o700)
    hashes = {}
    for name in FILES:
        raw = read_source(source_root / 'experiments/server' / name)
        hashes[name] = hashlib.sha256(raw).hexdigest(); write(staged / name, raw)
    reference = redis_reference(read_source(source_root / 'experiments/server/dependency-images.lock.json'))
    runner = Runner(ROOT)
    runner.call('pull', DOCKER + ['pull', '--platform', 'linux/amd64', reference], timeout=120)
    image = image_identity(json.loads(runner.call('image', DOCKER + ['image', 'inspect', reference])), reference)
    token = secrets.token_hex(16); cid = None; receipt = None
    try:
        cid = runner.call('create', DOCKER + ['create', '--pull', 'never', '--platform', 'linux/amd64',
            '--label', 'io.azd-santa.qualification=' + LABEL, '--label', 'io.azd-santa.ci-owner=' + token,
            '--user', '999:999', '--read-only', '--network', 'none', '--tmpfs', '/data:' + TMPFS,
            '--memory', '64m', '--memory-swap', '64m', '--cpus', '0.5', '--pids-limit', '32',
            '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true', '--log-driver', 'none',
            '--restart', 'no', image, 'redis-server', '--bind', '127.0.0.1', '--port', '6379',
            '--save', '', '--appendonly', 'no', '--maxmemory', '32mb', '--maxmemory-policy', 'noeviction']).strip()
        need(re.fullmatch(r'[a-f0-9]{64}', cid))
        isolated(runner.inspect('created', cid), cid, image, token)
        runner.call('start', DOCKER + ['start', cid])
        row = runner.inspect('started', cid); isolated(row, cid, image, token); need(row['running'] is True)
        deadline = time.monotonic() + 20
        for index in range(20):
            remaining = deadline - time.monotonic(); need(remaining > 0)
            raw = runner.call('ready-' + str(index), DOCKER + ['exec', cid, 'redis-cli', '--json', 'PING'],
                              timeout=min(5, remaining), allowed_failure=True)
            if raw is not None:
                need(json.loads(raw) == 'PONG'); break
            time.sleep(min(1, max(0, deadline - time.monotonic())))
        else: raise ValueError('Disposable Redis did not become ready')
        # Execute once. A timeout kills this client, not hypothetical server work;
        # finally closes only the owned disposable server and never retries it.
        result = runner.call('harness', ['/usr/bin/python3', '-I', str(staged / FILES[0]),
            '--container-id', cid, '--expected-image', image, '--destination', str(ROOT / 'evidence')], timeout=240)
        select_phase('harness_marker'); need(result.strip() == 'SANTA_ADMISSION_REDIS_LUA_OK')
        select_phase('receipt_validation')
        raw = read_source(ROOT / 'evidence/receipt.json')
        receipt = public_receipt(json.loads(raw), cid, image, hashes, source_commit, reference)
    except BaseException as error:
        original = failure(error)
        if original.phase == 'harness':
            original.completed = failed_count(ROOT / 'evidence/failed.json', cid, image, hashes)
        raise original from None
    finally:
        try:
            if cid is not None:
                select_phase('cleanup_owner'); need(re.fullmatch(r'[a-f0-9]{64}', cid))
                row = runner.inspect('cleanup-owner', cid); owned(row, cid, image, token)
                runner.call('stop-owned', DOCKER + ['stop', '--time', '5', cid], timeout=15)
                row = runner.inspect('cleanup-stopped', cid); owned(row, cid, image, token)
                need(row['running'] is False)
        except BaseException as error:
            raise failure(error) from None
    need(receipt is not None)
    return receipt


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', required=True)
    parser.add_argument('--source-commit', required=True)
    args = parser.parse_args()
    def cancelled(*_): raise SystemExit(1)
    for selected_signal in (signal.SIGTERM, signal.SIGINT): signal.signal(selected_signal, cancelled)
    try:
        print(json.dumps(run(args.source_root, args.source_commit), sort_keys=True))
    except BaseException as error:
        print('SANTA_REDIS_CI_FAILED_JSON:' + json.dumps(failure(error).diagnostic(), sort_keys=True), file=sys.stderr)
        raise SystemExit(1) from None
