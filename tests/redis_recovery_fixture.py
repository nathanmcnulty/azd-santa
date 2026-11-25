"""Preserve captured Redis history without starting Redis on that history."""

import ast
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import time

from prepare_zentral_eval import REDIS_COMMAND
import santa_admission as admission
from test_admission_redis_live import HarnessFailure, RedisError, parse_reply

SERVER = Path(__file__).resolve().parents[1] / 'experiments/server'
IMAGE = json.loads((SERVER / 'dependency-images.lock.json').read_text(encoding='utf-8'))['redis']
SOCKET = '/tmp/santa-redis.sock'
PREFIX = 'santa-recovery-fixture:'
HISTORY = ('consumed-mfa', 'failure-budget')
MANIFEST = 'appendonlydir/appendonly.aof.manifest'


def policy_constants():
    tree = ast.parse((SERVER / 'operator_mfa.py').read_bytes())
    names = {'STORE_MARKER', 'STORE_GUARD'}
    values = {node.targets[0].id: ast.literal_eval(node.value) for node in tree.body
              if isinstance(node, ast.Assign) and len(node.targets) == 1
              and isinstance(node.targets[0], ast.Name) and node.targets[0].id in names}
    assert set(values) == names
    return values['STORE_MARKER'], values['STORE_GUARD']


class Client:
    def __init__(self, name):
        self.name = name

    def run(self, *arguments):
        return subprocess.run(['docker', 'exec', self.name, 'redis-cli', '-s', SOCKET,
                               '--json', *map(str, arguments)], capture_output=True, text=True, timeout=10)

    def command(self, *arguments):
        return parse_reply(self.run(*arguments), arguments[0])

    def eval(self, script, count, *arguments):
        return self.command('EVAL', script, count, *arguments)

    @staticmethod
    def make_key(key):
        return PREFIX + key


@contextmanager
def redis(root, data, suffix):
    assert re.fullmatch(r'redis@sha256:[a-f0-9]{64}', IMAGE)
    data.mkdir(mode=0o700)
    name = 'ci' + root.name + '-redis-' + suffix
    subprocess.run(['docker', 'run', '--detach', '--pull=never', '--name', name, '--network', 'none',
                    '--memory', '128m', '--cpus', '1', '--pids-limit', '48', '--user', f'{os.getuid()}:0',
                    '--mount', f'type=bind,source={data},target=/data', IMAGE, *REDIS_COMMAND,
                    '--port', '0', '--unixsocket', SOCKET, '--unixsocketperm', '700'],
                   check=True, stdout=subprocess.DEVNULL, timeout=20)
    client = Client(name)
    try:
        for _ in range(30):
            try:
                if client.command('PING') == 'PONG':
                    break
            except HarnessFailure:
                pass
            time.sleep(0.5)
        else:
            raise RuntimeError('Synthetic Redis did not become ready')
        yield client
        subprocess.run(['docker', 'stop', '--timeout', '10', name], check=True,
                       stdout=subprocess.DEVNULL, timeout=15)
        exit_code = subprocess.check_output(['docker', 'inspect', '--format', '{{.State.ExitCode}}', name], timeout=10)
        assert exit_code.strip() == b'0'
    finally:
        subprocess.run(['docker', 'rm', '-f', '-v', name], check=True, stdout=subprocess.DEVNULL, timeout=15)


def inventory(data):
    files = {}
    for path in data.rglob('*'):
        assert not path.is_symlink()
        if path.is_file():
            with path.open('rb') as stream:
                files[path.relative_to(data).as_posix()] = hashlib.file_digest(stream, 'sha256').hexdigest()
    assert MANIFEST in files and any(name.endswith('.incr.aof') for name in files)
    return files


def expect_denied(client, marker, guard, identity):
    result = client.run('EVAL', guard + 'return 1', 1, client.make_key(marker), identity)
    try:
        parse_reply(result, 'EVAL')
    except RedisError:
        assert 'SECURITY_STORE_UNAVAILABLE' in result.stdout
        return
    raise AssertionError('Historical or missing security-store identity was admitted')


def capture(root):
    marker, guard = policy_constants()
    data = root / 'redis-source'
    identity = secrets.token_hex(32)
    with redis(root, data, 'source') as client:
        assert admission.initialize_fresh(client, client, identity, 0, marker) == 1
        for key, value in zip(HISTORY, (1, 7), strict=True):
            assert client.command('SET', client.make_key(key), value, 'EX', 3600) == 'OK'
        assert client.eval(guard + 'return 1', 1, client.make_key(marker), identity) == 1
        generation = client.command('HGET', client.make_key(admission.STATE), 'generation')
        assert re.fullmatch(r'[a-f0-9]{32}', generation)
    return data, identity, generation, inventory(data)


def verify(root, quarantine, historical_identity, historical_generation, expected_files):
    assert inventory(quarantine) == expected_files
    # The pinned checker opens even an unmodified base file for writing.
    # Its disposable input is separate from quarantine and both Redis stores.
    check_data = root / 'redis-check'
    shutil.copytree(quarantine, check_data)
    assert inventory(check_data) == expected_files
    subprocess.run(['docker', 'run', '--rm', '--name', 'ci' + root.name + '-redis-check',
                    '--network', 'none', '--memory', '128m', '--cpus', '1',
                    '--pids-limit', '32', '--user', f'{os.getuid()}:0',
                    '--mount', f'type=bind,source={check_data},target=/check',
                    '--entrypoint', 'redis-check-aof', IMAGE, '/check/' + MANIFEST],
                   check=True, timeout=20)
    assert inventory(check_data) == expected_files
    marker, guard = policy_constants()
    with redis(root, root / 'redis-fresh', 'fresh') as client:
        keys = [client.make_key(key) for key in (marker, admission.STATE, *HISTORY)]
        assert client.command('EXISTS', *keys) == 0
        expect_denied(client, marker, guard, historical_identity)
        identity = secrets.token_hex(32)
        assert identity != historical_identity
        assert admission.initialize_fresh(client, client, identity, 0, marker) == 1
        assert client.eval(guard + 'return 1', 1, client.make_key(marker), identity) == 1
        expect_denied(client, marker, guard, historical_identity)
        generation = client.command('HGET', client.make_key(admission.STATE), 'generation')
        assert re.fullmatch(r'[a-f0-9]{32}', generation) and generation != historical_generation
        assert client.command('EXISTS', *keys[2:]) == 0
    assert inventory(quarantine) == expected_files
    print('Redis AOF history stayed quarantined while a fresh generation rejected the historical identity')
