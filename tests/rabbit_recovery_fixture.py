"""Prove drained RabbitMQ state stays inert across the sealed recovery fixture."""

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess

SERVER = Path(__file__).resolve().parents[1] / 'experiments/server'
IMAGE = json.loads((SERVER / 'dependency-images.lock.json').read_text(encoding='utf-8'))['rabbitmq']
OLD_USER = 'santa-historical-broker'
NEW_USER = 'santa-fresh-broker'
VHOST = 'santa-historical'
QUEUE = 'historical-santa-worker'
COOKIE = '.erlang.cookie'


@contextmanager
def broker(root, data, suffix, user, password):
    assert re.fullmatch(r'rabbitmq@sha256:[a-f0-9]{64}', IMAGE)
    data.mkdir(mode=0o700)
    name = 'ci' + root.name + '-rabbit-' + suffix
    environment = {**os.environ, 'RABBITMQ_DEFAULT_USER': user, 'RABBITMQ_DEFAULT_PASS': password}
    subprocess.run(['docker', 'run', '--detach', '--pull=never', '--name', name, '--network', 'none',
                    '--hostname', 'rabbitmq', '--memory', '512m', '--cpus', '2', '--pids-limit', '192',
                    '--user', f'{os.getuid()}:0', '--mount', f'type=bind,source={data},target=/var/lib/rabbitmq',
                    '--env', 'RABBITMQ_DEFAULT_USER', '--env', 'RABBITMQ_DEFAULT_PASS',
                    '--env', 'RABBITMQ_SERVER_ADDITIONAL_ERL_ARGS=+S 2:2 +SDcpu 1 +SDio 1',
                    '--env', 'RABBITMQ_CTL_ERL_ARGS=+S 1:1 +SDcpu 1 +SDio 1', IMAGE],
                   env=environment, check=True, stdout=subprocess.DEVNULL, timeout=30)

    def ctl(*args, check=True, timeout=20):
        return subprocess.run(['docker', 'exec', name, 'rabbitmqctl', '-q', *args],
                              capture_output=True, text=True, check=check, timeout=timeout)

    try:
        ctl('await_startup', '--timeout', '45', timeout=55)
        assert 'rabbit@rabbitmq' in ctl('eval', 'node().').stdout
        yield name, ctl
        ctl('stop')
        exit_code = subprocess.check_output(['docker', 'wait', name], timeout=15)
        assert exit_code.strip() == b'0'
    except Exception:
        subprocess.run(['docker', 'logs', '--tail', '30', name], check=False, timeout=10)
        raise
    finally:
        subprocess.run(['docker', 'rm', '-f', '-v', name], check=True, stdout=subprocess.DEVNULL, timeout=15)


def inventory(data):
    files = {}
    for path in data.rglob('*'):
        assert not path.is_symlink()
        if path.is_file():
            with path.open('rb') as stream:
                files[path.relative_to(data).as_posix()] = hashlib.file_digest(stream, 'sha256').hexdigest()
    assert COOKIE in files and any(path.startswith('mnesia/') for path in files)
    return files


def observed(ctl, *arguments):
    return json.loads(ctl('--formatter=json', *arguments).stdout)


def capture(root):
    data = root / 'rabbit-source'
    password = secrets.token_hex(32)
    with broker(root, data, 'source', OLD_USER, password) as (name, ctl):
        ctl('authenticate_user', OLD_USER, password)
        ctl('add_vhost', VHOST)
        definitions = {'queues': [{'name': QUEUE, 'vhost': VHOST, 'durable': True,
                                   'auto_delete': False, 'arguments': {'x-queue-type': 'classic'}}]}
        subprocess.run(['docker', 'exec', '-i', name, 'sh', '-c',
                        'umask 077; cat >/tmp/santa-fixture-definitions.json'],
                       input=json.dumps(definitions).encode(), check=True, timeout=10)
        ctl('import_definitions', '/tmp/santa-fixture-definitions.json')
        queues = observed(ctl, 'list_queues', '-p', VHOST, 'name', 'durable',
                          'messages_ready', 'messages_unacknowledged')
        assert queues == [{'name': QUEUE, 'durable': True, 'messages_ready': 0, 'messages_unacknowledged': 0}]
    return data, password, inventory(data)


def verify(root, quarantine, historical_password, expected_files):
    assert inventory(quarantine) == expected_files
    data = root / 'rabbit-fresh'
    password = secrets.token_hex(32)
    assert password != historical_password
    with broker(root, data, 'fresh', NEW_USER, password) as (_, ctl):
        ctl('authenticate_user', NEW_USER, password)
        assert {row['user'] for row in observed(ctl, 'list_users')} == {NEW_USER}
        assert {row['name'] for row in observed(ctl, 'list_vhosts', 'name')} == {'/'}
        assert observed(ctl, 'list_queues', '-p', '/', 'name') == []
        for user in (OLD_USER, NEW_USER):
            rejected = ctl('authenticate_user', user, historical_password, check=False)
            assert rejected.returncode != 0
            assert 'failed to authenticate' in (rejected.stdout + rejected.stderr).casefold()
        ctl('authenticate_user', NEW_USER, password)
    assert inventory(data)[COOKIE] != expected_files[COOKIE]
    assert inventory(quarantine) == expected_files
    print('RabbitMQ history stayed quarantined while the fresh broker rejected historical credentials')
