"""Host driver for genuine held MFA requests across one bound Redis SIGKILL.

No Azure calls. All Docker mutations target the explicitly selected private
project, exact Redis container, and a newly named one-off test container. Raw
process output stays in private files; shared IPC contains bounded hashes/phases.
Original Unlicense tooling.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
import uuid

from test_security_store_live import validate_durable_compose
from test_live_zentral import require
from upgrade_core_runtime import write_private
from qualify_santa_profile import local_volumes

SCOPE = 'private-real-django-mfa-redis-restart'
LIMITATION = 'Genuine Django/crypto requests and Redis restart; audit delivery mocked, no TCP/browser/TLS/native-Mac/host-power-loss/backup proof'
RESULTS = {'webauthn_nonce_rejected', 'totp_step_rejected', 'budget_exhausted', 'accepted_logins',
           'marker_settings_ready', 'redis_restarted', 'limitation'}


def parse_phase(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, 'Duplicate restart IPC field')
            value[key] = item
        return value
    require(len(raw.encode('utf-8')) <= 4096, 'Restart IPC exceeded bound')
    return json.loads(raw, object_pairs_hook=unique)


def phase_record(value, context, phase):
    extra = {'redis_run_id_sha256'} if phase == 'ready' else RESULTS if phase == 'passed' else set()
    require(isinstance(value, dict) and set(value) == set(context) | {'phase'} | extra,
            'Unexpected restart IPC schema')
    require(all(value[key] == expected for key, expected in context.items()) and value['phase'] == phase,
            'Restart IPC binding mismatch')
    if phase == 'ready':
        require(re.fullmatch(r'[a-f0-9]{64}', value['redis_run_id_sha256']), 'Invalid Redis process evidence')
    elif phase == 'passed':
        require(value['accepted_logins'] == 2 and type(value['accepted_logins']) is int
                and all(value[key] is True for key in RESULTS - {'accepted_logins', 'limitation'})
                and value['limitation'] == LIMITATION, 'Incomplete cryptographic replay evidence')
    return value


def container_binding(info, project, service, expected_image, *, media=False, redis=False, database=False):
    labels = info['Config'].get('Labels', {})
    require(labels.get('com.docker.compose.project') == project
            and labels.get('com.docker.compose.service') == service
            and info.get('Image') == expected_image and info['State']['Running'] is True,
            'Actual container project/image/service/running binding mismatch')
    if media or redis or database:
        target, volume = ('/data', '_redis_data') if redis else ('/var/lib/postgresql', '_postgres_data') if database else ('/var/zentral', '_media_data')
        matches = [mount for mount in info['Mounts'] if mount['Destination'] == target]
        require(len(matches) == 1 and matches[0]['Type'] == 'volume'
                and matches[0]['Name'] == project + volume, 'Actual selected data volume mismatch')
    require(not any(mount['Destination'] == '/var/run/docker.sock' for mount in info['Mounts']),
            'App/test containers must not receive Docker socket access')
    require(set(info['NetworkSettings']['Networks']) == {project + '_default'},
            'Only the selected project-local default network is supported')


def owned_test(info, project, image, name, namespace):
    labels = info['Config'].get('Labels', {})
    require(info.get('Name') == '/' + name and info['Image'] == image
            and labels.get('com.docker.compose.project') == project
            and labels.get('com.docker.compose.service') == 'web'
            and labels.get('io.azd-santa.mfa-restart') == namespace,
            'Refusing an unrecognized one-off test container')


def run(compose_path, harness_path, destination, expected_image, expected_policy, expected_harness,
        *, allow_redis_restart=False):
    require(allow_redis_restart is True, 'Explicit Redis interruption authorization required')
    require(re.fullmatch(r'sha256:[a-f0-9]{64}', expected_image)
            and all(re.fullmatch(r'[a-f0-9]{64}', value) for value in (expected_policy, expected_harness)),
            'Expected exact immutable image/policy/harness bindings')
    harness = Path(harness_path).resolve(strict=True)
    require(harness.is_file() and hashlib.sha256(harness.read_bytes()).hexdigest() == expected_harness,
            'Local harness source differs from reviewed bytes')
    compose, digest, project = validate_durable_compose(compose_path)
    configured = json.loads(compose.read_text())
    local_volumes(configured)  # No external/name/driver_opts alias into unrelated host data.
    require(all(configured['services'][name]['image'] == expected_image for name in ('web', 'workers', 'celery')),
            'Declared application images differ from selected immutable image')
    destination = Path(destination).absolute(); destination.mkdir(mode=0o700)
    environment = {key: value for key, value in os.environ.items() if not key.startswith(('DOCKER_', 'COMPOSE_'))}
    docker = ['docker', '--host', 'unix:///var/run/docker.sock']
    command = docker + ['compose', '--project-name', project, '-f', str(compose)]
    namespace = 'azd-mfa-restart-' + uuid.uuid4().hex[:24]
    context = dict(scope=SCOPE, namespace=namespace, compose_sha256=digest, policy_sha256=expected_policy,
                   harness_sha256=expected_harness, image_id=expected_image)
    test_name = 'santa-mfa-restart-' + uuid.uuid4().hex[:24]
    sequence = 0

    def execute(label, args, *, timeout=20, missing=False, check=True):
        nonlocal sequence
        sequence += 1
        result = subprocess.run(args, capture_output=True, text=True, env=environment, timeout=timeout)
        write_private(destination / (str(sequence) + '-' + label + '.json'),
                      dict(returncode=result.returncode, stdout=result.stdout, stderr=result.stderr))
        require(not check or result.returncode == 0 or (missing and result.returncode == 2),
                'Selected restart operation failed; inspect private evidence')
        return result

    def inspect(name):
        return json.loads(execute('inspect', docker + ['inspect', name]).stdout)[0]

    def service(name):
        identifier = execute('container-id', command + ['ps', '--quiet', name]).stdout.strip()
        require(re.fullmatch(r'[a-f0-9]{64}', identifier), 'Expected exactly one selected running service')
        return identifier, inspect(identifier)

    def read_phase(filename):
        require(filename in ('ready.json', 'result.json'), 'Unexpected IPC filename')
        path = '/var/zentral/' + namespace + '/' + filename
        code = "from pathlib import Path; import sys; p=Path(" + repr(path) + "); " \
               "sys.exit(2) if not p.exists() else None; " \
               "assert p.is_file() and not p.is_symlink() and p.stat().st_size<=4096; sys.stdout.write(p.read_text())"
        output = execute('ipc-read', command + ['exec', '-T', 'web', 'python', '-c', code], missing=True)
        return None if output.returncode == 2 else parse_phase(output.stdout)

    def release():
        payload = json.dumps(dict(context, phase='resume'), separators=(',', ':'))
        code = "import os\nfrom pathlib import Path\np=Path(" + repr('/var/zentral/' + namespace + '/resume.json') + ")\n" \
               "tmp=p.with_suffix('.pending')\nfd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)\n" \
               "with os.fdopen(fd,'w') as f:\n    f.write(" + repr(payload) + ")\n    f.flush()\n    os.fsync(f.fileno())\n" \
               "os.link(tmp,p)\ntmp.unlink()\n"
        execute('ipc-resume', command + ['exec', '-T', 'web', 'python', '-c', code])

    networks = set()
    for name in ('web', 'workers', 'celery'):
        _, info = service(name)
        container_binding(info, project, name, expected_image, media=True)
        networks.add(info['NetworkSettings']['Networks'][project + '_default']['NetworkID'])
    _, db_info = service('db')
    require(db_info['Config']['Image'] == configured['services']['db']['image'], 'PostgreSQL digest declaration mismatch')
    container_binding(db_info, project, 'db', db_info['Image'], database=True)
    networks.add(db_info['NetworkSettings']['Networks'][project + '_default']['NetworkID'])
    redis_id, redis_info = service('redis')
    redis_image = redis_info['Image']
    require(redis_info['Config']['Image'] == configured['services']['redis']['image'], 'Redis digest declaration mismatch')
    container_binding(redis_info, project, 'redis', redis_image, redis=True)
    networks.add(redis_info['NetworkSettings']['Networks'][project + '_default']['NetworkID'])
    require(len(networks) == 1 and re.fullmatch(r'[a-f0-9]{64}', next(iter(networks))), 'Selected services are on different networks')
    server_info = execute('redis-process', command + ['exec', '-T', 'redis', 'redis-cli', '--raw', 'INFO', 'server']).stdout
    process_ids = re.findall(r'^run_id:([a-f0-9]{40})\r?$', server_info, flags=re.MULTILINE)
    require(len(process_ids) == 1, 'Expected one selected Redis process identity')
    context['redis_run_id_sha256'] = hashlib.sha256(process_ids[0].encode()).hexdigest()
    absent = execute('test-name-absence', docker + ['inspect', test_name], check=False)
    require(absent.returncode != 0 and re.search(r'No such (?:object|container)', absent.stderr, re.IGNORECASE),
            'New test container absence could not be established')
    write_private(destination / 'plan.json', dict(context, redis_container=redis_id,
                  redis_image=redis_image, test_container=test_name, scope_note='Exact selected Redis SIGKILL/start; no volumes removed'))
    code = "from pathlib import Path; p=Path('/tmp/azd_mfa_restart.py'); exec(compile(p.read_bytes(),str(p),'exec'),{'__name__':'__main__','__file__':str(p)})"
    launch = command + ['run', '--detach', '--no-deps', '--pull', 'never', '--name', test_name,
             '--label', 'io.azd-santa.mfa-restart=' + namespace,
             '--volume', str(harness) + ':/tmp/azd_mfa_restart.py:ro',
             '--env', 'AZD_MFA_RESTART_CONTEXT=' + json.dumps(context, separators=(',', ':')),
             '--entrypoint', 'python', 'web', 'server/manage.py', 'shell', '--no-imports', '-c', code]
    attempted = False
    try:
        attempted = True
        execute('launch', launch, timeout=40)
        test = inspect(test_name)
        owned_test(test, project, expected_image, test_name, namespace)
        container_binding(test, project, 'web', expected_image, media=True)
        require(test['NetworkSettings']['Networks'][project + '_default']['NetworkID'] in networks,
                'One-off test is not on the selected database/Redis network')
        mounted = [value for value in test['Mounts'] if value['Destination'] == '/tmp/azd_mfa_restart.py']
        require(len(mounted) == 1 and mounted[0]['Type'] == 'bind' and mounted[0]['RW'] is False
                and Path(mounted[0]['Source']).resolve() == harness, 'Actual mounted harness differs from selected source')
        deadline = time.monotonic() + 240
        last_process_check = 0
        while True:
            value = read_phase('ready.json')
            if value is not None:
                phase_record(value, context, 'ready'); break
            require(read_phase('result.json') is None and time.monotonic() < deadline,
                    'Held real-request preparation failed/timed out; Redis not interrupted')
            if time.monotonic() - last_process_check > 2:
                require(inspect(test_name)['State']['Running'] is True, 'Preparation process exited before readiness')
                last_process_check = time.monotonic()
            time.sleep(0.25)
        require(hashlib.sha256(compose.read_bytes()).hexdigest() == digest, 'Compose changed before Redis mutation')
        started = time.monotonic()
        execute('redis-kill', command + ['kill', '--signal', 'KILL', 'redis'])
        execute('redis-start', command + ['up', '--detach', '--no-deps', 'redis'])
        deadline = time.monotonic() + 12
        while True:
            pong = execute('redis-ping', command + ['exec', '-T', 'redis', 'redis-cli', 'PING'], check=False)
            if pong.returncode == 0 and pong.stdout.strip() == 'PONG':
                break
            require(time.monotonic() < deadline, 'Redis did not become ready in real-code headroom')
            time.sleep(0.1)
        current_id, current = service('redis')
        require(current_id == redis_id, 'Redis restart replaced the selected container')
        container_binding(current, project, 'redis', redis_image, redis=True)
        require(time.monotonic() - started < 18, 'Redis restart exceeded live TOTP-code headroom')
        release()  # App rechecks actual marker/settings before it releases requests.
        deadline = time.monotonic() + 90
        while True:
            result = read_phase('result.json')
            if result is not None:
                phase_record(result, context, 'passed'); break
            require(time.monotonic() < deadline, 'Held-request completion timed out')
            time.sleep(0.25)
        deadline = time.monotonic() + 10
        final = inspect(test_name)
        while final['State']['Running'] is True and time.monotonic() < deadline:
            time.sleep(0.1)
            final = inspect(test_name)
        owned_test(final, project, expected_image, test_name, namespace)
        require(final['State']['Running'] is False and final['State']['ExitCode'] == 0,
                'Test process did not finish successfully')
        result.update(redis_container_sha256=hashlib.sha256(redis_id.encode()).hexdigest(),
                      restart_scope='SIGKILL/start same bound container and volume')
        write_private(destination / 'receipt.json', result)
        return result
    finally:
        if attempted:
            # Bound this run's own test process on failure, preserving its
            # container/IPC/logs. Never stop another project or erase volumes.
            remaining = execute('test-final-inspect', docker + ['inspect', test_name], check=False)
            if remaining.returncode == 0:
                state = json.loads(remaining.stdout)[0]
                owned_test(state, project, expected_image, test_name, namespace)
                if state['State']['Running'] is True:
                    execute('stop-owned-test', docker + ['stop', '--time', '10', test_name])
                execute('private-process-output', docker + ['logs', test_name])
            else:
                require(re.search(r'No such (?:object|container)', remaining.stderr, re.IGNORECASE),
                        'Unknown launch outcome; inspect exact planned test container')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('compose', 'harness', 'destination', 'image', 'policy-sha256', 'harness-sha256'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--allow-redis-restart', action='store_true')
    args = parser.parse_args()
    try:
        result = run(args.compose, args.harness, args.destination, args.image, args.policy_sha256,
                     args.harness_sha256, allow_redis_restart=args.allow_redis_restart)
    except Exception:
        raise SystemExit('MFA restart qualification failed; inspect private output and exact selected service state. Do not replay security initialization.') from None
    print(json.dumps(result))
