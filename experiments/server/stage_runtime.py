"""Initialize one fresh private core namespace; never start its listener.

Developer qualification, not an azd hook or an existing-volume upgrade. Failures
retain private files/data and must not be retried over the selected destination.
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
import uuid

from prepare_zentral_eval import COMMIT, prepare
from prepare_database_roles import OUTPUT as ENTRYPOINT_SHA256

DOCKER = ['docker', '--host', 'unix:///var/run/docker.sock']


def write_private(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(value, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())


def private_directory(path):
    path = Path(path)
    if not path.is_absolute() or path != path.resolve(strict=True):
        raise ValueError('Canonical staging directory required')
    for parent in (path, *path.parents):
        info = parent.stat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('Staging ancestry must be root-owned and not writable by others')


def private_file(path):
    path = Path(path)
    private_directory(path.parent)
    info = path.stat()
    if (path != path.resolve(strict=True) or not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0 or info.st_mode & 0o077):
        raise ValueError('Root-owned non-link private staging file required')
    return path


def require_host():
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise ValueError('Fresh staging requires the selected privileged Linux host')


def stage(source, lock_path, destination, image_id):
    require_host()
    destination = Path(destination).absolute()
    if destination.exists() or destination.is_symlink():
        raise FileExistsError('Fresh destination already exists; inspect retained state')
    if (destination.parent != destination.parent.resolve(strict=True)
            or not re.fullmatch(r'sha256:[a-f0-9]{64}', image_id)):
        raise ValueError('Canonical fresh destination and exact image ID required')
    private_directory(destination.parent)
    environment = {k: v for k, v in os.environ.items() if not k.startswith(('DOCKER_', 'COMPOSE_'))}
    inspected = subprocess.run(DOCKER + ['image', 'inspect', image_id], capture_output=True,
                               text=True, env=environment, timeout=30, check=False)
    if inspected.returncode:
        raise ValueError('Selected local image unavailable')
    images = json.loads(inspected.stdout)
    if len(images) != 1 or images[0]['Id'] != image_id:
        raise ValueError('Selected image identity mismatch')
    labels = images[0]['Config'].get('Labels', {})
    if labels.get('org.opencontainers.image.revision') != COMMIT or labels.get('io.azd-santa.variant') != 'core-experiment':
        raise ValueError('Built image labels do not match the reviewed core experiment')
    lock = json.loads(Path(lock_path).read_text())
    prepare(source, image_id, lock, destination, 'core-experiment')
    config_dir = destination / 'docker-config'
    config_dir.mkdir(mode=0o700)
    environment['DOCKER_CONFIG'] = str(config_dir)
    compose_path = private_file(destination / 'compose.json')
    configured = json.loads(compose_path.read_text())
    project = configured['name']
    if not re.fullmatch(r'santa-zentral-eval-[a-f0-9]{12}', project):
        raise ValueError('Generated project identity mismatch')
    compose = DOCKER + ['compose', '--project-name', project, '-f', str(compose_path)]
    files = {}
    for filename in ('db.env', 'runtime.env', 'migration.env'):
        path = private_file(destination / filename)
        files[filename] = dict(line.split('=', 1) for line in path.read_text().splitlines())
    db, app, owner = (files[name] for name in ('db.env', 'runtime.env', 'migration.env'))
    if (db['POSTGRES_USER'] != 'zentral_owner' or app['POSTGRES_USER'] != 'zentral_runtime'
            or db['POSTGRES_PASSWORD'] == app['POSTGRES_PASSWORD']
            or owner != {**app, 'POSTGRES_USER': db['POSTGRES_USER'], 'POSTGRES_PASSWORD': db['POSTGRES_PASSWORD']}):
        raise ValueError('Fresh owner/runtime credential separation failed')
    module_hash = hashlib.sha256(Path(__file__).with_name('database_roles.py').read_bytes().replace(b'\r\n', b'\n')).hexdigest()
    sequence = 0

    def run(label, args, *, timeout=60, allowed_failure=False):
        nonlocal sequence
        sequence += 1
        output = destination / f'{sequence:03d}-{label}.json'
        try:
            result = subprocess.run(args, capture_output=True, text=True, env=environment, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            write_private(output, dict(timeout=True, stdout=str(error.stdout), stderr=str(error.stderr)))
            raise RuntimeError('Private staging step timed out: ' + label) from None
        write_private(output, dict(returncode=result.returncode, stdout=result.stdout, stderr=result.stderr))
        if result.returncode and not allowed_failure:
            raise RuntimeError('Private staging step failed: ' + label)
        return result

    def wait(label, args, seconds=120, expected=None):
        deadline = time.monotonic() + seconds
        while True:
            result = run(label, args, timeout=30, allowed_failure=True)
            if result.returncode == 0 and (expected is None or result.stdout.strip() == expected):
                return
            if time.monotonic() >= deadline:
                raise TimeoutError('Fresh dependency readiness failed: ' + label)
            time.sleep(2)

    if run('namespace', DOCKER + ['ps', '--all', '--quiet', '--filter', 'label=com.docker.compose.project=' + project]).stdout.strip():
        raise ValueError('Generated project already exists')
    volumes = run('volume-inventory', DOCKER + ['volume', 'ls', '--format', '{{.Name}}']).stdout.splitlines()
    networks = run('network-inventory', DOCKER + ['network', 'ls', '--format', '{{.Name}}']).stdout.splitlines()
    if project + '_default' in networks or any(project + '_' + name in volumes for name in configured['volumes']):
        raise ValueError('Generated backing namespace already exists')
    capabilities = run('compose-run-capabilities', compose + ['run', '--help']).stdout
    if '--env-from-file' not in capabilities:
        raise ValueError('Compose run must support job-only --env-from-file before staging')
    probe = ("from pathlib import Path; import hashlib; "
             "assert not Path('/zentral/ee').exists(); "
             f"assert hashlib.sha256(Path('/zentral/server/azd_santa_database_roles.py').read_bytes()).hexdigest()=={module_hash!r}; "
             f"assert hashlib.sha256(Path('/zentral/docker-entrypoint.py').read_bytes()).hexdigest()=={ENTRYPOINT_SHA256!r}; "
             "assert Path('/zentral/docker-entrypoint.py').stat().st_mode & 0o777 == 0o755")
    run('image-body', DOCKER + ['run', '--rm', '--network', 'none', '--pull', 'never', '--entrypoint', 'python', image_id, '-I', '-c', probe])
    run('compose-config', compose + ['config', '--quiet'])
    run('dependencies', compose + ['up', '--detach', '--no-recreate', '--pull', 'never', 'db', 'redis', 'rabbitmq', 'elastic'], timeout=120)
    wait('database', compose + ['exec', '-T', 'db', 'pg_isready', '-U', db['POSTGRES_USER'], '-d', db['POSTGRES_DB']])
    wait('broker', compose + ['exec', '-T', 'rabbitmq', 'rabbitmq-diagnostics', '-q', 'check_running'])
    wait('redis', compose + ['exec', '-T', 'redis', 'redis-cli', 'PING'], expected='PONG')
    search = "import json,urllib.request; o=urllib.request.build_opener(urllib.request.ProxyHandler({})); r=json.load(o.open('http://elastic:9200/_cluster/health?wait_for_status=yellow&timeout=5s',timeout=8)); assert not r['timed_out'] and r['status'] in ('yellow','green')"
    wait('search', compose + ['run', '--rm', '--no-deps', '--pull', 'never', '--entrypoint', 'python', 'web', '-c', search])
    evidence = destination / 'database-initialization'
    evidence.mkdir(mode=0o700)
    binding = dict(scope='fresh-private-database-initialization', image=image_id, project=project,
                   compose_sha256=hashlib.sha256(compose_path.read_bytes()).hexdigest(), module_sha256=module_hash,
                   environment_sha256={name: hashlib.sha256((destination / name).read_bytes()).hexdigest() for name in files},
                   state='outcome-unconfirmed; never repeat initialization automatically')
    write_private(evidence / 'binding.json', binding)
    name = 'santa-db-initialize-' + uuid.uuid4().hex
    try:
        run('initialize', compose + ['run', '--rm', '--no-deps', '--pull', 'never', '--name', name,
            '--user', '0', '--env-from-file', str(destination / 'migration.env'),
            '--volume', str(destination / 'runtime.env') + ':/run/azd-runtime.env:ro',
            '--volume', str(evidence) + ':/run/azd-db-init:rw', '--entrypoint', 'python',
            'web', 'server/manage.py', 'operator_database', 'initialize',
            '--runtime-env-file', '/run/azd-runtime.env', '--receipt', '/run/azd-db-init/attempt.json'], timeout=600)
    except Exception:
        inspected = run('initializer-inspection', DOCKER + ['inspect', name], allowed_failure=True)
        if inspected.returncode == 0:
            rows = json.loads(inspected.stdout)
            if (len(rows) != 1 or rows[0]['Name'] != '/' + name or rows[0]['Image'] != image_id
                    or not re.fullmatch(r'[a-f0-9]{64}', rows[0]['Id'])
                    or rows[0]['Config']['Labels'].get('com.docker.compose.project') != project
                    or rows[0]['Config']['Labels'].get('com.docker.compose.service') != 'web'
                    or rows[0]['Config']['Labels'].get('com.docker.compose.oneoff') != 'True'):
                raise RuntimeError('Initializer ownership/outcome requires private inspection') from None
            run('initializer-stop', DOCKER + ['stop', '--time', '5', rows[0]['Id']], timeout=20)
        else:
            inventory = run('initializer-inventory', DOCKER + ['ps', '--all', '--format', '{{.Names}}']).stdout.splitlines()
            if name in inventory:
                raise RuntimeError('Initializer outcome requires private inspection') from None
        raise
    complete = json.loads(private_file(evidence / 'attempt.json.complete').read_text())
    if complete.get('scope') != 'fresh-database-initialization' or complete.get('state') != 'runtime-role-checked':
        raise RuntimeError('Initialization completion receipt missing or invalid; inspect privately')
    # All remaining jobs inherit only the normal runtime environment.
    manage = compose + ['run', '--rm', '--no-deps', '--pull', 'never', '--entrypoint', 'python', 'web', 'server/manage.py']
    run('runtime-authority', manage + ['operator_database', 'check'])
    run('django-check', manage + ['check'])
    run('store-import-check', manage + ['shell', '--no-imports', '-c', "import importlib; importlib.import_module('zentral.core.stores.provisioning')"])
    result = dict(scope='private-synthetic-database-staging-only', image_id=image_id, upstream_commit=COMMIT,
                  compose_sha256=binding['compose_sha256'], database_initialization='runtime-role-checked',
                  listener_started=False, limitation='No security-store admission, live role harness, operator/browser or sync acceptance')
    write_private(destination / 'stage-receipt.json', result)
    print(json.dumps(result))
    print('SANTA_REAL_DJANGO_CHECK_PASSED')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'lock', 'destination', 'image'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    try:
        stage(args.source, args.lock, args.destination, args.image)
    except Exception:
        print('Private fresh staging failed; preserve files/data and inspect before any retry.', file=sys.stderr)
        raise SystemExit(1)
