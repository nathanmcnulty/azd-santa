"""Prepare and check the actual private core experiment; never expose ingress."""
import argparse
import json
import subprocess
import time
from pathlib import Path

from prepare_zentral_eval import COMMIT, prepare


def stage(source, lock_path, destination):
    tag = 'azd-santa-zentral-core-eval:' + COMMIT
    image = json.loads(subprocess.check_output(['docker', 'image', 'inspect', tag], text=True))[0]
    labels = image['Config'].get('Labels', {})
    if (labels.get('org.opencontainers.image.revision') != COMMIT or
            labels.get('io.azd-santa.variant') != 'core-experiment'):
        raise ValueError('Built image labels do not match the reviewed experiment')
    subprocess.run(['docker', 'run', '--rm', '--network', 'none', '--entrypoint', 'python', image['Id'],
                    '-c', "from pathlib import Path; assert not Path('/zentral/ee').exists(); assert Path('/usr/share/doc/zentral/CORE_BUILD_NOTICE.txt').is_file()"],
                   check=True, timeout=60)
    lock = json.loads(Path(lock_path).read_text())
    prepare(source, image['Id'], lock, destination, 'core-experiment')
    compose = ['docker', 'compose', '-f', str(Path(destination) / 'compose.json')]
    subprocess.run(compose + ['config', '--quiet'], check=True, timeout=30)
    subprocess.run(compose + ['up', '--detach', 'db', 'redis', 'rabbitmq', 'elastic'], check=True, timeout=120)
    deadline = time.monotonic() + 120
    while True:
        ready = subprocess.run(compose + ['exec', '-T', 'db', 'pg_isready', '-U', 'zentral', '-d', 'zentral'],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
        if ready.returncode == 0:
            break
        if time.monotonic() >= deadline:
            raise TimeoutError('Actual PostgreSQL startup did not pass readiness')
        time.sleep(2)
    # Run the real Django URL/config checks before starting any sync listener.
    checked = subprocess.run(compose + ['run', '--rm', '--no-deps', '--entrypoint', 'python',
                                        'web', 'server/manage.py', 'check'],
                             capture_output=True, text=True, timeout=120)
    # Keep full diagnostics private; an exception must not print generated secrets.
    with (Path(destination) / 'django-check.log').open('x') as output:
        output.write(checked.stdout + checked.stderr)
    result = dict(scope='private-synthetic-only', image_id=image['Id'],
                  upstream_commit=COMMIT, django_check_exit=checked.returncode)
    print(json.dumps(result))
    if checked.returncode:
        raise RuntimeError('Actual Django checks failed; inspect the private log before proceeding')
    # Django app discovery suppresses ImportError in optional modules. A clean
    # URL check alone does not prove that the required event-store provisioner
    # can load, and the upstream provision command can exit zero on save errors.
    provisioner = subprocess.run(compose + ['run', '--rm', '--no-deps', '--entrypoint', 'python',
        'web', 'server/manage.py', 'shell', '--no-imports', '-c',
        "import importlib; importlib.import_module('zentral.core.stores.provisioning')"],
        capture_output=True, text=True, timeout=120)
    with (Path(destination) / 'store-import-check.log').open('x') as output:
        output.write(provisioner.stdout + provisioner.stderr)
    if provisioner.returncode:
        raise RuntimeError('Required event-store provisioner cannot load; inspect the private log')
    print('SANTA_REAL_DJANGO_CHECK_PASSED')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True)
    parser.add_argument('--lock', required=True)
    parser.add_argument('--destination', required=True)
    args = parser.parse_args()
    stage(args.source, args.lock, args.destination)
