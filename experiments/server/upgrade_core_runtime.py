"""Explicit, private image-only transition; retain the prior fixture and volumes.

Developer qualification only. Failures leave private logs and require inspection;
this is not a production upgrade, rollback, or automatic recovery mechanism.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time

from test_live_zentral import (COMMIT, MARKER, assert_committed, load_fixture,
                               snapshot, validate_compose)


def write_private(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(data, stream, sort_keys=True, indent=2)


def transition(old_path, fixture_path, image_id, boot_id):
    old_path, old_hash = validate_compose(old_path)
    fixture = load_fixture(Path(fixture_path), old_hash)
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', image_id):
        raise ValueError('Expected an immutable local image ID')
    original = json.loads(old_path.read_text())
    updated = copy.deepcopy(original)
    for name in ('web', 'workers', 'celery'):
        if updated['services'][name]['image'] != original['services']['web']['image']:
            raise ValueError('Prior application images differ')
        updated['services'][name]['image'] = image_id
    if updated == original:
        raise ValueError('Image transition must change the application image')
    target = old_path.with_name('compose-stores.json')
    target_fixture = old_path.with_name('synthetic-fixture-stores.json')
    receipt = old_path.with_name('image-transition.json')
    if any(p.exists() or p.is_symlink() for p in (target, target_fixture, receipt)):
        raise FileExistsError('Existing transition requires inspection')
    write_private(target, updated)
    _, new_hash = validate_compose(target)
    updated_fixture = copy.deepcopy(fixture)
    updated_fixture['compose_sha256'] = new_hash
    write_private(target_fixture, updated_fixture)
    write_private(receipt, {
        'scope': 'private-synthetic-image-only-transition',
        'old_compose_sha256': old_hash, 'new_compose_sha256': new_hash,
        'old_image': original['services']['web']['image'], 'new_image': image_id,
        'project': original['name'], 'fixture_identity_preserved': True,
        'boot_id': boot_id,
        'status': 'prepared; runtime and persistence not yet verified'})
    return target, target_fixture


def upgrade(compose, fixture, image_id):
    old, _ = validate_compose(compose)
    # Read and verify existing credentials/rules/postflight before any change.
    assert_committed(snapshot(old, load_fixture(Path(fixture), validate_compose(old)[1])),
                     load_fixture(Path(fixture), validate_compose(old)[1]))
    environment = {k: v for k, v in os.environ.items()
                   if not k.startswith(('DOCKER_', 'COMPOSE_'))}
    inspected = json.loads(subprocess.check_output(
        ['docker', '--host', 'unix:///var/run/docker.sock', 'image', 'inspect', image_id],
        text=True, env=environment, timeout=30))[0]
    labels = inspected['Config'].get('Labels', {})
    if (labels.get('org.opencontainers.image.revision') != COMMIT or
            labels.get('io.azd-santa.variant') != 'core-experiment'):
        raise ValueError('Image provenance labels do not match')
    target, target_fixture = transition(old, fixture, image_id,
        Path('/proc/sys/kernel/random/boot_id').read_text().strip())
    command = ['docker', '--host', 'unix:///var/run/docker.sock', 'compose', '-f', str(target)]

    def run(label, args, *, timeout=180, input=None):
        result = subprocess.run(command + args, input=input, text=True,
                                capture_output=True, timeout=timeout, env=environment)
        write_private(target.parent / ('upgrade-' + label + '.json'),
                      dict(returncode=result.returncode, stdout=result.stdout, stderr=result.stderr))
        if result.returncode:
            raise RuntimeError('Private upgrade step failed: ' + label)
        return result.stdout

    run('config', ['config', '--quiet'])
    run('stop', ['stop', 'web', 'workers', 'celery'])
    manage = ['run', '--rm', '--no-deps', '--entrypoint', 'python', 'web', 'server/manage.py']
    # Run schema and provisioning once before workers, never infer store readiness
    # from upstream's success exit: its provisioner catches serializer errors.
    run('migrate', manage + ['migrate', '--noinput'])
    run('provision', manage + ['provision'])
    code = '''
import importlib,json
importlib.import_module('zentral.core.stores.provisioning')
from zentral.core.stores.models import Store
stores=list(Store.objects.all())
assert len(stores)==1
s=stores[0]
assert s.backend=='ELASTICSEARCH' and s.provisioning_uid=='elasticsearch' and s.admin_console
print('SANTA_SYNTHETIC_JSON:'+json.dumps({'queue':('store_events_'+s.name).replace(' ','_')}))
'''
    output = run('assert-store', manage + ['shell', '--no-imports'], input=code)
    records = [line[len(MARKER):] for line in output.splitlines() if line.startswith(MARKER)]
    if len(records) != 1:
        raise RuntimeError('Missing authoritative store receipt')
    queue = json.loads(records[0])['queue']
    run('start-workers', ['up', '--detach', '--no-deps', 'workers', 'celery'])
    deadline = time.monotonic() + 120
    while True:
        result = subprocess.run(command + ['exec', '-T', 'rabbitmq', 'rabbitmqctl',
            'list_queues', 'name', 'consumers', '--formatter', 'json'],
            capture_output=True, text=True, env=environment, timeout=30)
        if result.returncode == 0:
            queues = json.loads(result.stdout)
            if all(any(q['name'] == name and q['consumers'] > 0 for q in queues)
                   for name in (queue, 'enrich_events', 'process_events')):
                write_private(target.parent / 'upgrade-consumers.json', {'queues': queues})
                break
        if time.monotonic() >= deadline:
            raise TimeoutError('Event consumers not ready; listener remains stopped')
        time.sleep(2)
    run('start-web', ['up', '--detach', '--no-deps', 'web'])
    # No HTTP is sent here. Check the unchanged fixture database first.
    deadline = time.monotonic() + 90
    while True:
        try:
            state = snapshot(target, load_fixture(target_fixture, validate_compose(target)[1]))
            assert_committed(state, load_fixture(target_fixture, validate_compose(target)[1]))
            break
        except ValueError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(2)
    write_private(target.parent / 'upgrade-persistence.json', {
        'scope': 'private-synthetic-only', 'existing_fixture_preserved': True,
        'image_id': image_id, 'state': state, 'event_consumers_ready': True,
        'event_indexing': 'not yet verified'})
    print('SANTA_CORE_UPGRADE_PERSISTENCE_OK ' + str(target))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', required=True)
    parser.add_argument('--fixture', required=True)
    parser.add_argument('--image', required=True)
    args = parser.parse_args()
    upgrade(args.compose, args.fixture, args.image)
