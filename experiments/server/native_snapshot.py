"""Original Unlicense native ES/drain qualification primitives, not attestation.

The existing controller must own its supervisor lock/original generation before
calling these functions. Transports are caller-supplied and bounded; this module
does not select a deployment, start processes, authenticate or retry mutations.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import time

REPOSITORY_ROOT = '/mnt/azd-santa-snapshots'
HEX = r'[a-f0-9]{64}'
INDICES_PATH = '/_cat/indices?format=json&expand_wildcards=all&h=index,status,pri'


def need(value):
    if not value: raise ValueError('Native snapshot boundary failed')


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def sha(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def write_new(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(encoded(value)); stream.flush(); os.fsync(stream.fileno())
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(directory)
    finally: os.close(directory)


def publisher_quiescence(rows, original):
    need(set(original) == {'web', 'celery'} and len(set(original.values())) == 2
         and all(re.fullmatch(HEX, v) for v in original.values()))
    need(type(rows) is list and len(rows) == 2 and {row['Id'] for row in rows} == set(original.values()))
    for row in rows:
        state = row['State']
        need(state['Running'] is False and state['Paused'] is False and state['Restarting'] is False
             and type(state['Pid']) is int and state['Pid'] == 0 and state['ExitCode'] == 0
             and state['Status'] == 'exited' and state['OOMKilled'] is False and not state['Error'])


def drain(binding_sha256, original_publishers, expected_queues, publishers, queues, *, seconds=120, clock=time.monotonic, sleep=time.sleep):
    """Read only: two full zero samples after publishers close, never a subset."""
    need(re.fullmatch(HEX, binding_sha256) and type(seconds) is int and 2 <= seconds <= 300)
    need(type(expected_queues) is list and 0 < len(expected_queues) <= 64 and len(set(expected_queues)) == len(expected_queues)
         and all(re.fullmatch(r'[A-Za-z0-9_.:@-]{1,192}', name) for name in expected_queues))
    deadline = clock() + seconds; zero = 0
    while clock() < deadline:
        publisher_quiescence(publishers(), original_publishers)
        rows = queues()
        need(type(rows) is list and len(rows) == len(expected_queues) and {row['name'] for row in rows} == set(expected_queues))
        for row in rows:
            need(set(row) == {'name', 'messages_ready', 'messages_unacknowledged'} and
                 all(type(row[k]) is int and 0 <= row[k] <= 2**63-1 for k in ('messages_ready', 'messages_unacknowledged')))
        zero = zero + 1 if all(row['messages_ready'] == row['messages_unacknowledged'] == 0 for row in rows) else 0
        if zero == 2:
            publisher_quiescence(publishers(), original_publishers)
            need(clock() < deadline)
            return dict(scope='azd-santa-queue-drain-v1', binding_sha256=binding_sha256,
                        publisher_ids=original_publishers, queues=sorted(expected_queues), zero_samples=2)
        sleep(min(2, max(0, deadline-clock())))
    raise TimeoutError('Known queues did not drain')


def plan(binding_sha256, operation_id, cluster_uuid, version, indices, primary_shards):
    """Facts must come from selected ES readback, not operator-created JSON."""
    need(re.fullmatch(HEX, binding_sha256) and re.fullmatch(r'[a-f0-9]{32}', operation_id))
    need(re.fullmatch(r'[A-Za-z0-9_-]{22}', cluster_uuid) and version == '9.2.1')
    need(type(indices) is list and 0 < len(indices) <= 128 and len(set(indices)) == len(indices)
         and all(isinstance(name, str) and 1 <= len(name.encode()) <= 255 and not any(c in name for c in ('*', '?', ',', '/', '\\', '\0')) for name in indices))
    need(type(primary_shards) is int and len(indices) <= primary_shards <= 10000)
    value = dict(scope='azd-santa-native-snapshot-plan-v1', binding_sha256=binding_sha256,
                 operation_id=operation_id, cluster_uuid=cluster_uuid, version=version,
                 indices=sorted(indices), primary_shards=primary_shards,
                 repository='azd_santa_' + operation_id, snapshot='backup_' + operation_id,
                 location=REPOSITORY_ROOT + '/' + operation_id)
    return value


def validate_plan(value):
    need(value == plan(value['binding_sha256'], value['operation_id'], value['cluster_uuid'], value['version'], value['indices'], value['primary_shards']))


def repository_matches(value, selected):
    need(type(value) is dict and set(value) == {selected['repository']})
    repository = value[selected['repository']]
    readonly = repository['settings'].get('readonly', False)
    need(repository['type'] == 'fs' and repository['settings']['location'] == selected['location']
         and (readonly is False or (type(readonly) is str and readonly == 'false')))


def inventory_matches(rows, selected):
    need(type(rows) is list and len(rows) == len(selected['indices'])
         and {row['index'] for row in rows} == set(selected['indices']))
    for row in rows:
        need(set(row) == {'index', 'status', 'pri'} and row['status'] == 'open'
             and type(row['pri']) is str and re.fullmatch(r'[1-9][0-9]{0,3}', row['pri']))
    need(sum(int(row['pri']) for row in rows) == selected['primary_shards'])


def completed_snapshot(value, selected):
    validate_plan(selected)
    need(type(value) is dict and type(value.get('snapshots')) is list and len(value['snapshots']) == 1)
    snapshot = value['snapshots'][0]
    need(snapshot['snapshot'] == selected['snapshot'] and re.fullmatch(r'[A-Za-z0-9_-]{22}', snapshot['uuid'])
         and snapshot['version'] == selected['version'] and snapshot['state'] == 'SUCCESS'
         and snapshot.get('include_global_state') is True and snapshot.get('failures') == []
         and type(snapshot['indices']) is list and len(snapshot['indices']) == len(selected['indices'])
         and set(snapshot['indices']) == set(selected['indices']))
    need(snapshot['metadata'] == {'azd_santa_binding_sha256': selected['binding_sha256'],
                                'azd_santa_plan_sha256': sha(selected)})
    shards = snapshot['shards']
    need(set(shards) == {'total', 'successful', 'failed'} and all(type(x) is int for x in shards.values())
         and shards['total'] == shards['successful'] == selected['primary_shards'] and shards['failed'] == 0)
    return dict(scope='azd-santa-native-snapshot-complete-v1', plan=selected, plan_sha256=sha(selected),
                snapshot_uuid=snapshot['uuid'], result_sha256=sha(value), state='SUCCESS',
                include_global_state=True, failed_shards=0,
                restore_admission='not_implemented', current_authority='not_established')


def observe(directory, selected, api):
    """GET only. Missing/unknown is not permission to submit any mutation."""
    validate_plan(selected)
    need(json.loads((directory / 'plan.json').read_bytes()) == selected)
    info = api('GET', '/', None)
    need(info['cluster_uuid'] == selected['cluster_uuid'] and info['version']['number'] == selected['version'])
    repository = api('GET', '/_snapshot/' + selected['repository'], None)
    if repository is None: return None
    repository_matches(repository, selected)
    result = api('GET', '/_snapshot/' + selected['repository'] + '/' + selected['snapshot'], None)
    if result is None: return None
    snapshots = result.get('snapshots')
    need(type(snapshots) is list and len(snapshots) == 1)
    if snapshots[0].get('state') == 'IN_PROGRESS': return None
    receipt = completed_snapshot(result, selected)
    inventory_matches(api('GET', INDICES_PATH, None), selected)
    return receipt


def submit(directory, selected, api):
    """Single reserved repository PUT and snapshot PUT, no implicit resubmission.

    Caller verifies private canonical directory, its machine generation/lock,
    completed queue drain, stopped workers, and selected ES before this call.
    On any exception use observe() with this same plan; never call submit again.
    """
    validate_plan(selected)
    # API response bodies/output/time must be bounded by the trusted transport.
    # Plan and each intent are durable BEFORE their corresponding mutation.
    write_new(directory / 'plan.json', selected)
    info = api('GET', '/', None)
    need(info['cluster_uuid'] == selected['cluster_uuid'] and info['version']['number'] == selected['version'])
    inventory_matches(api('GET', INDICES_PATH, None), selected)
    need(api('GET', '/_snapshot/' + selected['repository'], None) is None)
    repository_path = '/_snapshot/' + selected['repository']
    repository_body = {'type': 'fs', 'settings': {'location': selected['location'], 'compress': True,
                                                'max_snapshot_bytes_per_sec': '20mb'}}
    write_new(directory / 'repository-intent.json', dict(path=repository_path, body=repository_body))
    need(api('PUT', repository_path, repository_body).get('acknowledged') is True)
    repository_matches(api('GET', repository_path, None), selected)
    inventory_matches(api('GET', INDICES_PATH, None), selected)
    snapshot_path = repository_path + '/' + selected['snapshot'] + '?wait_for_completion=false'
    body = dict(indices=','.join(selected['indices']), include_global_state=True, partial=False,
                ignore_unavailable=False, metadata={'azd_santa_binding_sha256': selected['binding_sha256'],
                                                  'azd_santa_plan_sha256': sha(selected)})
    write_new(directory / 'snapshot-intent.json', dict(path=snapshot_path, body=body))
    need(api('PUT', snapshot_path, body).get('accepted') is True)
    return observe(directory, selected, api)


def archive_roots(volumes, receipt, binding_sha256):
    """Sixth volume's completed repository replaces raw ES data in capture."""
    need(set(volumes) == {'postgres_data', 'redis_data', 'rabbitmq_data', 'elasticsearch_data', 'media_data', 'elasticsearch_snapshots'})
    need(set(receipt) == {'scope', 'plan', 'plan_sha256', 'snapshot_uuid', 'result_sha256', 'state',
                         'include_global_state', 'failed_shards', 'restore_admission', 'current_authority'})
    selected = receipt['plan']; validate_plan(selected)
    need(receipt['scope'] == 'azd-santa-native-snapshot-complete-v1' and receipt['plan_sha256'] == sha(selected)
         and selected['binding_sha256'] == binding_sha256 and receipt['state'] == 'SUCCESS'
         and receipt['include_global_state'] is True and type(receipt['failed_shards']) is int and receipt['failed_shards'] == 0
         and re.fullmatch(r'[A-Za-z0-9_-]{22}', receipt['snapshot_uuid']) and re.fullmatch(HEX, receipt['result_sha256'])
         and receipt['restore_admission'] == 'not_implemented' and receipt['current_authority'] == 'not_established')
    repository = volumes['elasticsearch_snapshots'] / selected['operation_id']
    need(repository == repository.resolve(strict=True) and repository.is_dir())
    # Root metadata files are necessary but not sufficient. Full repository is
    # captured only after the controller proves selected ES stopped/no writers.
    for name in ('snap-' + receipt['snapshot_uuid'] + '.dat', 'meta-' + receipt['snapshot_uuid'] + '.dat'):
        path = repository / name
        need(path == path.resolve(strict=True) and path.is_file() and path.stat().st_size > 0)
    need(any(re.fullmatch(r'index-[0-9]+', p.name) and p.is_file() and p.stat().st_size > 0 for p in repository.iterdir()))
    result = {'volumes/' + name: path for name, path in volumes.items() if name not in ('elasticsearch_data', 'elasticsearch_snapshots')}
    result['elasticsearch_snapshot_repository'] = repository
    return result
