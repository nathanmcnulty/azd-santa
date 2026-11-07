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
# ES 9.2.1 commit 4ad0ef0e98a2e72fafbd79a19fa5cae2f026117d:
# SnapshotInfo serializes IndexVersion, not the GET / node release. See
# IndexVersions.csv, IndexVersions.BACKPORT_UPGRADE_TO_LUCENE_10_3_1 and
# ReleaseVersions.generateVersionsLookup (current 9.2.1 + prior 9.2.0).
SNAPSHOT_INDEX_VERSION = 9039001
SNAPSHOT_RELEASE_RANGE = '9.2.0-9.2.1'


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
         and type(snapshot['version_id']) is int and snapshot['version_id'] == SNAPSHOT_INDEX_VERSION
         and snapshot['version'] == SNAPSHOT_RELEASE_RANGE and snapshot['state'] == 'SUCCESS'
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
    # Exact 9.2.1 SnapshotsService rejects concrete system-index names in
    # indices. Wildcard resolution selects regular/hidden indices and streams;
    # include_global_state with absent feature_states includes ALL features.
    # Full observed concrete index/shard equality is still required afterward.
    body = dict(indices='*', expand_wildcards='all', include_global_state=True, partial=False,
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


def run_reserved(directory, binding_sha256, operation_id, *, seconds=600, maximum_bytes):
    """Existing pinned-image helper only: bounded selected-network HTTP client.

    Host owns generation/lock/container identity and starts this helper ONCE.
    No Django imports, owner credentials, listener or datastore mounts are used.
    """
    import urllib.request
    import urllib.error
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs): return None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    end = time.monotonic() + seconds
    def api(method, path, body):
        need(time.monotonic() < end and path.startswith('/') and len(path) <= 4096)
        request = urllib.request.Request('http://elastic:9200' + path,
            data=encoded(body) if body is not None else None,
            headers={'Content-Type': 'application/json'}, method=method)
        try:
            with opener.open(request, timeout=min(5, max(0.1, end-time.monotonic()))) as response:
                raw = response.read(1024*1024+1)
        except urllib.error.HTTPError as error:
            code=error.code;error.close()
            if method == 'GET' and code == 404: return None
            raise ValueError('Native snapshot HTTP failed') from None
        need(len(raw) <= 1024*1024)
        return json.loads(raw)
    info = api('GET', '/', None)
    stats=api('GET','/_stats/store?expand_wildcards=all&filter_path=_all.primaries.store.size_in_bytes',None)
    size=stats['_all']['primaries']['store']['size_in_bytes']
    need(type(size) is int and size>=0 and size+64*1024**2<=maximum_bytes)
    rows = api('GET', INDICES_PATH, None)
    need(type(rows) is list and 0 < len(rows) <= 128)
    selected = plan(binding_sha256, operation_id, info['cluster_uuid'], info['version']['number'],
                    [row['index'] for row in rows], sum(int(row['pri']) for row in rows))
    result = submit(directory, selected, api)
    while result is None and time.monotonic() < end:
        time.sleep(1); result = observe(directory, selected, api)  # GET only.
    need(result is not None)
    observed=api('GET','/_snapshot/'+selected['repository']+'/'+selected['snapshot'],None)
    need(completed_snapshot(observed,selected)==result)
    write_new(directory/'native-observed.json',observed)
    write_new(directory / 'native-complete.json', result)
