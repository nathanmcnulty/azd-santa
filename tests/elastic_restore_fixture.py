"""Native Elasticsearch snapshot and read-only restore for the sealed CI fixture."""

from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import subprocess
import time

import native_snapshot as native

INDEX = 'santa-events-census'
ALIAS = 'santa-events-census-read'
TEMPLATE = 'santa-census-source-template'
EVENTS = {'allowed': {'decision': 'ALLOW', 'sequence': 1},
          'blocked': {'decision': 'BLOCK', 'sequence': 2}}
OPERATION = 'b' * 32
REPOSITORY = '/mnt/azd-santa-snapshots'
LOCK = Path(__file__).resolve().parents[1] / 'experiments/server/dependency-images.lock.json'


@contextmanager
def elastic(root, repository, *, restored=False):
    image = json.loads(LOCK.read_text(encoding='utf-8'))['elasticsearch']
    assert re.fullmatch(r'docker\.elastic\.co/elasticsearch/elasticsearch@sha256:[a-f0-9]{64}', image)
    name = 'ci' + root.name + ('-elastic-restored' if restored else '-elastic-source')
    uid = os.getuid()
    assert uid != 0
    mount = f'type=bind,source={repository},target={REPOSITORY}'
    if restored:
        mount += ',readonly'
    subprocess.run(['docker', 'run', '--detach', '--pull=never', '--name', name, '--network', 'none',
                    '--memory', '1536m', '--cpus', '2', '--pids-limit', '256', '--user', f'{uid}:0',
                    '--tmpfs', f'/usr/share/elasticsearch/data:rw,uid={uid},gid=0,mode=0700,size=128m',
                    '--mount', mount, '--env', 'discovery.type=single-node', '--env', 'network.host=127.0.0.1',
                    '--env', 'xpack.security.enabled=false', '--env', 'xpack.ml.enabled=false',
                    '--env', 'ingest.geoip.downloader.enabled=false', '--env', 'node.store.allow_mmap=false',
                    '--env', f'path.repo={REPOSITORY}', '--env', 'ES_JAVA_OPTS=-Xms512m -Xmx512m', image],
                   check=True, stdout=subprocess.DEVNULL, timeout=30)

    def api(method, path, body=None):
        args = ['docker', 'exec', '-i', name, 'curl', '--silent', '--show-error', '--noproxy', '*',
                '--max-time', '15', '--max-filesize', '1048576', '--request', method,
                '--write-out', '\n%{http_code}']
        if body is not None:
            args.extend(['--header', 'Content-Type: application/json', '--data-binary', '@-'])
        response = subprocess.run([*args, 'http://127.0.0.1:9200' + path],
                                  input=None if body is None else native.encoded(body),
                                  capture_output=True, check=True, timeout=20)
        raw, _, status = response.stdout.rpartition(b'\n')
        if method == 'GET' and status == b'404':
            return None
        if not status.startswith(b'2'):
            raise ValueError(f'Synthetic Elasticsearch {method} {path} returned {status.decode()}: {raw[:512]!r}')
        assert len(raw) <= 1048576
        return json.loads(raw)

    try:
        deadline = time.monotonic() + 75
        while time.monotonic() < deadline:
            try:
                info = api('GET', '/')
                if info['cluster_uuid'] != '_na_':
                    assert info['version']['number'] == '9.2.1'
                    break
            except (subprocess.CalledProcessError, ValueError):
                pass
            time.sleep(1)
        else:
            raise RuntimeError('Synthetic Elasticsearch did not become ready')
        yield api
    except Exception:
        subprocess.run(['docker', 'logs', '--tail', '35', name], check=False, timeout=10)
        raise
    finally:
        subprocess.run(['docker', 'rm', '-f', '-v', name], check=True, stdout=subprocess.DEVNULL, timeout=20)


def check_events(api):
    result = api('GET', '/' + ALIAS + '/_search?size=3&track_total_hits=true')['hits']
    assert result['total'] == {'value': len(EVENTS), 'relation': 'eq'}
    assert {hit['_id']: hit['_source'] for hit in result['hits']} == EVENTS


def capture(root, binding):
    repository = root / 'elastic-source-repository'
    repository.mkdir(mode=0o700)
    journal = root / 'elastic-native-journal'
    journal.mkdir(mode=0o700)
    with elastic(root, repository) as api:
        assert api('PUT', '/' + INDEX, {
            'settings': {'number_of_shards': 1, 'number_of_replicas': 0},
            'aliases': {ALIAS: {}},
        })['acknowledged']
        assert api('PUT', '/_index_template/' + TEMPLATE, {'index_patterns': ['not-restored-*']})['acknowledged']
        for identity, event in EVENTS.items():
            assert api('PUT', f'/{INDEX}/_doc/{identity}?refresh=true', event)['result'] == 'created'
        check_events(api)
        info = api('GET', '/')
        plan = native.plan(binding, OPERATION, info['cluster_uuid'], info['version']['number'], [INDEX], 1)
        result = native.submit(journal, plan, api)
        deadline = time.monotonic() + 40
        while result is None and time.monotonic() < deadline:
            time.sleep(1)
            result = native.observe(journal, plan, api)
        assert result is not None
        observed = api('GET', f"/_snapshot/{plan['repository']}/{plan['snapshot']}")
        assert native.completed_snapshot(observed, plan) == result
    return plan, observed, repository / OPERATION


def restore(root, repository, plan):
    with elastic(root, repository, restored=True) as api:
        assert api('GET', '/')['cluster_uuid'] != plan['cluster_uuid']
        assert api('GET', '/' + INDEX) is None
        path = '/_snapshot/' + plan['repository']
        assert api('PUT', path, {'type': 'fs', 'settings': {'location': REPOSITORY, 'readonly': True}})['acknowledged']
        snapshot = api('GET', path + '/' + plan['snapshot'])
        assert native.completed_snapshot(snapshot, plan)['state'] == 'SUCCESS'
        restored = api('POST', path + '/' + plan['snapshot'] + '/_restore?wait_for_completion=true', {
            'indices': INDEX, 'include_aliases': True, 'include_global_state': False,
            'feature_states': ['none'], 'partial': False,
        })['snapshot']
        assert restored['indices'] == [INDEX]
        assert restored['shards']['failed'] == 0 and restored['shards']['successful'] == 1
        check_events(api)
        assert api('GET', '/_index_template/' + TEMPLATE) is None
    print('Elasticsearch restored the quarantined native snapshot and matched both synthetic events')
