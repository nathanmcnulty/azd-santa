"""Count only this private synthetic fixture's indexed Santa events."""
import argparse
import json
import os
from pathlib import Path
import subprocess

from test_live_zentral import load_fixture, validate_compose


def verify(compose_path, fixture_path, expected_count):
    compose, digest = validate_compose(compose_path)
    fixture = load_fixture(Path(fixture_path), digest)
    query = {'query': {'bool': {'filter': [
        {'term': {'type': 'santa_event'}},
        {'terms': {'machine_serial_number': [d['serial'] for d in fixture['devices']]}}
    ]}}}
    code = (
        'import json,urllib.request; '
        f'query={query!r}; '
        "request=urllib.request.Request('http://elastic:9200/zentral-events/_count', "
        "json.dumps(query).encode(), {'Content-Type':'application/json'}, method='POST'); "
        "opener=urllib.request.build_opener(urllib.request.ProxyHandler({})); "
        "result=json.load(opener.open(request,timeout=15)); print(json.dumps({'count':result['count']}))"
    )
    environment = {k: v for k, v in os.environ.items() if not k.startswith(('DOCKER_', 'COMPOSE_'))}
    result = subprocess.run(['docker', '--host', 'unix:///var/run/docker.sock', 'compose', '-f', str(compose),
                             'exec', '-T', 'web', 'python', '-c', code],
                            capture_output=True, text=True, timeout=30, env=environment)
    if result.returncode:
        raise RuntimeError('Private indexing query failed; no raw diagnostics exported')
    count = json.loads(result.stdout)['count']
    print(json.dumps(dict(scope='private-synthetic-only', indexed_santa_events=count,
                         expected=expected_count, compose_sha256=digest)))
    if count != expected_count:
        raise RuntimeError('Indexed event receipt does not match this fixture')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', required=True)
    parser.add_argument('--fixture', required=True)
    parser.add_argument('--expected', type=int, required=True)
    args = parser.parse_args()
    verify(args.compose, args.fixture, args.expected)
