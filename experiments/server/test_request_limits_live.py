"""Explicit real loopback HTTP rejection gate using an existing synthetic fixture.

No fixture creation, device enrollment, publication, Azure access or ingress.
The selected source-bound runtime must already be healthy and fully committed.
Original Unlicense tooling. Executing this is a separate authorized live action.
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import urllib.error
import urllib.request
import uuid
import zlib

import prepare_request_limits as package
import test_live_zentral as live


def cases(bounds):
    raw = b'{"events":[]}'
    yield 'raw-limit', b' ' * (bounds['compressed'] + 1), None, 413
    bomb = b'{"padding":"' + b'x' * bounds['expanded'] + b'"}'
    for encoding, compress in (('deflate', zlib.compress), ('gzip', gzip.compress)):
        blob = compress(raw)
        yield encoding + '-expanded-limit', compress(bomb), encoding, 413
        yield encoding + '-truncated', blob[:-1], encoding, 400
        yield encoding + '-trailing', blob + b'trailing', encoding, 400
        yield encoding + '-concatenated', blob + compress(raw), encoding, 400
        yield encoding + '-corrupt', b'not compressed', encoding, 400
    yield 'unsupported-encoding', raw, 'br', 415
    yield 'stacked-encoding', raw, 'gzip, deflate', 415
    yield 'excess-depth', b'{"x":' + b'[' * bounds['depth'] + b'0' + b']' * bounds['depth'] + b'}', None, 400
    yield 'excess-events', json.dumps({'events': [{}] * (bounds['events'] + 1)}).encode(), None, 413
    yield 'aggregate-events', json.dumps({'events': [{}] * bounds['events'], 'file_access_events': [{}]}).encode(), None, 413
    yield 'invalid-event-shape', b'{"events":[null]}', None, 400
    yield 'duplicate-json-member', b'{"events":[],"events":[{}]}', None, 400
    yield 'non-finite-number', b'{"x":1e999}', None, 400
    yield 'invalid-utf8', b'{"x":"\xff"}', None, 400
    yield 'non-object', b'[]', None, 400


def post_raw(stage, device, payload, encoding, credential):
    live.require(stage in ('preflight', 'ruledownload', 'eventupload', 'postflight'), 'Unexpected stage')
    live.require(live.UUID_PATTERN.fullmatch(device), 'Only synthetic devices are accepted')
    headers = {'Content-Type': 'application/json', 'Zentral-Authorization': 'Bearer ' + credential,
               'User-Agent': 'azd-santa-synthetic-request-limits/1'}
    if encoding is not None:
        headers['Content-Encoding'] = encoding
    request = urllib.request.Request(live.BASE_URL + stage + '/' + device, payload, headers, method='POST')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), live.NoRedirect())
    try:
        response = opener.open(request, timeout=15)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        content = response.read(65537)
        live.require(len(content) <= 65536, 'Response exceeded bound')
        return response.status


def run(compose, fixture_path):
    compose, compose_hash = live.validate_compose(compose)
    fixture_path = Path(fixture_path).absolute()
    fixture = live.load_fixture(fixture_path, compose_hash)
    before = live.snapshot(compose, fixture)
    live.assert_committed(before, fixture)
    runtime = live.orm(compose, '''
import hashlib
from pathlib import Path
import azd_santa_request_limits as boundary
from zentral.contrib.santa import public_views
print(''' + repr(live.MARKER) + ''' + json.dumps(dict(
    bounds=boundary.DEFAULT_LIMITS.__dict__,
    helper_sha256=hashlib.sha256(Path(boundary.__file__).read_bytes()).hexdigest(),
    view_sha256=hashlib.sha256(Path(public_views.__file__).read_bytes()).hexdigest())))
''')
    expected = hashlib.sha256(Path(__file__).with_name('santa_request_limits.py').read_bytes().replace(b'\r\n', b'\n')).hexdigest()
    live.require(runtime.get('helper_sha256') == expected and runtime.get('view_sha256') == package.OUTPUT_SHA256,
                 'Runtime request boundary differs from selected source')
    bounds = runtime['bounds']
    # This gate intentionally qualifies the reviewed defaults. Custom deployment
    # limit choices require their own size/load qualification, not huge probes.
    live.require(bounds == dict(compressed=1048576, expanded=4194304, depth=32, events=100),
                 'Expected reviewed default limits')
    results = []
    device = fixture['devices'][0]
    for stage in ('preflight', 'ruledownload', 'eventupload', 'postflight'):
        for name, body, encoding, expected_status in cases(bounds):
            actual = post_raw(stage, device['uuid'], body, encoding, device['secret'])
            live.require(actual == expected_status, 'Hostile request was not rejected as specified')
            results.append(dict(stage=stage, case=name, status=actual))
    raw = b'{"events":[]}'
    for encoding, body in ((None, raw), ('identity', raw), ('deflate', zlib.compress(raw)),
                           ('zlib', zlib.compress(raw)), ('gzip', gzip.compress(raw))):
        live.require(post_raw('eventupload', device['uuid'], body, encoding, device['secret']) == 200,
                     'Valid empty event upload encoding failed')
        results.append(dict(stage='eventupload', case=encoding or 'none', status=200))
    after = live.snapshot(compose, fixture)
    live.require(after == before, 'Rejected/empty requests changed selected fixture state')
    receipt = fixture_path.with_name(fixture_path.stem + '.request-limits-' + uuid.uuid4().hex + '.json')
    data = dict(scope='synthetic-loopback-request-limits', compose_sha256=compose_hash,
                helper_sha256=expected, view_sha256=package.OUTPUT_SHA256,
                harness_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                results=results, selected_database_projection_unchanged=True,
                limitation='Real loopback HTTP only; no native Mac, public TLS, load/rate or full-database proof')
    descriptor = os.open(receipt, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'w') as output:
        json.dump(data, output)
    return receipt


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', required=True)
    parser.add_argument('--fixture', required=True)
    args = parser.parse_args()
    try:
        receipt = run(args.compose, args.fixture)
    except Exception:
        raise SystemExit('Request-limit qualification failed; retain private diagnostics and inspect the selected runtime.') from None
    print('SANTA_REQUEST_LIMITS_OK ' + str(receipt))
