"""Explicit real-Redis policy-storage crash gate on one selected private stack.

Runs the installed original claim/budget helpers against real Redis/AOF. This
does NOT replace full Django cryptographic MFA request tests. No fixture/user or
Azure mutation; Redis service interruption requires the explicit CLI flag.
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

from prepare_zentral_eval import REDIS_COMMAND
from test_live_zentral import MARKER, orm, require, validate_compose
from upgrade_core_runtime import write_private


def validate_durable_compose(path):
    path, digest = validate_compose(path)
    data = json.loads(path.read_text())
    redis = data['services']['redis']
    require(data.get('volumes', {}).get('redis_data') == {}
            and redis.get('volumes') == ['redis_data:/data'] and redis.get('command') == REDIS_COMMAND,
            'Expected the explicitly bound durable Redis candidate')
    require(re.fullmatch(r'[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}', redis.get('image', '')),
            'Expected a digest-pinned Redis image')
    return path, digest, data['name']


def policy_probe(compose, prefix, phase, expected_policy):
    require(re.fullmatch(r'azd-redis-durability-[0-9a-f]{24}', prefix), 'Invalid synthetic namespace')
    require(phase in ('prepare', 'probe', 'negative', 'cleanup'), 'Unexpected probe phase')
    require(re.fullmatch(r'[a-f0-9]{64}', expected_policy), 'Expected exact policy source')
    code = 'prefix=' + repr(prefix) + '\nphase=' + repr(phase) + '\nexpected_policy=' + repr(expected_policy) + '\n' + '''
import copy
import hashlib
from pathlib import Path
from django.conf import settings
from django.test import override_settings
import azd_santa_operator as policy
need(hashlib.sha256(Path(policy.__file__).read_bytes()).hexdigest() == expected_policy)
policy.check_security_store()
original_cache, original_client = policy._security_client()
original_marker = original_client.get(original_cache.make_key(policy.STORE_MARKER))
configuration = copy.deepcopy(settings.CACHES)
configuration['azd_santa_security']['KEY_PREFIX'] = prefix
with override_settings(CACHES=configuration):
    cache, client = policy._security_client()
    marker = cache.make_key(policy.STORE_MARKER)
    if phase == 'prepare':
        # Privileged synthetic storage fixture only: copy the already-admitted
        # instance marker to a unique namespace. Never repair product state.
        need(client.set(marker, original_marker, nx=True))
        need(policy._cache_add('challenge-used:synthetic', True, 360))
        need(policy._cache_add('totp-used:synthetic', True, 120))
        need([policy._budget('verify:synthetic', 5) for _ in range(6)] == [True] * 5 + [False])
    elif phase == 'probe':
        policy.check_security_store()
        need(not policy._cache_add('challenge-used:synthetic', True, 360))
        need(not policy._cache_add('totp-used:synthetic', True, 120))
        need(not policy._budget('verify:synthetic', 5))
    elif phase == 'negative':
        client.delete(marker)
        wrong = 'f' * 64 if policy._expected_store_id() != 'f' * 64 else 'e' * 64
        for value in (None, wrong + ':0'):
            if value is not None:
                client.set(marker, value)
            for operation in (policy.check_security_store,
                    lambda: policy._cache_add('negative-claim', True, 360),
                    lambda: policy._budget('negative-budget', 5)):
                try:
                    operation()
                except Exception:
                    pass
                else:
                    raise ValueError('Unadmitted marker accepted an operation')
            need(not client.exists(cache.make_key('negative-claim')))
            need(not client.exists(cache.make_key('negative-budget')))
        client.delete(marker)
        need(client.set(marker, original_marker, nx=True))
    else:
        client.delete(*(cache.make_key(key) for key in (policy.STORE_MARKER,
            'challenge-used:synthetic', 'totp-used:synthetic', 'verify:synthetic',
            'negative-claim', 'negative-budget')))
print(''' + repr(MARKER) + ''' + json.dumps(dict(phase=phase, passed=True,
    policy_sha256=hashlib.sha256(Path(policy.__file__).read_bytes()).hexdigest(),
    store_id_sha256=hashlib.sha256(policy._expected_store_id().encode()).hexdigest(),
    original_marker_sha256=hashlib.sha256(original_marker).hexdigest())))
'''
    return orm(compose, code)


def run(compose_path, destination, expected_policy, *, allow_redis_restart=False):
    if not allow_redis_restart:
        raise ValueError('Explicit Redis interruption authorization flag required')
    require(re.fullmatch(r'[a-f0-9]{64}', expected_policy), 'Expected exact installed policy SHA256')
    compose, digest, project = validate_durable_compose(compose_path)
    destination = Path(destination).absolute()
    destination.mkdir(mode=0o700)
    environment = {key: value for key, value in os.environ.items() if not key.startswith(('COMPOSE_', 'DOCKER_'))}
    docker = ['docker', '--host', 'unix:///var/run/docker.sock']
    command = docker + ['compose', '--project-name', project, '-f', str(compose)]

    def execute(label, args, timeout=30):
        result = subprocess.run(args, capture_output=True, text=True, env=environment, timeout=timeout)
        write_private(destination / (label + '.json'), dict(returncode=result.returncode,
                      stdout=result.stdout, stderr=result.stderr))
        require(result.returncode == 0, 'Selected Redis operation failed; inspect private evidence')
        return result.stdout.strip()

    def binding(label):
        container = execute(label + '-id', command + ['ps', '--all', '--quiet', 'redis'])
        require(re.fullmatch(r'[a-f0-9]{64}', container), 'Expected exactly one selected Redis container')
        data = json.loads(execute(label + '-inspect', docker + ['inspect', container]))[0]
        labels = data['Config'].get('Labels', {})
        mounts = [entry for entry in data['Mounts'] if entry['Destination'] == '/data']
        require(labels.get('com.docker.compose.project') == project
                and labels.get('com.docker.compose.service') == 'redis'
                and len(mounts) == 1 and mounts[0]['Type'] == 'volume'
                and mounts[0]['Name'] == project + '_redis_data', 'Redis container/volume binding mismatch')
        return container, mounts[0]['Name']

    def wait_ready(label):
        deadline = time.monotonic() + 30
        while True:
            result = subprocess.run(command + ['exec', '-T', 'redis', 'redis-cli', 'PING'],
                                    capture_output=True, text=True, env=environment, timeout=5)
            if result.returncode == 0 and result.stdout.strip() == 'PONG':
                return
            if time.monotonic() >= deadline:
                write_private(destination / (label + '-not-ready.json'), dict(stdout=result.stdout, stderr=result.stderr))
                raise TimeoutError('Redis did not become ready; retained state requires inspection')
            time.sleep(0.25)

    prefix = 'azd-redis-durability-' + uuid.uuid4().hex[:24]
    original_id, volume = binding('initial')
    write_private(destination / 'plan.json', dict(scope='real-redis-policy-storage-only', compose_sha256=digest,
                  policy_sha256=expected_policy, namespace=prefix, volume=volume))
    initial = policy_probe(compose, prefix, 'prepare', expected_policy)
    require(initial.get('policy_sha256') == expected_policy and initial.get('passed') is True,
            'Policy source mismatch; Redis not interrupted')
    started = time.monotonic()
    # Preparation may take time. Never resolve a replacement service when the
    # interruption was authorized for this inspected concrete container.
    execute('kill', docker + ['kill', '--signal', 'KILL', original_id])
    execute('start', docker + ['start', original_id])
    wait_ready('restart')
    restarted_id, restarted_volume = binding('restarted')
    require(restarted_id == original_id and restarted_volume == volume, 'Restart changed container or volume unexpectedly')
    restarted = policy_probe(compose, prefix, 'probe', expected_policy)
    execute('recreate', command + ['up', '--detach', '--force-recreate', '--no-deps', 'redis'])
    wait_ready('recreated')
    recreated_id, recreated_volume = binding('recreated')
    require(recreated_id != original_id and recreated_volume == volume, 'Recreation failed to preserve selected volume')
    require(time.monotonic() - started < 90, 'Replay probe exceeded live TOTP-claim lifetime headroom')
    recreated = policy_probe(compose, prefix, 'probe', expected_policy)
    negative = policy_probe(compose, prefix, 'negative', expected_policy)
    policy_probe(compose, prefix, 'cleanup', expected_policy)
    require(all(entry.get('passed') is True and entry.get('policy_sha256') == expected_policy
                and entry.get('original_marker_sha256') == initial['original_marker_sha256']
                and entry.get('store_id_sha256') == initial['store_id_sha256']
                for entry in (restarted, recreated, negative)), 'Inconsistent storage evidence')
    receipt = dict(scope='real-redis-policy-storage-only', compose_sha256=digest,
                   policy_sha256=expected_policy, harness_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                   store_id_sha256=initial['store_id_sha256'],
                   volume_name_sha256=hashlib.sha256(volume.encode()).hexdigest(),
                   crash_claims_and_budget_preserved=True, recreation_claims_and_budget_preserved=True,
                   missing_wrong_marker_operations_rejected=True,
                   limitation='Actual Redis/policy helpers only; full cryptographic HTTP MFA, host crash, AOF corruption/rewrite, load and old-backup authority reconciliation are separate gates')
    write_private(destination / 'receipt.json', receipt)
    return receipt


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', required=True)
    parser.add_argument('--destination', required=True)
    parser.add_argument('--policy-sha256', required=True)
    parser.add_argument('--allow-redis-restart', action='store_true')
    args = parser.parse_args()
    try:
        receipt = run(args.compose, args.destination, args.policy_sha256, allow_redis_restart=args.allow_redis_restart)
    except Exception:
        raise SystemExit('Redis durability qualification failed; inspect retained private evidence and selected service state. Do not reinitialize.') from None
    print(json.dumps(receipt))
