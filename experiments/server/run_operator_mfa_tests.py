"""Capture all real-app test output privately and export only the bounded receipt."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import uuid

from test_live_zentral import validate_compose
from upgrade_core_runtime import write_private


def run(compose_path, harness_path, destination, expected_policy):
    compose, digest = validate_compose(compose_path)
    if not re.fullmatch(r'[a-f0-9]{64}', expected_policy):
        raise ValueError('Expected an exact policy source hash')
    harness = Path(harness_path).resolve(strict=True)
    if not harness.is_file():
        raise ValueError('Expected the reviewed harness file')
    destination = Path(destination)
    destination.mkdir(mode=0o700)
    project = json.loads(compose.read_text())['name']
    env = {k: v for k, v in os.environ.items() if not k.startswith(('DOCKER_', 'COMPOSE_'))}
    name = 'santa-mfa-test-' + uuid.uuid4().hex[:16]
    code = "from pathlib import Path; p=Path('/tmp/azd_operator_mfa_tests.py'); exec(compile(p.read_bytes(),str(p),'exec'),{'__name__':'__main__','__file__':str(p)})"
    command = ['docker', '--host', 'unix:///var/run/docker.sock', 'compose',
        '--project-name', project, '-f', str(compose), 'run', '--rm', '--no-deps',
        '--name', name, '--volume', str(harness) + ':/tmp/azd_operator_mfa_tests.py:ro',
        '--entrypoint', 'python', 'web', 'server/manage.py', 'shell', '--no-imports', '-c', code]
    try:
        result = subprocess.run(command, capture_output=True, text=True, env=env, timeout=600)
    except subprocess.TimeoutExpired as error:
        write_private(destination / 'timeout.json', dict(scope='private-mfa-tests-timeout',
            stdout=str(error.stdout), stderr=str(error.stderr), container=name))
        # This exact generated test container is disposable. Preserve its data
        # volumes/log receipts; never prune or target any unrelated container.
        inspect = subprocess.run(['docker', '--host', 'unix:///var/run/docker.sock',
            'inspect', name], capture_output=True, text=True, env=env, timeout=20)
        if inspect.returncode == 0:
            info = json.loads(inspect.stdout)[0]
            if info['Config'].get('Labels', {}).get('com.docker.compose.project') == project:
                subprocess.run(['docker', '--host', 'unix:///var/run/docker.sock',
                    'rm', '--force', name], capture_output=True, env=env, timeout=30, check=True)
        raise RuntimeError('MFA requests timed out; inspect retained private evidence') from None
    write_private(destination / 'private-process-output.json', dict(returncode=result.returncode,
        stdout=result.stdout, stderr=result.stderr))
    records = []
    for line in result.stdout.splitlines():
        if line.startswith('{'):
            try:
                item = json.loads(line)
            except ValueError:
                continue
            if item.get('scope') == 'private-real-django-operator-mfa':
                records.append(item)
    if len(records) != 1:
        raise RuntimeError('No unique real-app receipt; inspect retained private process output')
    receipt = records[0]
    allowed = {'scope', 'namespace', 'tests', 'passed', 'skipped', 'failures', 'errors',
               'harness_sha256', 'policy_sha256', 'limitation'}
    if (set(receipt) != allowed or
            not re.fullmatch(r'azd-mfa-[a-f0-9]{24}', receipt.get('namespace', '')) or
            type(receipt.get('passed')) is not bool or
            any(not isinstance(receipt.get(key), list) or any(not isinstance(item, str) or
                not re.fullmatch(r'__main__\.OperatorRequests\.test_[a-z0-9_]+', item)
                for item in receipt[key]) for key in ('failures', 'errors')) or
            receipt.get('limitation') != 'Synthetic operators, direct Django request client; no real-browser/TLS/native-Mac/restore proof'):
        raise RuntimeError('Unrecognized MFA receipt schema; raw output remains private')
    source_hash = hashlib.sha256(harness.read_bytes()).hexdigest()
    if (receipt.get('tests') != 14 or receipt.get('skipped') != 0 or
            receipt.get('harness_sha256') != source_hash or receipt.get('policy_sha256') != expected_policy):
        raise RuntimeError('Incomplete or mismatched MFA request-test receipt')
    if receipt['passed'] and (receipt['failures'] or receipt['errors']):
        raise RuntimeError('Inconsistent MFA success receipt')
    receipt.update(compose_sha256=digest, process_returncode=result.returncode)
    write_private(destination / 'receipt.json', receipt)
    print(json.dumps(receipt))
    if result.returncode != 0 or receipt.get('passed') is not True:
        raise RuntimeError('Real MFA request checks failed; inspect private redacted diagnostics')
    print('SANTA_OPERATOR_MFA_ACCEPTED_REQUESTS ' + str(destination))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', required=True)
    parser.add_argument('--harness', required=True)
    parser.add_argument('--destination', required=True)
    parser.add_argument('--policy-sha256', required=True)
    args = parser.parse_args()
    run(args.compose, args.harness, args.destination, args.policy_sha256)
