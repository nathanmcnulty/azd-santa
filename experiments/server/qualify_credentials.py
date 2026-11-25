"""Observe revocation/expiry on isolated, already-enrolled synthetic credentials.

Creates a new Monitor fixture and leaves its credentials revoked/expired. Never
use on a real device; a failed gate is evidence to fix, not permission to expose.
This narrow probe covers empty eventupload only, not the full lifecycle suite.
"""
import argparse
import json
from pathlib import Path

import test_live_zentral as live
from upgrade_core_runtime import write_private


def qualify(compose, fixture_path):
    compose, digest = live.validate_compose(compose)
    fixture_path = Path(fixture_path)
    if fixture_path.exists() or fixture_path.is_symlink():
        raise FileExistsError('Existing credential fixture requires inspection')
    live.run(compose, fixture_path, initialize=True)
    fixture = live.load_fixture(fixture_path, digest)
    live.assert_committed(live.snapshot(compose, fixture), fixture)
    code = 'fixture=json.loads(' + repr(json.dumps(fixture)) + ')\n' + '''
from django.utils import timezone
from datetime import timedelta
from django.db import transaction
with transaction.atomic():
    first=EnrollmentSecret.objects.get(pk=fixture['devices'][0]['secret_id'])
    second=EnrollmentSecret.objects.get(pk=fixture['devices'][1]['secret_id'])
    need(first.secret==fixture['devices'][0]['secret'] and second.secret==fixture['devices'][1]['secret'])
    first.revoked_at=timezone.now()
    first.save(update_fields=['revoked_at'])
    second.expired_at=timezone.now()-timedelta(seconds=1)
    second.save(update_fields=['expired_at'])
    need(first.is_revoked and second.is_expired)
print('SANTA_SYNTHETIC_JSON:'+json.dumps({'revoked':first.is_revoked,'expired':second.is_expired}))
'''
    flags = live.orm(compose, code)
    live.require(flags == {'revoked': True, 'expired': True}, 'Credential mutation receipt missing')
    observations = []
    for state, device in zip(('revoked', 'expired'), fixture['devices']):
        status, _ = live.post('eventupload', device['uuid'], {'events': []}, device['secret'])
        observations.append({'state': state, 'stage': 'eventupload', 'http_status': status,
                             'rejected': status == 403})
    passed = all(row['rejected'] for row in observations)
    receipt = dict(scope='isolated-synthetic-credential-gate', commit=live.COMMIT,
                   compose_sha256=digest, observations=observations,
                   gate_passed=passed, credential_flags_verified=flags,
                   limitations='Empty eventupload only; no real-device, rotation or other-stage proof')
    write_private(fixture_path.with_suffix('.credential-gate.json'), receipt)
    print(json.dumps(receipt))
    print('SANTA_CREDENTIAL_GATE_PASSED' if passed else 'SANTA_CREDENTIAL_GATE_FAILED')
    return passed


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', required=True)
    parser.add_argument('--fixture', required=True)
    args = parser.parse_args()
    raise SystemExit(0 if qualify(args.compose, args.fixture) else 2)
