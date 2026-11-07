"""Real-app, isolated synthetic authority tests. Explicit invocation only.

Creates new Monitor fixtures; never edits a real enrollment or existing receipt.
Backup/restore authority and native MDM delivery are separate acceptance gates.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import secrets
import string

import test_live_zentral as live
from upgrade_core_runtime import write_private


def orm(compose, fixture, code):
    return live.orm(compose, 'fixture=json.loads(' + repr(json.dumps(fixture)) + ')\n' + code)


def state(compose, fixture):
    return orm(compose, fixture, '''
configuration=Configuration.objects.get(pk=fixture['configuration_id'],name=fixture['name'])
need(configuration.client_mode==Configuration.MONITOR_MODE)
secrets=[]
for device in fixture['devices']:
    s=EnrollmentSecret.objects.get(pk=device['secret_id'])
    need(s.secret==device['secret'] and s.udids==[device['uuid']] and s.serial_numbers==[device['serial']])
    need(s.quota==1 and s.request_count==1)
    secrets.append(dict(id=s.pk,revoked_at=s.revoked_at,expired_at=s.expired_at,request_count=s.request_count))
machines=EnrolledMachine.objects.filter(enrollment__configuration=configuration)
need(machines.count()==2)
data=dict(secrets=secrets,
    machines=list(machines.order_by('pk').values('pk','serial_number','client_mode','last_preflight_at','last_postflight_at','sync_session')),
    rules=list(MachineRule.objects.filter(enrolled_machine__in=machines).order_by('pk').values('pk','enrolled_machine_id','target_id','policy','version','cursor','sync_session','staged_removal','committed_policy','committed_version')),
    counters=list(TargetCounter.objects.filter(configuration=configuration).order_by('pk').values('target_id','blocked_count')))
print('SANTA_SYNTHETIC_JSON:'+json.dumps(data,default=str))
''')


def reject_stages(compose, fixture, device, credential, case, observations):
    before = state(compose, fixture)
    payloads = dict(eventupload={'events': []},
        preflight=dict(machine_id=device['uuid'], serial_num=device['serial'], hostname='azd-synthetic',
            os_version='15.0', os_build='24A335', santa_version='2026.8.244',
            client_mode='MONITOR', request_clean_sync=True),
        ruledownload={}, postflight=dict(rules_received=6,rules_processed=6,syncType='CLEAN'))
    passed = True
    for stage, payload in payloads.items():
        status, _ = live.post(stage, device['uuid'], payload, credential)
        observations.append(dict(case=case, stage=stage, http_status=status))
        if status != 403:
            passed = False
            break  # Do not continue mutating a fixture through a broken guard.
    after = state(compose, fixture)
    unchanged = before == after
    observations.append(dict(case=case, database_unchanged=unchanged,
        before_sha256=hashlib.sha256(json.dumps(before,sort_keys=True).encode()).hexdigest(),
        after_sha256=hashlib.sha256(json.dumps(after,sort_keys=True).encode()).hexdigest()))
    return passed and unchanged


def run(compose_path, fixture_path):
    compose, digest = live.validate_compose(compose_path)
    fixture_path = Path(fixture_path)
    live.require(not fixture_path.exists() and not fixture_path.is_symlink(), 'Existing lifecycle fixture requires inspection')
    live.run(compose, fixture_path, initialize=True)
    fixture = live.load_fixture(fixture_path, digest)
    observations = []
    receipt_path = fixture_path.with_suffix('.lifecycle.json')

    def finish(passed):
        receipt = dict(scope='private-synthetic-credential-lifecycle', commit=live.COMMIT,
            compose_sha256=digest, passed=passed, observations=observations,
            harness_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            sync_harness_sha256=hashlib.sha256(Path(live.__file__).read_bytes()).hexdigest(),
            limitation='Actual loopback server only; no native Mac, backup restoration or ingress proof')
        write_private(receipt_path, receipt)
        print(json.dumps(receipt))
        print('SANTA_CREDENTIAL_LIFECYCLE_OK' if passed else 'SANTA_CREDENTIAL_LIFECYCLE_FAILED')
        return passed

    first, second = fixture['devices']
    orm(compose, fixture, '''
from django.utils import timezone
s=EnrollmentSecret.objects.get(pk=fixture['devices'][0]['secret_id'],secret=fixture['devices'][0]['secret'])
s.revoked_at=timezone.now();s.save(update_fields=['revoked_at'])
need(s.is_revoked)
print('SANTA_SYNTHETIC_JSON:'+json.dumps({'revoked':True}))
''')
    if not reject_stages(compose, fixture, first, first['secret'], 'revoked', observations):
        return finish(False)
    status, _ = live.post('eventupload', second['uuid'], {'events': []}, second['secret'])
    observations.append(dict(case='other-device-after-revocation', http_status=status))
    if status != 200:
        return finish(False)

    rotated = copy.deepcopy(fixture)
    rotated['devices'][0]['secret'] = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(64))
    orm(compose, fixture, 'new_secret=' + repr(rotated['devices'][0]['secret']) + '\n' + '''
s=EnrollmentSecret.objects.get(pk=fixture['devices'][0]['secret_id'],secret=fixture['devices'][0]['secret'])
need(s.is_revoked and s.request_count==1 and s.quota==1)
s.secret=new_secret;s.revoked_at=None;s.save(update_fields=['secret','revoked_at'])
print('SANTA_SYNTHETIC_JSON:'+json.dumps({'rotated':True}))
''')
    live.validate_fixture(rotated, digest)
    rotated_path = fixture_path.with_suffix('.rotated.json')
    write_private(rotated_path, rotated)
    if not reject_stages(compose, rotated, first, first['secret'], 'rotated-old', observations):
        return finish(False)
    for case, device in (('rotated-new', rotated['devices'][0]), ('other-device-after-rotation', second)):
        status, _ = live.post('eventupload', device['uuid'], {'events': []}, device['secret'])
        observations.append(dict(case=case, http_status=status))
        if status != 200:
            return finish(False)

    # Both devices are still active here. Prove a complete renewed sync for
    # the rotated credential and unchanged device, including quota==1 readback,
    # exact rule paging, event counters and committed postflight. No re-enroll.
    live.run(compose, rotated_path, initialize=False)
    observations.append(dict(case='rotated-and-unaffected-full-sync', passed=True,
                             reinitialized=False, enrolled_request_count_per_device=1))

    orm(compose, rotated, '''
from django.utils import timezone
from datetime import timedelta
s=EnrollmentSecret.objects.get(pk=fixture['devices'][1]['secret_id'],secret=fixture['devices'][1]['secret'])
s.expired_at=timezone.now()-timedelta(seconds=1);s.save(update_fields=['expired_at'])
need(s.is_expired)
print('SANTA_SYNTHETIC_JSON:'+json.dumps({'expired':True}))
''')
    if not reject_stages(compose, rotated, second, second['secret'], 'expired', observations):
        return finish(False)
    status, _ = live.post('eventupload', first['uuid'], {'events': []}, rotated['devices'][0]['secret'])
    observations.append(dict(case='rotated-device-after-other-expiry', http_status=status))
    return finish(status == 200)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', required=True)
    parser.add_argument('--fixture', required=True)
    args = parser.parse_args()
    raise SystemExit(0 if run(args.compose, args.fixture) else 2)
