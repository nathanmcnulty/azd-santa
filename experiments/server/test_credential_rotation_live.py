"""Original Unlicense. Explicit synthetic loopback authority/paging qualification.

Never installs code or edits an existing fixture. Failure leaves private evidence;
initialization/rotation is not automatically resumed. No native/MDM/restore proof.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import string
import sys
import time
import types
import urllib.error
import urllib.request
import zlib

VIEW_SHA256 = '205315d6cf592fe53efaebb58fb6843c4f17f842d85b7c74816964385df1ec6a'
STAGES = ('preflight', 'ruledownload', 'eventupload', 'postflight')
live = None


def need(value):
    if not value: raise ValueError('Synthetic credential rotation gate failed; inspect private evidence')


def write(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as output:
        json.dump(value, output, sort_keys=True); output.flush(); os.fsync(output.fileno())


def load_helpers(expected, expected_generator):
    need(all(re.fullmatch('[a-f0-9]{64}', value) for value in (expected, expected_generator)))
    root = Path(__file__).resolve().parent
    hashes = {}; sources = {}
    for name in ('prepare_zentral_eval', 'test_live_zentral'):
        path = root / (name + '.py'); info = path.lstat()
        need(stat.S_ISREG(info.st_mode) and not path.is_symlink())
        if os.name != 'nt':
            need(info.st_uid == os.geteuid() and not info.st_mode & 0o022)
            need(root.stat().st_uid == os.geteuid() and not root.stat().st_mode & 0o022)
        raw = path.read_bytes(); hashes[name] = hashlib.sha256(raw).hexdigest(); sources[name] = (path, raw)
        need(hashes[name] == (expected if name == 'test_live_zentral' else expected_generator))
    # No helper executes until both exact selected sources have been checked.
    for name, (path, raw) in sources.items():
        module = types.ModuleType(name); module.__file__ = str(path); sys.modules[name] = module
        exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module, hashes


def preflight(device, clean=True):
    body = dict(machine_id=device['uuid'], serial_num=device['serial'], hostname='azd-synthetic',
                os_version='15.0', os_build='24A335', santa_version='2026.8.244',
                client_mode='MONITOR')
    if clean: body['request_clean_sync'] = True
    else:
        # Last completed client database had six binary rules. Neither a forced
        # clean nor zero reported counts may mask lost-session reconciliation.
        body.update({kind + '_rule_count': 6 if kind == 'binary' else 0
                     for kind in ('binary', 'cdhash', 'certificate', 'compiler', 'signingid', 'transitive', 'teamid')})
    return body


def synthetic_event(fixture):
    return dict(file_sha256=fixture['identifiers'][0], file_name='synthetic-only',
        file_path='/azd-synthetic-not-real', decision='BLOCK_BINARY', execution_time=time.time(),
        executing_user='azd-synthetic', logged_in_users=[], current_sessions=[], signing_chain=[],
        pid=123, ppid=1, parent_name='azd-synthetic')


def attest_web(compose, project, image):
    environment = {key: value for key, value in os.environ.items() if not key.startswith(('DOCKER_', 'COMPOSE_'))}
    def read(args):
        result = subprocess.run(['docker', '--host', 'unix:///var/run/docker.sock'] + args,
            capture_output=True, text=True, timeout=30, env=environment)
        need(result.returncode == 0 and len(result.stdout) <= 65536)
        return result.stdout.strip()
    cid = read(['compose', '--project-name', project, '-f', str(compose), 'ps', '--all', '--quiet', 'web'])
    need(re.fullmatch('[a-f0-9]{64}', cid))
    # Select only nonsecret inspect fields; never collect Config.Env.
    template = '{"id":{{json .Id}},"image":{{json .Image}},"running":{{json .State.Running}},"labels":{{json .Config.Labels}},"bindings":{{json .HostConfig.PortBindings}},"ports":{{json .NetworkSettings.Ports}}}'
    data = json.loads(read(['inspect', '--format', template, cid]))
    need(data['id'] == cid and data['image'] == image and data['running'] is True
         and data['labels']['com.docker.compose.project'] == project and data['labels']['com.docker.compose.service'] == 'web')
    expected = [{'HostIp': '127.0.0.1', 'HostPort': '8000'}]
    need(data['bindings'] == {'8000/tcp': expected} and data['ports'].get('8000/tcp') == expected
         and all(port == '8000/tcp' or value is None for port, value in data['ports'].items()))
    return cid


def post(stage, device, body, header=None, legacy=None):
    need(stage in STAGES and live.UUID_PATTERN.fullmatch(device['uuid']))
    need(header is None or isinstance(header, str) and len(header) <= 136
         and re.fullmatch('[A-Za-z0-9 ]+', header))
    need(legacy is None or re.fullmatch('[A-Za-z0-9]{64}', legacy))
    path = (legacy + '/' if legacy else '') + stage + '/' + device['uuid']
    headers = {'Content-Type': 'application/json', 'Content-Encoding': 'deflate',
               'User-Agent': 'azd-santa-synthetic-rotation/1'}
    if header is not None: headers['Zentral-Authorization'] = header
    request = urllib.request.Request(live.BASE_URL + path,
        zlib.compress(json.dumps(body).encode()), headers, method='POST')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), live.NoRedirect())
    try: response = opener.open(request, timeout=15)
    except urllib.error.HTTPError as error: response = error
    with response:
        raw = response.read(65537); need(len(raw) <= 65536)
        value = json.loads(raw) if response.status == 200 else None
        need(value is None or isinstance(value, dict))
        return response.status, value


def orm(compose, fixture, code):
    return live.orm(compose, 'fixture=json.loads(' + repr(json.dumps(fixture)) + ')\n' + code)


def state(compose, fixture):
    return orm(compose, fixture, '''
c=Configuration.objects.get(pk=fixture['configuration_id'],name=fixture['name'])
need(c.client_mode==Configuration.MONITOR_MODE and c.batch_size==5)
need(Enrollment.objects.filter(configuration=c).count()==2)
need(MetaBusinessUnit.objects.filter(pk=fixture['meta_business_unit_id'],name=fixture['name']).exists())
authority=[]
for d in fixture['devices']:
 s=EnrollmentSecret.objects.get(pk=d['secret_id'],secret=d['secret'],meta_business_unit_id=fixture['meta_business_unit_id'])
 need(s.udids==[d['uuid']] and s.serial_numbers==[d['serial']] and s.quota==1 and s.request_count in (0,1))
 need(Enrollment.objects.filter(pk=d['enrollment_id'],configuration=c,secret=s).exists())
 authority.append(dict(id=s.pk,count=s.request_count,revoked=s.revoked_at,expired=s.expired_at))
m=EnrolledMachine.objects.filter(enrollment__configuration=c)
need(m.count()<=2)
for em in m:
 d=next(d for d in fixture['devices'] if d['enrollment_id']==em.enrollment_id)
 need(str(em.hardware_uuid)==d['uuid'] and em.serial_number==d['serial'] and em.client_mode==Configuration.MONITOR_MODE)
result=dict(authority=authority,machines=list(m.order_by('pk').values('pk','enrollment_id','hardware_uuid','last_preflight_at','last_postflight_at','sync_session','sync_session_clean','forced_sync_type')),
 rules=list(MachineRule.objects.filter(enrolled_machine__in=m).order_by('pk').values('pk','enrolled_machine_id','target__identifier','policy','version','cursor','sync_session','staged_removal','committed_policy','committed_version')),
 counters=list(TargetCounter.objects.filter(configuration=c).order_by('pk').values('target_id','blocked_count')))
print('SANTA_SYNTHETIC_JSON:'+json.dumps(result,default=str))
''')


def change_authority(compose, fixture, index, action):
    need(index in (0, 1) and action in ('revoke', 'expire', 'rotate'))
    updated = copy.deepcopy(fixture)
    replacement = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(64)) if action == 'rotate' else None
    code = 'index=' + str(index) + '\naction=' + repr(action) + '\nreplacement=' + repr(replacement) + '\n' + '''
from django.utils import timezone
from datetime import timedelta
with transaction.atomic():
 c=Configuration.objects.get(pk=fixture['configuration_id'],name=fixture['name'])
 need(c.client_mode==Configuration.MONITOR_MODE)
 d=fixture['devices'][index]
 s=EnrollmentSecret.objects.select_for_update().get(pk=d['secret_id'],secret=d['secret'],meta_business_unit_id=fixture['meta_business_unit_id'])
 need(s.udids==[d['uuid']] and s.serial_numbers==[d['serial']] and s.quota==1)
 if action=='rotate':
  need(s.is_revoked or s.is_expired)
  s.secret=replacement;s.revoked_at=None;s.expired_at=None
  s.save(update_fields=['secret','revoked_at','expired_at'])
 elif action=='revoke':
  s.revoked_at=timezone.now();s.save(update_fields=['revoked_at'])
 else:
  s.expired_at=timezone.now()-timedelta(seconds=1);s.save(update_fields=['expired_at'])
print('SANTA_SYNTHETIC_JSON:'+json.dumps({'changed':True}))
'''
    need(orm(compose, fixture, code) == {'changed': True})
    if replacement: updated['devices'][index]['secret'] = replacement
    return updated


def deny_all(compose, fixture, device, credential, observations, case, cursor=None, legacy=None, expected=403):
    before = state(compose, fixture)
    # A positive-shaped event would increment a counter if authority were bypassed.
    bodies = dict(preflight=preflight(device), ruledownload={'cursor': cursor} if cursor else {},
                  eventupload={'events': [synthetic_event(fixture)]}, postflight={'rules_received': 6, 'rules_processed': 6, 'syncType': 'CLEAN'})
    for stage in STAGES:
        status, _ = post(stage, device, bodies[stage], credential, legacy)
        unchanged = state(compose, fixture) == before
        observations.append(dict(case=case, stage=stage, status=status, database_unchanged=unchanged))
        need(status == expected and unchanged)


def partial_projection(snapshot, fixture, index, page):
    machine = next(m for m in snapshot['machines'] if m['enrollment_id'] == fixture['devices'][index]['enrollment_id'])
    need(machine['sync_session'] and machine['sync_session_clean'] is True and machine['forced_sync_type'] is None)
    cursor = page.get('cursor'); need(isinstance(cursor, str) and 0 < len(cursor) <= 128)
    identifiers = sorted(rule['identifier'] for rule in page['rules'])
    need(len(identifiers) == 5 and len(set(identifiers)) == 5 and set(identifiers) <= set(fixture['identifiers']))
    need(sorted(page['rules'], key=lambda rule: rule['identifier']) == [dict(identifier=value, rule_type='BINARY', policy='BLOCKLIST') for value in identifiers])
    rows = [row for row in snapshot['rules'] if row['enrolled_machine_id'] == machine['pk']]
    need(sorted(row['target__identifier'] for row in rows) == sorted(fixture['identifiers']))
    normalized = []
    for row in rows:
        staged = row['target__identifier'] in identifiers
        need(row['policy'] == 2 and row['version'] == 1 and row['staged_removal'] is False
             and row['cursor'] == (cursor if staged else None)
             and row['sync_session'] == (machine['sync_session'] if staged else None)
             and row['committed_policy'] == (2 if staged else None)
             and row['committed_version'] == (1 if staged else None))
        normalized.append({key: ('page' if key == 'cursor' and value else value)
                           for key, value in row.items() if key != 'pk'})
    # A resend may legitimately regenerate selected-row PKs and the page cursor.
    # Every authority, rule semantic, session and unrelated-device field remains.
    return dict(machine=machine, authority=snapshot['authority'], counters=snapshot['counters'],
        rules=sorted(normalized, key=lambda row: row['target__identifier']),
        others=[m for m in snapshot['machines'] if m['pk'] != machine['pk']],
        other_rules=[r for r in snapshot['rules'] if r['enrolled_machine_id'] != machine['pk']])


def full_sync(compose, fixture, index, observations, case, changed=False, legacy=None, header=None, stale_cursor=None, reconcile=False):
    device = fixture['devices'][index]
    if header is None and legacy is None: header = 'Bearer ' + device['secret']
    if reconcile:
        prior = next(m for m in state(compose, fixture)['machines'] if m['enrollment_id'] == device['enrollment_id'])
        need(prior['sync_session'] and prior['sync_session_clean'] is True and prior['forced_sync_type'] is None)
    status, reply = post('preflight', device, preflight(device, clean=not reconcile), header, legacy)
    need(status == 200 and reply['client_mode'] == 'MONITOR' and reply['sync_type'] == 'CLEAN' and reply['batch_size'] == 5)
    rules = []; cursor = stale_cursor
    for page in range(2):
        status, reply = post('ruledownload', device, {'cursor': cursor} if cursor else {}, header, legacy)
        need(status == 200 and len(reply['rules']) == (5 if page == 0 else 1))
        rules.extend(reply['rules']); cursor = reply.get('cursor')
        need(isinstance(cursor, str) and 0 < len(cursor) <= 128 if page == 0 else not cursor)
    changed_identifier = fixture.get('changed_identifier', fixture['identifiers'][0])
    expected = [dict(identifier=value, rule_type='BINARY', policy='ALLOWLIST' if changed and value == changed_identifier else 'BLOCKLIST') for value in sorted(fixture['identifiers'])]
    need(sorted(rules, key=lambda rule: rule['identifier']) == expected)
    need(post('eventupload', device, {'events': []}, header, legacy)[0] == 200)
    need(post('postflight', device, {'rules_received': 6, 'rules_processed': 6, 'syncType': 'CLEAN'}, header, legacy)[0] == 200)
    receipt = state(compose, fixture)
    machine = next(m for m in receipt['machines'] if m['enrollment_id'] == device['enrollment_id'])
    ledger = [r for r in receipt['rules'] if r['enrolled_machine_id'] == machine['pk']]
    need(machine['sync_session'] is None and machine['last_postflight_at'] and len(ledger) == 6)
    need(sorted(row['target__identifier'] for row in ledger) == sorted(fixture['identifiers']))
    for row in ledger:
        updated = changed and row['target__identifier'] == changed_identifier
        need(row['policy'] == (1 if updated else 2) and row['version'] == (2 if updated else 1)
             and row['cursor'] is None and row['sync_session'] is None and not row['staged_removal']
             and row['committed_policy'] is None and row['committed_version'] is None)
    observations.append(dict(case=case, complete_two_pages=True, exact_rules=True, committed_ledger=True,
                             lost_session_reconciliation=reconcile, explicit_clean_requested=not reconcile))


def run(compose_path, destination, expected_image, expected_helper, expected_generator):
    global live
    need(sys.platform == 'linux' and os.geteuid() == 0)
    live, helpers = load_helpers(expected_helper, expected_generator)
    compose, digest = live.validate_compose(compose_path)
    config = json.loads(compose.read_bytes())
    need(re.fullmatch('sha256:[a-f0-9]{64}', expected_image) and all(
        config['services'][name]['image'] == expected_image for name in ('web', 'workers', 'celery')))
    destination = Path(destination)
    need(destination.is_absolute() and destination.parent == destination.parent.resolve(strict=True)
         and not destination.exists() and not destination.is_symlink())
    if os.name != 'nt':
        info = destination.parent.stat()
        need(info.st_uid == os.geteuid() and not info.st_mode & 0o022)
    destination.mkdir(mode=0o700)
    write(destination / 'attempt.json', dict(scope='private-credential-rotation-attempt', compose_sha256=digest,
        image_id=expected_image, harness_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), helpers=helpers,
        state='outcome-unconfirmed; never automatically replay this directory'))
    observations = []
    try:
        container = attest_web(compose, config['name'], expected_image)
        runtime = live.orm(compose, "import hashlib\nfrom pathlib import Path\nfrom zentral.contrib.santa import public_views\nprint('SANTA_SYNTHETIC_JSON:'+json.dumps({'view_sha256':hashlib.sha256(Path(public_views.__file__).read_bytes()).hexdigest()}))")
        need(runtime == {'view_sha256': VIEW_SHA256})
        fixture = live.initialize_fixture(compose, destination / 'fixture-initial.json', digest)
        epoch = 0
        def authority(index, action):
            nonlocal fixture, epoch
            fixture = change_authority(compose, fixture, index, action); epoch += 1
            write(destination / ('fixture-epoch-' + str(epoch) + '.json'), fixture)
        # Newly enrolling authority, then genuinely different replacement bytes.
        for index, action in ((0, 'revoke'), (1, 'expire')):
            retired = fixture['devices'][index]['secret']
            authority(index, action)
            deny_all(compose, fixture, fixture['devices'][index], 'Bearer ' + fixture['devices'][index]['secret'], observations, 'new-' + action)
            authority(index, 'rotate')
            selected = fixture['devices'][index]
            deny_all(compose, fixture, selected, 'Bearer ' + retired, observations, 'new-retired-' + action)
            wrong_serial = dict(selected, serial=selected['serial'] + '-wrong')
            deny_all(compose, fixture, wrong_serial, 'Bearer ' + selected['secret'], observations, 'new-serial-binding-' + str(index))
            wrong_uuid = dict(selected, uuid=fixture['devices'][1-index]['uuid'])
            deny_all(compose, fixture, wrong_uuid, 'Bearer ' + selected['secret'], observations, 'new-uuid-binding-' + str(index))
            full_sync(compose, fixture, index, observations, 'replacement-enrollment-' + str(index))
        device, other = fixture['devices']; old = device['secret']
        need(post('preflight', device, preflight(device), 'Bearer ' + old)[0] == 200)
        status, first = post('ruledownload', device, {}, 'Bearer ' + old)
        need(status == 200 and len(first['rules']) == 5 and first.get('cursor'))
        partial = state(compose, fixture)
        before_projection = partial_projection(partial, fixture, 0, first)
        write(destination / 'partial-before-retry.json', partial)
        status, retried = post('ruledownload', device, {}, 'Bearer ' + old)
        need(status == 200 and retried['rules'] == first['rules'] and retried.get('cursor'))
        after_retry = state(compose, fixture)
        need(partial_projection(after_retry, fixture, 0, retried) == before_projection)
        write(destination / 'partial-after-retry.json', after_retry)
        # Change a rule actually present in the interrupted page, rather than
        # assuming the fixture's construction order is the SQL page order.
        fixture['changed_identifier'] = first['rules'][0]['identifier']
        need(fixture['changed_identifier'] in fixture['identifiers'])
        observations.append(dict(case='unacknowledged-page-retry', exact_page=True, staged_semantics_equal=True))
        cursor = retried['cursor']; authority(0, 'revoke')
        deny_all(compose, fixture, device, 'Bearer ' + old, observations, 'revoked-during-page', cursor)
        authority(0, 'rotate'); device = fixture['devices'][0]
        deny_all(compose, fixture, device, 'Bearer ' + old, observations, 'rotated-old', cursor)
        deny_all(compose, fixture, device, None, observations, 'rotated-old-legacy', cursor, old)
        deny_all(compose, fixture, other, 'Bearer ' + device['secret'], observations, 'replacement-cross-device', cursor)
        deny_all(compose, fixture, device, 'Bearer ' + other['secret'], observations, 'other-cross-device', cursor)
        deny_all(compose, fixture, device, 'Bearer ' + old, observations, 'old-header-over-new-url', cursor, device['secret'])
        deny_all(compose, fixture, device, 'Bearer', observations, 'malformed-header-no-url-fallback', cursor, device['secret'], 401)
        deny_all(compose, fixture, device, 'Basic ' + device['secret'], observations, 'wrong-scheme-no-url-fallback', cursor, device['secret'], 401)
        # Change exactly one synthetic rule while an old partial page exists.
        orm(compose, fixture, '''
with transaction.atomic():
 r=Rule.objects.select_for_update().get(configuration_id=fixture['configuration_id'],target__identifier=fixture['changed_identifier'])
 need(r.policy==Rule.Policy.BLOCKLIST and r.version==1)
 r.policy=Rule.Policy.ALLOWLIST;r.version=2;r.full_clean();r.save(update_fields=['policy','version'])
print('SANTA_SYNTHETIC_JSON:'+json.dumps({'changed':True}))
''')
        full_sync(compose, fixture, 0, observations, 'replacement-reconciles-stale-cursor', True, old, 'Bearer ' + device['secret'], cursor, reconcile=True)
        full_sync(compose, fixture, 0, observations, 'legacy-replacement-full-sync', True, device['secret'])
        full_sync(compose, fixture, 1, observations, 'unaffected-device-full-sync', True)
        counter_before = sum(c['blocked_count'] for c in state(compose, fixture)['counters'])
        need(post('eventupload', device, {'events': [synthetic_event(fixture)]}, 'Bearer ' + device['secret'])[0] == 200)
        need(sum(c['blocked_count'] for c in state(compose, fixture)['counters']) == counter_before + 1)
        observations.append(dict(case='replacement-positive-event', status=200, counter_increment=1, indexing='not_proven'))
        authority(1, 'expire')
        deny_all(compose, fixture, other, 'Bearer ' + other['secret'], observations, 'existing-expired')
        full_sync(compose, fixture, 0, observations, 'replacement-unaffected-by-expiry', True)
        need(all(s['count'] == 1 for s in state(compose, fixture)['authority']))
        need(attest_web(compose, config['name'], expected_image) == container)
        write(destination / 'receipt.json', dict(scope='private-server-credential-rotation', passed=True,
            compose_sha256=digest, image_id=expected_image, web_container_id=container, view_sha256=VIEW_SHA256, helpers=helpers,
            harness_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), observations=observations,
            limitation='Actual server/DB loopback only; native MDM/profile rotation, client-local rule application and backup/restore authority unproven'))
        return destination / 'receipt.json'
    except BaseException:
        write(destination / 'failed.json', dict(scope='private-credential-rotation-failed', passed=False,
            observations=observations, action='Inspect retained private fixture/ORM evidence; do not replay this directory'))
        raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('compose', 'destination', 'expected-image', 'expected-helper-sha256', 'expected-generator-sha256'): parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    try:
        result = run(args.compose, args.destination, args.expected_image, args.expected_helper_sha256, args.expected_generator_sha256)
        print('SANTA_CREDENTIAL_ROTATION_OK')
    except BaseException:
        raise SystemExit('Credential rotation qualification failed; inspect retained private evidence. No automatic replay.') from None
