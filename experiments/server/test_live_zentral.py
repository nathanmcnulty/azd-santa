"""Real loopback HTTP qualification of pinned Zentral, with synthetic data only.

Runs only when explicitly invoked. Uses a local Docker Compose web container for
fixture creation/readback; never imports upstream code on the invoking machine.
No certificate/device-identity/native-Santa claim is made by these tests.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time
import urllib.error
import urllib.request
import uuid
import zlib

COMMIT = '88e67b3ce49033aab028029937a6e14f7c489073'
BASE_URL = 'http://127.0.0.1:8000/public/santa/sync/'
UUID_PATTERN = re.compile(r'00000000-0000-4000-8000-[0-9a-f]{12}')
RULE_COUNT = 6
BATCH_SIZE = 5
MARKER = 'SANTA_SYNTHETIC_JSON:'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate_compose(path):
    path = Path(path).resolve(strict=True)
    require(path.is_file(), 'Compose input must be a regular file')
    raw = path.read_bytes()
    data = json.loads(raw)
    require(set(data) <= {'name', 'services', 'volumes'}, 'Compose includes or overrides are not supported')
    require(re.fullmatch(r'santa-zentral-eval-[0-9a-f]{12}', data.get('name', '')),
            'Expected a uniquely named synthetic Compose project')
    require(set(data.get('services', {})) == {
        'db', 'redis', 'rabbitmq', 'elastic', 'web', 'workers', 'celery'},
        'Expected the isolated seven-service evaluation')
    for name, service in data['services'].items():
        require(not any(service.get(key) for key in (
            'privileged', 'network_mode', 'build', 'extends', 'devices', 'networks', 'cap_add')),
            'Unsafe evaluation service options')
        require(all(volume in {
            'postgres_data:/var/lib/postgresql', 'rabbitmq_data:/var/lib/rabbitmq',
            'redis_data:/data',
            'elasticsearch_data:/usr/share/elasticsearch/data', 'media_data:/var/zentral',
            'elasticsearch_snapshots:/mnt/azd-santa-snapshots',
            './conf:/zentral-eval-conf:ro'} for volume in service.get('volumes', [])),
            'Unexpected evaluation volume or host mount')
        require(service.get('ports', []) == (['127.0.0.1:8000:8000'] if name == 'web' else []),
                'Only loopback web ingress is supported')
        require(name == 'redis' or 'redis_data:/data' not in service.get('volumes', []),
                'Only Redis may mount security-store data')
    redis = data['services']['redis']
    if 'redis_data' in data.get('volumes', {}) or redis.get('volumes'):
        from prepare_zentral_eval import REDIS_COMMAND
        require(redis.get('volumes') == ['redis_data:/data'] and redis.get('command') == REDIS_COMMAND,
                'Persistent security Redis requires exact reviewed mount and durability settings')
        require(data.get('volumes', {}).get('redis_data') == {},
                'Security-store data must be a new project-local named volume')
    require(re.fullmatch(r'sha256:[0-9a-f]{64}', data['services']['web'].get('image', '')),
            'Expected a locally built immutable web image ID')
    return path, hashlib.sha256(raw).hexdigest()


ORM_COMMON = '''
import json
from django.db import transaction
from zentral.contrib.inventory.models import MetaBusinessUnit, EnrollmentSecret
from zentral.contrib.santa.models import Configuration, Enrollment, EnrolledMachine, Rule, Target, MachineRule, TargetCounter
def need(condition):
    if not condition:
        raise ValueError("Synthetic fixture database mismatch")
'''


def orm(compose, code):
    compose, _ = validate_compose(compose)
    project = json.loads(compose.read_text(encoding='utf-8'))['name']
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith(('COMPOSE_', 'DOCKER_'))}
    result = subprocess.run(
        ['docker', '--host', 'unix:///var/run/docker.sock', 'compose',
         '--project-name', project, '-f', str(compose), 'exec', '-T', 'web',
         'python', 'server/manage.py', 'shell', '--no-imports'],
        input=ORM_COMMON + '\n' + code, text=True, capture_output=True,
        timeout=120, check=False, env=environment)
    audit = compose.parent / ('private-orm-' + uuid.uuid4().hex + '.json')
    descriptor = os.open(audit, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
        json.dump(dict(scope='synthetic-loopback-only', command_sha256=hashlib.sha256(code.encode()).hexdigest(),
                       returncode=result.returncode, stdout=result.stdout, stderr=result.stderr), stream)
    # Never echo captured output: initialization includes private enrollment secrets.
    require(result.returncode == 0, 'Private ORM command failed; inspect locally without exposing secrets')
    records = [line[len(MARKER):] for line in result.stdout.splitlines() if line.startswith(MARKER)]
    require(len(records) == 1, 'Private ORM JSON receipt missing or ambiguous')
    return json.loads(records[0])


def validate_fixture(data, compose_hash):
    require(isinstance(data, dict) and data.get('scope') == 'synthetic-loopback-only'
            and data.get('commit') == COMMIT and data.get('compose_sha256') == compose_hash,
            'Fixture scope, source pin or Compose binding mismatch')
    require(re.fullmatch(r'azd-synthetic-[0-9a-f]{24}', data.get('name', '')),
            'Unexpected fixture namespace')
    devices = data.get('devices', [])
    require(len(devices) == 2, 'Expected exactly two synthetic devices')
    for index, device in enumerate(devices):
        require(isinstance(device, dict) and UUID_PATTERN.fullmatch(device.get('uuid', ''))
                and device.get('serial') == data['name'] + '-' + str(index)
                and re.fullmatch(r'[A-Za-z0-9]{64}', device.get('secret', '')),
                'Invalid synthetic device credential scope')
        for key in ('enrollment_id', 'secret_id'):
            require(type(device.get(key)) is int and device[key] > 0, 'Invalid fixture object ID')
    require(len({d['uuid'] for d in devices}) == 2 and len({d['secret'] for d in devices}) == 2,
            'Synthetic device credentials must be unique')
    expected = [hashlib.sha256((data['name'] + ':' + str(i)).encode()).hexdigest()
                for i in range(RULE_COUNT)]
    require(data.get('identifiers') == expected, 'Unexpected synthetic rule identifiers')
    for key in ('configuration_id', 'meta_business_unit_id'):
        require(type(data.get(key)) is int and data[key] > 0, 'Invalid fixture object ID')
    return data


def initialize_fixture(compose, path, compose_hash):
    # Reserve the exact absent path before any database write. Interrupted runs
    # leave evidence and must not be retried with --initialize over that path.
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'w', encoding='utf-8') as output:
        name = 'azd-synthetic-' + uuid.uuid4().hex[:24]
        data = dict(scope='synthetic-loopback-only', commit=COMMIT,
                    compose_sha256=compose_hash, name=name,
                    identifiers=[hashlib.sha256((name + ':' + str(i)).encode()).hexdigest()
                                 for i in range(RULE_COUNT)],
                    devices=[dict(uuid='00000000-0000-4000-8000-' + uuid.uuid4().hex[:12],
                                  serial=name + '-' + str(i)) for i in range(2)])
        code = 'fixture = json.loads(' + repr(json.dumps(data)) + ')\n' + '''
with transaction.atomic():
    need(not Configuration.objects.filter(name=fixture['name']).exists())
    need(not MetaBusinessUnit.objects.filter(name=fixture['name']).exists())
    need(not Target.objects.filter(identifier__in=fixture['identifiers']).exists())
    need(not EnrolledMachine.objects.filter(hardware_uuid__in=[d['uuid'] for d in fixture['devices']]).exists())
    configuration = Configuration.objects.create(name=fixture['name'], client_mode=Configuration.MONITOR_MODE, batch_size=5)
    configuration.full_clean()
    mbu = MetaBusinessUnit.objects.create(name=fixture['name'])
    mbu.create_enrollment_business_unit()
    fixture['configuration_id'] = configuration.pk
    fixture['meta_business_unit_id'] = mbu.pk
    for device in fixture['devices']:
        secret = EnrollmentSecret.objects.create(meta_business_unit=mbu, udids=[device['uuid']], serial_numbers=[device['serial']], quota=1)
        secret.full_clean()
        enrollment = Enrollment.objects.create(configuration=configuration, secret=secret)
        device.update(secret=secret.secret, secret_id=secret.pk, enrollment_id=enrollment.pk)
    for identifier in fixture['identifiers']:
        target = Target.objects.create(type=Target.Type.BINARY, identifier=identifier)
        Rule.objects.create(configuration=configuration, target=target, policy=Rule.Policy.BLOCKLIST)
print(''' + repr(MARKER) + ''' + json.dumps(fixture))
'''
        fixture = validate_fixture(orm(compose, code), compose_hash)
        require(fixture['name'] == data['name'] and fixture['identifiers'] == data['identifiers']
                and [(d['uuid'], d['serial']) for d in fixture['devices']]
                == [(d['uuid'], d['serial']) for d in data['devices']],
                'ORM initialization returned another fixture namespace')
        json.dump(fixture, output, sort_keys=True)
        output.write('\n')
        output.flush()
        os.fsync(output.fileno())
        return fixture


def load_fixture(path, compose_hash):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and not path.is_symlink(), 'Fixture must be a regular private file')
    require(info.st_size <= 65536, 'Fixture exceeded size bound')
    if os.name != 'nt':
        require(stat.S_IMODE(info.st_mode) == 0o600, 'Fixture must have mode 0600')
    return validate_fixture(json.loads(path.read_text(encoding='utf-8')), compose_hash)


def snapshot(compose, fixture):
    code = 'fixture = json.loads(' + repr(json.dumps(fixture)) + ')\n' + '''
configuration = Configuration.objects.get(pk=fixture['configuration_id'], name=fixture['name'])
need(configuration.client_mode == Configuration.MONITOR_MODE and configuration.batch_size == 5)
need(MetaBusinessUnit.objects.filter(pk=fixture['meta_business_unit_id'], name=fixture['name']).exists())
need(Enrollment.objects.filter(configuration=configuration).count() == 2)
expected = sorted((identifier, 'BINARY', 2) for identifier in fixture['identifiers'])
actual = sorted(Rule.objects.filter(configuration=configuration).values_list('target__identifier', 'target__type', 'policy'))
need(actual == expected)
machines = []
for device in fixture['devices']:
    secret = EnrollmentSecret.objects.get(pk=device['secret_id'])
    need(secret.secret == device['secret'] and secret.meta_business_unit_id == fixture['meta_business_unit_id'])
    need(secret.udids == [device['uuid']] and secret.serial_numbers == [device['serial']] and secret.quota == 1)
    need(secret.request_count in (0, 1) and secret.revoked_at is None and secret.expired_at is None)
    need(Enrollment.objects.filter(pk=device['enrollment_id'], configuration=configuration, secret=secret).exists())
    machine = EnrolledMachine.objects.filter(enrollment_id=device['enrollment_id'], hardware_uuid=device['uuid']).first()
    entry = dict(uuid=device['uuid'], request_count=secret.request_count, machine=None)
    if machine is not None:
        need(machine.serial_number == device['serial'] and machine.client_mode == Configuration.MONITOR_MODE)
        entry['machine'] = dict(pk=machine.pk, preflight=machine.last_preflight_at, postflight=machine.last_postflight_at, sync_session=machine.sync_session,
            rules=list(MachineRule.objects.filter(enrolled_machine=machine).order_by('target__identifier').values('target__identifier', 'policy', 'version', 'cursor', 'sync_session', 'staged_removal', 'committed_policy', 'committed_version')))
    machines.append(entry)
need(EnrolledMachine.objects.filter(enrollment__configuration=configuration).count() == sum(d['machine'] is not None for d in machines))
counter = TargetCounter.objects.filter(configuration=configuration, target__identifier=fixture['identifiers'][0]).first()
print(''' + repr(MARKER) + ''' + json.dumps(dict(configuration_id=configuration.pk, machines=machines, synthetic_blocked_count=counter.blocked_count if counter else 0), default=str))
'''
    return orm(compose, code)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        return None


def post(stage, device, body, credential=None):
    require(stage in ('preflight', 'ruledownload', 'eventupload', 'postflight'), 'Invalid sync stage')
    require(UUID_PATTERN.fullmatch(device), 'Only synthetic UUIDs are supported')
    headers = {'Content-Type': 'application/json', 'Content-Encoding': 'deflate',
               'User-Agent': 'azd-santa-synthetic-qualification/1'}
    if credential is not None:
        require(re.fullmatch(r'[A-Za-z0-9]{1,128}', credential), 'Unexpected credential format')
        headers['Zentral-Authorization'] = 'Bearer ' + credential
    request = urllib.request.Request(BASE_URL + stage + '/' + device,
                                     zlib.compress(json.dumps(body).encode()), headers, method='POST')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        response = opener.open(request, timeout=15)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        payload = response.read(65537)
        require(len(payload) <= 65536, 'HTTP response exceeded bound')
        if response.status == 200:
            value = json.loads(payload)
            require(isinstance(value, dict), 'Expected JSON object response')
        else:
            value = None
        return response.status, value


def assert_committed(state, fixture):
    require(len(state.get('machines', [])) == 2, 'Expected two machine receipts')
    for entry, device in zip(state['machines'], fixture['devices']):
        machine = entry['machine']
        require(entry['uuid'] == device['uuid'] and entry['request_count'] == 1 and machine
                and machine['preflight'] and machine['postflight'] and machine['sync_session'] is None,
                'Committed machine receipt missing')
        rules = machine['rules']
        require([rule['target__identifier'] for rule in rules] == sorted(fixture['identifiers']),
                'Committed rule identifiers differ')
        require(all(rule['policy'] == 2 and rule['version'] == 1 and rule['cursor'] is None
                    and rule['sync_session'] is None and not rule['staged_removal']
                    and rule['committed_policy'] is None and rule['committed_version'] is None
                    for rule in rules), 'Rule ledger is not completely committed')


def run(compose, fixture_path, initialize=False):
    compose, compose_hash = validate_compose(compose)
    fixture_path = Path(fixture_path).absolute()
    fixture = (initialize_fixture(compose, fixture_path, compose_hash) if initialize
               else load_fixture(fixture_path, compose_hash))
    before = snapshot(compose, fixture)
    # This is before all HTTP, preventing resynchronization from masking data loss.
    if not initialize:
        assert_committed(before, fixture)
    for device in fixture['devices']:
        body = dict(machine_id=device['uuid'], serial_num=device['serial'], hostname='azd-synthetic',
                    os_version='15.0', os_build='24A335', santa_version='2026.8.244',
                    client_mode='MONITOR', request_clean_sync=True)
        require(post('preflight', device['uuid'], body)[0] == 401, 'Missing credentials were not rejected')
        require(post('preflight', device['uuid'], body, 'invalid')[0] == 403, 'Bad credentials were not rejected')
        other = next(item for item in fixture['devices'] if item is not device)
        require(post('preflight', device['uuid'], body, other['secret'])[0] == 403,
                'Cross-device enrollment credential accepted')
        status, response = post('preflight', device['uuid'], body, device['secret'])
        require(status == 200 and response.get('client_mode') == 'MONITOR'
                and response.get('sync_type') == 'CLEAN' and response.get('batch_size') == BATCH_SIZE,
                'Unexpected Monitor preflight response')
        received, cursor = [], None
        for page in range(2):
            status, response = post('ruledownload', device['uuid'], {'cursor': cursor} if cursor else {}, device['secret'])
            require(status == 200, 'Rule download failed')
            rules = response.get('rules')
            require(isinstance(rules, list) and len(rules) == (5 if page == 0 else 1), 'Unexpected rule page size')
            received.extend(rules)
            cursor = response.get('cursor')
            require((isinstance(cursor, str) and 0 < len(cursor) <= 128) if page == 0 else not cursor,
                    'Unexpected rule pagination termination')
        expected = [dict(identifier=value, rule_type='BINARY', policy='BLOCKLIST')
                    for value in sorted(fixture['identifiers'])]
        require(sorted(received, key=lambda rule: rule.get('identifier', '')) == expected,
                'Downloaded rules differed from exact synthetic rules')
        require(post('eventupload', device['uuid'], {'events': []}, device['secret'])[0] == 200,
                'Empty event upload failed')
        event = dict(file_sha256=fixture['identifiers'][0], file_name='synthetic-only',
                     file_path='/azd-synthetic-not-a-real-file', decision='BLOCK_BINARY',
                     execution_time=time.time(), executing_user='azd-synthetic',
                     logged_in_users=[], current_sessions=[], signing_chain=[], pid=123, ppid=1,
                     parent_name='azd-synthetic')
        require(post('eventupload', device['uuid'], {'events': [event]}, device['secret'])[0] == 200,
                'Synthetic event upload failed')
        require(post('postflight', device['uuid'], {'rules_received': RULE_COUNT,
                     'rules_processed': RULE_COUNT, 'syncType': 'CLEAN'}, device['secret'])[0] == 200,
                'Postflight failed')
    for device in fixture['devices']:
        other = next(item for item in fixture['devices'] if item is not device)
        for stage in ('ruledownload', 'eventupload', 'postflight'):
            require(post(stage, device['uuid'], {}, other['secret'])[0] == 403,
                    'Cross-device credential accepted outside preflight')
    after = snapshot(compose, fixture)
    assert_committed(after, fixture)
    require(after['synthetic_blocked_count'] == before['synthetic_blocked_count'] + 2,
            'Synthetic event database counter receipt missing')
    for old, new in zip(before['machines'], after['machines']):
        require(not old['machine'] or not old['machine']['postflight']
                or new['machine']['postflight'] > old['machine']['postflight'], 'Postflight timestamp did not advance')
    receipt = fixture_path.with_name(fixture_path.stem + '.receipt-' + uuid.uuid4().hex + '.json')
    descriptor = os.open(receipt, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
        json.dump(dict(scope='synthetic-loopback-only', commit=COMMIT, compose_sha256=compose_hash,
                       reopened=not initialize, before=before, after=after,
                       event_store_indexing='not verified; app/PostgreSQL counter receipt only',
                       limitation='Server database/client-reported receipt only; no native Mac or device identity proof'), stream)
    return receipt


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', required=True)
    parser.add_argument('--fixture', required=True)
    parser.add_argument('--initialize', action='store_true')
    arguments = parser.parse_args()
    try:
        receipt = run(arguments.compose, arguments.fixture, arguments.initialize)
    except Exception:
        # stdout/stderr can cross Run Command receipts; never include ORM output,
        # request headers, secrets or detailed exception objects in these streams.
        raise SystemExit('Synthetic live qualification failed; inspect private local evidence. Do not blindly reinitialize.')
    print('SANTA_LIVE_ZENTRAL_OK ' + str(receipt))
