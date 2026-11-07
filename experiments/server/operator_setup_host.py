"""Original Unlicense privileged host setup/readback. No CLI auth or grants.

Executed as root by the bound Run Command transport, never imported to deploy.
All child diagnostics stay private. Unknown outcomes never re-run recovery.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import struct
import subprocess
import sys
import urllib.request

ROOT = Path('/var/lib/azd-santa-qualification')
DOCKER = ['docker', '--host', 'unix:///var/run/docker.sock']
MARKER = 'SANTA_SEALED_SETUP_JSON:'
BINDINGS = sorted(('TenantId', 'SubscriptionId', 'EnvironmentName', 'ResourceGroup', 'VmName', 'VmId',
    'VmInstanceId', 'ImageId', 'ComposePath', 'ComposeSha256', 'SourceCommit', 'AdmissionSha256', 'RecoverySha256',
    'SealedSha256', 'Origin', 'RemoteProgramSha256'))
HEX = re.compile('[0-9a-f]{64}')
GUID = re.compile('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
REDIS = ['redis-server', '--appendonly', 'yes', '--appendfsync', 'always', '--aof-load-truncated',
         'no', '--maxmemory-policy', 'noeviction', '--no-appendfsync-on-rewrite', 'no', '--save', '']
VOLUMES = {'postgres_data', 'redis_data', 'rabbitmq_data', 'elasticsearch_data', 'media_data', 'elasticsearch_snapshots'}
ENV_KEYS = {'db.env': {'POSTGRES_DB', 'POSTGRES_USER', 'POSTGRES_PASSWORD'},
    'rabbitmq.env': {'RABBITMQ_DEFAULT_USER', 'RABBITMQ_DEFAULT_PASS'},
    'runtime.env': {'POSTGRES_USER', 'POSTGRES_PASSWORD', 'ZENTRAL_DJANGO_SECRET', 'ZENTRAL_METRICS_TOKEN',
                    'AZD_SANTA_SECURITY_STORE_ID', 'ZENTRAL_QUEUE_URL'}}


def need(value):
    if not value:
        raise ValueError('Private setup binding/state check failed')


def unique(pairs):
    value = {}
    for key, item in pairs:
        need(key not in value)
        value[key] = item
    return value


def loads(raw):
    return json.loads(raw, object_pairs_hook=unique)


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode('utf-8')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def target(username, email):
    return sha(b''.join(struct.pack('>I', len(v)) + v for v in (username.encode(), email.encode())))


def request_from_environment():
    value = os.environ['AZD_SANTA_SETUP_REQUEST_B64']
    need(len(value) <= 16384)
    raw = base64.b64decode(value, validate=True)
    need(base64.b64encode(raw).decode() == value)
    request = loads(raw.decode('utf-8'))
    need(set(request) == {'context', 'context_sha256', 'recipient_public_key', 'username', 'email', 'reason'})
    context, binding = request['context'], request['context']['binding']
    need(list(context) == ['scope', 'nonce', 'binding', 'mode', 'target_sha256', 'recipient_sha256'])
    need(list(binding) == BINDINGS and all(type(v) is str for v in binding.values()))
    need(context['scope'] == 'azd-santa-setup-request-v1' and context['mode'] in ('bootstrap', 'recover'))
    need(all(type(context[k]) is str and HEX.fullmatch(context[k]) for k in ('nonce', 'target_sha256', 'recipient_sha256')))
    need(HEX.fullmatch(request['context_sha256']) and sha(encoded(context)) == request['context_sha256'])
    for key, limit in (('username', 150), ('email', 254), ('reason', 256)):
        v = request[key]
        need(type(v) is str and 0 < len(v) <= limit and v.strip() == v and not any(ord(c) < 32 for c in v))
    need(target(request['username'], request['email']) == context['target_sha256'])
    key = base64.b64decode(request['recipient_public_key'], validate=True)
    need(len(key) <= 768 and base64.b64encode(key).decode() == request['recipient_public_key']
         and sha(key) == context['recipient_sha256'])
    need(all(GUID.fullmatch(binding[k]) for k in ('TenantId', 'SubscriptionId', 'VmInstanceId')))
    need(all(HEX.fullmatch(binding[k]) for k in ('ComposeSha256', 'AdmissionSha256', 'RecoverySha256', 'SealedSha256', 'RemoteProgramSha256')))
    need(re.fullmatch('sha256:[0-9a-f]{64}', binding['ImageId']) and re.fullmatch('[0-9a-f]{40}', binding['SourceCommit']))
    need(re.fullmatch('[a-z0-9-]{2,32}', binding['EnvironmentName'])
         and binding['ResourceGroup'] == 'rg-azd-santa-vm-' + binding['EnvironmentName'] and binding['VmName'] == 'vm-santa-lab')
    expected = '/subscriptions/' + binding['SubscriptionId'] + '/resourceGroups/' + binding['ResourceGroup'] + '/providers/Microsoft.Compute/virtualMachines/vm-santa-lab'
    need(binding['VmId'] == expected and len(binding['ComposePath']) <= 512)
    need(re.fullmatch(r'/(?:[A-Za-z0-9_-]+/)+[A-Za-z0-9_-]+\.json', binding['ComposePath']))
    need(binding['Origin'].isascii() and len(binding['Origin']) <= 256 and binding['Origin'].startswith('https://'))
    return request, raw


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def attest_metadata(binding):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    req = urllib.request.Request('http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01', headers={'Metadata': 'true'})
    with opener.open(req, timeout=2) as response:
        raw = response.read(65537)
    need(len(raw) <= 65536)
    value = loads(raw)
    need(value['subscriptionId'].lower() == binding['SubscriptionId'] and value['vmId'].lower() == binding['VmInstanceId']
         and value['resourceId'].lower() == binding['VmId'].lower() and value['name'] == binding['VmName']
         and value['resourceGroupName'].lower() == binding['ResourceGroup'])
    # Tenant is independently checked by the authenticated ARM caller. IMDS
    # compute does not supply tenant ID; never request an MSI token to infer it.


def private_path(path, *, directory=False, mode=0o600):
    path = Path(path)
    need(path.is_absolute() and path.is_relative_to(ROOT))
    current = ROOT
    for name in ('', *path.relative_to(ROOT).parts):
        if name:
            current /= name
        value = current.lstat()
        need(value.st_uid == 0 and not stat.S_ISLNK(value.st_mode) and not value.st_mode & 0o022)
        if current != path or directory:
            need(stat.S_ISDIR(value.st_mode))
    value = path.lstat()
    need(stat.S_ISDIR(value.st_mode) if directory else stat.S_ISREG(value.st_mode))
    if not directory:
        need(stat.S_IMODE(value.st_mode) == mode)
    return path


def write_new(path, raw):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as output:
        os.fchmod(output.fileno(), 0o600)
        need(os.fstat(output.fileno()).st_uid == 0)
        output.write(raw); output.flush(); os.fsync(output.fileno())
    sync_directory(path.parent)


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def docker(arguments, *, timeout=30, input=None):
    environment = {k: v for k, v in os.environ.items() if not k.startswith(('DOCKER_', 'COMPOSE_'))}
    result = subprocess.run(DOCKER + arguments, input=input, capture_output=True, timeout=timeout, env=environment)
    need(result.returncode == 0 and len(result.stdout) <= 262144 and len(result.stderr) <= 262144)
    return result.stdout


def actual_ports(info, service, exposed=()):
    expected = {'8000/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '8000'}]} if service == 'web' else {}
    need(not info['HostConfig'].get('PublishAllPorts'))
    # Exposed but unpublished image ports appear as null in NetworkSettings.
    # Ignore only those null entries; empty/extra/list-valued mappings are not
    # equivalent to the one explicitly allowed loopback publication.
    declared = info['HostConfig'].get('PortBindings') or {}
    observed = info['NetworkSettings'].get('Ports') or {}
    need(type(declared) is dict and type(observed) is dict)
    need(all(k in exposed for mapping in (declared, observed) for k, v in mapping.items() if v is None))
    need({k: v for k, v in declared.items() if v is not None} == expected)
    need({k: v for k, v in observed.items() if v is not None} == expected)


def attest_runtime(request):
    b = request['context']['binding']
    compose = private_path(b['ComposePath'])
    raw = compose.read_bytes(); need(len(raw) <= 65536 and sha(raw) == b['ComposeSha256'])
    config = loads(raw)
    project = config['name']
    need(set(config) == {'name', 'services', 'volumes'} and re.fullmatch('santa-zentral-eval-[0-9a-f]{12}', project))
    need(set(config['volumes']) == VOLUMES and all(v == {} for v in config['volumes'].values()))
    need(set(config['services']) == {'web', 'workers', 'celery', 'db', 'redis', 'rabbitmq', 'elastic'})
    environments = {}
    for filename, keys in ENV_KEYS.items():
        path = private_path(compose.parent / filename)
        with path.open('rb') as stream:
            raw_env = stream.read(4097)
        need(len(raw_env) <= 4096 and raw_env.endswith(b'\n'))
        pairs = [line.split('=', 1) for line in raw_env.decode('ascii').splitlines()]
        need(all(len(pair) == 2 and pair[1] for pair in pairs))
        environments[filename] = unique(pairs)
        need(set(environments[filename]) == keys)
    need(environments['db.env']['POSTGRES_USER'] == 'zentral_owner'
         and environments['runtime.env']['POSTGRES_USER'] == 'zentral_runtime'
         and environments['db.env']['POSTGRES_PASSWORD'] != environments['runtime.env']['POSTGRES_PASSWORD'])
    conf = compose.parent / 'conf'
    private_path(conf, directory=True)
    private_path(conf / 'base.json', mode=0o644)
    allowed = {'image', 'pull_policy', 'restart', 'mem_limit', 'logging', 'security_opt', 'command',
               'env_file', 'environment', 'volumes', 'depends_on', 'ports', 'hostname'}
    dependency_mounts = {'db': ['postgres_data:/var/lib/postgresql'], 'redis': ['redis_data:/data'],
        'rabbitmq': ['rabbitmq_data:/var/lib/rabbitmq'], 'elastic': ['elasticsearch_data:/usr/share/elasticsearch/data', 'elasticsearch_snapshots:/mnt/azd-santa-snapshots']}
    need(config['services']['elastic'].get('environment', {}).get('path.repo') == '/mnt/azd-santa-snapshots')
    web, networks, services = None, set(), {}
    for service, declaration in config['services'].items():
        need(set(declaration) <= allowed and declaration.get('ports', []) == (['127.0.0.1:8000:8000'] if service == 'web' else []))
        expected_mounts = dependency_mounts.get(service, ['./conf:/zentral-eval-conf:ro', 'media_data:/var/zentral'])
        need(declaration.get('volumes') == expected_mounts)
        envfile = 'db.env' if service == 'db' else 'rabbitmq.env' if service == 'rabbitmq' else 'runtime.env'
        need(declaration.get('env_file', []) == ([] if service in ('redis', 'elastic') else ['./' + envfile]))
        image = declaration['image']
        need(image == b['ImageId'] if service in ('web', 'workers', 'celery') else re.fullmatch('[a-z0-9][a-z0-9./:_-]*@sha256:[a-f0-9]{64}', image))
        ids = docker(['compose', '--project-name', project, '-f', str(compose), 'ps', '--quiet', service]).decode().strip()
        need(re.fullmatch('[a-f0-9]{64}', ids))
        services[service] = ids
        info = loads(docker(['inspect', ids]))[0]
        if service == 'elastic':
            need(unique([item.split('=', 1) for item in info['Config']['Env']]).get('path.repo') == '/mnt/azd-santa-snapshots')
        labels = info['Config'].get('Labels', {})
        need(info['State']['Running'] is True and labels.get('com.docker.compose.project') == project
             and labels.get('com.docker.compose.service') == service and info['Config']['Image'] == image)
        sensitive = set().union(*ENV_KEYS.values())
        actual_env = unique([item.split('=', 1) for item in info['Config']['Env'] if item.split('=', 1)[0] in sensitive])
        need(actual_env == ({} if service in ('redis', 'elastic') else environments[envfile]))
        image_info = loads(docker(['image', 'inspect', image]))[0]
        need(info['Image'] == image_info['Id'])
        need(not info['HostConfig']['Privileged'] and not info['HostConfig'].get('CapAdd')
             and set(info['NetworkSettings']['Networks']) == {project + '_default'})
        actual_ports(info, service, image_info['Config'].get('ExposedPorts') or {})
        network = info['NetworkSettings']['Networks'][project + '_default']['NetworkID']
        need(re.fullmatch('[a-f0-9]{64}', network)); networks.add(network)
        actual_mounts = info['Mounts']
        need(len(actual_mounts) == len(declaration.get('volumes', [])))
        for mount in actual_mounts:
            if mount['Destination'] == '/zentral-eval-conf':
                need(mount['Type'] == 'bind' and mount['Source'] == str(conf) and mount['RW'] is False)
            else:
                destinations = {'/var/lib/postgresql': 'postgres_data', '/data': 'redis_data', '/var/lib/rabbitmq': 'rabbitmq_data',
                                '/usr/share/elasticsearch/data': 'elasticsearch_data', '/var/zentral': 'media_data',
                                '/mnt/azd-santa-snapshots': 'elasticsearch_snapshots'}
                need(mount['Type'] == 'volume' and mount['Destination'] in destinations
                     and mount['Name'] == project + '_' + destinations[mount['Destination']] and mount['RW'] is True)
        if service in ('web', 'workers', 'celery'):
            need(info['Image'] == b['ImageId'] and labels.get('org.opencontainers.image.revision') == b['SourceCommit'])
            need(image_info['Config']['Labels'].get('io.azd-santa.variant') == 'core-experiment')
        if service == 'web':
            web = ids
    need(len(networks) == 1 and config['services']['redis']['command'] == REDIS and config['services']['redis']['volumes'] == ['redis_data:/data'])
    probe = """import base64,hashlib,json,os
from pathlib import Path
from django.conf import settings
from urllib.parse import urlsplit
from base.deployment import version
from zentral.conf import api_base_url
import azd_santa_operator_recovery as recovery
import azd_santa_sealed_setup as sealed
import azd_santa_operator as policy
import azd_santa_admission as admission
p=json.loads(base64.b64decode(os.environ['AZD_SANTA_SETUP_REQUEST_B64']))
b=p['context']['binding']
assert not settings.DEBUG and version.strip()==b['SourceCommit']
assert settings.DATABASES['default']['HOST']=='db' and settings.DATABASES['default']['NAME']=='zentral'
cache=urlsplit(settings.CACHES['azd_santa_security']['LOCATION'])
assert cache.hostname=='redis' and cache.path=='/2' and cache.scheme in ('redis','rediss')
assert hashlib.sha256(Path(recovery.__file__).read_bytes()).hexdigest()==b['RecoverySha256']
assert hashlib.sha256(Path(sealed.__file__).read_bytes()).hexdigest()==b['SealedSha256']
assert hashlib.sha256(Path(admission.__file__).read_bytes()).hexdigest()==b['AdmissionSha256']
admission.check()
assert sealed.origin(api_base_url())==sealed.origin(b['Origin'])
recovery.validate_request(p['context']['mode'],p['username'],p['email'],p['reason'])
sealed.prepare_recipient(p['recipient_public_key'],p['context_sha256'],p['context']['mode'],p['username'],p['email'],api_base_url())
policy.check_security_store()
print('SANTA_SETUP_HOST_ATTESTED')
"""
    value = base64.b64encode(encoded(request)).decode()
    output = docker(['exec', '--env', 'AZD_SANTA_SETUP_REQUEST_B64=' + value, web,
                     'python', 'server/manage.py', 'shell', '--no-imports', '-c', probe], timeout=60)
    need(output.decode().splitlines().count('SANTA_SETUP_HOST_ATTESTED') == 1)
    return services


def envelope(raw, request):
    need(len(raw) <= 2600)
    value = loads(raw)
    need(set(value) == {'scope', 'version', 'algorithm', 'mode', 'kid_sha256', 'context_sha256', 'target_sha256',
                        'wrapped_key_base64', 'nonce_base64', 'ciphertext_base64'})
    c = request['context']
    need(value['scope'] == 'azd-santa-sealed-setup' and type(value['version']) is int and value['version'] == 1
         and value['algorithm'] == 'RSA-OAEP-256+A256GCM' and value['mode'] == c['mode']
         and value['context_sha256'] == request['context_sha256'] and value['kid_sha256'] == c['recipient_sha256']
         and value['target_sha256'] == c['target_sha256'])
    for key, low, high in (('wrapped_key_base64', 384, 384), ('nonce_base64', 12, 12), ('ciphertext_base64', 17, 1600)):
        decoded = base64.b64decode(value[key], validate=True)
        need(low <= len(decoded) <= high and base64.b64encode(decoded).decode() == value[key])
    return encoded(value)


def read_artifact(web, artifact, request):
    code = """import os,stat,sys
p=sys.argv[1]
fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
with os.fdopen(fd,'rb') as f:
 s=os.fstat(f.fileno()); assert stat.S_ISREG(s.st_mode) and stat.S_IMODE(s.st_mode)==0o600 and s.st_uid==os.getuid() and s.st_size<=2601
 sys.stdout.buffer.write(f.read(2602))
"""
    return envelope(docker(['exec', web, 'python', '-c', code, artifact]).strip(), request)


def run():
    need(os.geteuid() == 0)
    os.umask(0o077)
    request, raw = request_from_environment()
    operation = os.environ['AZD_SANTA_SETUP_OPERATION']; need(operation in ('create', 'readback'))
    attest_metadata(request['context']['binding'])
    web = attest_runtime(request)['web']
    store = ROOT / 'operator-setup'
    if not store.exists():
        try:
            store.mkdir(mode=0o700); sync_directory(ROOT)
        except FileExistsError:
            pass
    private_path(store, directory=True)
    folder = store / request['context_sha256']
    artifact = '/var/zentral/azd-operator-setup-' + request['context_sha256'] + '.json'
    if operation == 'create':
        # Exclusive directory reservation is the cross-process mutation lock.
        # It persists across failure, timeout and host restart; never replay it.
        folder.mkdir(mode=0o700); sync_directory(store)
        write_new(folder / 'request.json', raw)
        write_new(folder / 'attempt.json', encoded({'state': 'mutation-may-have-started', 'container': web}))
        args = DOCKER + ['exec', web, 'python', 'server/manage.py', 'operator_access', request['context']['mode'],
            '--username=' + request['username'], '--email=' + request['email'], '--reason=' + request['reason'],
            '--output', artifact, '--recipient-public-key', request['recipient_public_key'],
            '--context-sha256', request['context_sha256'], '--sealed-stdout']
        environment = {k: v for k, v in os.environ.items() if not k.startswith(('DOCKER_', 'COMPOSE_'))}
        # Reserved output files retain partial diagnostics without Azure output.
        out = os.open(folder / 'command.stdout', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        err = os.open(folder / 'command.stderr', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(out, 'wb') as stdout, os.fdopen(err, 'wb') as stderr:
            result = subprocess.run(args, stdout=stdout, stderr=stderr, timeout=180, env=environment)
            stdout.flush(); os.fsync(stdout.fileno()); stderr.flush(); os.fsync(stderr.fileno())
        write_new(folder / 'exit.json', encoded({'returncode': result.returncode}))
        need(result.returncode == 0)
        with (folder / 'command.stdout').open('rb') as stream:
            output = stream.read(16385)
        need(len(output) <= 16384)
        records = [line[len(MARKER):] for line in output.decode().splitlines() if line.startswith(MARKER)]
        need(len(records) == 1)
        sealed = envelope(records[0], request)
        need(read_artifact(web, artifact, request) == sealed)
        write_new(folder / 'sealed.json', sealed)
    else:
        private_path(folder, directory=True)
        need(private_path(folder / 'request.json').read_bytes() == raw)
        # Readback never invokes operator_access. A valid original artifact may
        # recover delivery after an unknown response; it proves no audit delivery.
        need(private_path(folder / 'attempt.json').is_file())
        sealed = read_artifact(web, artifact, request)
        if (folder / 'sealed.json').exists():
            need(private_path(folder / 'sealed.json').read_bytes() == sealed)
    print(MARKER + sealed.decode('ascii'))


if __name__ == '__main__':
    try:
        if sys.argv[1:] == ['--validate-request']:
            request, _ = request_from_environment()
            print('SANTA_SETUP_REQUEST_VALID:' + request['context_sha256'])
        else:
            need(not sys.argv[1:])
            def deadline(*args):
                raise TimeoutError('Private host operation exceeded its process budget')
            signal.signal(signal.SIGALRM, deadline); signal.alarm(300)
            run()
    except Exception:
        raise SystemExit('Private setup did not return a confirmed sealed artifact. Inspect the retained context checkpoint; do not retry create.') from None
