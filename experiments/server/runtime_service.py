"""Supervise one initialized private runtime; never bootstrap or restore its data.

The generated systemd unit is opt-in qualification tooling, not an azd hook.
All subprocess diagnostics stay in an exclusive private evidence directory.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import stat
import subprocess
import sys
import time
import uuid
import urllib.request

from test_live_zentral import COMMIT, validate_compose

ROOT = Path('/var/lib/azd-santa-qualification')
UNIT = Path('/etc/systemd/system/azd-santa-runtime.service')
DOCKER = ['docker', '--host', 'unix:///var/run/docker.sock']
APPS = ('web', 'workers', 'celery')
DEPENDENCIES = ('db', 'redis', 'rabbitmq', 'elastic')
POLICIES = {'policy': 'azd_santa_operator.py',
            'recovery': 'azd_santa_operator_recovery.py',
            'sealed': 'azd_santa_sealed_setup.py'}
HELPERS = ('test_live_zentral.py', 'prepare_zentral_eval.py')
VOLUMES = {'db': ['postgres_data:/var/lib/postgresql'],
           'redis': ['redis_data:/data'], 'rabbitmq': ['rabbitmq_data:/var/lib/rabbitmq'],
           'elastic': ['elasticsearch_data:/usr/share/elasticsearch/data'],
           **{name: ['./conf:/zentral-eval-conf:ro', 'media_data:/var/zentral'] for name in APPS}}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def private_write(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        json.dump(data, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())


def checked_path(value, *, private=False):
    path = Path(value)
    if not path.is_absolute() or path != path.resolve(strict=True) or not path.is_relative_to(ROOT):
        raise ValueError('Runtime path must stay in the selected private root without links')
    if os.name != 'nt':
        for parent in (ROOT, *path.relative_to(ROOT).parents):
            parent = parent if parent.is_absolute() else ROOT / parent
            info = parent.stat()
            if not parent.is_dir() or info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError('Runtime parents must be root-owned and not publicly writable')
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or (os.name != 'nt' and info.st_uid != 0):
        raise ValueError('Root-owned regular runtime file required')
    if private and info.st_mode & 0o077:
        raise ValueError('Private runtime file permissions required')
    return path


def bundle(compose):
    path, digest = validate_compose(checked_path(compose, private=True))
    data = json.loads(path.read_text())
    if (data['volumes'] != {name: {} for name in ('postgres_data', 'redis_data', 'rabbitmq_data', 'elasticsearch_data', 'media_data')} or
            any(sorted(data['services'][name].get('volumes', [])) != sorted(expected) for name, expected in VOLUMES.items())):
        raise ValueError('Exact per-service persistent data/configuration mounts required')
    if any(s.get('restart') != 'no' for s in data['services'].values()):
        raise ValueError('Boot admission requires containers without independent auto-start')
    app_images = {data['services'][name]['image'] for name in APPS}
    if len(app_images) != 1 or not re.fullmatch(r'sha256:[a-f0-9]{64}', next(iter(app_images))):
        raise ValueError('One immutable application image required')
    if any(not re.fullmatch(r'[a-z0-9][a-z0-9./:_-]*@sha256:[a-f0-9]{64}', data['services'][name]['image']) for name in DEPENDENCIES):
        raise ValueError('Immutable dependency image digests required')
    files = {str(path): digest}
    config = checked_path(path.parent / 'conf/base.json')
    files[str(config)] = sha(config.read_bytes())
    for service in data['services'].values():
        for name in service.get('env_file', []):
            if not re.fullmatch(r'\./[a-z][a-z0-9-]*\.env', name):
                raise ValueError('Only local generated env files are supported')
            file = checked_path(path.parent / name[2:], private=True)
            files[str(file)] = sha(file.read_bytes())
    return path, data, files


def prepare(compose, destination, policy_hashes):
    if set(policy_hashes) != set(POLICIES) or any(not re.fullmatch(r'[a-f0-9]{64}', x) for x in policy_hashes.values()):
        raise ValueError('Exact installed security-module hashes required')
    path, data, files = bundle(compose)
    destination = Path(destination)
    if (not destination.is_absolute() or destination.parent != destination.parent.resolve(strict=True) or
            destination.parent != path.parent or destination.name != 'runtime-service'):
        raise ValueError('Service control directory must be local to its selected runtime')
    manifest = dict(scope='private-initialized-runtime-service-v1', compose=str(path),
                    project=data['name'], files=files, policy_hashes=policy_hashes,
                    source_commit=COMMIT, controller_sha256=sha(Path(__file__).read_bytes()),
                    helpers_sha256={name: sha(Path(__file__).with_name(name).read_bytes()) for name in HELPERS})
    if destination.exists() or destination.is_symlink():
        existing = checked_path(destination / 'manifest.json', private=True)
        if existing.read_bytes() != json.dumps(manifest, sort_keys=True).encode():
            raise FileExistsError('Existing service binding differs; deliberate upgrade required')
        return existing
    destination.mkdir(mode=0o700)
    private_write(destination / 'manifest.json', manifest)
    return destination / 'manifest.json'


def load_manifest(path, expected):
    path = checked_path(path, private=True)
    raw = path.read_bytes()
    if not re.fullmatch(r'[a-f0-9]{64}', expected) or sha(raw) != expected:
        raise ValueError('Selected service manifest changed')
    manifest = json.loads(raw)
    keys = {'scope', 'compose', 'project', 'files', 'policy_hashes', 'source_commit', 'controller_sha256', 'helpers_sha256'}
    if set(manifest) != keys or manifest['scope'] != 'private-initialized-runtime-service-v1' or manifest['source_commit'] != COMMIT:
        raise ValueError('Unrecognized runtime service manifest')
    if manifest['controller_sha256'] != sha(Path(__file__).read_bytes()):
        raise ValueError('Selected runtime controller changed')
    if manifest['helpers_sha256'] != {name: sha(Path(__file__).with_name(name).read_bytes()) for name in HELPERS}:
        raise ValueError('Selected runtime validation helpers changed')
    compose, data, files = bundle(manifest['compose'])
    if files != manifest['files'] or data['name'] != manifest['project'] or path.parent != compose.parent / 'runtime-service':
        raise ValueError('Selected runtime/configuration changed')
    if set(manifest['policy_hashes']) != set(POLICIES) or any(not re.fullmatch(r'[a-f0-9]{64}', x) for x in manifest['policy_hashes'].values()):
        raise ValueError('Invalid installed-module binding')
    return manifest, data


def unit_text(script, manifest, digest):
    # No shell evaluation in systemd; still reject its specifiers and word syntax.
    for value in (str(script), str(manifest)):
        if not re.fullmatch(r'/[A-Za-z0-9/_.-]+', value):
            raise ValueError('Safe absolute service paths required')
    if not re.fullmatch(r'[a-f0-9]{64}', digest):
        raise ValueError('Exact service manifest digest required')
    return f'''[Unit]
Description=Private Santa initialized runtime
Requires=docker.service
After=docker.service network-online.target
Wants=network-online.target
StartLimitIntervalSec=600
StartLimitBurst=3

[Service]
Type=notify
NotifyAccess=main
ExecStart=/usr/bin/python3 {script} run --manifest {manifest} --sha256 {digest}
Restart=on-failure
RestartSec=30
TimeoutStartSec=420
TimeoutStopSec=240
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true

[Install]
WantedBy=multi-user.target
'''


def install_unit(manifest, digest, *, enable_now=False):
    load_manifest(manifest, digest)
    raw = unit_text(Path(__file__).resolve(), Path(manifest), digest).encode()
    target = UNIT
    if target.is_symlink():
        raise ValueError('Existing service link requires inspection')
    if target.exists():
        info = target.stat()
        if info.st_uid != 0 or info.st_mode & 0o022 or target.read_bytes() != raw:
            raise ValueError('Existing service differs; deliberate upgrade required')
    else:
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    subprocess.run(['systemctl', 'daemon-reload'], check=True, capture_output=True, timeout=30)
    if enable_now:
        subprocess.run(['systemctl', 'enable', '--now', target.name], check=True, capture_output=True, timeout=450)
    print('SANTA_PRIVATE_RUNTIME_UNIT_INSTALLED', flush=True)


class Runtime:
    def __init__(self, manifest, digest):
        self.manifest_path, self.digest = Path(manifest), digest
        self.binding, self.data = load_manifest(manifest, digest)
        self.project = self.data['name']
        self.environment = {k: v for k, v in os.environ.items() if not k.startswith(('DOCKER_', 'COMPOSE_'))}
        self.command = DOCKER + ['compose', '--project-name', self.project, '-f', self.binding['compose']]
        self.evidence = self.manifest_path.parent / ('attempt-' + uuid.uuid4().hex)
        self.evidence.mkdir(mode=0o700)
        self.ids = []
        self.images = {}
        self.rendered = None
        self.stopping = False
        self.phase = 'prepared'

    def call(self, label, args, *, timeout=30, allowed_failure=False, record=True):
        self.phase = label
        try:
            result = subprocess.run(args, capture_output=True, text=True, env=self.environment, timeout=timeout)
        except subprocess.TimeoutExpired:
            private_write(self.evidence / (label + '-' + uuid.uuid4().hex + '.json'), {'timeout': True})
            raise RuntimeError('Private runtime step timed out: ' + label) from None
        if record or result.returncode:
            private_write(self.evidence / (label + '-' + uuid.uuid4().hex + '.json'),
                          dict(returncode=result.returncode, stdout=result.stdout, stderr=result.stderr))
        if result.returncode and not allowed_failure:
            raise RuntimeError('Private runtime step failed: ' + label)
        return result

    def inspect(self, *, running, record=True):
        ids = self.call('container-selection', self.command + ['ps', '--all', '--quiet'], record=record).stdout.split()
        if len(ids) != 7 or any(not re.fullmatch(r'[a-f0-9]{64}', x) for x in ids):
            raise ValueError('Exactly seven previously initialized containers required')
        if self.ids and set(ids) != set(self.ids):
            raise ValueError('Selected container identity changed')
        rows = json.loads(self.call('container-inspection', DOCKER + ['inspect', *ids], record=record).stdout)
        if self.rendered is None:
            self.rendered = json.loads(self.call('rendered-compose', self.command + ['config', '--format', 'json']).stdout)
        selected = {}
        for row in rows:
            labels = row['Config'].get('Labels', {})
            name = labels.get('com.docker.compose.service')
            if labels.get('com.docker.compose.project') != self.project or name not in self.data['services'] or name in selected:
                raise ValueError('Container ownership mismatch')
            ref = self.data['services'][name]['image']
            if ref not in self.images:
                self.images[ref] = json.loads(self.call('image-inspection', DOCKER + ['image', 'inspect', ref]).stdout)[0]
            image = self.images[ref]
            if row['Image'] != image['Id'] or row['HostConfig']['RestartPolicy']['Name'] != 'no' or (running and not row['State']['Running']):
                raise ValueError('Container image/restart/readiness mismatch')
            if name in APPS and image['Config'].get('Labels', {}).get('org.opencontainers.image.revision') != COMMIT:
                raise ValueError('Application source revision mismatch')
            config, host = row['Config'], row['HostConfig']
            if (config.get('Cmd') != self.data['services'][name].get('command', image['Config'].get('Cmd')) or
                    config.get('Entrypoint') != image['Config'].get('Entrypoint') or
                    config.get('User') != image['Config'].get('User') or host.get('Privileged') or
                    host.get('CapAdd') or host.get('PidMode') or host.get('Devices') or host.get('PublishAllPorts') or
                    host.get('SecurityOpt') != ['no-new-privileges:true']):
                raise ValueError('Container command or privilege boundary changed')
            environment = dict(item.split('=', 1) for item in image['Config'].get('Env', []))
            environment.update({k: str(v) for k, v in self.rendered['services'][name].get('environment', {}).items()})
            actual = row['Config'].get('Env', [])
            if len({item.split('=', 1)[0] for item in actual}) != len(actual) or dict(item.split('=', 1) for item in actual) != environment:
                raise ValueError('Container environment differs from selected files/image')
            expected_mounts = set()
            for volume in self.data['services'][name].get('volumes', []):
                source, target, *flags = volume.split(':')
                if source == './conf':
                    expected_mounts.add(('bind', str(Path(self.binding['compose']).parent / 'conf'), target, False))
                else:
                    expected_mounts.add(('volume', self.project + '_' + source, target, True))
            actual_mounts = {(m['Type'], m['Source'] if m['Type'] == 'bind' else m.get('Name'), m['Destination'], m['RW']) for m in row['Mounts']}
            if actual_mounts != expected_mounts or len(row['Mounts']) != len(expected_mounts):
                raise ValueError('Container data/configuration mounts changed')
            ports = {'8000/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '8000'}]} if name == 'web' else {}
            if ((host.get('PortBindings') or {}) != ports or host.get('NetworkMode') != self.project + '_default' or
                    set(row['NetworkSettings']['Networks']) != {self.project + '_default'}):
                raise ValueError('Container network/port ownership mismatch')
            actual_ports = row['NetworkSettings'].get('Ports') or {}
            if any(value == [] for value in actual_ports.values()):
                raise ValueError('Ambiguous actual port publication')
            published = {port: value for port, value in actual_ports.items() if value is not None}
            allowed_unbound = set(image['Config'].get('ExposedPorts') or {}) | ({'8000/tcp'} if name == 'web' else set())
            if (any(value is None and port not in allowed_unbound for port, value in actual_ports.items()) or
                    (row['State']['Running'] and published != ports) or
                    (not row['State']['Running'] and published not in ({}, ports))):
                raise ValueError('Actual port publication differs from selected private binding')
            selected[name] = row['Id']
        self.ids = list(selected.values())
        return selected

    def wait(self, label, check, seconds=100):
        deadline = time.monotonic() + seconds
        while not check():
            if self.stopping or time.monotonic() >= deadline:
                raise RuntimeError('Private runtime readiness failed: ' + label)
            time.sleep(2)

    def python(self, label, code):
        return self.call(label, self.command + ['run', '--rm', '--no-deps', '--entrypoint', 'python',
                                               'web', 'server/manage.py', 'shell', '--no-imports', '-c', code], timeout=60)

    def start(self):
        selected = self.inspect(running=False)
        # A deliberate hot start must close admission before inspecting stores.
        self.call('close-admission', DOCKER + ['stop', '--time', '30', *(selected[name] for name in APPS)], timeout=100)
        self.call('compose-config', self.command + ['config', '--quiet'])
        # Never create replacement volumes or initialize a missing security store.
        for name in self.data['volumes']:
            volume = json.loads(self.call('volume-inspection', DOCKER + ['volume', 'inspect', self.project + '_' + name]).stdout)[0]
            if volume.get('Labels', {}).get('com.docker.compose.project') != self.project:
                raise ValueError('Existing volume ownership mismatch')
        if Path('/proc/sys/vm/max_map_count').read_text().strip() != '1048576':
            raise ValueError('Qualified Elasticsearch kernel prerequisite missing')
        self.call('dependencies', self.command + ['up', '--detach', '--no-recreate', '--pull', 'never', *DEPENDENCIES], timeout=120)
        self.wait('database', lambda: self.call('database', self.command + ['exec', '-T', 'db', 'pg_isready', '-U', 'zentral', '-d', 'zentral'], allowed_failure=True).returncode == 0)
        code = 'from pathlib import Path; import hashlib; '
        for name, file in POLICIES.items():
            code += f"assert hashlib.sha256(Path('/zentral/server/{file}').read_bytes()).hexdigest()=={self.binding['policy_hashes'][name]!r}; "
        code += "from django.db import connection; from django.db.migrations.executor import MigrationExecutor; e=MigrationExecutor(connection); assert not e.migration_plan(e.loader.graph.leaf_nodes()); "
        code += "from zentral.core.stores.models import Store; assert Store.objects.count()==1; s=Store.objects.get(provisioning_uid='elasticsearch'); assert s.backend=='ELASTICSEARCH' and s.admin_console"
        self.python('source-schema-store', code)
        self.call('security-store', self.command + ['run', '--rm', '--no-deps', '--entrypoint', 'python', 'web', 'server/manage.py', 'operator_security_store', 'check'], timeout=60)
        self.python('search', "import json,time,urllib.request; o=urllib.request.build_opener(urllib.request.ProxyHandler({})); deadline=time.monotonic()+45\nwhile True:\n try:\n  r=json.load(o.open('http://elastic:9200/_cluster/health',timeout=3)); assert r['status'] in ('yellow','green'); break\n except Exception:\n  if time.monotonic()>deadline: raise RuntimeError('Search not ready') from None\n  time.sleep(2)")
        self.call('workers', self.command + ['up', '--detach', '--no-recreate', '--no-deps', '--pull', 'never', 'workers', 'celery'], timeout=120)

        def consumers():
            result = self.call('queues', self.command + ['exec', '-T', 'rabbitmq', 'rabbitmqctl', 'list_queues', 'name', 'consumers', '--formatter', 'json'], allowed_failure=True)
            if result.returncode:
                return False
            rows = json.loads(result.stdout)
            return all(any(q['name'] == name and q['consumers'] > 0 for q in rows) for name in ('store_events_Elasticsearch', 'enrich_events', 'process_events'))
        self.wait('consumers', consumers)
        self.call('listener', self.command + ['up', '--detach', '--no-recreate', '--no-deps', '--pull', 'never', 'web'], timeout=120)
        self.inspect(running=True)
        # A running PID is not an HTTP readiness receipt.
        from test_live_zentral import NoRedirect
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        def http_ready():
            try:
                with opener.open('http://127.0.0.1:8000/accounts/login/', timeout=3) as response:
                    return response.status == 200
            except Exception:
                return False
        self.wait('http', http_ready, seconds=45)
        print('SANTA_PRIVATE_RUNTIME_READY', flush=True)

    def stop(self):
        if self.ids:
            self.call('stop', DOCKER + ['stop', '--time', '30', *self.ids], timeout=100)

    def supervise(self):
        import fcntl
        with (self.manifest_path.parent / 'supervisor.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            def stopping(*_):
                self.stopping = True
            signal.signal(signal.SIGTERM, stopping)
            signal.signal(signal.SIGINT, stopping)
            try:
                self.start()
                address = os.environ.get('NOTIFY_SOCKET')
                if address:
                    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
                        sock.sendto(b'READY=1', '\0' + address[1:] if address.startswith('@') else address)
                while not self.stopping:
                    time.sleep(5)
                    self.phase = 'binding-check'
                    load_manifest(self.manifest_path, self.digest)
                    self.inspect(running=True, record=False)
            except Exception as error:
                private_write(self.evidence / 'failure.json', dict(phase=self.phase,
                              error_type=type(error).__name__, detail=str(error)))
                raise
            finally:
                self.stop()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='operation', required=True)
    prepare_parser = commands.add_parser('prepare')
    prepare_parser.add_argument('--compose', required=True)
    prepare_parser.add_argument('--destination', required=True)
    for name in POLICIES:
        prepare_parser.add_argument('--' + name + '-sha256', required=True)
    for name in ('run', 'unit', 'install'):
        command = commands.add_parser(name)
        command.add_argument('--manifest', required=True)
        command.add_argument('--sha256', required=True)
        if name == 'install':
            command.add_argument('--enable-now', action='store_true')
    args = parser.parse_args()
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise RuntimeError('Privileged Linux runtime management required')
    if args.operation == 'prepare':
        path = prepare(args.compose, args.destination, {name: getattr(args, name + '_sha256') for name in POLICIES})
        print(str(path) + ' ' + sha(path.read_bytes()))
    elif args.operation == 'unit':
        load_manifest(args.manifest, args.sha256)
        print(unit_text(Path(__file__).resolve(), Path(args.manifest), args.sha256), end='')
    elif args.operation == 'install':
        install_unit(args.manifest, args.sha256, enable_now=args.enable_now)
    else:
        Runtime(args.manifest, args.sha256).supervise()


if __name__ == '__main__':
    try:
        main()
    except Exception:
        # Raw Docker/Django failures can contain secrets. Details are private.
        print('Private runtime service failed; inspect retained private evidence.', file=sys.stderr)
        raise SystemExit(1)
