"""Supervise one initialized private runtime; never bootstrap or restore its data.

The generated systemd unit is opt-in qualification tooling, not an azd hook.
All subprocess diagnostics stay in an exclusive private evidence directory.
"""
import sys

if __name__ == '__main__' and not sys.flags.isolated:
    raise SystemExit('Use python3 -I for privileged runtime management.')

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import secrets
import socket
import stat
import subprocess
import time
import types
import uuid
import urllib.request

ROOT = Path('/var/lib/azd-santa-qualification')
COMMIT = '88e67b3ce49033aab028029937a6e14f7c489073'
UNIT = Path('/etc/systemd/system/azd-santa-runtime.service')
DOCKER = ['docker', '--host', 'unix:///var/run/docker.sock']
APPS = ('web', 'workers', 'celery')
DEPENDENCIES = ('db', 'redis', 'rabbitmq', 'elastic')
POLICIES = {'policy': 'azd_santa_operator.py',
            'recovery': 'azd_santa_operator_recovery.py',
            'sealed': 'azd_santa_sealed_setup.py', 'admission': 'azd_santa_admission.py'}
HELPERS = ('test_live_zentral.py', 'prepare_zentral_eval.py', 'cold_backup.py', 'native_snapshot.py', 'worker_lifecycle.py')
WORKER_HASHES = {'azd_santa_worker_lifecycle.py': 'e86d20287324eca25ef24c4c405e7d923feafb2d2760c1f22b799f0a02d0a50f',
                 'base/management/commands/runworkers.py': 'be379c804120c5a0dd3620bab14adbd5f8a0b89f51ed43ee2284d6eb1f0d9515'}
_HELPER = None
VOLUMES = {'db': ['postgres_data:/var/lib/postgresql'],
           'redis': ['redis_data:/data'], 'rabbitmq': ['rabbitmq_data:/var/lib/rabbitmq'],
           'elastic': ['elasticsearch_data:/usr/share/elasticsearch/data', 'elasticsearch_snapshots:/mnt/azd-santa-snapshots'],
           **{name: ['./conf:/zentral-eval-conf:ro', 'media_data:/var/zentral'] for name in APPS}}


class Cancelled(RuntimeError):
    pass


_ADMISSION_KEY = object()


class _AdmissionQuiescence:
    """Process-local authorization under the already-held controller flock."""
    def __init__(self, runtime, selected, generation, key):
        if key is not _ADMISSION_KEY or runtime.supervisor_lock_fd is None:
            raise ValueError('Admission recovery requires the current controller lock')
        self.runtime=runtime;self.selected=dict(selected);self.generation=generation
        self.fd=runtime.supervisor_lock_fd;self.pid=os.getpid();self.key=key

    def verify(self):
        runtime=self.runtime;runtime.ensure_running()
        if (self.key is not _ADMISSION_KEY or self.pid!=os.getpid()
                or getattr(runtime,'_admission_capability',None) is not self
                or runtime.supervisor_lock_fd!=self.fd):
            raise ValueError('Expired admission quiescence capability')
        info=os.fstat(self.fd);path=(runtime.manifest_path.parent/'supervisor.lock').stat()
        if (info.st_dev,info.st_ino)!=(path.st_dev,path.st_ino):
            raise ValueError('Admission controller lock changed')
        load_manifest(runtime.manifest_path,runtime.digest)
        if runtime.inspect(running=False,record=False)!=self.selected or runtime.container_generation(self.selected)!=self.generation:
            raise ValueError('Original admission generation changed')
        ids=[self.selected[name] for name in APPS]
        rows=json.loads(runtime.call('admission-quiescence',DOCKER+['inspect',*ids],record=False).stdout)
        if (len(rows)!=3 or {r['Id'] for r in rows}!=set(ids) or any(
                r['State'].get('Status') not in ('created','exited') or r['State'].get('Running') is not False
                or r['State'].get('Paused') is not False or r['State'].get('Restarting') is not False
                or type(r['State'].get('Pid')) is not int or r['State']['Pid']!=0 for r in rows)):
            raise ValueError('All exact old app processes must already be stopped')
        return rows


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def private_write(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        json.dump(data, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)


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
    if not stat.S_ISREG(info.st_mode) or (os.name != 'nt' and (info.st_uid != 0 or info.st_mode & 0o022)):
        raise ValueError('Root-owned regular runtime file required')
    if private and info.st_mode & 0o077:
        raise ValueError('Private runtime file permissions required')
    return path


def trusted_sources():
    controller = checked_path(Path(__file__).absolute())
    for name in HELPERS:
        checked_path(controller.with_name(name))
    if sha(controller.with_name('worker_lifecycle.py').read_bytes()) != WORKER_HASHES['azd_santa_worker_lifecycle.py']:
        raise ValueError('Reviewed worker lifecycle helper changed')
    return controller


def compose_helper():
    # Executable helpers must not run before their ownership/ancestry checks.
    global _HELPER
    controller = trusted_sources()
    if _HELPER is None:
        for name in ('prepare_zentral_eval', 'test_live_zentral'):
            path = controller.with_name(name + '.py')
            module = types.ModuleType(name)
            module.__file__ = str(path)
            module.__package__ = ''
            sys.modules[name] = module
            # Execute the checked source itself, never a timestamp-valid .pyc.
            exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
        if module.COMMIT != COMMIT:
            raise ValueError('Runtime helper source revision changed')
        _HELPER = module
    return _HELPER


def state_path(root, relative, *, directory=False, nonempty=False):
    path = root / relative
    if path != path.resolve(strict=True) or not path.is_relative_to(root):
        raise ValueError('Backing data sentinel must stay inside its existing volume')
    if directory:
        if not path.is_dir() or (nonempty and next(path.iterdir(), None) is None):
            raise ValueError('Initialized backing directory missing')
    elif not path.is_file() or (nonempty and path.stat().st_size == 0):
        raise ValueError('Initialized backing file missing')
    return path


def check_postgres_data(root, image_environment, configured_environment):
    major, pgdata = image_environment.get('PG_MAJOR', ''), image_environment.get('PGDATA', '')
    if not re.fullmatch(r'[1-9][0-9]*', major) or any(configured_environment.get(k, v) != v for k, v in (('PG_MAJOR', major), ('PGDATA', pgdata))):
        raise ValueError('Pinned PostgreSQL data-directory configuration required')
    base, selected = PurePosixPath('/var/lib/postgresql'), PurePosixPath(pgdata)
    if not selected.is_relative_to(base) or '..' in selected.parts:
        raise ValueError('PostgreSQL data directory is outside its selected volume')
    directory = state_path(root, str(selected.relative_to(base)), directory=True)
    version = state_path(directory, 'PG_VERSION', nonempty=True)
    if version.stat().st_size > 16 or version.read_text().strip() != major:
        raise ValueError('Initialized PostgreSQL version mismatch')
    for name in ('global/pg_control', 'postgresql.conf', 'pg_hba.conf'):
        state_path(directory, name, nonempty=True)
    for name in ('base', 'pg_wal'):
        state_path(directory, name, directory=True)


def check_redis_data(root):
    directory = state_path(root, 'appendonlydir', directory=True)
    manifest = state_path(directory, 'appendonly.aof.manifest', nonempty=True)
    if manifest.stat().st_size > 65536:
        raise ValueError('Redis append-only manifest exceeds bound')
    lines = manifest.read_text().splitlines()
    if not lines or len(lines) > 100:
        raise ValueError('Initialized Redis append-only manifest required')
    kinds = []
    for line in lines:
        match = re.fullmatch(r'file (appendonly\.aof\.[0-9]+\.(?:base\.(?:rdb|aof)|incr\.aof)) seq [0-9]+ type ([bih])', line)
        if not match:
            raise ValueError('Redis append-only manifest format changed')
        name, kind = match.groups()
        if kind != 'h':
            state_path(directory, name, nonempty=kind == 'b')
            kinds.append(kind)
    if kinds.count('b') != 1 or 'i' not in kinds:
        raise ValueError('Redis base/incremental backing data missing')


def bundle(compose):
    path, digest = compose_helper().validate_compose(checked_path(compose, private=True))
    data = json.loads(path.read_text())
    if (data['volumes'] != {name: {} for name in ('postgres_data', 'redis_data', 'rabbitmq_data', 'elasticsearch_data', 'media_data', 'elasticsearch_snapshots')} or
            any(sorted(data['services'][name].get('volumes', [])) != sorted(expected) for name, expected in VOLUMES.items())):
        raise ValueError('Exact per-service persistent data/configuration mounts required')
    if data['services']['elastic'].get('environment', {}).get('path.repo') != '/mnt/azd-santa-snapshots':
        raise ValueError('Fixed native snapshot repository required')
    if data['services']['rabbitmq'].get('hostname') != 'rabbitmq':
        raise ValueError('Pinned broker node identity required')
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
    trusted_sources()
    if set(policy_hashes) != set(POLICIES) or any(not re.fullmatch(r'[a-f0-9]{64}', x) for x in policy_hashes.values()):
        raise ValueError('Exact installed security-module hashes required')
    path, data, files = bundle(compose)
    destination = Path(destination)
    if (not destination.is_absolute() or destination.parent != destination.parent.resolve(strict=True) or
            destination.parent != path.parent or destination.name != 'runtime-service'):
        raise ValueError('Service control directory must be local to its selected runtime')
    manifest = dict(scope='private-initialized-runtime-service-v1', compose=str(path),
                    project=data['name'], files=files, policy_hashes=policy_hashes, worker_hashes=WORKER_HASHES,
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
    trusted_sources()
    path = checked_path(path, private=True)
    raw = path.read_bytes()
    if not re.fullmatch(r'[a-f0-9]{64}', expected) or sha(raw) != expected:
        raise ValueError('Selected service manifest changed')
    manifest = json.loads(raw)
    keys = {'scope', 'compose', 'project', 'files', 'policy_hashes', 'source_commit', 'controller_sha256', 'helpers_sha256', 'worker_hashes'}
    if set(manifest) != keys or manifest['scope'] != 'private-initialized-runtime-service-v1' or manifest['source_commit'] != COMMIT:
        raise ValueError('Unrecognized runtime service manifest')
    if manifest['controller_sha256'] != sha(Path(__file__).read_bytes()):
        raise ValueError('Selected runtime controller changed')
    if manifest['helpers_sha256'] != {name: sha(Path(__file__).with_name(name).read_bytes()) for name in HELPERS}:
        raise ValueError('Selected runtime validation helpers changed')
    if manifest['worker_hashes'] != WORKER_HASHES:
        raise ValueError('Selected worker lifecycle source changed')
    compose, data, files = bundle(manifest['compose'])
    if files != manifest['files'] or data['name'] != manifest['project'] or path.parent != compose.parent / 'runtime-service':
        raise ValueError('Selected runtime/configuration changed')
    if set(manifest['policy_hashes']) != set(POLICIES) or any(not re.fullmatch(r'[a-f0-9]{64}', x) for x in manifest['policy_hashes'].values()):
        raise ValueError('Invalid installed-module binding')
    return manifest, data


def unit_text(script, manifest, digest):
    # No shell evaluation in systemd; still reject its specifiers and word syntax.
    for value in (str(script), str(manifest)):
        if (not re.fullmatch(r'/[A-Za-z0-9/_.-]+', value) or
                not PurePosixPath(value).is_relative_to(PurePosixPath(ROOT.as_posix())) or
                '..' in PurePosixPath(value).parts):
            raise ValueError('Safe absolute service paths required')
    if not re.fullmatch(r'[a-f0-9]{64}', digest):
        raise ValueError('Exact service manifest digest required')
    return f'''[Unit]
Description=Private Santa initialized runtime
Requires=docker.service
PartOf=docker.service
After=docker.service network-online.target
Wants=network-online.target
StartLimitIntervalSec=1800
StartLimitBurst=3

[Service]
Type=notify
NotifyAccess=main
ExecStart=/usr/bin/python3 -I {script} run --manifest {manifest} --sha256 {digest}
Restart=on-failure
RestartSec=30
TimeoutStartSec=420
TimeoutStopSec=3600
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true

[Install]
WantedBy=multi-user.target
'''


def install_unit(manifest, digest, *, enable_now=False):
    controller = trusted_sources()
    load_manifest(manifest, digest)
    raw = unit_text(controller, Path(manifest), digest).encode()
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
        config_directory = self.evidence / 'docker-config'
        config_directory.mkdir(mode=0o700)
        self.environment['DOCKER_CONFIG'] = str(config_directory)
        self.ids = []
        self.cleanup_ids = ()  # Inspection alone never authorizes container stops.
        self.images = {}
        self.rendered = None
        self.stopping = False
        self.phase = 'prepared'
        self.helpers = set()
        self.supervisor_lock_fd = None
        self.backup_ready = False
        self._admission_capability = None

    def backup_module(self):
        path = trusted_sources().with_name('cold_backup.py')
        if sha(path.read_bytes()) != self.binding['helpers_sha256']['cold_backup.py']:
            raise ValueError('Bound backup source changed')
        module = types.ModuleType('runtime_backup'); module.__file__ = str(path)
        exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
        return module

    def ensure_running(self):
        if self.stopping:
            raise Cancelled('Runtime startup cancelled')

    def call(self, label, args, *, timeout=30, allowed_failure=False, record=True, allow_stopping=False):
        if not allow_stopping:
            self.ensure_running()
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
        if not allow_stopping:
            self.ensure_running()
        return result

    def inspect(self, *, running, record=True):
        ids = self.ids or self.call('container-selection', DOCKER + ['ps', '--all', '--quiet', '--no-trunc',
                    '--filter', 'label=com.docker.compose.project=' + self.project,
                    '--filter', 'label=com.docker.compose.oneoff=False'], record=record).stdout.split()
        if len(ids) != 7 or any(not re.fullmatch(r'[a-f0-9]{64}', x) for x in ids):
            raise ValueError('Exactly seven previously initialized containers required')
        if self.ids and set(ids) != set(self.ids):
            raise ValueError('Selected container identity changed')
        rows = json.loads(self.call('container-inspection', DOCKER + ['inspect', *ids], record=record).stdout)
        if len(rows) != 7 or {row['Id'] for row in rows} != set(ids):
            raise ValueError('Selected container identity changed')
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
                    (config.get('User') or '') != (image['Config'].get('User') or '') or host.get('Privileged') or
                    host.get('CapAdd') or host.get('PidMode') or host.get('Devices') or host.get('PublishAllPorts') or
                    host.get('SecurityOpt') != ['no-new-privileges:true']):
                raise ValueError('Container command or privilege boundary changed')
            if 'hostname' in self.data['services'][name] and config.get('Hostname') != self.data['services'][name]['hostname']:
                raise ValueError('Container node identity changed')
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
        while True:
            self.ensure_running()
            ready = check()
            self.ensure_running()
            if ready:
                return
            if time.monotonic() >= deadline:
                raise RuntimeError('Private runtime readiness failed: ' + label)
            time.sleep(2)

    def start_ids(self, label, names):
        self.ensure_running()
        load_manifest(self.manifest_path, self.digest)
        selected = self.inspect(running=False)
        self.call(label, DOCKER + ['start', *(selected[name] for name in names)], timeout=120)

    def oneoff(self, label, args, timeout=60):
        self.ensure_running()
        load_manifest(self.manifest_path, self.digest)
        self.inspect(running=False)
        name = 'santa-runtime-check-' + uuid.uuid4().hex
        self.helpers.add(name)
        try:
            return self.call(label, self.command + ['run', '--rm', '--no-deps', '--name', name,
                            '--entrypoint', 'python', 'web', *args], timeout=timeout)
        finally:
            self.stop_helpers()

    def python(self, label, code, timeout=60):
        return self.oneoff(label, ['server/manage.py', 'shell', '--no-imports', '-c', code],timeout=timeout)

    def backing_data(self):
        # Check real entrypoint data sentinels before starting dependencies.
        docker_root = Path(self.call('docker-root', DOCKER + ['info', '--format', '{{.DockerRootDir}}']).stdout.strip())
        if not docker_root.is_absolute() or docker_root != docker_root.resolve(strict=True):
            raise ValueError('Canonical local Docker data directory required')
        volumes = {}
        for name in self.data['volumes']:
            full_name = self.project + '_' + name
            volume = json.loads(self.call('volume-inspection', DOCKER + ['volume', 'inspect', full_name]).stdout)[0]
            expected = docker_root / 'volumes' / full_name / '_data'
            if (volume.get('Name') != full_name or volume.get('Driver') != 'local' or volume.get('Options') or
                    volume.get('Labels', {}).get('com.docker.compose.project') != self.project or
                    volume.get('Mountpoint') != str(expected) or expected != expected.resolve(strict=True) or not expected.is_dir()):
                raise ValueError('Existing volume ownership mismatch')
            volumes[name] = expected
        db_image = self.images[self.data['services']['db']['image']]
        check_postgres_data(volumes['postgres_data'], dict(x.split('=', 1) for x in db_image['Config']['Env']),
                            self.rendered['services']['db'].get('environment', {}))
        check_redis_data(volumes['redis_data'])
        state_path(volumes['rabbitmq_data'], '.erlang.cookie', nonempty=True)
        state_path(volumes['rabbitmq_data'], 'mnesia/rabbit@rabbitmq', directory=True, nonempty=True)
        elastic = volumes['elasticsearch_data']
        metadata = [p for pattern in ('_state/node-*.st', 'nodes/0/_state/node-*.st') for p in elastic.glob(pattern)]
        if not 1 <= len(metadata) <= 8:
            raise ValueError('Existing search-node metadata missing')
        for path in metadata:
            state_path(elastic, path.relative_to(elastic), nonempty=True)

    def container_generation(self, selected):
        """Require the separately produced original generation, never adopt labels."""
        path = checked_path(self.manifest_path.parent / 'container-generation.json', private=True)
        value = json.loads(path.read_bytes())
        keys = {'scope', 'manifest_sha256', 'project', 'image_id', 'generation', 'container_ids'}
        if (set(value) != keys or value['scope'] != 'private-runtime-container-generation-v1'
                or value['manifest_sha256'] != self.digest or value['project'] != self.project
                or value['image_id'] != self.data['services']['web']['image']
                or not re.fullmatch(r'[a-f0-9]{32}', value['generation'])
                or set(value['container_ids']) != set((*APPS, *DEPENDENCIES))
                or any(not re.fullmatch(r'[a-f0-9]{64}', cid) for cid in value['container_ids'].values())
                or len(set(value['container_ids'].values())) != 7
                or value['container_ids'] != selected):
            raise ValueError('Original admission container generation differs or is missing')
        return value

    def bind_admission_fresh(self):
        """Machine-produce a first generation before any app has ever started."""
        import fcntl
        with (self.manifest_path.parent / 'supervisor.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            target = self.manifest_path.parent / 'container-generation.json'
            if target.exists() or target.is_symlink() or UNIT.exists() or UNIT.is_symlink():
                raise ValueError('Fresh binding requires no existing anchor or installed runtime unit')
            selected = self.inspect(running=False)
            ids = list(selected.values())
            rows = json.loads(self.call('admission-fresh-generation', DOCKER + ['inspect', *ids]).stdout)
            if len(rows) != 7 or {r['Id'] for r in rows} != set(ids):
                raise ValueError('Exact seven-container generation required')
            states = {r['Id']: r['State'] for r in rows}
            for name, cid in selected.items():
                state = states[cid]
                if (state.get('Paused') is not False or state.get('Restarting') is not False
                        or state.get('OOMKilled') is not False):
                    raise ValueError('Stable generation required')
                if name in APPS:
                    if (state.get('Status') != 'created' or state.get('Running') is not False
                            or state.get('Pid') != 0 or not state.get('StartedAt', '').startswith('0001-')):
                        raise ValueError('Fresh generation requires all exact apps never started')
                elif (state.get('Status') != 'running' or state.get('Running') is not True
                        or type(state.get('Pid')) is not int or state['Pid'] <= 0
                        or not state.get('StartedAt') or state['StartedAt'].startswith('0001-')):
                    raise ValueError('Initialized dependencies must be running')
            self.backing_data()
            load_manifest(self.manifest_path, self.digest)
            if self.inspect(running=False) != selected:
                raise ValueError('Fresh container generation changed during binding')
            private_write(target, dict(scope='private-runtime-container-generation-v1',
                manifest_sha256=self.digest, project=self.project, image_id=self.data['services']['web']['image'],
                generation=secrets.token_hex(16), container_ids=selected))
            sync_directory(target.parent)
            return target

    def start(self):
        self.ensure_running()
        request = self.manifest_path.parent / 'backup-request.json'
        if request.exists() or request.is_symlink():
            self.backup_module().startup_allowed(self)
        selected = self.inspect(running=False)
        generation = self.container_generation(selected)
        self.cleanup_ids = tuple(generation['container_ids'].values())
        # A deliberate hot start must close admission before inspecting stores.
        self.call('close-admission', DOCKER + ['stop', '--time', '30', *(selected[name] for name in APPS)], timeout=100)
        self.call('compose-config', self.command + ['config', '--quiet'])
        self.backing_data()
        if Path('/proc/sys/vm/max_map_count').read_text().strip() != '1048576':
            raise ValueError('Qualified Elasticsearch kernel prerequisite missing')
        self.start_ids('dependencies', DEPENDENCIES)
        database = self.rendered['services']['db']['environment']
        self.wait('database', lambda: self.call('database', self.command + ['exec', '-T', 'db', 'pg_isready', '-U', database['POSTGRES_USER'], '-d', database['POSTGRES_DB']], allowed_failure=True).returncode == 0)
        code = 'from pathlib import Path; import hashlib; '
        for name, file in POLICIES.items():
            code += f"assert hashlib.sha256(Path('/zentral/server/{file}').read_bytes()).hexdigest()=={self.binding['policy_hashes'][name]!r}; "
        for file, digest in WORKER_HASHES.items():
            code += f"assert hashlib.sha256(Path('/zentral/server/{file}').read_bytes()).hexdigest()=={digest!r}; "
        code += "from django.db import connection; from django.db.migrations.executor import MigrationExecutor; e=MigrationExecutor(connection); assert not e.migration_plan(e.loader.graph.leaf_nodes()); "
        code += "from zentral.core.stores.models import Store; assert Store.objects.count()==1; s=Store.objects.get(provisioning_uid='elasticsearch'); assert s.backend=='ELASTICSEARCH' and s.admin_console"
        self.python('source-schema-store', code)
        self.oneoff('security-store', ['server/manage.py', 'operator_security_store', 'check'])
        self._recover_admission_locked()
        self.python('sync-admission', 'from azd_santa_admission import check; check(require_empty=True)')
        self.ensure_running()
        self.python('search', "import json,time,urllib.request; o=urllib.request.build_opener(urllib.request.ProxyHandler({})); deadline=time.monotonic()+45\nwhile True:\n try:\n  r=json.load(o.open('http://elastic:9200/_cluster/health',timeout=3)); assert r['status'] in ('yellow','green'); break\n except Exception:\n  if time.monotonic()>deadline: raise RuntimeError('Search not ready') from None\n  time.sleep(2)")
        self.start_ids('workers', ('workers', 'celery'))

        def consumers():
            result = self.call('queues', self.command + ['exec', '-T', 'rabbitmq', 'rabbitmqctl', 'list_queues', 'name', 'consumers', '--formatter', 'json'], allowed_failure=True)
            if result.returncode:
                return False
            rows = json.loads(result.stdout)
            return all(any(q['name'] == name and q['consumers'] > 0 for q in rows) for name in ('store_events_Elasticsearch', 'enrich_events', 'process_events'))
        self.wait('consumers', consumers)
        self.start_ids('listener', ('web',))
        self.inspect(running=True)
        # A running PID is not an HTTP readiness receipt.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), compose_helper().NoRedirect())
        def http_ready():
            try:
                with opener.open('http://127.0.0.1:8000/accounts/login/', timeout=3) as response:
                    return response.status == 200
            except Exception:
                return False
        self.wait('http', http_ready, seconds=45)
        self.ensure_running()
        print('SANTA_PRIVATE_RUNTIME_READY', flush=True)

    @staticmethod
    def _admission_json(result):
        prefix='SANTA_ADMISSION_JSON:'
        lines=[line[len(prefix):] for line in result.stdout.splitlines() if line.startswith(prefix)]
        if len(lines)!=1 or len(lines[0])>4096:
            raise ValueError('Admission recovery readback is incomplete')
        return json.loads(lines[0])

    def _admission_call(self,label,statement,timeout=15):
        code='from pathlib import Path;import hashlib,json; '
        code+=f"assert hashlib.sha256(Path('/zentral/server/azd_santa_admission.py').read_bytes()).hexdigest()=={self.binding['policy_hashes']['admission']!r}; "
        code+='from azd_santa_admission import state,reconcile; '+statement
        return self._admission_json(self.python(label,code,timeout=timeout))

    def _runtime_database_quiet(self,timeout):
        # Same-role activity is visible without pg_monitor or owner credentials.
        # Never cancel/terminate another backend or assume dead Python cancelled SQL.
        code='''import json
from django.db import connection
from azd_santa_database_roles import check_runtime
check_runtime()
with connection.cursor() as cursor:
 cursor.execute('SELECT pg_backend_pid(),current_user,current_database()')
 pid,role,database=cursor.fetchone()
 assert type(pid) is int and pid>0 and role=='zentral_runtime' and database
 cursor.execute('SELECT pid,usename,datname,state,backend_start FROM pg_stat_activity WHERE pid=pg_backend_pid()')
 own=cursor.fetchall()
 assert len(own)==1 and own[0][:4]==(pid,role,database,'active') and own[0][4] is not None
 cursor.execute('SELECT pid,state,backend_start FROM pg_stat_activity WHERE usename=current_user AND datname=current_database() AND pid<>pg_backend_pid()')
 other=cursor.fetchall()
 assert all(type(row[0]) is int and row[0]>0 and row[1] is not None and row[2] is not None for row in other)
print('SANTA_ADMISSION_JSON:'+json.dumps({'quiet':not other}))
'''
        result=self._admission_json(self.python('admission-database-quiescence',code,timeout=timeout))
        if set(result)!={'quiet'} or type(result['quiet']) is not bool:
            raise ValueError('Runtime database visibility is unknown')
        return result['quiet']

    def _recover_admission_locked(self,*,initialize_missing=False):
        """Automatic existing-state recovery; caller already owns supervisor flock."""
        if type(initialize_missing) is not bool:
            raise ValueError('Explicit admission recovery mode required')
        selected=self.inspect(running=False);generation=self.container_generation(selected)
        cap=_AdmissionQuiescence(self,selected,generation,_ADMISSION_KEY)
        self._admission_capability=cap
        try:
            rows=cap.verify()
            deadline=time.monotonic()+60
            while True:
                cap.verify()
                if time.monotonic()>=deadline:raise TimeoutError('Runtime database did not quiesce')
                if self._runtime_database_quiet(timeout=min(15,max(1,deadline-time.monotonic()))):
                    if time.monotonic()>=deadline:raise TimeoutError('Runtime database quiescence deadline exceeded')
                    break
                if time.monotonic()>=deadline:raise TimeoutError('Runtime database did not quiesce')
                time.sleep(min(2,max(0,deadline-time.monotonic())))
            cap.verify()
            before=self._admission_call('admission-state',f"print('SANTA_ADMISSION_JSON:'+json.dumps(state(allow_missing={initialize_missing!r})))")
            if (set(before)!={'generation','active'} or type(before['active']) is not int or not 0<=before['active']<=1
                    or (before['generation'] is None and not initialize_missing)
                    or (before['generation'] is not None and not re.fullmatch(r'[a-f0-9]{32}',before['generation']))):
                raise ValueError('Invalid admission recovery state')
            if initialize_missing and before['generation'] is not None:
                raise ValueError('Existing admission state is not a missing-state migration')
            target=secrets.token_hex(16)
            if target==before['generation']:raise ValueError('A fresh admission recovery fence is required')
            intent=dict(scope='private-quiesced-admission-recovery-v1',manifest_sha256=self.digest,
                generation=generation['generation'],container_ids=selected,app_states=rows,
                expected_generation=before['generation'],target_generation=target,initialize_missing=initialize_missing,
                runtime_database_no_other_sessions=True)
            private_write(self.evidence/'admission-recovery-intent.json',intent);sync_directory(self.evidence)
            cap.verify()
            unknown=False
            try:
                self._admission_call('admission-recovery-submit',
                    f"print('SANTA_ADMISSION_JSON:'+json.dumps(reconcile(expected_generation={before['generation']!r},generation={target!r},initialize_missing={initialize_missing!r})))")
            except Exception:
                self.ensure_running();unknown=True  # Never submit a second EVAL.
            deadline=time.monotonic()+30
            while True:
                cap.verify()
                # Read-only confirmation of this exact transition; a timed-out
                # old job cannot clear a later generation or its live permit.
                after=self._admission_call('admission-recovery-observe',"print('SANTA_ADMISSION_JSON:'+json.dumps(state()))",
                                           timeout=min(15,max(1,deadline-time.monotonic())))
                if (set(after)!={'generation','active'} or type(after['active']) is not int or not 0<=after['active']<=1
                        or after['generation'] not in (before['generation'],target) or time.monotonic()>=deadline
                        or (after['generation']==target and after['active']!=0)):
                    raise ValueError('Admission recovery outcome requires inspection')
                if after=={'generation':target,'active':0}:break
                time.sleep(min(2,max(0,deadline-time.monotonic())))
            cap.verify()
            private_write(self.evidence/'admission-reconciled.json',dict(
                scope='proven-quiesced-sync-admission',app_ids=[selected[name] for name in APPS],
                initialize_missing=initialize_missing,manifest_sha256=self.digest,generation=generation['generation'],
                admission_generation=target,submission_was_unknown=unknown))
            sync_directory(self.evidence)
        finally:self._admission_capability=None

    def reconcile_admission(self, *, initialize_missing=False):
        """Explicit wrapper uses the same fenced recovery, with one lock only."""
        import fcntl
        with (self.manifest_path.parent/'supervisor.lock').open('a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            previous=getattr(self,'supervisor_lock_fd',None);self.supervisor_lock_fd=lock.fileno()
            try:
                request=self.manifest_path.parent/'backup-request.json'
                if request.exists() or request.is_symlink():self.backup_module().startup_allowed(self)
                self._recover_admission_locked(initialize_missing=initialize_missing)
            finally:self.supervisor_lock_fd=previous

    def stop_helpers(self):
        for name in list(self.helpers):
            result = self.call('helper-inspection', DOCKER + ['inspect', name], allowed_failure=True, allow_stopping=True)
            if result.returncode == 0:
                rows = json.loads(result.stdout)
                if len(rows) != 1:
                    raise ValueError('Ambiguous startup helper')
                row = rows[0]
                labels = row['Config'].get('Labels', {})
                if (row['Name'] != '/' + name or labels.get('com.docker.compose.project') != self.project or
                        labels.get('com.docker.compose.service') != 'web' or row['Image'] != self.data['services']['web']['image']):
                    raise ValueError('Startup helper ownership mismatch')
                self.call('helper-stop', DOCKER + ['stop', '--time', '5', row['Id']], timeout=15, allow_stopping=True)
            else:
                # Confirm absence with a successful daemon inventory, rather
                # than treating transport failure as completed helper cleanup.
                names = self.call('helper-inventory', DOCKER + ['ps', '--all', '--format', '{{.Names}}'], allow_stopping=True).stdout.splitlines()
                if name in names:
                    raise RuntimeError('Startup helper outcome requires inspection')
            self.helpers.remove(name)

    def stop(self):
        captured = False
        try:
            self.stop_helpers()
            if (getattr(self, 'stopping', False) and getattr(self, 'backup_ready', False)
                    and getattr(self, 'supervisor_lock_fd', None) is not None):
                request = self.manifest_path.parent / 'backup-request.json'
                if request.exists() or request.is_symlink():
                    captured = self.backup_module().stop_capture(self)
        finally:
            authorized = getattr(self, 'cleanup_ids', ())
            if authorized and not captured:
                current = self.call('cleanup-selection', DOCKER + ['ps', '--all', '--quiet', '--no-trunc'], allow_stopping=True).stdout.split()
                selected = [cid for cid in authorized if cid in current]
                if selected:
                    self.call('stop', DOCKER + ['stop', '--time', '30', *selected], timeout=100, allow_stopping=True)

    def supervise(self):
        import fcntl
        with (self.manifest_path.parent / 'supervisor.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.supervisor_lock_fd = lock.fileno()
            def stopping(*_):
                self.stopping = True
            signal.signal(signal.SIGTERM, stopping)
            signal.signal(signal.SIGINT, stopping)
            try:
                self.start()
                self.backup_ready = True
                self.ensure_running()
                address = os.environ.get('NOTIFY_SOCKET')
                if address:
                    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
                        sock.sendto(b'READY=1', '\0' + address[1:] if address.startswith('@') else address)
                while not self.stopping:
                    time.sleep(5)
                    self.phase = 'binding-check'
                    load_manifest(self.manifest_path, self.digest)
                    self.inspect(running=True, record=False)
            except Cancelled:
                private_write(self.evidence / 'cancelled.json', dict(phase=self.phase, cancelled=True))
            except Exception as error:
                private_write(self.evidence / 'failure.json', dict(phase=self.phase,
                              error_type=type(error).__name__, detail=str(error)))
                raise
            finally:
                try: self.stop()
                finally: self.supervisor_lock_fd = None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='operation', required=True)
    prepare_parser = commands.add_parser('prepare')
    prepare_parser.add_argument('--compose', required=True)
    prepare_parser.add_argument('--destination', required=True)
    for name in POLICIES:
        prepare_parser.add_argument('--' + name + '-sha256', required=True)
    for name in ('run', 'unit', 'install', 'admission-reconcile', 'admission-bind-fresh', 'backup', 'backup-resume'):
        command = commands.add_parser(name)
        command.add_argument('--manifest', required=True)
        command.add_argument('--sha256', required=True)
        if name == 'admission-reconcile':
            command.add_argument('--initialize-missing', action='store_true')
        if name == 'install':
            command.add_argument('--enable-now', action='store_true')
        if name == 'backup':
            for field in ('vm-id', 'vm-instance-id', 'recipient-public-der', 'destination'):
                command.add_argument('--' + field, required=True)
            command.add_argument('--seconds', type=int, default=1800)
            command.add_argument('--maximum-bytes', type=int, default=8*1024**3)
            command.add_argument('--maximum-files', type=int, default=100000)
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
    elif args.operation == 'admission-bind-fresh':
        print(Runtime(args.manifest, args.sha256).bind_admission_fresh())
    elif args.operation == 'admission-reconcile':
        Runtime(args.manifest, args.sha256).reconcile_admission(initialize_missing=args.initialize_missing)
    elif args.operation in ('backup', 'backup-resume'):
        runtime = Runtime(args.manifest, args.sha256)
        backup = runtime.backup_module()
        if args.operation == 'backup':
            recipient = checked_path(args.recipient_public_der)
            if recipient.stat().st_size > 1024: raise ValueError('Bounded public recipient required')
            public = recipient.read_bytes()
            backup.request_backup(runtime, {'VmId': args.vm_id, 'VmInstanceId': args.vm_instance_id}, public,
                                  args.destination, seconds=args.seconds, maximum=args.maximum_bytes, maximum_files=args.maximum_files)
        else:
            backup.resume_original(runtime)
    else:
        Runtime(args.manifest, args.sha256).supervise()


if __name__ == '__main__':
    try:
        main()
    except Exception:
        # Raw Docker/Django failures can contain secrets. Details are private.
        print('Private runtime service failed; inspect retained private evidence.', file=sys.stderr)
        raise SystemExit(1)
