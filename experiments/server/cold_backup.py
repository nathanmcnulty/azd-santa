"""Original Unlicense cold encrypted capture; NOT restore or current authority.

Linux/root qualification component. The selected binding must come from a
trusted machine producer; this input contract does not attest its own origin.
Standalone capture never mutates containers. Explicit controller-owned
maintenance closes/drains/stops; completion-gated resume starts originals only.
No restore, initialization, container/volume deletion or automatic replay.
"""
import sys
if __name__ == '__main__' and not sys.flags.isolated:
    raise SystemExit('Use python3 -I for privileged backup.')

import argparse
import base64
from contextlib import contextmanager
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import signal
import stat
import struct
import subprocess
import tarfile
import time
import types
import urllib.request
import uuid

ROOT = Path('/var/lib/azd-santa-qualification')
CONTROLLER_SHA = 'a4aa813dd792dcb941ebfae71562b7bcf24578f2b6b41a67f82c5ed40058527f'
MAGIC = b'AZDSANTABACKUP1\n'
CHUNK = 1024 * 1024
HEX = r'[a-f0-9]{64}'
_MAINTENANCE_KEY = object()
STATE_FIELDS = ('Status', 'Running', 'Paused', 'Restarting', 'OOMKilled', 'Pid', 'ExitCode', 'Error', 'StartedAt', 'FinishedAt')


def need(value):
    if not value: raise ValueError('Cold backup boundary failed')


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result); result[key] = value
    return result


def checked_file(path, *, private=False, limit=1024 * 1024, within_root=True):
    path = Path(path)
    need(path.is_absolute() and path == path.resolve(strict=True) and (not within_root or path.is_relative_to(ROOT)))
    for directory in (path.parent, *path.parent.parents):
        info = directory.stat()
        need(info.st_uid == 0 and not info.st_mode & 0o022)
    info = path.stat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & (0o077 if private else 0o022)
         and info.st_size <= limit)
    return path


def load_selection(path, expected):
    raw = checked_file(path, private=True).read_bytes()
    need(re.fullmatch(HEX, expected) and digest(raw) == expected)
    value = json.loads(raw, object_pairs_hook=unique)
    need(set(value) == {'scope', 'target', 'runtime_manifest', 'controller_sha256', 'backup_program_sha256', 'recipient_sha256', 'containers', 'generation_sha256', 'maintenance_sha256', 'native_snapshot'})
    need(value['scope'] == 'azd-santa-native-cold-backup-selection-v1' and value['controller_sha256'] == CONTROLLER_SHA
         and value['backup_program_sha256'] == digest(Path(__file__).read_bytes()))
    need(re.fullmatch(HEX, value['recipient_sha256']))
    need(re.fullmatch(HEX, value['generation_sha256']) and re.fullmatch(HEX, value['maintenance_sha256'])
         and set(value['native_snapshot']) == {'path', 'sha256', 'program_sha256'}
         and all(re.fullmatch(HEX, value['native_snapshot'][k]) for k in ('sha256', 'program_sha256')))
    need(set(value['target']) == {'VmId', 'VmInstanceId'})
    guid = r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}'
    need(re.fullmatch(guid, value['target']['VmInstanceId']))
    need(re.fullmatch('/subscriptions/' + guid + r'/resourceGroups/rg-azd-santa-vm-[a-z0-9-]{2,32}/providers/Microsoft.Compute/virtualMachines/vm-santa-lab', value['target']['VmId']))
    need(set(value['runtime_manifest']) == {'path', 'sha256'} and re.fullmatch(HEX, value['runtime_manifest']['sha256']))
    need(set(value['containers']) == {'db', 'redis', 'rabbitmq', 'elastic', 'web', 'workers', 'celery'}
         and all(re.fullmatch(HEX, item) for item in value['containers'].values())
         and len(set(value['containers'].values())) == 7)
    return value


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs): return None


def host_identity(target):
    guid=r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}'
    need(set(target)=={'VmId','VmInstanceId'} and re.fullmatch(guid,target['VmInstanceId'])
         and re.fullmatch('/subscriptions/'+guid+r'/resourceGroups/rg-azd-santa-vm-[a-z0-9-]{2,32}/providers/Microsoft.Compute/virtualMachines/vm-santa-lab',target['VmId']))
    request = urllib.request.Request('http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01', headers={'Metadata': 'true'})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(request, timeout=3) as response: raw = response.read(65537)
    need(len(raw) <= 65536)
    value = json.loads(raw, object_pairs_hook=unique)
    need(value['resourceId'].lower() == target['VmId'].lower() and value['vmId'].lower() == target['VmInstanceId'])
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    need(re.fullmatch(r'[a-f0-9-]{36}', boot))
    return {**target, 'boot_id': boot}


def command(args, environment, timeout=30, allowed_failure=False):
    """Bound both command output and time; never print Docker/secret diagnostics."""
    process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment)
    buffers = {process.stdout: bytearray(), process.stderr: bytearray()}
    end = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            for pipe in buffers: selector.register(pipe, selectors.EVENT_READ)
            while selector.get_map():
                need(time.monotonic() < end)
                for key, _ in selector.select(min(0.2, max(0, end - time.monotonic()))):
                    raw = os.read(key.fileobj.fileno(), 65536)
                    if not raw: selector.unregister(key.fileobj)
                    else:
                        buffers[key.fileobj].extend(raw)
                        need(sum(map(len, buffers.values())) <= 4 * CHUNK)
        code = process.wait(timeout=max(0.01, end - time.monotonic()))
        need(code == 0 or allowed_failure)
        return types.SimpleNamespace(stdout=bytes(buffers[process.stdout]).decode(), returncode=code)
    finally:
        if process.poll() is None:
            process.kill(); process.wait(timeout=5)
        for pipe in buffers: pipe.close()


def load_controller():
    path = checked_file(Path(__file__).absolute().with_name('runtime_service.py'))
    need(digest(path.read_bytes()) == CONTROLLER_SHA)
    module = types.ModuleType('backup_runtime'); module.__file__ = str(path)
    exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
    module.trusted_sources()
    return module


def cold_state(runtime, selected, volumes, capability=None):
    need(runtime.inspect(running=False, record=False) == selected)
    rows = json.loads(runtime.call('cold-inspect', runtime_module_docker(runtime) + ['inspect', *selected.values()]).stdout)
    need(len(rows) == 7 and {row['Id'] for row in rows} == set(selected.values()))
    for row in rows:
        state = row['State']
        name = next(name for name, cid in selected.items() if cid == row['Id'])
        valid_exit = state['ExitCode'] == 0
        if capability is not None:
            capability.verify(runtime, selected)
            need({k: state[k] for k in STATE_FIELDS} == capability.states[row['Id']])
            valid_exit = valid_exit or (name == 'elastic' and state['ExitCode'] == 143)
        need(state['Status'] == 'exited' and not state['Running'] and not state.get('Restarting')
             and not state.get('Paused') and not state.get('OOMKilled') and valid_exit
             and not state.get('Error') and state['StartedAt'][:4] != '0001' and state['FinishedAt'][:4] != '0001')
    unit = dict(line.split('=', 1) for line in runtime.call('unit-cold', ['systemctl', 'show', 'azd-santa-runtime.service',
        '--property=LoadState,ActiveState,SubState,Job']).stdout.splitlines() if '=' in line)
    if capability is None:
        need(unit == {'LoadState': 'loaded', 'ActiveState': 'inactive', 'SubState': 'dead', 'Job': ''})
    else:
        capability.verify(runtime, selected)
        need(unit['LoadState'] == 'loaded' and unit['ActiveState'] == 'deactivating'
             and unit['SubState'].startswith('stop') and unit['Job'])
        pid = runtime.call('maintenance-main-pid', ['systemctl', 'show', 'azd-santa-runtime.service', '--value', '--property=MainPID']).stdout.strip()
        need(pid == str(os.getpid()))
    ids = runtime.call('all-containers', runtime_module_docker(runtime) + ['ps', '--all', '--quiet', '--no-trunc']).stdout.split()
    need(len(ids) <= 256 and all(re.fullmatch(HEX, cid) for cid in ids) and set(selected.values()) <= set(ids))
    all_rows = json.loads(runtime.call('all-mounts', runtime_module_docker(runtime) + ['inspect', *ids]).stdout)
    need(len(all_rows) == len(ids) and {row['Id'] for row in all_rows} == set(ids))
    protected = [*volumes.values(), Path(runtime.binding['compose']).parent / 'conf']
    for row in all_rows:
        if row['Id'] in selected.values(): continue
        # Dedicated-host contract: no foreign running/paused/restarting
        # container, regardless of lexical mount path or bind/symlink aliases.
        need(row['State'].get('Running') is False and row['State'].get('Paused') is False
             and row['State'].get('Restarting') is False and row['State'].get('Pid') == 0)
        for mount in row['Mounts']:
            source = Path(mount['Source'])
            need(source.is_absolute())
            need(not any(source == root or source.is_relative_to(root) or root.is_relative_to(source) for root in protected))
    return {row['Id']: row['State'] for row in rows}


def parse_mountinfo(raw):
    need(len(raw) <= 4 * CHUNK)
    lines = raw.decode('utf-8', errors='strict').splitlines()
    need(0 < len(lines) <= 10000)
    result = []
    def unescape(value):
        need(not re.search(r'\\(?!040|011|012|134)', value))
        return re.sub(r'\\(040|011|012|134)', lambda m: chr(int(m[1], 8)), value)
    for line in lines:
        fields = line.split(); need(fields.count('-') == 1)
        separator = fields.index('-')
        need(separator >= 6 and len(fields) == separator + 4)
        need(all(re.fullmatch(r'[0-9]+', fields[i]) for i in (0, 1)) and re.fullmatch(r'[0-9]+:[0-9]+', fields[2]))
        root, point = (unescape(fields[i]) for i in (3, 4))
        need(all(PurePosixPath(p).is_absolute() and PurePosixPath(p).as_posix() == p and '..' not in PurePosixPath(p).parts for p in (root, point)))
        result.append(dict(id=int(fields[0]), parent=int(fields[1]), device=fields[2], root=root, point=point,
            options=fields[5], optional=fields[6:separator], filesystem=fields[separator+1],
            source=unescape(fields[separator+2]), super_options=fields[separator+3]))
    need(len({m['id'] for m in result}) == len(result))
    return result


def mount_bindings(paths, mounts):
    """Pure metadata check: selected trees cannot contain ANY mountpoint."""
    result = {}
    for name, value in paths.items():
        path = PurePosixPath(value)
        need(path.is_absolute() and '..' not in path.parts)
        covering = [m for m in mounts if path.is_relative_to(PurePosixPath(m['point']))]
        need(covering)
        depth = max(len(PurePosixPath(m['point']).parts) for m in covering)
        covering = [m for m in covering if len(PurePosixPath(m['point']).parts) == depth]
        need(len(covering) == 1)
        mount = covering[0]
        # A bind of a filesystem subtree has a non-root mountinfo root. No
        # overlay/network/tmpfs/subvolume or exact/nested selected mount support.
        need(mount['root'] == '/' and mount['filesystem'] in ('ext4', 'xfs') and mount['source'].startswith('/dev/'))
        need(not any(PurePosixPath(m['point']).is_relative_to(path) for m in mounts))
        result[name] = mount
    return result


def mount_snapshot(paths):
    with Path('/proc/self/mountinfo').open('rb') as stream: raw = stream.read(4 * CHUNK + 1)
    bindings = mount_bindings(paths, parse_mountinfo(raw))
    result = {}
    for name, path in paths.items():
        info = path.stat(); mount = bindings[name]
        need(f'{os.major(info.st_dev)}:{os.minor(info.st_dev)}' == mount['device'])
        result[name] = dict(mount=mount, device=info.st_dev, inode=info.st_ino)
    return result


def check_descriptor_mount(fd, expected):
    with Path('/proc/self/fdinfo/' + str(fd)).open('rb') as source: raw = source.read(8193)
    need(len(raw) <= 8192)
    ids = re.findall(rb'^mnt_id:\s+([0-9]+)$', raw, re.MULTILINE)
    info = os.fstat(fd)
    need(len(ids) == 1 and int(ids[0]) == expected['mount']['id'] and info.st_dev == expected['device'])


def runtime_module_docker(runtime):
    return runtime.command[:3]  # ['docker', '--host', 'unix:///var/run/docker.sock']


def volume_paths(runtime):
    docker = runtime_module_docker(runtime)
    root = Path(runtime.call('docker-root', docker + ['info', '--format', '{{.DockerRootDir}}']).stdout.strip())
    need(root.is_absolute() and root == root.resolve(strict=True))
    result = {}
    for name in runtime.data['volumes']:
        full = runtime.project + '_' + name
        rows = json.loads(runtime.call('volume', docker + ['volume', 'inspect', full]).stdout)
        need(len(rows) == 1); value = rows[0]
        path = root / 'volumes' / full / '_data'
        need(value['Name'] == full and value['Driver'] == 'local' and not value.get('Options')
             and value['Labels']['com.docker.compose.project'] == runtime.project
             and value['Mountpoint'] == str(path) and path == path.resolve(strict=True) and path.is_dir())
        result[name] = path
    return result


def verify_storage_snapshot(runtime, roots, volumes, mounts):
    # These exact initial identities, not a newly accepted volume map, must
    # survive the entire stream before its authentication tag is committed.
    need(volume_paths(runtime) == volumes)
    need(mount_snapshot(roots) == mounts)


def storage_fingerprint(runtime):
    volumes=volume_paths(runtime)
    return digest(encoded({'volumes':{k:str(v) for k,v in volumes.items()},'mounts':mount_snapshot(volumes)}))


def recipient_key(public_der):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    need(len(public_der) <= 1024)
    public = serialization.load_der_public_key(public_der)
    need(isinstance(public, rsa.RSAPublicKey) and public.key_size == 3072 and public.public_numbers().e == 65537
         and public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) == public_der)
    # API/backend preflight only. Selected OS package supplier/support is a
    # separate packaging gate; a version string alone is not security evidence.
    probe = Cipher(algorithms.AES256(os.urandom(32)), modes.GCM(os.urandom(12))).encryptor()
    probe.finalize()
    return public


class EncryptedSink:
    def __init__(self, stream, public_der, maximum, deadline):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        public = recipient_key(public_der)
        key, nonce = os.urandom(32), os.urandom(12)
        wrapped = public.encrypt(key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=MAGIC))
        self.header = encoded(dict(algorithm='RSA-OAEP-256+A256GCM', recipient_sha256=digest(public_der),
            nonce=base64.b64encode(nonce).decode(), wrapped_key=base64.b64encode(wrapped).decode()))
        self.encryptor = Cipher(algorithms.AES256(key), modes.GCM(nonce)).encryptor()
        self.aad = MAGIC + struct.pack('>I', len(self.header)) + self.header
        self.encryptor.authenticate_additional_data(self.aad)
        self.stream, self.maximum, self.deadline = stream, maximum, deadline
        self.hasher = hashlib.sha256(); self.total = 0; self.plain = 0
        self.output(self.aad)

    def output(self, data):
        need(time.monotonic() < self.deadline and self.total + len(data) <= self.maximum)
        self.stream.write(data); self.hasher.update(data); self.total += len(data)

    def write(self, data):
        need(len(data) <= CHUNK)
        self.output(self.encryptor.update(data)); self.plain += len(data)
        return len(data)

    def finish(self):
        self.output(self.encryptor.finalize()); self.output(self.encryptor.tag)


def signature(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)


@contextmanager
def directory_entries(path, before, expected):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        need(signature(os.fstat(fd)) == signature(before))
        if expected is not None: check_descriptor_mount(fd, expected)
        # Descriptor-relative traversal cannot switch into a newly overmounted
        # pathname between open and scandir.
        with os.scandir(fd) as entries: yield entries
        need(signature(os.fstat(fd)) == signature(before))
    finally: os.close(fd)


def archive(sink, roots, compatibility, maximum_files, mounts=None):
    """Stream ordinary files only; reject links/devices and concurrent changes."""
    count = 0
    def add_json(output, name, value):
        raw = encoded(value); need(len(raw) <= CHUNK)
        info = tarfile.TarInfo(name); info.size = len(raw); info.mode = 0o600
        output.addfile(info, io.BytesIO(raw))
    with tarfile.open(fileobj=sink, mode='w|', format=tarfile.PAX_FORMAT) as output:
        add_json(output, 'backup/compatibility.json', compatibility)
        def add(path, name, expected):
            nonlocal count
            count += 1; need(count <= maximum_files and len(name.encode()) <= 1024)
            before = path.lstat()
            need(not path.is_symlink() and (stat.S_ISDIR(before.st_mode) or stat.S_ISREG(before.st_mode)))
            need(stat.S_ISDIR(before.st_mode) or before.st_nlink == 1)
            info = tarfile.TarInfo(name); info.mode = stat.S_IMODE(before.st_mode)
            info.uid, info.gid, info.mtime = before.st_uid, before.st_gid, before.st_mtime
            if stat.S_ISDIR(before.st_mode):
                with directory_entries(path, before, expected) as entries:
                    info.type = tarfile.DIRTYPE; output.addfile(info)
                    for entry in entries: add(path / entry.name, name + '/' + entry.name, expected)
            else:
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
                with os.fdopen(fd, 'rb') as source:
                    need(signature(os.fstat(source.fileno())) == signature(before))
                    if expected is not None: check_descriptor_mount(source.fileno(), expected)
                    info.size = before.st_size; output.addfile(info, source)
                    need(signature(os.fstat(source.fileno())) == signature(before))
            need(signature(path.lstat()) == signature(before))
        for name, path in roots.items(): add(path, name, mounts[name] if mounts is not None else None)
        add_json(output, 'backup/capture.json', dict(entries=count,
            restore_admission='not_implemented', current_authority='not_established'))
    return count


def write_capture(destination, public_der, roots, compatibility, maximum, maximum_files, deadline, final_check, mounts=None):
    """Completion is exclusive and follows cold readback and GCM finalization."""
    output = destination / 'backup.sealed'
    with os.fdopen(os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'wb') as stream:
        sink = EncryptedSink(stream, public_der, maximum, deadline)
        entries = archive(sink, roots, compatibility, maximum_files, mounts)
        final_check()
        sink.finish(); stream.flush(); os.fsync(stream.fileno())
    fd = os.open(destination / 'complete.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(encoded(dict(scope='azd-santa-cold-backup-ciphertext-v1',
            ciphertext_sha256=sink.hasher.hexdigest(), ciphertext_bytes=sink.total,
            recipient_sha256=digest(public_der), entries=entries, restore_admission='not_implemented',
            current_authority='not_established', maintenance_sha256=compatibility['selection']['maintenance_sha256'],
            generation_sha256=compatibility['selection']['generation_sha256'])))
        stream.flush(); os.fsync(stream.fileno())
    directory = os.open(destination, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(directory)
    finally: os.close(directory)
    return output


def _capture_locked(runtime, service, selection, selection_path, public_der, destination, maximum, maximum_files, deadline, native, native_path, native_receipt, native_receipt_path, capability=None):
    manifest = selection['runtime_manifest']; path = Path(manifest['path'])
    # Coherent native-backup integration must supply the sixth volume
    # and the SINGLE admission/controller generation anchor. Legacy
    # five-volume controllers cannot produce a backup-success receipt.
    generation_path = checked_file(path.parent / 'container-generation.json', private=True)
    generation_raw = generation_path.read_bytes()
    need(digest(generation_raw) == selection['generation_sha256'])
    generation = json.loads(generation_raw, object_pairs_hook=unique)
    need(set(generation) == {'scope', 'manifest_sha256', 'project', 'image_id', 'generation', 'container_ids'}
         and generation['scope'] == 'private-runtime-container-generation-v1'
         and generation['manifest_sha256'] == manifest['sha256'] and generation['project'] == runtime.project
         and generation['container_ids'] == selection['containers'] and re.fullmatch(r'[a-f0-9]{32}', generation['generation'])
         and generation['image_id'] == runtime.data['services']['web']['image'])
    runtime.call = lambda label, args, timeout=30, **_: command(args, runtime.environment, timeout=min(timeout, max(0.01, deadline-time.monotonic())))
    unit = checked_file(service.UNIT, within_root=False)
    need(unit.read_bytes() == service.unit_text(Path(service.__file__), path, manifest['sha256']).encode())
    identity = host_identity(selection['target'])
    runtime.inspect(running=False, record=False)
    if capability is not None: need(storage_fingerprint(runtime)==capability.storage_sha)
    volumes = volume_paths(runtime)
    before = cold_state(runtime, selection['containers'], volumes, capability)
    runtime.backing_data()
    # postmaster.pid survives an unclean PostgreSQL stop; never bless it.
    db = runtime.images[runtime.data['services']['db']['image']]
    db_env = dict(item.split('=', 1) for item in db['Config']['Env'])
    pgdata = volumes['postgres_data'] / str(Path(db_env['PGDATA']).relative_to('/var/lib/postgresql'))
    need(not (pgdata / 'postmaster.pid').exists() and not (pgdata / 'postmaster.pid').is_symlink())
    roots = native.archive_roots(volumes, native_receipt, selection['maintenance_sha256'])
    operation=Path(selection_path).parent
    need(operation==path.parent/('backup-'+native_receipt['plan']['operation_id']) and native_receipt_path.parent==operation/'snapshot')
    request_path=checked_file(path.parent/'backup-request.json',private=True)
    need(digest(request_path.read_bytes())==selection['maintenance_sha256'])
    evidence={request_path,operation/'drain-complete.json',operation/'worker-stop-complete.json',operation/'stop-complete.json',
              operation/'snapshot/plan.json',operation/'snapshot/repository-intent.json',
              operation/'snapshot/snapshot-intent.json',operation/'snapshot/native-observed.json'}
    for file in evidence: checked_file(file,private=True)
    files = {Path(p) for p in runtime.binding['files']}
    files.update(evidence)
    conf = Path(runtime.binding['compose']).parent / 'conf'
    need(set(conf.iterdir()) == {conf / 'base.json'})
    files.update({path, Path(selection_path), Path(__file__).absolute(), Path(service.__file__), native_path, native_receipt_path, generation_path,
                  *(Path(service.__file__).with_name(name) for name in service.HELPERS),
                  Path(runtime.binding['compose']).parent / 'migration.env', unit})
    for index, file in enumerate(sorted(files)):
        checked_file(file, private=file.suffix == '.env' or file == Path(selection_path), within_root=file != unit)
        roots['control/' + str(index) + '/' + file.name] = file
    mounts = mount_snapshot(roots)
    control_hashes = {name: digest(file.read_bytes()) for name, file in roots.items() if name.startswith('control/')}
    destination = Path(destination)
    need(destination.is_absolute() and not destination.exists() and not destination.is_symlink()
         and destination.parent == destination.parent.resolve(strict=True))
    for parent in (destination.parent, *destination.parent.parents):
        info = parent.stat(); need(info.st_uid == 0 and not info.st_mode & 0o022)
    need(not any(destination.is_relative_to(root) for root in [*volumes.values(), path.parent.parent]))
    destination.mkdir(mode=0o700)
    compatibility = dict(scope='azd-santa-cold-backup-v1', selection=selection, host=identity,
        images={name: {'reference': data['image'], 'id': runtime.images[data['image']]['Id']}
                for name, data in runtime.data['services'].items()},
        postgres_major=db_env['PG_MAJOR'], rabbit_node='rabbit@rabbitmq', volumes={k:str(v) for k,v in volumes.items()},
        control_files={name:str(file) for name,file in roots.items() if name.startswith('control/')},
        control_files_sha256=control_hashes,
        mounts=mounts,
        elasticsearch_backup='native-filesystem-snapshot-repository', native_snapshot=native_receipt,
        selected_files_sha256=runtime.binding['files'], source_commit=service.COMMIT,
        crypto_version=__import__('cryptography').__version__,
        restore_admission='not_implemented', current_authority='not_established')
    def final_check():
        if capability is not None: need(storage_fingerprint(runtime)==capability.storage_sha)
        verify_storage_snapshot(runtime, roots, volumes, mounts)
        need(cold_state(runtime, selection['containers'], volumes, capability) == before)
        need(host_identity(selection['target']) == identity)
        service.load_manifest(path, manifest['sha256'])
        need(digest(generation_path.read_bytes()) == selection['generation_sha256'])
        need(control_hashes == {name: digest(file.read_bytes()) for name, file in roots.items() if name.startswith('control/')})
    return write_capture(destination, public_der, roots, compatibility, maximum, maximum_files, deadline, final_check, mounts)


def capture(selection_path, expected, public_der, destination, *, maximum=8 * 1024**3, maximum_files=100000, seconds=1800):
    need(sys.platform == 'linux' and os.geteuid() == 0)
    need(type(maximum) is int and CHUNK <= maximum <= 32 * 1024**3
         and type(maximum_files) is int and 1 <= maximum_files <= 1000000 and type(seconds) is int and 1 <= seconds <= 7200)
    selection = load_selection(selection_path, expected)
    need(digest(public_der) == selection['recipient_sha256'])
    recipient_key(public_der)  # Verified prerequisite before output or Docker reads.
    service = load_controller()
    native_path = checked_file(Path(__file__).absolute().with_name('native_snapshot.py'))
    need(digest(native_path.read_bytes()) == selection['native_snapshot']['program_sha256'])
    native = types.ModuleType('backup_native'); native.__file__ = str(native_path)
    exec(compile(native_path.read_bytes(), str(native_path), 'exec'), native.__dict__)
    native_receipt_path = checked_file(selection['native_snapshot']['path'], private=True)
    native_raw = native_receipt_path.read_bytes()
    need(digest(native_raw) == selection['native_snapshot']['sha256'])
    native_receipt = json.loads(native_raw, object_pairs_hook=unique)
    manifest = selection['runtime_manifest']
    path = service.checked_path(manifest['path'], private=True)
    lock_path = path.parent / 'supervisor.lock'
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    import fcntl
    with os.fdopen(fd, 'r+b') as lock:
        need(lock_path == lock_path.resolve(strict=True) and os.fstat(lock.fileno()).st_uid == 0
             and not os.fstat(lock.fileno()).st_mode & 0o077)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        deadline = time.monotonic() + seconds
        def expired(*_): raise TimeoutError('Cold backup deadline exceeded')
        prior = signal.signal(signal.SIGALRM, expired); signal.alarm(seconds)
        try:
            runtime = service.Runtime(path, manifest['sha256'])
            return _capture_locked(runtime, service, selection, selection_path, public_der, destination, maximum, maximum_files, deadline, native, native_path, native_receipt, native_receipt_path)
        finally:
            signal.alarm(0); signal.signal(signal.SIGALRM, prior)


def _native_module(runtime):
    path = checked_file(Path(__file__).with_name('native_snapshot.py').absolute())
    need(digest(path.read_bytes()) == runtime.binding['helpers_sha256']['native_snapshot.py'])
    module = types.ModuleType('maintenance_native'); module.__file__ = str(path)
    exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
    return module, path


def _bounded_calls(runtime, deadline):
    previous = runtime.call
    def call(label, args, *, timeout=30, allowed_failure=False, **_):
        runtime.phase = 'backup-' + label
        return command(args, runtime.environment, timeout=min(timeout, max(0.01, deadline-time.monotonic())), allowed_failure=allowed_failure)
    runtime.call = call
    return previous


def _states(runtime, ids):
    rows = json.loads(runtime.call('selected-states', runtime_module_docker(runtime) + ['inspect', *ids]).stdout)
    need(len(rows) == len(ids) and {row['Id'] for row in rows} == set(ids))
    return {row['Id']: {k: row['State'][k] for k in STATE_FIELDS} for row in rows}


def _dedicated(runtime, original):
    ids = runtime.call('dedicated-inventory', runtime_module_docker(runtime) + ['ps', '--all', '--quiet', '--no-trunc']).stdout.split()
    need(len(ids) <= 256 and set(original.values()) <= set(ids) and all(re.fullmatch(HEX, cid) for cid in ids))
    rows = json.loads(runtime.call('dedicated-states', runtime_module_docker(runtime) + ['inspect', *ids]).stdout)
    need(len(rows) == len(ids) and {r['Id'] for r in rows} == set(ids))
    for row in rows:
        if row['Id'] not in original.values():
            need(row['State']['Running'] is False and row['State']['Paused'] is False
                 and row['State']['Restarting'] is False and row['State']['Pid'] == 0)


def _queue_inventory(runtime, broker, *, metadata=False):
    fields = ['name', 'messages_ready', 'messages_unacknowledged']
    if metadata: fields += ['durable', 'auto_delete']
    raw = runtime.call('queue-inventory', runtime_module_docker(runtime) +
        ['exec', broker, 'rabbitmqctl', 'list_queues', *fields, '--formatter', 'json'], timeout=25).stdout
    rows = json.loads(raw)
    need(type(rows) is list and 0 < len(rows) <= 64 and len({r['name'] for r in rows}) == len(rows))
    for row in rows:
        need(set(row) == set(fields) and re.fullmatch(r'[A-Za-z0-9_.:@-]{1,192}', row['name'])
             and all(type(row[k]) is int and row[k] >= 0 for k in ('messages_ready', 'messages_unacknowledged')))
        if metadata: need(type(row['durable']) is bool and type(row['auto_delete']) is bool)
    return rows


def storage_headroom(repository, destination_parent, maximum):
    """Conservative local disk reservation check, not a filesystem quota."""
    first,second=os.statvfs(repository),os.statvfs(destination_parent)
    same=repository.stat().st_dev==destination_parent.stat().st_dev
    margin=128*1024**2
    need(first.f_bavail*first.f_frsize >= maximum*(2 if same else 1)+margin)
    need(second.f_bavail*second.f_frsize >= maximum*(2 if same else 1)+margin)


def _request(runtime):
    path = checked_file(runtime.manifest_path.parent / 'backup-request.json', private=True)
    raw = path.read_bytes(); value = json.loads(raw, object_pairs_hook=unique)
    need(set(value) == {'scope', 'operation_id', 'manifest_sha256', 'generation_sha256', 'target', 'boot_id',
                       'recipient_der_base64', 'recipient_sha256', 'destination', 'maximum_bytes', 'maximum_files', 'seconds',
                       'queue_inventory', 'backup_program_sha256', 'storage_sha256', 'worker_instance'})
    need(value['scope'] == 'azd-santa-backup-maintenance-v1' and re.fullmatch(r'[a-f0-9]{32}', value['operation_id'])
         and value['manifest_sha256'] == runtime.digest and value['backup_program_sha256'] == digest(Path(__file__).read_bytes())
         and re.fullmatch(HEX, value['generation_sha256']) and re.fullmatch(HEX,value['storage_sha256']))
    need(type(value['maximum_bytes']) is int and CHUNK <= value['maximum_bytes'] <= 32*1024**3
         and type(value['maximum_files']) is int and 1 <= value['maximum_files'] <= 1000000
         and type(value['seconds']) is int and 60 <= value['seconds'] <= 3300)
    public = base64.b64decode(value['recipient_der_base64'], validate=True)
    need(base64.b64encode(public).decode() == value['recipient_der_base64'] and digest(public) == value['recipient_sha256'])
    recipient_key(public)
    host_identity(value['target'])  # Completed/resumed originals may reboot.
    need(re.fullmatch(r'[a-f0-9-]{36}', value['boot_id']))
    generation_path = checked_file(runtime.manifest_path.parent / 'container-generation.json', private=True)
    need(digest(generation_path.read_bytes()) == value['generation_sha256'])
    return value, digest(raw), public


def request_backup(runtime, target, public, destination, *, maximum=8*1024**3, maximum_files=100000, seconds=1800):
    """Machine producer; selected host invocation is authorized by its caller.

    This reserves once and invokes normal systemctl stop once. Timeout means
    observe the retained operation, never request/stop/submit it again.
    """
    recipient_key(public)
    need(type(maximum) is int and CHUNK <= maximum <= 32*1024**3 and type(maximum_files) is int
         and 1 <= maximum_files <= 1000000 and type(seconds) is int and 60 <= seconds <= 3300)
    identity = host_identity(target)
    previous = _bounded_calls(runtime, time.monotonic()+60)
    try:
        selected = runtime.inspect(running=True)
        runtime.container_generation(selected); _dedicated(runtime, selected)
        status = dict(line.split('=', 1) for line in runtime.call('ready-unit', ['systemctl', 'show', 'azd-santa-runtime.service',
            '--property=LoadState,ActiveState,SubState,MainPID']).stdout.splitlines())
        need(status['LoadState'] == 'loaded' and status['ActiveState'] == 'active' and status['SubState'] == 'running'
             and re.fullmatch(r'[1-9][0-9]*', status['MainPID']))
        service=load_controller()
        unit=checked_file(service.UNIT,within_root=False)
        need(unit.read_bytes()==service.unit_text(Path(service.__file__),runtime.manifest_path,runtime.digest).encode())
        with Path('/proc/'+status['MainPID']+'/cmdline').open('rb') as stream: argv=stream.read(8193)
        need(len(argv)<=8192 and argv.rstrip(b'\0').split(b'\0')[1:]==[v.encode() for v in (
            '-I',str(service.__file__),'run','--manifest',str(runtime.manifest_path),'--sha256',runtime.digest)])
        worker_instance=_worker_current(runtime,selected['workers'])
        inventory = _queue_inventory(runtime, selected['rabbitmq'], metadata=True)
        need(all(r['durable'] or (r['auto_delete'] and r['messages_ready'] == r['messages_unacknowledged'] == 0) for r in inventory))
        destination = Path(destination)
        need(destination.is_absolute() and destination.parent == destination.parent.resolve(strict=True)
             and not destination.exists() and not destination.is_symlink())
        for parent in (destination.parent, *destination.parent.parents):
            info=parent.stat(); need(info.st_uid == 0 and not info.st_mode & 0o022)
        storage_headroom(volume_paths(runtime)['elasticsearch_snapshots'],destination.parent,maximum)
        generation = checked_file(runtime.manifest_path.parent / 'container-generation.json', private=True)
        request = dict(scope='azd-santa-backup-maintenance-v1', operation_id=uuid.uuid4().hex,
            manifest_sha256=runtime.digest, generation_sha256=digest(generation.read_bytes()), target=target,
            boot_id=identity['boot_id'], recipient_der_base64=base64.b64encode(public).decode(), recipient_sha256=digest(public),
            destination=str(destination), maximum_bytes=maximum, maximum_files=maximum_files, seconds=seconds,
            queue_inventory=inventory, worker_instance=worker_instance, backup_program_sha256=digest(Path(__file__).read_bytes()),storage_sha256=storage_fingerprint(runtime))
        request_path=runtime.manifest_path.parent/'backup-request.json'
        write_private = load_controller().private_write
        write_private(request_path, request); load_controller().sync_directory(request_path.parent)
    finally: runtime.call=previous
    # Submission boundary: no automatic second stop after an unknown result.
    runtime.call('backup-stop-submitted', ['systemctl', 'stop', 'azd-santa-runtime.service'], timeout=seconds+120)
    completion=checked_file(request_path.parent/('backup-'+request['operation_id'])/'maintenance-complete.json',private=True)
    need(json.loads(completion.read_bytes())['request_sha256']==digest(request_path.read_bytes()))
    return completion


def _stopped(runtime, original, names, term_names=()):
    rows = _states(runtime, [original[name] for name in names])
    for name in names:
        state=rows[original[name]]
        need(state['Status']=='exited' and state['Running'] is False and state['Paused'] is False
             and state['Restarting'] is False and state['Pid']==0 and state['OOMKilled'] is False and not state['Error']
             and (state['ExitCode']==0 or (name in term_names and state['ExitCode']==143)))
    return rows


def _worker_markers(raw, hashes, *, completed):
    """Only source-owned stdout markers from this container start are eligible."""
    need(isinstance(raw,str) and len(raw.encode()) <= 4*CHUNK)
    starts=[];ends=[]
    for line in raw.splitlines():
        need(len(line.encode())<=65536)
        match=re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z (SANTA_WORKERS_(?:START|CLEAN_STOP)_JSON:)(.*)',line)
        if not match: continue
        value=json.loads(match[2],object_pairs_hook=unique)
        keys={'scope','nonce','parent_pid','grace_seconds','module_sha256','command_sha256'}
        clean=match[1]=='SANTA_WORKERS_CLEAN_STOP_JSON:'
        need(set(value)==keys|({'children'} if clean else set())
             and value['scope']==('azd-santa-workers-clean-stop-v1' if clean else 'azd-santa-workers-start-v1')
             and re.fullmatch(r'[a-f0-9]{32}',value['nonce'])
             and type(value['parent_pid']) is int and value['parent_pid']>0
             and type(value['grace_seconds']) is int and value['grace_seconds']==20
             and value['module_sha256']==hashes['azd_santa_worker_lifecycle.py']
             and value['command_sha256']==hashes['base/management/commands/runworkers.py'])
        if clean: need(len(starts)==1)
        (ends if clean else starts).append(value)
    need(len(starts)==1 and len(ends)==(1 if completed else 0))
    if completed:
        clean=ends[0];start=starts[0]
        need({k:v for k,v in clean.items() if k not in ('scope','children')}=={k:v for k,v in start.items() if k!='scope'})
        children=clean['children']
        need(type(children) is list and 0<len(children)<=64)
        for child in children:
            need(set(child)=={'pid','exit_code','clean'} and type(child['pid']) is int and child['pid']>0
                 and child['pid']!=start['parent_pid'] and type(child['exit_code']) is int
                 and child['exit_code']==0 and child['clean'] is True)
        pids=[c['pid'] for c in children]
        need(pids==sorted(set(pids)))
        return start,clean
    return starts[0],None


def _worker_logs(runtime, worker_id, started_at):
    need(re.fullmatch(HEX,worker_id) and re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z',started_at)
         and not started_at.startswith('0001'))
    return runtime.call('worker-instance-logs',runtime_module_docker(runtime)+
        ['logs','--since',started_at,'--timestamps',worker_id]).stdout


def _worker_current(runtime, worker_id):
    """Pre-mutation source/process/startup observation, not operator JSON."""
    service=load_controller();hashes=service.WORKER_HASHES
    need(runtime.binding['worker_hashes']==hashes)
    before=_states(runtime,[worker_id])[worker_id]
    need(before['Status']=='running' and before['Running'] is True and before['Pid']>0
         and before['Paused'] is False and before['Restarting'] is False and before['OOMKilled'] is False)
    start,_=_worker_markers(_worker_logs(runtime,worker_id,before['StartedAt']),hashes,completed=False)
    # Parent PID is inside the container's namespace, independent of Docker's
    # host State.Pid. Verify the real current command, never assume PID1/tini.
    code=("from pathlib import Path;import hashlib,json;"
          f"p=Path('/proc/{start['parent_pid']}');"
          "argv=p.joinpath('cmdline').read_bytes().rstrip(bytes([0])).split(bytes([0]));"
          "assert argv==[b'python',b'server/manage.py',b'runworkers'];"
          f"paths={list(hashes)!r};"
          "print(json.dumps({name:hashlib.sha256(Path('/zentral/server',name).read_bytes()).hexdigest() for name in paths}))")
    observed=json.loads(runtime.call('worker-source-process',runtime_module_docker(runtime)+
        ['exec',worker_id,'python','-I','-S','-c',code]).stdout,object_pairs_hook=unique)
    need(observed==hashes and _states(runtime,[worker_id])[worker_id]==before)
    return dict(container_id=worker_id,started_at=before['StartedAt'],start_marker=start)


def _worker_join_proof(runtime, worker_id, worker_state, request_sha, instance):
    need(set(instance)=={'container_id','started_at','start_marker'} and instance['container_id']==worker_id
         and instance['started_at']==worker_state['StartedAt'])
    service=load_controller();need(runtime.binding['worker_hashes']==service.WORKER_HASHES)
    start,clean=_worker_markers(_worker_logs(runtime,worker_id,instance['started_at']),service.WORKER_HASHES,completed=True)
    need(start==instance['start_marker'])
    return dict(scope='azd-santa-workers-clean-stop-proof-v1',request_sha256=request_sha,
                container_id=worker_id,started_at=instance['started_at'],start_marker=start,clean_marker=clean)


def _worker_clean_stop(runtime, original, request_sha, expected_queues, instance):
    """Require original exit zero, empty queues AND current joined-child proof."""
    states=_stopped(runtime,original,('workers',))
    publishers=_stopped(runtime,original,('web','celery'))
    rows=_queue_inventory(runtime,original['rabbitmq'])
    need(len(rows)==len(expected_queues) and {r['name'] for r in rows}==set(expected_queues)
         and all(r['messages_ready']==r['messages_unacknowledged']==0 for r in rows))
    return dict(scope='azd-santa-worker-exit-zero-v1',request_sha256=request_sha,
                worker_id=original['workers'],worker_state=states[original['workers']],
                publisher_states=publishers,queues=rows,
                child_join_proof=_worker_join_proof(runtime,original['workers'],states[original['workers']],request_sha,instance))


class _MaintenanceCapability:
    """Unserialized, process-local proof; no CLI/JSON bypass of cold checks."""
    def __init__(self, runtime, original, states, request_sha, key, storage_sha=None):
        need(key is _MAINTENANCE_KEY)
        need(isinstance(storage_sha,str) and re.fullmatch(HEX,storage_sha))
        self.runtime=runtime;self.original=dict(original);self.states=states;self.request_sha=request_sha
        self.pid=os.getpid();self.key=key
        self.storage_sha=storage_sha

    def verify(self, runtime, selected):
        need(self.key is _MAINTENANCE_KEY and self.runtime is runtime and self.pid==os.getpid()
             and selected==self.original and runtime.stopping is True and runtime.backup_ready is True
             and runtime.supervisor_lock_fd is not None)
        info=os.fstat(runtime.supervisor_lock_fd)
        lock=(runtime.manifest_path.parent/'supervisor.lock').stat()
        need((info.st_dev,info.st_ino)==(lock.st_dev,lock.st_ino))


def _snapshot_job(runtime, checkpoint, native_path, request_sha, operation_id, maximum_bytes):
    for path in (checkpoint,native_path): need(re.fullmatch(r'/[A-Za-z0-9/_.-]+',str(path)))
    name='santa-backup-native-'+operation_id
    source_sha=runtime.binding['helpers_sha256']['native_snapshot.py']
    need(digest(native_path.read_bytes())==source_sha)
    code=("from pathlib import Path;import types,hashlib;raw=Path('/run/native.py').read_bytes();"
          f"assert hashlib.sha256(raw).hexdigest()=={source_sha!r};"
          "m=types.ModuleType('native');exec(compile(raw,'/run/native.py','exec'),m.__dict__);"
          f"m.run_reserved(Path('/run/backup'),{request_sha!r},{operation_id!r},seconds=600,maximum_bytes={maximum_bytes!r})")
    runtime.helpers.add(name)
    try:
        runtime.call('native-snapshot',runtime_module_docker(runtime)+['run','--rm','--pull','never','--name',name,
            '--network',runtime.project+'_default','--read-only','--user','0','--cap-drop','ALL','--security-opt','no-new-privileges:true',
            '--label','com.docker.compose.project='+runtime.project,'--label','com.docker.compose.service=web','--label','com.docker.compose.oneoff=True',
            '--mount','type=bind,source='+str(checkpoint)+',target=/run/backup',
            '--mount','type=bind,source='+str(native_path)+',target=/run/native.py,readonly',
            '--entrypoint','python',runtime.data['services']['web']['image'],'-I','-S','-c',code],timeout=650)
    finally: runtime.stop_helpers()


def stop_capture(runtime):
    """Called only from the original supervisor's stopping path, under its lock."""
    request_path=runtime.manifest_path.parent/'backup-request.json'
    if not request_path.exists() and not request_path.is_symlink(): return False
    request, request_sha, public=_request(runtime)
    operation=runtime.manifest_path.parent/('backup-'+request['operation_id'])
    if (operation/'resume-authorized.json').exists():
        startup_allowed(runtime); return False  # Completed request is never replayed.
    need(host_identity(request['target'])['boot_id'] == request['boot_id'])
    need(runtime.stopping is True and runtime.backup_ready is True and runtime.supervisor_lock_fd is not None)
    native,native_path=_native_module(runtime)
    operation.mkdir(mode=0o700)  # Existing/unknown operation is never resumed here.
    native.write_new(operation/'maintenance-intent.json',dict(request_sha256=request_sha,generation_sha256=request['generation_sha256']))
    deadline=time.monotonic()+request['seconds'];previous=_bounded_calls(runtime,deadline)
    def expired(*_): raise TimeoutError('Backup maintenance deadline exceeded')
    prior=signal.signal(signal.SIGALRM,expired);signal.alarm(request['seconds'])
    try:
        selected=runtime.inspect(running=True);runtime.container_generation(selected)
        need(storage_fingerprint(runtime)==request['storage_sha256'])
        need(set(runtime.cleanup_ids)==set(selected.values()));_dedicated(runtime,selected)
        def stop(names, seconds=30):
            runtime.call('close-'+ '-'.join(names),runtime_module_docker(runtime)+['stop','--time',str(seconds),*(selected[n] for n in names)],timeout=seconds+60)
        stop(('web','celery'),60)
        publishers={name:selected[name] for name in ('web','celery')}
        def publisher_states(): return [dict(Id=cid,State=s) for cid,s in _stopped(runtime,selected,('web','celery')).items()]
        original={r['name']:r for r in request['queue_inventory']}
        # Known empty auto-delete control queues must disappear after publishers
        # close. Every durable queue remains; no synthetic zero rows are added.
        durable=sorted(name for name,r in original.items() if r['durable'])
        need(durable)
        quiet_deadline=min(deadline,time.monotonic()+30)
        while True:
            rows=_queue_inventory(runtime,selected['rabbitmq'])
            need(set(r['name'] for r in rows)<=set(original))
            if set(r['name'] for r in rows)==set(durable): break
            need(time.monotonic()<quiet_deadline);publisher_states();time.sleep(1)
        drain=native.drain(request_sha,publishers,durable,publisher_states,
            lambda:_queue_inventory(runtime,selected['rabbitmq']),seconds=min(120,max(2,int(deadline-time.monotonic()))))
        native.write_new(operation/'drain-complete.json',drain)
        need(_worker_current(runtime,selected['workers'])==request['worker_instance'])
        stop(('workers',))
        worker = _worker_clean_stop(runtime,selected,request_sha,durable,request['worker_instance'])
        native.write_new(operation/'worker-stop-complete.json',worker)
        # One owned, existing-image stdlib-only helper. No Django/SQL imports,
        # owner env, socket, source tree or data volumes are mounted.
        checkpoint=operation/'snapshot';checkpoint.mkdir(mode=0o700)
        _snapshot_job(runtime,checkpoint,native_path,request_sha,request['operation_id'],request['maximum_bytes'])
        receipt_path=checked_file(checkpoint/'native-complete.json',private=True)
        receipt=json.loads(receipt_path.read_bytes(),object_pairs_hook=unique)
        need(receipt['plan']['binding_sha256']==request_sha and receipt['plan']['operation_id']==request['operation_id'])
        native.archive_roots(volume_paths(runtime),receipt,request_sha)
        stop(('elastic',));_stopped(runtime,selected,('elastic',),('elastic',))
        stop(('rabbitmq','redis','db'))
        states=_stopped(runtime,selected,tuple(selected),('elastic',))
        native.write_new(operation/'stop-complete.json',dict(request_sha256=request_sha,states=states))
        selection=dict(scope='azd-santa-native-cold-backup-selection-v1',target=request['target'],
            runtime_manifest={'path':str(runtime.manifest_path),'sha256':runtime.digest},controller_sha256=CONTROLLER_SHA,
            backup_program_sha256=digest(Path(__file__).read_bytes()),recipient_sha256=digest(public),containers=selected,
            generation_sha256=request['generation_sha256'],maintenance_sha256=request_sha,
            native_snapshot={'path':str(receipt_path),'sha256':digest(receipt_path.read_bytes()),'program_sha256':digest(native_path.read_bytes())})
        selection_path=operation/'capture-selection.json';native.write_new(selection_path,selection)
        cap=_MaintenanceCapability(runtime,selected,states,request_sha,_MAINTENANCE_KEY,request['storage_sha256'])
        cap.verify(runtime,selected)
        service=load_controller()
        result=_capture_locked(runtime,service,selection,selection_path,public,request['destination'],request['maximum_bytes'],
            request['maximum_files'],deadline,native,native_path,receipt,receipt_path,cap)
        complete=checked_file(result.with_name('complete.json'),private=True,within_root=False)
        native.write_new(operation/'maintenance-complete.json',dict(request_sha256=request_sha,
            generation_sha256=request['generation_sha256'],ciphertext_receipt_sha256=digest(complete.read_bytes())))
        return True
    except Exception as error:
        native.write_new(operation/'maintenance-failed.json',dict(request_sha256=request_sha,error_type=type(error).__name__,automatic_replay=False))
        raise
    finally:
        signal.alarm(0);signal.signal(signal.SIGALRM,prior);runtime.call=previous


def startup_allowed(runtime):
    request,request_sha,_=_request(runtime)
    operation=runtime.manifest_path.parent/('backup-'+request['operation_id'])
    completed=json.loads(checked_file(operation/'maintenance-complete.json',private=True).read_bytes())
    authorized=json.loads(checked_file(operation/'resume-authorized.json',private=True).read_bytes())
    need(completed['request_sha256']==request_sha and completed['generation_sha256']==request['generation_sha256']
         and authorized=={'scope':'azd-santa-original-runtime-resume-v1','request_sha256':request_sha,
            'completion_sha256':digest((operation/'maintenance-complete.json').read_bytes())})


def _authorize_resume(runtime):
    request,request_sha,_=_request(runtime)
    operation=runtime.manifest_path.parent/('backup-'+request['operation_id'])
    complete_path=checked_file(operation/'maintenance-complete.json',private=True)
    complete=json.loads(complete_path.read_bytes());need(complete['request_sha256']==request_sha)
    destination=Path(request['destination'])
    receipt_path=checked_file(destination/'complete.json',private=True,within_root=False)
    need(digest(receipt_path.read_bytes())==complete['ciphertext_receipt_sha256'])
    receipt=json.loads(receipt_path.read_bytes())
    need(receipt['maintenance_sha256']==request_sha and receipt['generation_sha256']==request['generation_sha256'])
    ciphertext=checked_file(destination/'backup.sealed',private=True,limit=request['maximum_bytes'],within_root=False)
    with ciphertext.open('rb') as stream: actual=hashlib.file_digest(stream,'sha256').hexdigest()
    need(actual==receipt['ciphertext_sha256'] and ciphertext.stat().st_size==receipt['ciphertext_bytes'])
    selected=runtime.inspect(running=False);runtime.container_generation(selected)
    need(_stopped(runtime,selected,tuple(selected),('elastic',))==json.loads((operation/'stop-complete.json').read_bytes())['states'])
    unit=dict(line.split('=',1) for line in runtime.call('resume-unit',['systemctl','show','azd-santa-runtime.service',
        '--property=LoadState,ActiveState,SubState,MainPID,Result']).stdout.splitlines())
    need(unit=={'LoadState':'loaded','ActiveState':'inactive','SubState':'dead','MainPID':'0','Result':'success'})
    source=load_controller();unit_path=checked_file(source.UNIT,within_root=False)
    need(unit_path.read_bytes()==source.unit_text(Path(source.__file__),runtime.manifest_path,runtime.digest).encode())
    native,_=_native_module(runtime)
    native.write_new(operation/'resume-authorized.json',dict(scope='azd-santa-original-runtime-resume-v1',request_sha256=request_sha,
        completion_sha256=digest(complete_path.read_bytes())))
    startup_allowed(runtime)


def resume_original(runtime):
    """Verify under the existing lock, then release it before one unit start."""
    import fcntl
    deadline=time.monotonic()+600;previous=_bounded_calls(runtime,deadline)
    def expired(*_): raise TimeoutError('Original-runtime resume deadline exceeded')
    prior=signal.signal(signal.SIGALRM,expired);signal.alarm(600)
    try:
        lock_path=checked_file(runtime.manifest_path.parent/'supervisor.lock',private=True)
        with lock_path.open('r+b') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            _authorize_resume(runtime)
        runtime.call('explicit-backup-resume',['systemctl','start','azd-santa-runtime.service'],timeout=450)
    finally:
        signal.alarm(0);signal.signal(signal.SIGALRM,prior);runtime.call=previous


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--selection', required=True); parser.add_argument('--sha256', required=True)
    parser.add_argument('--recipient-public-der', required=True); parser.add_argument('--destination', required=True)
    parser.add_argument('--maximum-bytes', type=int, default=8 * 1024**3)
    parser.add_argument('--maximum-files', type=int, default=100000); parser.add_argument('--seconds', type=int, default=1800)
    args = parser.parse_args()
    recipient = Path(args.recipient_public_der)
    need(recipient.stat().st_size <= 1024)
    capture(args.selection, args.sha256, recipient.read_bytes(), args.destination,
            maximum=args.maximum_bytes, maximum_files=args.maximum_files, seconds=args.seconds)
    print('Cold encrypted capture complete; restore admission remains unimplemented.')


if __name__ == '__main__':
    try: main()
    except Exception:
        print('Cold backup failed; preserve private partial output and inspect original state. Do not replay automatically.', file=sys.stderr)
        raise SystemExit(1)
