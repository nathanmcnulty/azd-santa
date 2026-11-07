"""Original Unlicense cold encrypted capture; NOT restore or current authority.

Linux/root qualification component. The selected binding must come from a
trusted machine producer; this input contract does not attest its own origin.
Never stops, starts, initializes, restores or deletes a container or volume.
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

ROOT = Path('/var/lib/azd-santa-qualification')
CONTROLLER_SHA = 'e662b57c4a55a38a27785daa99cc09a6dd8c9e9d6792cef0b60ec0a9ab0d4f0e'
MAGIC = b'AZDSANTABACKUP1\n'
CHUNK = 1024 * 1024
HEX = r'[a-f0-9]{64}'


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
    need(set(value) == {'scope', 'target', 'runtime_manifest', 'controller_sha256', 'backup_program_sha256', 'recipient_sha256', 'containers'})
    need(value['scope'] == 'azd-santa-cold-backup-selection-v1' and value['controller_sha256'] == CONTROLLER_SHA
         and value['backup_program_sha256'] == digest(Path(__file__).read_bytes()))
    need(re.fullmatch(HEX, value['recipient_sha256']))
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
    request = urllib.request.Request('http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01', headers={'Metadata': 'true'})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(request, timeout=3) as response: raw = response.read(65537)
    need(len(raw) <= 65536)
    value = json.loads(raw, object_pairs_hook=unique)
    need(value['resourceId'].lower() == target['VmId'].lower() and value['vmId'].lower() == target['VmInstanceId'])
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    need(re.fullmatch(r'[a-f0-9-]{36}', boot))
    return {**target, 'boot_id': boot}


def command(args, environment, timeout=30):
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
        need(process.wait(timeout=max(0.01, end - time.monotonic())) == 0)
        return types.SimpleNamespace(stdout=bytes(buffers[process.stdout]).decode(), returncode=0)
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


def cold_state(runtime, selected, volumes):
    need(runtime.inspect(running=False, record=False) == selected)
    rows = json.loads(runtime.call('cold-inspect', runtime_module_docker(runtime) + ['inspect', *selected.values()]).stdout)
    need(len(rows) == 7 and {row['Id'] for row in rows} == set(selected.values()))
    for row in rows:
        state = row['State']
        need(state['Status'] == 'exited' and not state['Running'] and not state.get('Restarting')
             and not state.get('Paused') and not state.get('OOMKilled') and state['ExitCode'] == 0
             and not state.get('Error') and state['StartedAt'][:4] != '0001' and state['FinishedAt'][:4] != '0001')
    unit = dict(line.split('=', 1) for line in runtime.call('unit-cold', ['systemctl', 'show', 'azd-santa-runtime.service',
        '--property=LoadState,ActiveState,SubState,Job']).stdout.splitlines() if '=' in line)
    need(unit == {'LoadState': 'loaded', 'ActiveState': 'inactive', 'SubState': 'dead', 'Job': ''})
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
            current_authority='not_established')))
        stream.flush(); os.fsync(stream.fileno())
    directory = os.open(destination, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(directory)
    finally: os.close(directory)
    return output


def capture(selection_path, expected, public_der, destination, *, maximum=8 * 1024**3, maximum_files=100000, seconds=1800):
    need(sys.platform == 'linux' and os.geteuid() == 0)
    need(type(maximum) is int and CHUNK <= maximum <= 32 * 1024**3
         and type(maximum_files) is int and 1 <= maximum_files <= 1000000 and type(seconds) is int and 1 <= seconds <= 7200)
    selection = load_selection(selection_path, expected)
    need(digest(public_der) == selection['recipient_sha256'])
    recipient_key(public_der)  # Verified prerequisite before output or Docker reads.
    service = load_controller()
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
            runtime.call = lambda label, args, timeout=30, **_: command(args, runtime.environment, timeout=min(timeout, max(0.01, deadline-time.monotonic())))
            unit = checked_file(service.UNIT, within_root=False)
            need(unit.read_bytes() == service.unit_text(Path(service.__file__), path, manifest['sha256']).encode())
            identity = host_identity(selection['target'])
            runtime.inspect(running=False, record=False)
            volumes = volume_paths(runtime)
            before = cold_state(runtime, selection['containers'], volumes)
            runtime.backing_data()
            # postmaster.pid survives an unclean PostgreSQL stop; never bless it.
            db = runtime.images[runtime.data['services']['db']['image']]
            db_env = dict(item.split('=', 1) for item in db['Config']['Env'])
            pgdata = volumes['postgres_data'] / str(Path(db_env['PGDATA']).relative_to('/var/lib/postgresql'))
            need(not (pgdata / 'postmaster.pid').exists() and not (pgdata / 'postmaster.pid').is_symlink())
            roots = {'volumes/' + name: value for name, value in volumes.items()}
            files = {Path(p) for p in runtime.binding['files']}
            conf = Path(runtime.binding['compose']).parent / 'conf'
            need(set(conf.iterdir()) == {conf / 'base.json'})
            files.update({path, Path(selection_path), Path(__file__).absolute(), Path(service.__file__),
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
                selected_files_sha256=runtime.binding['files'], source_commit=service.COMMIT,
                crypto_version=__import__('cryptography').__version__,
                restore_admission='not_implemented', current_authority='not_established')
            def final_check():
                verify_storage_snapshot(runtime, roots, volumes, mounts)
                need(cold_state(runtime, selection['containers'], volumes) == before)
                need(host_identity(selection['target']) == identity)
                service.load_manifest(path, manifest['sha256'])
                need(control_hashes == {name: digest(file.read_bytes()) for name, file in roots.items() if name.startswith('control/')})
            return write_capture(destination, public_der, roots, compatibility, maximum, maximum_files, deadline, final_check, mounts)
        finally:
            signal.alarm(0); signal.signal(signal.SIGALRM, prior)


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
