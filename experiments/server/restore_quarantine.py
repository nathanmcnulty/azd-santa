"""Original Unlicense. Strict sealed archive quarantine, never application restore.

Linux descriptor-relative output only. Plaintext and archived metadata stay in
the private quarantine; original permissions/owners are never applied. No CLI,
SQL, service, authentication, cleanup or automatic retry is provided.
"""
import base64
from contextlib import ExitStack
import hashlib
import json
import math
import os
from pathlib import PurePosixPath
import re
import stat
import struct
import sys
import tarfile
import time

import restore_cipher
import native_snapshot

CHUNK = 1024 * 1024
HEX = r'[a-f0-9]{64}'
ROOT = '/var/lib/azd-santa-qualification'
COMMIT = '88e67b3ce49033aab028029937a6e14f7c489073'
PROGRAMS = {'runtime_service.py': 'f0a8961f64e48471eed71757805ae4e29ee080aef30c6ab9ec040eafaf443099',
    'cold_backup.py': 'c61618d81dc53c1d9bbfad31526757be47bd88760ff12b7683cbdb4e51c86e78',
    'native_snapshot.py': 'ee657b986e9ac49e4cffab0a3336d000ecfa236994a7dae7941c2604907edca1',
    'worker_lifecycle.py': 'e86d20287324eca25ef24c4c405e7d923feafb2d2760c1f22b799f0a02d0a50f'}
CONTROL = frozenset(('compose.json', 'base.json', 'db.env', 'rabbitmq.env', 'runtime.env',
    'migration.env', 'manifest.json', 'container-generation.json', 'backup-request.json',
    'drain-complete.json', 'worker-stop-complete.json', 'stop-complete.json',
    'plan.json', 'repository-intent.json', 'snapshot-intent.json', 'native-observed.json',
    'capture-selection.json', 'native-complete.json', 'azd-santa-runtime.service',
    'runtime_service.py', 'cold_backup.py', 'native_snapshot.py', 'worker_lifecycle.py',
    'prepare_zentral_eval.py', 'test_live_zentral.py'))
DATA_ROOTS = frozenset(('volumes/postgres_data', 'volumes/redis_data',
    'volumes/rabbitmq_data', 'volumes/media_data', 'elasticsearch_snapshot_repository'))
COMPAT_KEYS = frozenset(('scope', 'selection', 'host', 'images', 'postgres_major', 'rabbit_node',
    'volumes', 'control_files', 'control_files_sha256', 'mounts', 'elasticsearch_backup',
    'native_snapshot', 'selected_files_sha256', 'source_commit', 'crypto_version',
    'restore_admission', 'current_authority'))


class QuarantineRejected(ValueError):
    pass


def need(ok):
    if not ok:
        raise QuarantineRejected('Archive quarantine rejected; retain original and partial quarantine')


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def document(raw, *, canonical=False):
    need(len(raw) <= CHUNK)
    value = json.loads(raw, object_pairs_hook=restore_cipher.unique, parse_constant=lambda _: need(False))
    need(type(value) is dict and (not canonical or encoded(value) == raw))
    return value


def canonical(name, directory=False):
    need(type(name) is str and 0 < len(name.encode()) <= 1024 and '\\' not in name
         and not any(ord(c) < 32 or ord(c) == 127 for c in name))
    if directory and name.endswith('/'):
        name = name[:-1]
    parts = name.split('/')
    need(len(parts) <= 64 and all(p not in ('', '.', '..') and ':' not in p for p in parts))
    return name


def absolute(name):
    need(type(name) is str and name.startswith('/') and not name.startswith('//') and str(PurePosixPath(name)) == name
         and '..' not in PurePosixPath(name).parts and '\\' not in name and len(name.encode()) <= 4096
         and not any(ord(c) < 32 or ord(c) == 127 for c in name))
    return name


def compatibility(value):
    need(set(value) == COMPAT_KEYS and value['scope'] == 'azd-santa-cold-backup-v1'
         and value['source_commit'] == COMMIT and value['restore_admission'] == 'not_implemented'
         and value['current_authority'] == 'not_established'
         and value['elasticsearch_backup'] == 'native-filesystem-snapshot-repository')
    selection = value['selection']
    need(type(selection) is dict and set(selection) == {'scope', 'target', 'runtime_manifest',
        'controller_sha256', 'backup_program_sha256', 'recipient_sha256', 'containers',
        'generation_sha256', 'maintenance_sha256', 'native_snapshot'})
    need(selection['scope'] == 'azd-santa-native-cold-backup-selection-v1'
         and selection['controller_sha256'] == PROGRAMS['runtime_service.py']
         and selection['backup_program_sha256'] == PROGRAMS['cold_backup.py'])
    target = selection['target']; guid = r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}'
    need(type(target) is dict and set(target) == {'VmId', 'VmInstanceId'}
         and re.fullmatch(guid, target['VmInstanceId'])
         and re.fullmatch('/subscriptions/' + guid + r'/resourceGroups/rg-azd-santa-vm-[a-z0-9-]{2,32}/providers/Microsoft.Compute/virtualMachines/vm-santa-lab', target['VmId']))
    need(type(value['host']) is dict and set(value['host']) == {'VmId', 'VmInstanceId', 'boot_id'}
         and {k: value['host'][k] for k in target} == target and re.fullmatch(guid, value['host']['boot_id']))
    for key in ('recipient_sha256', 'generation_sha256', 'maintenance_sha256'):
        need(type(selection[key]) is str and re.fullmatch(HEX, selection[key]))
    need(set(selection['runtime_manifest']) == {'path', 'sha256'}
         and re.fullmatch(HEX, selection['runtime_manifest']['sha256']))
    path = absolute(selection['runtime_manifest']['path'])
    need(path.startswith(ROOT + '/') and path.endswith('/runtime-service/manifest.json'))
    need(set(selection['native_snapshot']) == {'path', 'sha256', 'program_sha256'}
         and selection['native_snapshot']['program_sha256'] == PROGRAMS['native_snapshot.py']
         and re.fullmatch(HEX, selection['native_snapshot']['sha256']))
    native = value['native_snapshot']; native_snapshot.validate_plan(native['plan'])
    need(native['scope'] == 'azd-santa-native-snapshot-complete-v1'
         and native['plan_sha256'] == native_snapshot.sha(native['plan'])
         and native['plan']['binding_sha256'] == selection['maintenance_sha256']
         and native['state'] == 'SUCCESS' and type(native['failed_shards']) is int and native['failed_shards'] == 0
         and native['include_global_state'] is True
         and native['restore_admission'] == 'not_implemented' and native['current_authority'] == 'not_established'
         and re.fullmatch(r'[A-Za-z0-9_-]{22}', native['snapshot_uuid']))
    need(set(selection['containers']) == {'web', 'workers', 'celery', 'db', 'redis', 'rabbitmq', 'elastic'}
         and len(set(selection['containers'].values())) == 7
         and all(re.fullmatch(HEX, v) for v in selection['containers'].values()))
    need(type(value['images']) is dict and set(value['images']) == set(selection['containers']))
    for image in value['images'].values():
        need(type(image) is dict and set(image) == {'reference', 'id'}
             and re.fullmatch(r'sha256:' + HEX, image['id'])
             and re.fullmatch(r'(?:sha256:[a-f0-9]{64}|[a-z0-9][a-z0-9./:_-]*@sha256:[a-f0-9]{64})', image['reference']))
    need(type(value['postgres_major']) is str and re.fullmatch(r'[1-9][0-9]', value['postgres_major'])
         and value['rabbit_node'] == 'rabbit@rabbitmq' and type(value['crypto_version']) is str
         and 0 < len(value['crypto_version']) <= 128)
    need(set(value['volumes']) == {'postgres_data', 'redis_data', 'rabbitmq_data', 'elasticsearch_data', 'media_data', 'elasticsearch_snapshots'})
    for path in value['volumes'].values(): absolute(path)
    controls = value['control_files']; digests = value['control_files_sha256']
    need(type(controls) is dict and len(controls) == len(CONTROL) and set(controls) == set(digests))
    basenames = set(); numbers = set(); sources = set()
    for name, source in controls.items():
        need(canonical(name) == name and re.fullmatch(r'control/(0|[1-9][0-9]*)/[^/]+', name))
        basenames.add(name.rsplit('/', 1)[1]); numbers.add(int(name.split('/')[1]))
        absolute(source); sources.add(source)
        need(source == '/etc/systemd/system/azd-santa-runtime.service' or source.startswith(ROOT + '/'))
        need(PurePosixPath(source).name == name.rsplit('/', 1)[1] and re.fullmatch(HEX, digests[name]))
    need(basenames == CONTROL and numbers == set(range(len(CONTROL))) and len(sources) == len(CONTROL))
    by_name = {name.rsplit('/', 1)[1]: source for name, source in controls.items()}
    control_root = PurePosixPath(selection['runtime_manifest']['path']).parent
    runtime_root = control_root.parent
    operation = control_root / ('backup-' + native['plan']['operation_id'])
    source_root = PurePosixPath(by_name['runtime_service.py']).parent
    expected = {str(runtime_root / name) for name in ('compose.json', 'conf/base.json', 'db.env', 'rabbitmq.env', 'runtime.env', 'migration.env')}
    expected.update(str(control_root / name) for name in ('manifest.json', 'container-generation.json', 'backup-request.json'))
    expected.update(str(operation / name) for name in ('drain-complete.json', 'worker-stop-complete.json', 'stop-complete.json', 'capture-selection.json'))
    expected.update(str(operation / 'snapshot' / name) for name in ('plan.json', 'repository-intent.json', 'snapshot-intent.json', 'native-observed.json', 'native-complete.json'))
    expected.update(str(source_root / name) for name in ('runtime_service.py', 'cold_backup.py', 'native_snapshot.py', 'worker_lifecycle.py', 'prepare_zentral_eval.py', 'test_live_zentral.py'))
    expected.add('/etc/systemd/system/azd-santa-runtime.service')
    need(sources == expected and by_name['manifest.json'] == selection['runtime_manifest']['path']
         and by_name['native-complete.json'] == selection['native_snapshot']['path']
         and [controls[name] for name in sorted(controls, key=lambda n: int(n.split('/')[1]))] == sorted(sources))
    selected = value['selected_files_sha256']
    need(type(selected) is dict and set(selected) == {str(runtime_root / name) for name in
        ('compose.json', 'conf/base.json', 'db.env', 'rabbitmq.env', 'runtime.env')}
         and all(re.fullmatch(HEX, v) for v in selected.values()))
    return value


def pax(raw):
    need(0 < len(raw) <= 4096)
    result = {}; offset = 0
    while offset < len(raw):
        space = raw.find(b' ', offset, min(len(raw), offset + 12))
        need(space > offset and re.fullmatch(rb'[1-9][0-9]*', raw[offset:space]))
        length = int(raw[offset:space]); end = offset + length
        need(space + 3 < end <= len(raw) and raw[end-1:end] == b'\n')
        key, separator, value = raw[space+1:end-1].partition(b'=')
        need(separator and key in (b'path', b'size', b'uid', b'gid', b'mtime') and key not in result)
        result[key] = value.decode('utf-8'); offset = end
    return result


def members(stream, *, maximum, maximum_member, maximum_entries, deadline):
    """Bounded producer-specific USTAR/PAX parser. Never calls extract/extractall.

    Yield metadata plus member bytes as a bounded iterator; consumer must exhaust
    each payload before advancing. Only one local PAX header may precede a member.
    """
    total = 0; entries = 0; pending = None
    def read(length):
        nonlocal total
        need(time.monotonic() < deadline and total + length <= maximum)
        raw = stream.read(length); need(len(raw) == length); total += length
        return raw
    while True:
        header = read(512)
        if header == bytes(512):
            need(pending is None and read(512) == bytes(512))
            # Producer emits one 10240-byte-record-aligned tar, never concatenated archives.
            trailing = stream.read(10240 + 1)
            need(len(trailing) <= 10240 and not any(trailing) and not stream.read(1)
                 and total + len(trailing) <= maximum and time.monotonic() < deadline
                 and (total + len(trailing)) % 10240 == 0)
            return
        need(header[257:265] == b'ustar\x0000')
        info = tarfile.TarInfo.frombuf(header, 'utf-8', 'strict')
        need(info.type in (tarfile.REGTYPE, tarfile.DIRTYPE, tarfile.XHDTYPE)
             and not info.linkname and not info.uname and not info.gname and not info.devmajor and not info.devminor)
        if info.type == tarfile.XHDTYPE:
            need(pending is None and info.name == '././@PaxHeader' and 0 < info.size <= 4096)
            pending = pax(read(info.size))
            need(read((-info.size) % 512) == bytes((-info.size) % 512))
            continue
        values = pending or {}; pending = None
        raw_name = header[:100].split(b'\0', 1)[0].decode('utf-8')
        prefix = header[345:500].split(b'\0', 1)[0].decode('utf-8')
        raw_name = prefix + '/' + raw_name if prefix else raw_name
        name = canonical(values.get(b'path', raw_name), info.isdir())
        size = values.get(b'size', info.size)
        uid = values.get(b'uid', info.uid); gid = values.get(b'gid', info.gid)
        for value in (size, uid, gid):
            need(type(value) is int or (type(value) is str and re.fullmatch(r'0|[1-9][0-9]*', value)))
        size, uid, gid = int(size), int(uid), int(gid)
        mtime = float(values.get(b'mtime', info.mtime))
        need(0 <= size <= maximum_member and 0 <= uid <= 2**63-1 and 0 <= gid <= 2**63-1
             and math.isfinite(mtime) and abs(mtime) <= 2**63-1 and 0 <= info.mode <= 0o7777
             and (not info.isdir() or size == 0))
        entries += 1; need(entries <= maximum_entries)
        metadata = dict(path=name, directory=info.isdir(), size=size, uid=uid, gid=gid, mode=info.mode, mtime=mtime)
        remaining = [size]
        def chunks():
            while remaining[0]:
                chunk = read(min(CHUNK, remaining[0])); remaining[0] -= len(chunk); yield chunk
        yield metadata, chunks()
        need(remaining[0] == 0)
        padding = (-size) % 512; need(read(padding) == bytes(padding))


def validate_archive(stream, writer, *, maximum, maximum_member, maximum_entries, deadline, recipient_sha256=None):
    """Validate/extract authenticated bytes through a private writer interface."""
    seen = {}; sizes = {}; metadata = []; controls = {}; compat = None; capture = None; roots = set(); metadata_bytes = 0
    for member, chunks in members(stream, maximum=maximum, maximum_member=maximum_member,
                                   maximum_entries=maximum_entries + 2, deadline=deadline):
        name = member['path']; need(name not in seen and capture is None)
        sizes[name] = member['size']
        metadata_bytes += len(encoded(member)) + 1; need(metadata_bytes <= 16 * CHUNK - 128)
        if compat is None:
            need(name == 'backup/compatibility.json' and not member['directory'] and member['size'] <= CHUNK)
            raw = b''.join(chunks); compat = compatibility(document(raw, canonical=True))
            need(recipient_sha256 is None or compat['selection']['recipient_sha256'] == recipient_sha256)
            writer.file(name, iter((raw,))); seen[name] = False; metadata.append(member); continue
        if name == 'backup/capture.json':
            need(not member['directory'] and member['size'] <= CHUNK)
            raw = b''.join(chunks); capture = document(raw, canonical=True)
            need(capture == {'entries': len(seen)-1, 'restore_admission': 'not_implemented', 'current_authority': 'not_established'})
            writer.file(name, iter((raw,))); seen[name] = False; metadata.append(member); continue
        if name in compat['control_files']:
            need(not member['directory'] and member['size'] <= CHUNK)
            raw = b''.join(chunks); need(hashlib.sha256(raw).hexdigest() == compat['control_files_sha256'][name])
            controls[name.rsplit('/', 1)[1]] = raw
            writer.file(name, iter((raw,)))
        else:
            matches = [root for root in DATA_ROOTS if name == root or name.startswith(root + '/')]
            need(len(matches) == 1); root = matches[0]
            if name == root:
                need(member['directory']); roots.add(root)
            else:
                need(seen.get(name.rsplit('/', 1)[0]) is True)
            if member['directory']: writer.directory(name)
            else: writer.file(name, chunks)
        seen[name] = member['directory']; metadata.append(member)
    need(compat is not None and capture is not None and roots == DATA_ROOTS and set(controls) == CONTROL)
    selection = compat['selection']; native = compat['native_snapshot']
    need(document(controls['capture-selection.json']) == selection)
    need(document(controls['native-complete.json']) == native
         and hashlib.sha256(controls['native-complete.json']).hexdigest() == selection['native_snapshot']['sha256'])
    need(document(controls['plan.json']) == native['plan'])
    need(native_snapshot.completed_snapshot(document(controls['native-observed.json']), native['plan']) == native)
    for filename, digest in PROGRAMS.items(): need(hashlib.sha256(controls[filename]).hexdigest() == digest)
    need(hashlib.sha256(controls['manifest.json']).hexdigest() == selection['runtime_manifest']['sha256']
         and hashlib.sha256(controls['container-generation.json']).hexdigest() == selection['generation_sha256']
         and hashlib.sha256(controls['backup-request.json']).hexdigest() == selection['maintenance_sha256'])
    manifest = document(controls['manifest.json'])
    need(set(manifest) == {'scope', 'compose', 'project', 'files', 'policy_hashes', 'source_commit',
        'controller_sha256', 'helpers_sha256', 'worker_hashes'}
         and manifest['scope'] == 'private-initialized-runtime-service-v1'
         and manifest['files'] == compat['selected_files_sha256'] and manifest['controller_sha256'] == selection['controller_sha256']
         and manifest['source_commit'] == COMMIT)
    helpers = ('test_live_zentral.py', 'prepare_zentral_eval.py', 'cold_backup.py', 'native_snapshot.py', 'worker_lifecycle.py')
    need(manifest['helpers_sha256'] == {name: hashlib.sha256(controls[name]).hexdigest() for name in helpers})
    need(manifest['worker_hashes'] == {
        'azd_santa_worker_lifecycle.py': PROGRAMS['worker_lifecycle.py'],
        'base/management/commands/runworkers.py': 'be379c804120c5a0dd3620bab14adbd5f8a0b89f51ed43ee2284d6eb1f0d9515'})
    need(set(manifest['policy_hashes']) == {'policy', 'recovery', 'sealed', 'admission'}
         and all(re.fullmatch(HEX, v) for v in manifest['policy_hashes'].values()))
    generation = document(controls['container-generation.json'])
    need(set(generation) == {'scope', 'manifest_sha256', 'project', 'image_id', 'generation', 'container_ids'}
         and generation['scope'] == 'private-runtime-container-generation-v1'
         and generation['manifest_sha256'] == selection['runtime_manifest']['sha256']
         and generation['container_ids'] == selection['containers'] and generation['project'] == manifest['project']
         and generation['image_id'] == compat['images']['web']['reference'] and re.fullmatch(r'[a-f0-9]{32}', generation['generation']))
    request = document(controls['backup-request.json'])
    need(set(request) == {'scope', 'operation_id', 'manifest_sha256', 'generation_sha256', 'target', 'boot_id',
        'recipient_der_base64', 'recipient_sha256', 'destination', 'maximum_bytes', 'maximum_files', 'seconds',
        'queue_inventory', 'backup_program_sha256', 'storage_sha256', 'worker_instance'}
         and request['scope'] == 'azd-santa-backup-maintenance-v1' and request['target'] == selection['target']
         and request['operation_id'] == native['plan']['operation_id'] and request['boot_id'] == compat['host']['boot_id']
         and request['manifest_sha256'] == selection['runtime_manifest']['sha256']
         and request['generation_sha256'] == selection['generation_sha256']
         and request['backup_program_sha256'] == selection['backup_program_sha256']
         and request['recipient_sha256'] == selection['recipient_sha256'])
    public = base64.b64decode(request['recipient_der_base64'], validate=True)
    need(base64.b64encode(public).decode() == request['recipient_der_base64'] and hashlib.sha256(public).hexdigest() == selection['recipient_sha256'])
    for name, source in compat['control_files'].items():
        if source in compat['selected_files_sha256']:
            need(compat['control_files_sha256'][name] == compat['selected_files_sha256'][source])
    snapshot_prefix = 'elasticsearch_snapshot_repository/'
    for basename in ('snap-' + native['snapshot_uuid'] + '.dat', 'meta-' + native['snapshot_uuid'] + '.dat'):
        need(snapshot_prefix + basename in seen and not seen[snapshot_prefix + basename] and sizes[snapshot_prefix + basename] > 0)
    need(any(re.fullmatch(snapshot_prefix + r'index-[0-9]+', p) and not isdir and sizes[p] > 0 for p, isdir in seen.items()))
    return metadata


class Directory:
    def __init__(self, fd): self.fd = fd

    def parent(self, path):
        parts = canonical(path).split('/'); fd = os.dup(self.fd)
        try:
            for part in parts[:-1]:
                try: os.mkdir(part, 0o700, dir_fd=fd)
                except FileExistsError: pass
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd); fd = child
                info = os.fstat(fd); need(info.st_uid == os.geteuid() and not info.st_mode & 0o077)
            return fd, parts[-1]
        except BaseException:
            os.close(fd); raise

    def directory(self, path):
        fd, name = self.parent(path)
        try: os.mkdir(name, 0o700, dir_fd=fd); os.fsync(fd)
        finally: os.close(fd)

    def file(self, path, chunks):
        fd, name = self.parent(path)
        try:
            output = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
            with os.fdopen(output, 'wb') as stream:
                info = os.fstat(stream.fileno())
                need(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                     and info.st_nlink == 1 and not info.st_mode & 0o077)
                for chunk in chunks: stream.write(chunk)
                stream.flush(); os.fsync(stream.fileno())
            os.fsync(fd)
        finally: os.close(fd)


def private_parent(path, stack):
    path = str(path); absolute(path); need(path != '/')
    parts = PurePosixPath(path).parts[1:]
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW); stack.callback(os.close, fd)
    for part in parts[:-1]:
        fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd); stack.callback(os.close, fd)
        info = os.fstat(fd)
        need(info.st_uid in (0, os.geteuid()) and not info.st_mode & 0o022)
    parent = os.fstat(fd); need(parent.st_uid == os.geteuid() and not parent.st_mode & 0o077)
    return fd, parts[-1]


def decrypt_staging(source, size, expected, key, output, deadline):
    """Second authenticated pass; staged bytes are never parsed before finalize."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    source.seek(0); prefix = source.read(len(restore_cipher.MAGIC) + 4)
    length = struct.unpack('>I', prefix[-4:])[0]; need(1 <= length <= 2048)
    header = source.read(length); value = document(header)
    secret = key.decrypt(base64.b64decode(value['wrapped_key']), padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=restore_cipher.MAGIC))
    source.seek(size-16); tag = source.read(16)
    decryptor = Cipher(algorithms.AES256(secret), modes.GCM(base64.b64decode(value['nonce']), tag)).decryptor()
    decryptor.authenticate_additional_data(prefix + header); digest = hashlib.sha256(prefix + header)
    source.seek(len(prefix) + length); remaining = size - len(prefix) - length - 16
    while remaining:
        need(time.monotonic() < deadline)
        raw = source.read(min(CHUNK, remaining)); need(0 < len(raw) <= remaining)
        remaining -= len(raw); digest.update(raw); output.write(decryptor.update(raw))
    need(source.read(16) == tag and not source.read(1)); digest.update(tag)
    output.write(decryptor.finalize()); need(digest.hexdigest() == expected and time.monotonic() < deadline)
    output.flush(); os.fsync(output.fileno()); output.seek(0)


def extract(source, expected_sha256, private_key, destination, *, maximum=1024**3,
            maximum_member=512*1024**2, maximum_entries=100000, seconds=1800):
    """Exclusive Linux private quarantine. No output path or secret in receipts.

    Caller supplies trusted ciphertext digest/key, an outer process deadline,
    enough disk for staging+extraction, and exclusion of concurrent same-UID/root
    writers. Failure retains private partial state without a completion marker.
    """
    try:
        return _extract(source, expected_sha256, private_key, destination,
                        maximum, maximum_member, maximum_entries, seconds)
    except Exception:
        raise QuarantineRejected('Archive quarantine rejected; retain original and partial quarantine') from None


def _extract(source, expected, key, destination, maximum, maximum_member, maximum_entries, seconds):
    need(sys.platform == 'linux' and type(maximum) is int and CHUNK <= maximum <= 32*1024**3
         and type(maximum_member) is int and 0 < maximum_member <= maximum
         and type(maximum_entries) is int and 1 <= maximum_entries <= 1000000
         and type(seconds) is int and 1 <= seconds <= 7200)
    deadline = time.monotonic() + seconds
    with ExitStack() as stack:
        source_parent, source_name = private_parent(source, stack)
        fd = os.open(source_name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=source_parent)
        source_stream = stack.enter_context(os.fdopen(fd, 'rb')); before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
             and not before.st_mode & 0o077 and before.st_nlink == 1)
        auth = restore_cipher.authenticate(source_stream, before.st_size, expected, key, maximum=maximum,
            seconds=max(1, int(deadline-time.monotonic())))
        def unchanged():
            need(restore_cipher.identity(before) == restore_cipher.identity(os.fstat(fd))
                 == restore_cipher.identity(os.stat(source_name, dir_fd=source_parent, follow_symlinks=False)))
        unchanged(); parent, name = private_parent(destination, stack)
        os.mkdir(name, 0o700, dir_fd=parent)
        directory = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent); stack.callback(os.close, directory)
        identity = os.fstat(directory)
        need(identity.st_uid == os.geteuid() and not identity.st_mode & 0o077)
        stage_fd = os.open('archive.authenticated.tar', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        staging = stack.enter_context(os.fdopen(stage_fd, 'w+b'))
        stage_info = os.fstat(stage_fd)
        need(stat.S_ISREG(stage_info.st_mode) and stage_info.st_uid == os.geteuid()
             and stage_info.st_nlink == 1 and not stage_info.st_mode & 0o077)
        decrypt_staging(source_stream, before.st_size, expected, key, staging, deadline); unchanged()
        stage_identity = restore_cipher.identity(os.fstat(stage_fd))
        output = Directory(directory); output.directory('contents')
        contents = os.open('contents', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory); stack.callback(os.close, contents)
        metadata = validate_archive(staging, Directory(contents), maximum=maximum, maximum_member=maximum_member,
            maximum_entries=maximum_entries, deadline=deadline, recipient_sha256=auth['recipient_sha256'])
        need(stage_identity == restore_cipher.identity(os.fstat(stage_fd))); unchanged()
        output.file('metadata.json', iter((encoded({'scope': 'inert-quarantine-metadata-v1', 'entries': metadata}),)))
        current = os.stat(name, dir_fd=parent, follow_symlinks=False)
        need(time.monotonic() < deadline and (identity.st_dev, identity.st_ino) == (current.st_dev, current.st_ino))
        receipt = dict(scope='authenticated-archive-quarantine-v1', ciphertext_sha256=expected,
            ciphertext_bytes=auth['ciphertext_bytes'], entries=len(metadata),
            restore_accepted=False, current_authority_established=False)
        output.file('completion.pending', iter((encoded(receipt),)))
        unchanged(); need(time.monotonic() < deadline and stage_identity == restore_cipher.identity(os.fstat(stage_fd)))
        current = os.stat(name, dir_fd=parent, follow_symlinks=False)
        need((identity.st_dev, identity.st_ino) == (current.st_dev, current.st_ino))
        # Last mutation publishes an already-fsynced receipt exclusively. No
        # overwrite, unlink or cleanup. Crash may lose this final directory link;
        # absence always means inspection, never replay or activation.
        publication = os.dup(directory)
        try:
            # Finish fallible stream/descriptor cleanup before publication, so
            # a close failure cannot report a failed extraction with a marker.
            stack.close()
            os.link('completion.pending', 'complete.json', src_dir_fd=publication, dst_dir_fd=publication, follow_symlinks=False)
        finally:
            try: os.close(publication)
            except OSError: pass  # Publication already defines the outcome.
        return receipt
