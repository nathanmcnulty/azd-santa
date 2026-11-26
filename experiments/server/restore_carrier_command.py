"""Stage reviewed recovery transport code and deliver sealed Blob capabilities."""

from contextlib import ExitStack
from dataclasses import asdict
import hashlib
import io
import json
import lzma
import os
from pathlib import Path
import stat
import uuid
import zipfile

import blob_retention as blob
import private_arm_adapter as arm
import restore_arm_authorization as operator
from restore_authority_transaction import Target
from restore_guest_job import Job
from restore_input_blob import PacketTransfer
from restore_input_handoff import Handoff, MAX_ENVELOPE
from restore_quarantine_journal import is_digest
from retained_image_delivery import read_at, write_at
from retained_image_handoff import b64, boot, decode, sha
from retained_image_parts import checked_document
from retained_image_run_command import build_script, submit_action
from retained_image_runner import MAX_ARCHIVE, SOURCES, source_file

SCOPE = 'santa-restore-carrier-v1'
CONFIG = 'restore-carrier.json'
PART_BYTES = 32 * 1024
PACKET_PART_BYTES = 44 * 1024
MAX_PARTS = 8
MODULES = (*SOURCES, 'retained_image_run_command.py', 'restore_arm_authorization.py',
           'restore_authority_plan.py', 'restore_authority_transaction.py', 'restore_carrier_command.py',
           'restore_census.py', 'restore_census_review.py', 'restore_guest_job.py', 'restore_guest_readback.py',
           'restore_input_blob.py', 'restore_input_handoff.py', 'restore_quarantine_journal.py',
           'restore_sealed_inputs.py', 'restore_secret_transaction.py', 'secret_rewrap.py')

BOOTSTRAP = """import base64, contextlib, hashlib, io, json, lzma, os, re, stat, sys
from pathlib import Path

def main():
    raw = base64.b64decode(os.environ.pop('SANTA_CARRIER_FRAME'), validate=True)
    frame = json.loads(raw)
    capsule = frame['capsule']
    assert os.geteuid() == 0 and re.fullmatch('[a-f0-9]{64}', capsule)
    base = Path('/run/azd-santa-recovery-carrier')
    base.mkdir(mode=0o700, exist_ok=True)
    info = base.lstat()
    assert stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700
    folder = base / capsule
    staging = frame['action'] == 'stage'
    if staging and frame['index'] == 0:
        folder.mkdir(mode=0o700)
    info = folder.lstat()
    assert stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700
    archive = folder / 'tools.zip'

    def read(path, cap):
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            assert stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and not info.st_mode & 0o077
            data = stream.read(cap + 1)
            assert 0 < len(data) <= cap and len(data) == info.st_size
            return data

    def write(path, data):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())

    if staging:
        index, parts = frame['index'], frame['parts']
        assert type(index) is int and type(parts) is int and 0 <= index < parts <= 8
        part = base64.b64decode(frame['bytes'], validate=True)
        assert 0 < len(part) <= 32768
        assert index == parts - 1 or len(part) == 32768
        write(folder / str(index), part)
        if index == parts - 1:
            packed = b''.join(read(folder / str(i), 32768) for i in range(parts))
            decoder = lzma.LZMADecompressor(memlimit=32 * 1024**2)
            recovered = decoder.decompress(packed, max_length=524289)
            assert decoder.eof and not decoder.unused_data and len(recovered) <= 524288
            assert hashlib.sha256(recovered).hexdigest() == capsule
            write(archive, recovered)
            for i in range(parts):
                (folder / str(i)).unlink()
        reply = {'state': 'staged', 'index': index, 'installed': index == parts - 1}
    else:
        package = read(archive, 524288)
        assert hashlib.sha256(package).hexdigest() == capsule
        sys.path.insert(0, str(archive))
        with open(os.devnull, 'w') as sink, contextlib.redirect_stdout(sink):
            from restore_carrier_command import dispatch
            encoded_part = os.environ.pop('SANTA_CARRIER_PACKET_PART', None)
            if encoded_part is None:
                reply = dispatch(folder, package, raw)
            else:
                packet_part = base64.b64decode(encoded_part, validate=True)
                reply = dispatch(folder, package, raw, packet_part=packet_part)
    reply.update(scope='santa-restore-carrier-v1', batch_sha256=hashlib.sha256(raw).hexdigest())
    print('SANTA_IMAGE_FRAME_JSON:' + json.dumps(reply, sort_keys=True, separators=(',', ':'), allow_nan=False))

try:
    main()
except Exception:
    raise SystemExit(1) from None
"""


def configuration(selection, transfer, permission, boot_id, packet_path):
    Handoff(selection, transfer, permission, boot_id=boot_id)
    return dict(tenant=selection.tenant, subscription=selection.subscription,
                store=asdict(selection.store), source=asdict(selection.source),
                receiver=asdict(selection.verifier), operator=asdict(transfer.job.selection),
                target=asdict(transfer.job.target), generation=transfer.job.generation,
                archive_sha256=transfer.job.archive_sha256, packet_sha256=transfer.packet_sha256,
                packet_bytes=transfer.packet_bytes, permission=permission, boot_id=boot_id,
                packet_path=None if packet_path is None else source_file(packet_path, permission))


def stage_part(directory, transfer, index, part, part_sha256):
    """Add an exact next part and publish only a fully digest-verified packet."""
    import fcntl

    blob.need(type(index) is int and 0 <= index <= (transfer.packet_bytes - 1) // PACKET_PART_BYTES
              and type(part) is bytes and is_digest(part_sha256) and sha(part) == part_sha256)
    offset = index * PACKET_PART_BYTES
    blob.need(len(part) == min(PACKET_PART_BYTES, transfer.packet_bytes - offset))
    end = offset + len(part)
    with ExitStack() as stack:
        parent, _ = blob.parent(directory / 'packet.partial', stack)
        flags = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK
        if index == 0:
            flags |= os.O_CREAT | os.O_EXCL
        fd = os.open('packet.partial', flags, 0o600, dir_fd=parent)
        with os.fdopen(fd, 'r+b') as stream:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            info = os.fstat(stream.fileno())
            blob.need(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1
                      and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size == offset)
            stream.seek(offset)
            stream.write(part)
            stream.flush()
            os.fsync(stream.fileno())
            if end == transfer.packet_bytes:
                stream.seek(0)
                blob.need(hashlib.file_digest(stream, 'sha256').hexdigest() == transfer.packet_sha256)
                os.link('packet.partial', 'packet.sealed', src_dir_fd=parent, dst_dir_fd=parent,
                        follow_symlinks=False)
                os.unlink('packet.partial', dir_fd=parent)
        os.fsync(parent)
    return dict(state='packet-staged' if end == transfer.packet_bytes else 'packet-part-staged',
                index=index, received_bytes=end)


def dispatch(directory, package, request, *, packet_part=None):
    frame = checked_document(request, sha(request), 12 * 1024)
    with zipfile.ZipFile(io.BytesIO(package)) as archive:
        blob.need(tuple(archive.namelist()) == (*MODULES, CONFIG))
        raw = archive.read(CONFIG)
    config = checked_document(raw, sha(raw), 8192)
    blob.need(isinstance(directory, Path))
    blob.need(frame['capsule'] == sha(package) == directory.name)
    info = config['store']
    store = blob.Store(blob.Blob(**info['blob']), info['region'], tuple(info['owned_subnets']), info['ownership_id'])
    sender, receiver = (blob.SelectedTarget(**config[name]) for name in ('source', 'receiver'))
    selection = arm.Selection(config['tenant'], config['subscription'], store, sender, receiver)
    target = Target(**config['target'])
    job = Job(operator.Selection(**config['operator']), target, config['archive_sha256'],
              config['generation'], target.boot_id)
    transfer = PacketTransfer(job, store, receiver, config['packet_sha256'], config['packet_bytes'])
    permission = config['permission']
    packet_path = config['packet_path']
    if packet_path is not None:
        packet_path = Path(source_file(packet_path, permission))
    boot_id = config['boot_id']
    handoff = Handoff(selection, transfer, permission, boot_id=boot_id)
    offers = directory / 'offers'
    if frame['action'] == 'packet-part':
        blob.need(permission == 'c' and packet_path is None and boot(sender) == boot_id
                  and set(frame) == {'action', 'capsule', 'index', 'part_sha256'})
        return stage_part(directory, transfer, frame['index'], packet_part, frame['part_sha256'])
    blob.need(packet_part is None)
    if permission == 'c' and packet_path is None:
        packet_path = directory / 'packet.sealed'
        blob.need(packet_path.is_file() and not packet_path.is_symlink())
    if frame['action'] == 'offer':
        blob.need(set(frame) == {'action', 'capsule'})
        offers.mkdir(mode=0o700)
        return {'state': 'offered', 'offer': b64(handoff.offer(offers))}
    blob.need(frame['action'] == 'transfer'
              and set(frame) == {'action', 'capsule', 'offer_sha256', 'envelope_sha256', 'envelope'}
              and all(is_digest(frame[name]) for name in ('offer_sha256', 'envelope_sha256')))
    ciphertext = None
    if permission == 'c':
        with ExitStack() as stack:
            fd, name = blob.parent(packet_path, stack)
            ciphertext = read_at(fd, name, transfer.packet_bytes)
        blob.need(len(ciphertext) == transfer.packet_bytes and sha(ciphertext) == transfer.packet_sha256)
    result = handoff.use(offers, decode(frame['envelope'], MAX_ENVELOPE), frame['offer_sha256'],
                         frame['envelope_sha256'], packet=ciphertext)
    if permission == 'c':
        blob.need(result['uploaded'] is True and result['packet_sha256'] == transfer.packet_sha256
                  and result['packet_bytes'] == transfer.packet_bytes)
    else:
        blob.need(len(result) == transfer.packet_bytes and sha(result) == transfer.packet_sha256)
        with ExitStack() as stack:
            fd, name = blob.parent(directory / 'packet.sealed', stack)
            write_at(fd, name, result)
    return dict(state='uploaded' if permission == 'c' else 'verified',
                packet_sha256=transfer.packet_sha256, packet_bytes=transfer.packet_bytes)


class Command:
    """One host, one boot and one packet."""

    def __init__(self, selection, transfer, permission, tooling, *, commit, tooling_sha256,
                 boot_id, packet_path=None, _cli=None):
        from restore_tooling_bundle import PACKET_STAGING_SCOPES, SERVER, verify

        files = verify(tooling, commit=commit, bundle_sha256=tooling_sha256)
        if permission == 'c' and packet_path is None:
            blob.need(json.loads(tooling)['scope'] in PACKET_STAGING_SCOPES)
        config = configuration(selection, transfer, permission, boot_id, packet_path)
        data = blob.encoded(config)
        blob.need(len(data) <= 8192)
        output = io.BytesIO()
        with zipfile.ZipFile(output, 'w') as archive:
            for name in MODULES:
                archive.writestr(zipfile.ZipInfo(name), files[SERVER + name])
            archive.writestr(zipfile.ZipInfo(CONFIG), data)
        package = output.getvalue()
        blob.need(len(package) <= MAX_ARCHIVE)
        self.capsule = sha(package)
        compressed = lzma.compress(package, preset=6)
        self._parts = [compressed[start:start + PART_BYTES] for start in range(0, len(compressed), PART_BYTES)]
        blob.need(0 < len(self._parts) <= MAX_PARTS)
        host = selection.source if permission == 'c' else selection.verifier
        self._identity = operator.Selection(selection.tenant, selection.subscription,
            transfer.job.selection.account, host.vm_id, host.instance_id, host.region)
        self._handoff = Handoff(selection, transfer, permission, boot_id=boot_id)
        self._transfer = transfer
        self._permission = permission
        self._packet_path = packet_path
        self._cli = _cli
        self._application = None

    def _script(self, nonce, action, *, packet_part=None, **values):
        raw = blob.encoded(dict(capsule=self.capsule, action=action, **values))
        exports = f"export SANTA_CARRIER_FRAME='{b64(raw)}'\n"
        if packet_part is not None:
            exports += f"export SANTA_CARRIER_PACKET_PART='{b64(packet_part)}'\n"
        return build_script(exports, BOOTSTRAP, nonce), sha(raw)

    def _send(self, action, **values):
        def cli(args, seconds):
            if self._cli is not None:
                return self._cli(args, seconds)
            if self._application is None:
                self._application = arm.resolve_cli()
            return arm.bounded_cli(args, seconds, application=self._application)
        observe = operator.observe(self._identity, _cli=cli)
        nonce = uuid.uuid4().hex
        script, digest = self._script(nonce, action, **values)
        args = ['--subscription', self._identity.subscription, '--resource-group',
                self._identity.vm_id.split('/')[4], '--name', 'vm-santa-lab']
        result = submit_action(cli, args, script, nonce, digest, 180, scope=SCOPE)
        blob.need(operator.observe(self._identity, _cli=cli) == observe)
        return {name: value for name, value in result.items() if name not in ('scope', 'batch_sha256')}

    def install(self):
        for index, part in enumerate(self._parts):
            reply = self._send('stage', index=index, parts=len(self._parts), bytes=b64(part))
            blob.need(reply == dict(state='staged', index=index, installed=index == len(self._parts) - 1))

    def stage_packet(self, packet):
        """Queue verified ciphertext in bounded frames before offering a SAS."""
        blob.need(self._permission == 'c' and self._packet_path is None and type(packet) is bytes
                  and len(packet) == self._transfer.packet_bytes and sha(packet) == self._transfer.packet_sha256)
        for index, offset in enumerate(range(0, len(packet), PACKET_PART_BYTES)):
            part = packet[offset:offset + PACKET_PART_BYTES]
            received = offset + len(part)
            reply = self._send('packet-part', index=index, part_sha256=sha(part), packet_part=part)
            state = 'packet-staged' if received == len(packet) else 'packet-part-staged'
            blob.need(reply == dict(state=state, index=index, received_bytes=received))

    def offer(self):
        reply = self._send('offer')
        blob.need(set(reply) == {'state', 'offer'} and reply['state'] == 'offered')
        return decode(reply['offer'], 4096)

    def transfer(self, offer, offer_sha256, issued):
        envelope = self._handoff.seal(offer, offer_sha256, issued)
        reply = self._send('transfer', offer_sha256=offer_sha256, envelope_sha256=sha(envelope),
                           envelope=b64(envelope))
        blob.need(reply == dict(state='uploaded' if self._permission == 'c' else 'verified',
                               packet_sha256=self._transfer.packet_sha256, packet_bytes=self._transfer.packet_bytes))
        return reply
