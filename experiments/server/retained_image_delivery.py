"""Original Unlicense. Bounded, journaled image handoff frames for a trusted VM channel."""

from contextlib import ExitStack
import os
from pathlib import Path
import re
import stat

import blob_retention as blob
import retained_image_handoff as handoff
from retained_image_parts import checked_document
from retained_image_sas import sync_directory, write_record

MAX_FRAME = 14 * 1024
MAX_BATCH = 8192
SCOPE = 'azd-santa-image-delivery-v1'


def build_batch(offer, packets, transfer, target, permission):
    blob.need(type(offer) is bytes and 0 < len(offer) <= 4096)
    offer_sha = handoff.sha(offer)
    handoff.check_offer(offer, offer_sha, transfer, target, permission)
    names = [part['object'] for part in transfer.selection['parts']]
    blob.need(type(packets) is dict and set(packets) == set(names))
    entries = []
    for name in names:
        packet = packets[name]
        blob.need(type(packet) is bytes and 0 < len(packet) <= handoff.MAX_PACKET)
        entries.append({'object': name, 'sha256': handoff.sha(packet), 'bytes': len(packet)})
    raw = blob.encoded({'scope': SCOPE, 'offer_sha256': offer_sha, 'permission': permission,
                        'manifest_sha256': transfer.pins['manifest_sha256'], 'parts': entries})
    blob.need(len(raw) <= MAX_BATCH)
    return raw


def frame(operation, batch_sha256, **payload):
    raw = blob.encoded({'scope': SCOPE, 'action': operation, 'batch_sha256': batch_sha256, **payload})
    blob.need(len(raw) <= MAX_FRAME)
    return raw


def check_result(reply, digest, transfer, permission):
    blob.need(type(reply) is dict and set(reply) == {'scope', 'batch_sha256', 'state', 'result'}
              and reply['scope'] == SCOPE and reply['batch_sha256'] == digest and reply['state'] == 'finished')
    result = reply['result']
    blob.need(type(result) is dict and result.get('manifest_sha256') == transfer.pins['manifest_sha256'])
    count = len(transfer.selection['parts'])
    if permission == 'c':
        blob.need(set(result) == {'state', 'confirmed_parts', 'automatic_replay', 'manifest_sha256',
                                 'independent_bytes_verified'} and result['state'] in ('uploaded', 'unknown')
                  and type(result['confirmed_parts']) is int and 0 <= result['confirmed_parts'] <= count
                  and (result['state'] == 'unknown' or result['confirmed_parts'] == count)
                  and result['automatic_replay'] is False and result['independent_bytes_verified'] is False)
    else:
        selection = transfer.selection
        blob.need(result == {'scope': 'azd-santa-retained-image-parts-readback-v1',
                  'manifest_sha256': transfer.pins['manifest_sha256'], 'completion_sha256': transfer.pins['completion_sha256'],
                  'ciphertext_bytes': selection['ciphertext_bytes'], 'ciphertext_sha256': selection['ciphertext_sha256'],
                  'verified_parts': count})
    return reply


def send(invoke, journal_root, offer, packets, transfer, target, permission, *, apply=False):
    """Use a selected, trusted request/reply callback; never reissue a lost frame."""
    try:
        blob.need(type(apply) is bool)
        batch = build_batch(offer, packets, transfer, target, permission)
        digest = handoff.sha(batch)
        names = [part['object'] for part in transfer.selection['parts']]
        commands = [frame('begin', digest, batch=handoff.b64(batch))]
        commands.extend(frame('part', digest, index=index, packet=handoff.b64(packets[name]))
                        for index, name in enumerate(names))
        commands.append(frame('finish', digest))
        if not apply:
            return {'scope': SCOPE, 'performs_mutation': False, 'frames': len(commands),
                    'maximum_frame_bytes': max(map(len, commands))}
        root = Path(journal_root)
        blob.need(root.is_absolute() and root == root.resolve(strict=True) and root.is_dir())
        if os.name != 'nt':
            info = root.stat()
            blob.need(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700)
        journal = root / (handoff.offer_name(transfer, permission) + '-delivery')
        journal.mkdir(mode=0o700)
        sync_directory(root)
        write_record(journal / 'intent.json', {'batch_sha256': digest, 'offer_sha256': handoff.sha(offer),
                     'frames': len(commands), 'permission': permission, 'vm_instance_id': target.instance_id})
        sync_directory(journal)
        for index, command in enumerate(commands):
            reply = invoke(command)
            expected = {'scope': SCOPE, 'batch_sha256': digest}
            if index < len(commands) - 1:
                expected.update(state='begun' if index == 0 else 'staged', index=index - 1)
                blob.need(reply == expected)
            else:
                check_result(reply, digest, transfer, permission)
        write_record(journal / 'finished.json', {'batch_sha256': digest, 'state': 'reported'})
        sync_directory(journal)
        return reply
    except Exception:
        raise blob.RetentionRejected('Santa image delivery rejected or unknown; inspect the existing journal') from None


def read_at(folder, name, limit):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=folder)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(fd)
        blob.need(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                  and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1 and 0 < info.st_size <= limit)
        raw = stream.read(limit + 1)
        blob.need(len(raw) == info.st_size and blob.identity(info) == blob.identity(os.fstat(fd)))
        return raw


def write_at(folder, name, raw):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=folder)
    with os.fdopen(fd, 'wb') as output:
        output.write(raw)
        output.flush()
        os.fsync(fd)
    os.fsync(folder)


class Guest:
    """Dispatch only fixed handoff actions against separately selected local inputs."""

    def __init__(self, staging_root, offer_root, offer, offer_sha256, transfer, target,
                 permission, attempt_root, *, source_path=None, seconds=900, transport=None):
        self.path = Path(staging_root) / (handoff.offer_name(transfer, permission) + '-delivery')
        self.offer_root, self.offer, self.offer_sha256 = offer_root, offer, offer_sha256
        self.transfer, self.target, self.permission = transfer, target, permission
        self.attempt_root, self.source_path, self.seconds, self.transport = attempt_root, source_path, seconds, transport

    def batch(self, raw, digest):
        batch = checked_document(raw, digest, MAX_BATCH)
        expected = {'scope': SCOPE, 'offer_sha256': self.offer_sha256, 'permission': self.permission,
                    'manifest_sha256': self.transfer.pins['manifest_sha256']}
        entries = batch['parts']
        names = [part['object'] for part in self.transfer.selection['parts']]
        blob.need(type(entries) is list and len(entries) == len(names) and batch == {**expected, 'parts': entries})
        for entry, name in zip(entries, names):
            blob.need(type(entry) is dict and set(entry) == {'object', 'sha256', 'bytes'} and entry['object'] == name
                      and type(entry['sha256']) is str and re.fullmatch(blob.HEX, entry['sha256'])
                      and type(entry['bytes']) is int and 0 < entry['bytes'] <= handoff.MAX_PACKET)
        return entries

    def __call__(self, raw):
        try:
            blob.need(type(raw) is bytes and 0 < len(raw) <= MAX_FRAME)
            request = checked_document(raw, handoff.sha(raw), MAX_FRAME)
            action, digest = request['action'], request['batch_sha256']
            blob.need(request['scope'] == SCOPE and type(digest) is str and re.fullmatch(blob.HEX, digest))
            fields = {'scope', 'action', 'batch_sha256'}
            if action == 'observe':
                blob.need(set(request) == fields)
                blob.host_identity(self.target)
                return self.observe(digest)
            offer, _ = handoff.check_offer(self.offer, self.offer_sha256, self.transfer, self.target, self.permission)
            blob.need(handoff.boot(self.target) == offer['boot_id'])
            with ExitStack() as stack:
                if action == 'begin':
                    blob.need(set(request) == fields | {'batch'})
                    batch = handoff.decode(request['batch'], MAX_BATCH)
                    self.batch(batch, digest)
                    journal = blob.Journal(self.path, {'batch_sha256': digest, 'offer_sha256': self.offer_sha256}, stack)
                    write_at(journal.fd, 'batch.json', batch)
                    return {'scope': SCOPE, 'batch_sha256': digest, 'state': 'begun', 'index': -1}

                folder, _ = blob.parent(self.path / 'batch.json', stack)
                entries = self.batch(read_at(folder, 'batch.json', MAX_BATCH), digest)
                if action == 'part':
                    blob.need(set(request) == fields | {'index', 'packet'})
                    index = request['index']
                    blob.need(type(index) is int and 0 <= index < len(entries))
                    packet = handoff.decode(request['packet'], handoff.MAX_PACKET)
                    self.check_packet(packet, entries[index])
                    write_at(folder, f'part-{index:03d}.bin', packet)
                    return {'scope': SCOPE, 'batch_sha256': digest, 'state': 'staged', 'index': index}

                blob.need(action == 'finish' and set(request) == fields)
                packets = {}
                for index, entry in enumerate(entries):
                    packet = read_at(folder, f'part-{index:03d}.bin', handoff.MAX_PACKET)
                    self.check_packet(packet, entry)
                    packets[entry['object']] = packet
                write_at(folder, 'submitted.json', blob.encoded({'batch_sha256': digest}))
                result = handoff.receive_and_transfer(self.offer_root, self.offer, self.offer_sha256, packets,
                    self.transfer, self.target, self.permission, self.attempt_root, source_path=self.source_path,
                    seconds=self.seconds, transport=self.transport, apply=True)
                reply = {'scope': SCOPE, 'batch_sha256': digest, 'state': 'finished', 'result': result}
                check_result(reply, digest, self.transfer, self.permission)
                write_at(folder, 'result.json', blob.encoded(reply))
                return reply
        except Exception:
            raise blob.RetentionRejected('Santa VM image delivery rejected or unknown; do not replay') from None

    @staticmethod
    def check_packet(packet, entry):
        blob.need(len(packet) == entry['bytes'] and handoff.sha(packet) == entry['sha256'])

    def observe(self, digest):
        with ExitStack() as stack:
            folder, _ = blob.parent(self.path / 'batch.json', stack)
            entries = self.batch(read_at(folder, 'batch.json', MAX_BATCH), digest)
            try:
                raw = read_at(folder, 'result.json', 4096)
            except FileNotFoundError:
                try:
                    read_at(folder, 'submitted.json', 4096)
                except FileNotFoundError:
                    observed = []
                    for index, entry in enumerate(entries):
                        try:
                            self.check_packet(read_at(folder, f'part-{index:03d}.bin', handoff.MAX_PACKET), entry)
                            observed.append(index)
                        except FileNotFoundError:
                            continue
                    return {'scope': SCOPE, 'batch_sha256': digest, 'state': 'staging', 'staged': observed}
                return {'scope': SCOPE, 'batch_sha256': digest, 'state': 'submitted-unknown'}
            return check_result(checked_document(raw, handoff.sha(raw), 4096), digest, self.transfer, self.permission)
