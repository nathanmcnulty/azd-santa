"""Original Unlicense. Encrypt each image SAS for one selected VM and boot."""

import base64
from contextlib import ExitStack
from dataclasses import asdict
import hashlib
import os
from pathlib import Path
import re
import stat
import time
import uuid

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import blob_retention as blob
from cold_backup import recipient_key
from retained_image_blob import Transfer, capability
from retained_image_parts import checked_document
from retained_image_sas import IssuedBatch

DOMAIN = b'azd-santa/image-sas-handoff/v1\0'
MAX_PACKET = 8192
OFFER_SCOPE = 'azd-santa-image-sas-offer-v1'
PACKET_SCOPE = 'azd-santa-sealed-image-sas-v1'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def b64(raw):
    return base64.b64encode(raw).decode('ascii')


def decode(value, maximum):
    blob.need(type(value) is str and len(value) <= 2 * maximum)
    raw = base64.b64decode(value, validate=True)
    blob.need(len(raw) <= maximum and b64(raw) == value)
    return raw


def oaep():
    return padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=DOMAIN)


def boot(target):
    blob.host_identity(target)
    value = Path('/proc/sys/kernel/random/boot_id').read_text(encoding='ascii').strip()
    blob.need(re.fullmatch(blob.GUID, value))
    return value


def context(transfer, target, permission):
    blob.need(type(transfer) is Transfer and permission in ('c', 'r'))
    transfer.check_target(target)
    blob.need(target == transfer.source if permission == 'c' else
              target.vm_id.casefold() != transfer.source.vm_id.casefold()
              and target.instance_id != transfer.source.instance_id)
    return {**transfer.pins, 'scope': OFFER_SCOPE, 'target': asdict(target), 'permission': permission,
            'account_id': transfer.store.blob.account_id}


def check_offer(offer_raw, offer_sha256, transfer, target, permission):
    offer = checked_document(offer_raw, offer_sha256, 4096)
    expected = context(transfer, target, permission)
    blob.need(set(offer) == set(expected) | {'created', 'expires', 'boot_id', 'key', 'offer_id'}
              and all(offer[name] == value for name, value in expected.items())
              and type(offer['created']) is int and type(offer['expires']) is int
              and offer['created'] <= int(time.time()) < offer['expires'] <= offer['created'] + 1800
              and re.fullmatch(blob.GUID, offer['boot_id']) and re.fullmatch(r'[a-f0-9]{32}', offer['offer_id']))
    public = decode(offer['key'], 1024)
    return offer, recipient_key(public)


def offer_name(transfer, permission):
    return transfer.pins['operation'] + '-' + permission


def create_offer(root, transfer, target, permission, *, apply=False):
    """Create one owner-private, boot-bound recipient on a selected Linux VM."""
    try:
        blob.need(type(apply) is bool)
        expected = context(transfer, target, permission)
        if not apply:
            return {'scope': OFFER_SCOPE, 'performs_mutation': False, 'permission': permission}
        now = int(time.time())
        boot_id = boot(target)
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        public = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        private = key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        offer = blob.encoded({**expected, 'created': now, 'expires': now + 1800, 'boot_id': boot_id,
                              'key': b64(public), 'offer_id': uuid.uuid4().hex})
        blob.need(boot(target) == boot_id)
        check_offer(offer, sha(offer), transfer, target, permission)
        with ExitStack() as stack:
            state = blob.Journal(Path(root) / offer_name(transfer, permission),
                                {'offer_sha256': sha(offer), 'permission': permission}, stack)
            fd = os.open('recipient.der', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=state.fd)
            with os.fdopen(fd, 'wb') as output:
                output.write(private)
                output.flush()
                os.fsync(output.fileno())
            os.fsync(state.fd)
        return offer
    except Exception:
        raise blob.RetentionRejected('Santa image handoff offer rejected; preserve state') from None


def seal(offer_raw, offer_sha256, issued, transfer, target, permission):
    """Consume a private issued batch and return bounded encrypted packets only."""
    try:
        offer, public = check_offer(offer_raw, offer_sha256, transfer, target, permission)
        blob.need(type(issued) is IssuedBatch and issued.account_id == offer['account_id'])
        tokens = issued.take(target, permission, offer['manifest_sha256'])
        validated = transfer.tokens_for(tokens, target, permission)
        packets = {}
        for name, selected in validated.items():
            blob.need(int(selected.expires.timestamp()) <= offer['expires'])
            key, nonce = AESGCM.generate_key(bit_length=256), os.urandom(12)
            aad = DOMAIN + offer_raw + b'\0' + name.encode('ascii')
            ciphertext = AESGCM(key).encrypt(nonce, selected._token.encode('ascii'), aad)
            packet = blob.encoded({'scope': PACKET_SCOPE, 'object': name, 'offer_sha256': offer_sha256,
                'key': b64(public.encrypt(key, oaep())), 'nonce': b64(nonce), 'ciphertext': b64(ciphertext)})
            blob.need(len(packet) <= MAX_PACKET)
            packets[name] = packet
        return packets
    except Exception:
        raise blob.RetentionRejected('Santa image handoff sealing rejected; never replay a consumed batch') from None


def receive_and_transfer(root, offer_raw, offer_sha256, packets, transfer, target, permission,
                         attempt_root, *, source_path=None, apply=False, seconds=900, transport=None):
    """Reserve a delivery from the trusted operator channel before decryption."""
    try:
        blob.need(type(apply) is bool)
        offer, public = check_offer(offer_raw, offer_sha256, transfer, target, permission)
        if not apply:
            return {'scope': PACKET_SCOPE, 'performs_mutation': False, 'permission': permission}
        names = {part['object'] for part in transfer.selection['parts']}
        blob.need(type(packets) is dict and set(packets) == names)
        blob.need(boot(target) == offer['boot_id'])
        with ExitStack() as stack:
            folder, name = blob.parent(Path(root) / offer_name(transfer, permission) / 'intent.json', stack)
            blob.need(name == 'intent.json')

            def read(name, limit):
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=folder)
                with os.fdopen(fd, 'rb') as source:
                    info = os.fstat(fd)
                    blob.need(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1
                              and stat.S_IMODE(info.st_mode) == 0o600 and 0 < info.st_size <= limit)
                    value = source.read(limit + 1)
                    blob.need(len(value) == info.st_size and blob.identity(info) == blob.identity(os.fstat(fd)))
                    return value

            blob.need(read('intent.json', 4096) == blob.encoded({'offer_sha256': offer_sha256, 'permission': permission}))
            raw = read('recipient.der', 8192)
            key = serialization.load_der_private_key(raw, password=None)
            blob.need(isinstance(key, rsa.RSAPrivateKey) and key.public_key().public_numbers() == public.public_numbers())
            marker = os.open('consumed', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=folder)
            os.close(marker)
            os.fsync(folder)
            os.unlink('recipient.der', dir_fd=folder)
            os.fsync(folder)

        tokens = {}
        for part in transfer.selection['parts']:
            name = part['object']
            raw = packets[name]
            blob.need(type(raw) is bytes and 0 < len(raw) <= MAX_PACKET)
            packet = checked_document(raw, sha(raw), MAX_PACKET)
            blob.need(set(packet) == {'scope', 'object', 'offer_sha256', 'key', 'nonce', 'ciphertext'}
                      and packet['scope'] == PACKET_SCOPE and packet['object'] == name
                      and packet['offer_sha256'] == offer_sha256)
            wrapped, nonce = decode(packet['key'], 384), decode(packet['nonce'], 12)
            blob.need(len(wrapped) == 384 and len(nonce) == 12)
            aad = DOMAIN + offer_raw + b'\0' + name.encode('ascii')
            token = AESGCM(key.decrypt(wrapped, oaep())).decrypt(nonce, decode(packet['ciphertext'], 4112), aad).decode('ascii')
            selected = capability(transfer.store, target, part, token, permission)
            blob.need(int(selected.expires.timestamp()) <= offer['expires'])
            tokens[name] = token
        blob.need(boot(target) == offer['boot_id'])
        if permission == 'c':
            return transfer.upload(source_path, attempt_root, tokens, apply=True, seconds=seconds, transport=transport)
        return transfer.download(attempt_root, target, tokens, apply=True, seconds=seconds, transport=transport)
    except Exception:
        raise blob.RetentionRejected('Santa image handoff rejected or unknown; preserve state and never replay') from None
