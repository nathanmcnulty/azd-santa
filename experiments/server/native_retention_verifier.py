"""Original Unlicense. One encrypted read capability for an independent native verifier."""

from contextlib import ExitStack
from copy import deepcopy
from dataclasses import asdict, replace
import datetime as dt
import io
import os
from pathlib import Path
import re
import stat
import time
import uuid
import zipfile

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import blob_retention as blob
from private_arm_adapter import CachedArm, Selection
from retained_image_blob import capability as exact_object_capability
from retained_image_delivery import read_at, write_at
from retained_image_handoff import b64, boot, decode, sha
from retained_image_parts import checked_document
from retained_image_sas import sync_directory, write_record

ROOT = '/var/lib/azd-santa-qualification/native-retention-verify'
SCOPE = 'azd-santa-native-retention-verifier-v1'
DOMAIN = b'azd-santa/native-verify-read-sas/v1\0'
MAX_PACKET = 1536
CONFIG = 'native-verifier.json'


def oaep():
    return padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=DOMAIN)


class Verifier:
    def __init__(self, selection, record, *, root=ROOT):
        blob.need(type(selection) is Selection and selection.verifier is not None)
        selection.intent()
        store, target = selection.store, selection.verifier
        blob.selection(record, store.blob, store, target, 'r')
        blob.need(record['source_vm_id'] == selection.source.vm_id
                  and record['source_instance_id'] == selection.source.instance_id
                  and target.instance_id != selection.source.instance_id)
        self.selection, self.record, self.target = selection, deepcopy(record), target
        self.root = Path(root)
        self.path = self.root / record['operation_id']
        self.binding = {'scope': SCOPE, 'permission': 'r', 'operation': record['operation_id'],
                        'blob_uri': store.blob.uri, 'account_id': store.blob.account_id,
                        'record_sha256': sha(blob.encoded(record)), 'target': asdict(target)}

    def check_offer(self, raw, *, require_current=True):
        digest = sha(raw)
        value = checked_document(raw, digest, 4096)
        fields = {'boot_id', 'created', 'expires', 'offer_id', 'public_key'}
        blob.need(set(value) == set(self.binding) | fields
                  and all(value[name] == expected for name, expected in self.binding.items())
                  and re.fullmatch(blob.GUID, value['boot_id'])
                  and re.fullmatch(r'[0-9a-f]{32}', value['offer_id'])
                  and type(value['created']) is int and type(value['expires']) is int
                  and 0 < value['expires'] - value['created'] <= 1800)
        if require_current:
            blob.need(value['created'] <= int(time.time()) < value['expires'])
        key = serialization.load_der_public_key(decode(value['public_key'], 1024))
        blob.need(isinstance(key, rsa.RSAPublicKey) and key.key_size == 3072 and key.public_numbers().e == 65537
                  and b64(key.public_bytes(serialization.Encoding.DER,
                                           serialization.PublicFormat.SubjectPublicKeyInfo)) == value['public_key'])
        return value, key

    def offer(self, *, apply=False):
        blob.need(type(apply) is bool)
        if not apply:
            return {**self.binding, 'performs_mutation': False}
        boot_id = boot(self.target)
        private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        public = private.public_key().public_bytes(serialization.Encoding.DER,
                                                   serialization.PublicFormat.SubjectPublicKeyInfo)
        now = int(time.time())
        raw = blob.encoded({**self.binding, 'boot_id': boot_id, 'created': now, 'expires': now + 1800,
                            'offer_id': uuid.uuid4().hex, 'public_key': b64(public)})
        self.check_offer(raw)
        blob.need(boot(self.target) == boot_id)
        with ExitStack() as stack:
            parent, name = blob.parent(self.root, stack)
            try:
                os.mkdir(name, 0o700, dir_fd=parent)
                os.fsync(parent)
            except FileExistsError:
                pass
            journal = blob.Journal(self.path, {'offer_sha256': sha(raw), **self.binding}, stack)
            write_at(journal.fd, 'recipient.der', private.private_bytes(serialization.Encoding.DER,
                       serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            os.mkdir('download', 0o700, dir_fd=journal.fd)
            write_at(journal.fd, 'offer.json', raw)
        return raw

    def check_token(self, token, expiry):
        store = self.selection.store
        part = {'object': store.blob.operation + '/backup.sealed',
                'sha256': self.record['complete']['ciphertext_sha256']}
        try:
            checked = exact_object_capability(store, self.target, part, token, 'r')
            blob.need(checked.blob.uri == store.blob.uri and checked.expires.timestamp() == expiry
                      and 0 < (checked.expires - dt.datetime.now(dt.timezone.utc)).total_seconds() <= 900)
        except (TypeError, ValueError):
            raise blob.RetentionRejected('Native verifier rejected an invalid read capability') from None
        return replace(checked, blob=store.blob)

    def seal(self, offer, capability):
        value, key = self.check_offer(offer)
        blob.valid_capability(capability, self.record, 'r')
        blob.need(capability.target == self.target and capability.blob == self.selection.store.blob
                  and int(capability.expires.timestamp()) <= value['expires'])
        checked = self.check_token(capability._token, int(capability.expires.timestamp()))
        secret, nonce = AESGCM.generate_key(bit_length=256), os.urandom(12)
        # The encrypted token and expiry are bound to the entire offer.
        body = blob.encoded({'token': checked._token, 'expires': int(checked.expires.timestamp())})
        packet = blob.encoded({'offer_sha256': sha(offer), 'key': b64(key.encrypt(secret, oaep())),
            'nonce': b64(nonce), 'ciphertext': b64(AESGCM(secret).encrypt(nonce, body, DOMAIN + offer))})
        blob.need(len(packet) <= MAX_PACKET)
        return packet

    def issue(self, offer, journal_root, *, apply=False):
        """Keep the exact read SAS in the operator process and return sealed bytes only."""
        blob.need(type(apply) is bool)
        value, _ = self.check_offer(offer)
        arm = CachedArm(self.selection, self.record, self.target, 'r')
        if not apply:
            return arm.mint()
        root = Path(journal_root)
        blob.need(root.is_absolute() and root == root.resolve(strict=True) and root.is_dir())
        if os.name != 'nt':
            info = root.stat()
            blob.need(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700)
        journal = root / (self.record['operation_id'] + '-native-read')
        journal.mkdir(mode=0o700)
        sync_directory(root)
        write_record(journal / 'intent.json', {**self.binding, 'offer_sha256': sha(offer)})
        sync_directory(journal)
        arm.initialize(live=True)
        blob.need(int(time.time()) + 900 <= value['expires'])
        return self.seal(offer, arm.mint(apply=True))

    def receive(self, packet, offer_sha256, *, apply=False, transport=None):
        """On the verifier, consume one boot-bound capability before the exact GET."""
        blob.need(type(apply) is bool)
        if not apply:
            return {**self.binding, 'performs_mutation': False}
        with ExitStack() as stack:
            folder, _ = blob.parent(self.path / 'offer.json', stack)
            offer = read_at(folder, 'offer.json', 4096)
            value, public = self.check_offer(offer)
            blob.need(sha(offer) == offer_sha256 and boot(self.target) == value['boot_id'])
            intent = read_at(folder, 'intent.json', 4096)
            blob.need(intent == blob.encoded({'offer_sha256': offer_sha256, **self.binding}))
            envelope = checked_document(packet, sha(packet), MAX_PACKET)
            blob.need(set(envelope) == {'offer_sha256', 'key', 'nonce', 'ciphertext'}
                      and envelope['offer_sha256'] == offer_sha256)
            private = serialization.load_der_private_key(read_at(folder, 'recipient.der', 8192), password=None)
            blob.need(isinstance(private, rsa.RSAPrivateKey)
                      and private.public_key().public_numbers() == public.public_numbers())
            wrapped, nonce = decode(envelope['key'], 384), decode(envelope['nonce'], 12)
            blob.need(len(wrapped) == 384 and len(nonce) == 12)
            secret = private.decrypt(wrapped, oaep())
            blob.need(len(secret) == 32)
            raw = AESGCM(secret).decrypt(nonce,
                    decode(envelope['ciphertext'], 6144), DOMAIN + offer)
            body = checked_document(raw, sha(raw), 6144)
            blob.need(set(body) == {'token', 'expires'} and type(body['expires']) is int
                      and body['expires'] <= value['expires'])
            capability = self.check_token(body['token'], body['expires'])
            blob.need(boot(self.target) == value['boot_id'])
            write_at(folder, 'submitted.json', blob.encoded({'offer_sha256': offer_sha256}))
            os.unlink('recipient.der', dir_fd=folder)
            os.fsync(folder)
            return blob.verify_download(self.path / 'download' / 'backup.sealed', self.record, capability,
                                        self.path / 'attempt', apply=True, transport=transport)

    def observe(self):
        """Read durable verification evidence without minting or repeating a GET."""
        blob.host_identity(self.target)
        if not self.path.exists():
            return {'state': 'not-attempted'}
        with ExitStack() as stack:
            folder, _ = blob.parent(self.path / 'offer.json', stack)
            offer = read_at(folder, 'offer.json', 4096)
            self.check_offer(offer, require_current=False)
            blob.need(read_at(folder, 'intent.json', 4096) == blob.encoded({'offer_sha256': sha(offer), **self.binding}))
            try:
                submitted = read_at(folder, 'submitted.json', 4096)
            except FileNotFoundError:
                return {'state': 'offered', 'offer': b64(offer)}
            blob.need(submitted == blob.encoded({'offer_sha256': sha(offer)}))
            try:
                attempt, _ = blob.parent(self.path / 'attempt' / 'verified.json', stack)
                raw = read_at(attempt, 'verified.json', 4096)
            except FileNotFoundError:
                return {'state': 'submitted-unknown'}
            return {'state': 'verified', 'result': self.check_result(checked_document(raw, sha(raw), 4096))}

    def check_result(self, value):
        flags = {'independent_bytes_verified': True, 'sealed_authenticated': False, 'exact_image_retained': False,
                 'restore_accepted': False, 'current_authority_established': False}
        fields = {'scope', 'blob_uri', 'ciphertext_sha256', 'ciphertext_bytes', 'etag', 'verifier_vm_id'}
        blob.need(set(value) == fields | set(flags) and all(value[key] is flag for key, flag in flags.items())
                      and value['scope'] == 'independent-native-ciphertext-verification-v1'
                      and value['blob_uri'] == self.record['blob_uri']
                      and value['ciphertext_sha256'] == self.record['complete']['ciphertext_sha256']
                      and type(value['ciphertext_bytes']) is int
                      and value['ciphertext_bytes'] == self.record['complete']['ciphertext_bytes']
                      and value['verifier_vm_id'] == self.target.vm_id and re.fullmatch(r'"[A-Za-z0-9._-]{1,128}"', value['etag']))
        return value


def dispatch(archive_bytes, request_bytes):
    """Dispatch the fixed guest operations from a digest-verified tooling archive."""
    with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
        entry = archive.getinfo(CONFIG)
        blob.need(0 < entry.file_size <= 8192)
        raw = archive.read(entry)
    config = checked_document(raw, sha(raw), 8192)
    blob.need(set(config) == {'tenant', 'subscription', 'source', 'verifier', 'store', 'record'})
    facts = config['store']
    blob.need(set(facts) == {'blob', 'region', 'owned_subnets', 'ownership_id'} and type(facts['owned_subnets']) is list)
    store = blob.Store(blob.Blob(**facts['blob']), facts['region'], tuple(facts['owned_subnets']), facts['ownership_id'])
    selection = Selection(config['tenant'], config['subscription'], store, blob.SelectedTarget(**config['source']),
                          blob.SelectedTarget(**config['verifier']))
    job = Verifier(selection, config['record'])
    request = checked_document(request_bytes, sha(request_bytes), 4096)
    verb = request['action']
    if verb == 'receive':
        blob.need(set(request) == {'action', 'packet', 'offer_sha256'})
        result = job.receive(decode(request['packet'], MAX_PACKET), request['offer_sha256'], apply=True)
        reply = {'state': 'verified', 'result': job.check_result(result)}
    else:
        blob.need(set(request) == {'action'} and verb in ('offer', 'observe'))
        reply = {'state': 'offered', 'offer': b64(job.offer(apply=True))} if verb == 'offer' else job.observe()
    return {**reply, 'scope': SCOPE, 'batch_sha256': sha(request_bytes), 'record_sha256': job.binding['record_sha256']}
