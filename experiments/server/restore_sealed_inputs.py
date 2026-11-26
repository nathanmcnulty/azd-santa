"""Seal the private inputs for one confirmed Santa recovery step."""

from contextlib import ExitStack
from dataclasses import asdict
from datetime import datetime
import hashlib
import hmac
import os
from pathlib import Path
import threading
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import blob_retention as blob
from cold_backup import recipient_key
from retained_image_delivery import read_at, write_at
from retained_image_handoff import b64, boot, decode
from retained_image_parts import checked_document
import restore_authority_transaction as authority
import restore_census as census
import restore_census_review as review
from restore_guest_job import Job
import restore_quarantine_journal as journal
from secret_rewrap import MAX_BYTES, Material

SCOPE = 'santa-restore-input-offer-v1'
DOMAIN = b'azd-santa/restore-inputs/v1\0'
WRAPPED_BYTES = 384
NONCE_BYTES = 12
MAX_OPTIONS = MAX_BYTES
MAX_PAYLOAD = 36 + review.MAX_REVIEW_BYTES + MAX_OPTIONS
MAX_PACKET = WRAPPED_BYTES + NONCE_BYTES + MAX_PAYLOAD + 16
RECIPIENT_ROOT = Path('/run/azd-santa-recovery-recipients')


class InputRejected(ValueError):
    pass


def require(condition):
    if not condition:
        raise InputRejected('Sealed restore inputs rejected; retain the private recovery evidence')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def oaep():
    return padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=DOMAIN)


def operation(job, stage, binding, review_sha256, plan_digest):
    require(type(job) is Job and stage in journal.STAGES
            and all(journal.is_digest(value) for value in (binding, review_sha256, plan_digest)))
    return dict(scope=SCOPE, stage=stage, binding=binding, review_sha256=review_sha256,
                plan_digest=plan_digest, boot_id=job.verified_boot_id)


def check_offer(raw, digest, expected):
    value = checked_document(raw, digest, 4096)
    require(set(value) == set(expected) | {'key', 'created', 'expires'}
            and all(value[name] == item for name, item in expected.items())
            and type(value['created']) is int and type(value['expires']) is int
            and value['created'] <= int(time.time()) < value['expires'] == value['created'] + 600)
    return recipient_key(decode(value['key'], 1024))


def encode_options(stage, options):
    require(type(options) is dict and set(options) == journal.OPTIONS[stage])
    if stage == 'quarantine':
        cutoff = options['cutoff']
        require(type(cutoff) is datetime and cutoff.utcoffset() is not None)
        return review.encode({'cutoff': cutoff.isoformat()})
    return review.encode({**options, **{name: {engine: asdict(material) for engine, material in options[name].items()}
                                      for name in ('old_material', 'new_material')}})


def decode_options(stage, raw):
    value = census.parse(raw)
    require(type(value) is dict and set(value) == journal.OPTIONS[stage])
    if stage == 'quarantine':
        value['cutoff'] = datetime.fromisoformat(value['cutoff'])
    else:
        for name in ('old_material', 'new_material'):
            require(type(value[name]) is dict)
            for engine, material in value[name].items():
                require(type(material) is dict and set(material) == {'kind', 'passwords', 'signing_salt'}
                        and type(material['passwords']) is list)
                value[name][engine] = Material(material['kind'], tuple(material['passwords']), material['signing_salt'])
    require(raw == encode_options(stage, value))
    return value


def seal(job, offer, offer_sha256, *, stage, review_bytes, review_sha256, plan_digest, fingerprint_key, options):
    """Seal to the exact guest offer delivered by the trusted operator channel."""
    try:
        expected = operation(job, stage, job.binding(fingerprint_key), review_sha256, plan_digest)
        public = check_offer(offer, offer_sha256, expected)
        review.load(review_bytes, review_sha256, binding=expected['binding'], stage=stage)
        encoded = encode_options(stage, options)
        require(0 < len(encoded) <= MAX_OPTIONS)
        data = fingerprint_key + len(review_bytes).to_bytes(4, 'big') + review_bytes + encoded
        key, nonce = AESGCM.generate_key(bit_length=256), os.urandom(NONCE_BYTES)
        return public.encrypt(key, oaep()) + nonce + AESGCM(key).encrypt(nonce, data, DOMAIN + offer)
    except Exception:
        raise InputRejected('Could not seal the reviewed restore inputs') from None


class Recipient:
    """One ephemeral guest recipient. Offers and ciphertext confer no operator authority."""

    def __init__(self, job, *, stage, binding, review_sha256, plan_digest):
        self._job = job
        self._expected = operation(job, stage, binding, review_sha256, plan_digest)
        self._key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        public = self._key.public_key().public_bytes(serialization.Encoding.DER,
                                                    serialization.PublicFormat.SubjectPublicKeyInfo)
        now = int(time.time())
        self.offer = review.encode({**self._expected, 'key': b64(public), 'created': now, 'expires': now + 600})
        self._lock = threading.Lock()

    def run_approved(self, plan, plan_sha256, receipt, approval, public_key, public_key_sha256,
                     writer, observer, registry, *, directory, carrier_root=None):
        """Verify the operator's signature before opening the isolated recovery packet."""
        from restore_operator_approval import Verify

        authorize = Verify(public_key, public_key_sha256, approval, self._job, self.offer,
                           plan, plan_sha256, receipt)
        return self.run_received(plan, plan_sha256, receipt, writer, observer, registry,
                                 directory=directory, authorize=authorize, carrier_root=carrier_root)

    def run_received(self, plan, plan_sha256, receipt, writer, observer, registry, *,
                     directory, authorize, carrier_root=None):
        """Verify the approved transfer and local ciphertext before consuming this offer."""
        from restore_packet_operator import CARRIER_ROOT, received_packet

        try:
            require(authority.read_target(observer) == self._job.target)
            root = CARRIER_ROOT if carrier_root is None else carrier_root
            packet = received_packet(self._job, plan, plan_sha256, receipt, root=root)
        except Exception:
            raise InputRejected('Verified restore packet did not match the approved delivery') from None
        return self.run(packet, plan['packet_sha256'], writer, observer, registry,
                        directory=directory, authorize=authorize)

    def run(self, packet, packet_sha256, writer, observer, registry, *, directory, authorize):
        """Consume pinned ciphertext and call the existing isolated database job."""
        try:
            with self._lock:
                require(callable(authorize)
                        and type(packet) is bytes and WRAPPED_BYTES + NONCE_BYTES + 16 < len(packet) <= MAX_PACKET
                        and journal.is_digest(packet_sha256) and hmac.compare_digest(sha(packet), packet_sha256))
                public = check_offer(self.offer, sha(self.offer), self._expected)
                key = self._take_key(public)
                offset = WRAPPED_BYTES + NONCE_BYTES
                content_key = key.decrypt(packet[:WRAPPED_BYTES], oaep())
                raw = AESGCM(content_key).decrypt(packet[WRAPPED_BYTES:offset], packet[offset:], DOMAIN + self.offer)
            size = int.from_bytes(raw[32:36], 'big')
            require(0 < size <= review.MAX_REVIEW_BYTES and 0 < len(raw) - 36 - size <= MAX_OPTIONS)
            fingerprint_key = raw[:32]
            require(hmac.compare_digest(self._job.binding(fingerprint_key), self._expected['binding']))
            stage = self._expected['stage']
            options = decode_options(stage, raw[36 + size:])
        except Exception:
            raise InputRejected('Could not open the reviewed restore inputs') from None
        return self._job.run(writer, observer, registry, directory=directory, fingerprint_key=fingerprint_key,
                             stage=stage, review_bytes=raw[36:36 + size], review_sha256=self._expected['review_sha256'],
                             options=options, plan_digest=self._expected['plan_digest'], authorize=authorize)

    def _take_key(self, _public):
        key, self._key = self._key, None
        require(key is not None)
        return key


class BootRecipient:
    """Keep one guest offer available across commands on the same boot."""

    @staticmethod
    def _verify_host(job, target, get_boot):
        require(type(job) is Job)
        selected = job.selection
        require(type(target) is blob.SelectedTarget
                and blob.resource_id(target.vm_id) == blob.resource_id(selected.vm_id)
                and target.instance_id == selected.vm_instance_id and target.region == selected.region
                and get_boot(target) == job.verified_boot_id)

    @classmethod
    def prepare(cls, job, target, public_key_sha256, *, stage, binding, review_sha256, plan_digest,
                root=RECIPIENT_ROOT, _boot=boot):
        """Publish a public offer and persist its key with the pinned operator key digest."""
        try:
            cls._verify_host(job, target, _boot)
            require(journal.is_digest(public_key_sha256))
            recipient = Recipient(job, stage=stage, binding=binding,
                                  review_sha256=review_sha256, plan_digest=plan_digest)
            digest = sha(recipient.offer)
            root = Path(root)
            root.mkdir(mode=0o700, exist_ok=True)
            intent = {'offer_sha256': digest, 'public_key_sha256': public_key_sha256}
            with ExitStack() as stack:
                state = blob.Journal(root / digest, intent, stack)
                key = recipient._key.private_bytes(serialization.Encoding.DER,
                    serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
                write_at(state.fd, 'recipient.der', key)
                write_at(state.fd, 'offer.json', recipient.offer)
            return recipient.offer
        except Exception:
            raise InputRejected('Could not prepare the boot-local restore recipient') from None

    def __init__(self, job, target, offer_sha256, *, stage, binding, review_sha256, plan_digest,
                 root=RECIPIENT_ROOT, _boot=boot):
        try:
            self._verify_host(job, target, _boot)
            require(journal.is_digest(offer_sha256))
            expected = operation(job, stage, binding, review_sha256, plan_digest)
            self._recipient = _StoredRecipient(job, expected, Path(root) / offer_sha256)
        except Exception:
            raise InputRejected('Could not reopen the boot-local restore recipient') from None

    def apply(self, plan, plan_sha256, receipt, approval, public_key, writer, observer, registry, *,
              directory, carrier_root=None):
        """Use the operator key selected when the offer was created."""
        return self._recipient.run_approved(plan, plan_sha256, receipt, approval, public_key,
            self._recipient.operator_pin, writer, observer, registry, directory=directory, carrier_root=carrier_root)


class _StoredRecipient(Recipient):
    def __init__(self, job, expected, path):
        self._job = job
        self._expected = expected
        self._path = path
        self._lock = threading.Lock()
        with ExitStack() as stack:
            folder, name = blob.parent(path / 'offer.json', stack)
            self.offer = read_at(folder, name, 4096)
            check_offer(self.offer, path.name, expected)
            raw = read_at(folder, 'intent.json', 1024)
            intent = checked_document(raw, sha(raw), 1024)
            require(set(intent) == {'offer_sha256', 'public_key_sha256'}
                    and intent['offer_sha256'] == path.name and journal.is_digest(intent['public_key_sha256']))
            self.operator_pin = intent['public_key_sha256']

    def _take_key(self, public):
        with ExitStack() as stack:
            folder, name = blob.parent(self._path / 'recipient.der', stack)
            key = serialization.load_der_private_key(read_at(folder, name, 8192), password=None)
            require(isinstance(key, rsa.RSAPrivateKey)
                    and key.public_key().public_numbers() == public.public_numbers())
            write_at(folder, 'consumed.json', review.encode({'offer_sha256': self._path.name}))
            os.unlink(name, dir_fd=folder)
            os.fsync(folder)
        return key
