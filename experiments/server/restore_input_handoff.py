"""Deliver one exact-object SAS to the selected Santa recovery transfer VM."""

from contextlib import ExitStack
import os
from pathlib import Path
import re
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import blob_retention as blob
from cold_backup import recipient_key
import private_arm_adapter as arm
from restore_input_blob import PacketTransfer
from retained_image_blob import capability
from retained_image_delivery import read_at, write_at
from retained_image_handoff import b64, boot, decode, oaep, sha
from retained_image_parts import checked_document
from retained_image_sas import IssuedBatch

OFFER_SCOPE = 'santa-restore-input-sas-offer-v1'
DOMAIN = b'azd-santa/restore-input-sas/v1\0'
MAX_ENVELOPE = 384 + 12 + 4096 + 16


class Handoff:
    """The operator supplies the exact guest boot and trusted offer digest."""

    def __init__(self, selection, transfer, permission, *, boot_id):
        arm.require(type(selection) is arm.Selection and type(transfer) is PacketTransfer
                    and selection.store == transfer.store and selection.verifier == transfer.target
                    and permission in ('c', 'r') and re.fullmatch(blob.GUID, boot_id))
        selection.intent()
        chosen = transfer.job.selection
        arm.require(selection.tenant == chosen.tenant and selection.subscription == chosen.subscription
                    and selection.source.instance_id != selection.verifier.instance_id
                    and blob.resource_id(selection.source.vm_id) != blob.resource_id(selection.verifier.vm_id)
                    and (permission == 'c' or boot_id == transfer.job.verified_boot_id))
        self._transfer = transfer
        self._target = selection.source if permission == 'c' else selection.verifier
        self._permission = permission
        self._boot_id = boot_id
        self._part = transfer.object_metadata()
        self._context = dict(scope=OFFER_SCOPE, tenant=selection.tenant, account_id=selection.store.blob.account_id,
                             vm_id=self._target.vm_id, instance_id=self._target.instance_id, boot_id=boot_id,
                             permission=permission, object=self._part['object'],
                             packet_sha256=transfer.packet_sha256, packet_bytes=transfer.packet_bytes)

    def _path(self, root):
        return Path(root) / (self._transfer.packet_sha256 + '-sas-offer-' + self._permission)

    def _check(self, raw, digest):
        value = checked_document(raw, digest, 4096)
        blob.need(set(value) == set(self._context) | {'key', 'created', 'expires'}
                  and all(value[name] == expected for name, expected in self._context.items())
                  and type(value['created']) is int and type(value['expires']) is int
                  and value['created'] <= int(time.time()) < value['expires'] == value['created'] + 1800)
        return value, recipient_key(decode(value['key'], 1024))

    def _token(self, token, expiry):
        selected = capability(self._transfer.store, self._target, self._part, token, self._permission)
        blob.need(selected.expires.timestamp() <= expiry)
        return selected._token

    def offer(self, root, *, _boot=boot):
        """Write the temporary private recipient on its selected boot."""
        try:
            blob.need(_boot(self._target) == self._boot_id)
            key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
            public = key.public_key().public_bytes(serialization.Encoding.DER,
                                                   serialization.PublicFormat.SubjectPublicKeyInfo)
            now = int(time.time())
            raw = blob.encoded({**self._context, 'created': now, 'expires': now + 1800, 'key': b64(public)})
            self._check(raw, sha(raw))
            with ExitStack() as stack:
                journal = blob.Journal(self._path(root), {'offer_sha256': sha(raw)}, stack)
                write_at(journal.fd, 'recipient.der', key.private_bytes(serialization.Encoding.DER,
                         serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
                write_at(journal.fd, 'offer.json', raw)
            return raw
        except Exception:
            raise blob.RetentionRejected('Restore SAS recipient could not be prepared') from None

    def seal(self, raw, digest, batch):
        """Return ciphertext only, using the offer obtained on the trusted channel."""
        try:
            offer, public = self._check(raw, digest)
            blob.need(type(batch) is IssuedBatch and batch.account_id == self._transfer.store.blob.account_id)
            tokens = batch.take(self._target, self._permission, self._transfer.packet_sha256)
            blob.need(set(tokens) == {self._part['object']})
            token = self._token(tokens[self._part['object']], offer['expires'])
            key, nonce = AESGCM.generate_key(bit_length=256), os.urandom(12)
            return public.encrypt(key, oaep()) + nonce + AESGCM(key).encrypt(nonce, token.encode('ascii'), DOMAIN + raw)
        except Exception:
            raise blob.RetentionRejected('Restore SAS could not be sealed for the selected guest') from None

    def use(self, root, envelope, offer_sha256, envelope_sha256, *, packet=None, _boot=boot, _transport=None):
        """Consume the exact capability and run its one permitted transfer."""
        try:
            blob.need((self._permission == 'c' and type(packet) is bytes)
                      or (self._permission == 'r' and packet is None))
            blob.need(type(envelope) is bytes and 412 < len(envelope) <= MAX_ENVELOPE
                      and sha(envelope) == envelope_sha256)
            path = self._path(root)
            with ExitStack() as stack:
                folder, _ = blob.parent(path / 'offer.json', stack)
                raw = read_at(folder, 'offer.json', 4096)
                offer, public = self._check(raw, offer_sha256)
                blob.need(_boot(self._target) == self._boot_id
                          and read_at(folder, 'intent.json', 4096) == blob.encoded({'offer_sha256': offer_sha256}))
                private = serialization.load_der_private_key(read_at(folder, 'recipient.der', 8192), password=None)
                blob.need(isinstance(private, rsa.RSAPrivateKey)
                          and private.public_key().public_numbers() == public.public_numbers())
                write_at(folder, 'consumed.json', blob.encoded({'envelope_sha256': envelope_sha256}))
                os.unlink('recipient.der', dir_fd=folder)
                os.fsync(folder)
                key = private.decrypt(envelope[:384], oaep())
                token = AESGCM(key).decrypt(envelope[384:396], envelope[396:], DOMAIN + raw).decode('ascii')
                token = self._token(token, offer['expires'])
            if self._permission == 'c':
                return self._transfer.upload(packet, token, path, _transport=_transport)
            return self._transfer.download(token, _boot=_boot, _transport=_transport)
        except Exception:
            raise blob.RetentionRejected('Restore SAS transfer rejected or unknown; preserve its journal') from None
