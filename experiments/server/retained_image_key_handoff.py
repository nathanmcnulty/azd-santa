"""Delegate one retained image data key to the selected receiver boot."""

from contextlib import ExitStack
import hashlib
import io
import os
from pathlib import Path
import re
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

import blob_retention as blob
from cold_backup import recipient_key
import restore_cipher as cipher
from restore_recipient_key import private_input
from retained_image_delivery import read_at, write_at
from retained_image_export import IMAGE_NAMES
from retained_image_handoff import b64, boot, decode, sha
from retained_image_load import verify_or_load
from retained_image_parts import checked_completion, checked_document

SCOPE = 'azd-santa-retained-image-key-handoff-v1'
DOMAIN = b'azd-santa/retained-image-key-handoff/v1\0'
LIFETIME = 600


def oaep(offer):
    return padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(),
                        label=DOMAIN + hashlib.sha256(offer).digest())


class Handoff:
    def __init__(self, target, completion, *, completion_sha256, inventory_sha256,
                 recipient_sha256, image_name, image_id, boot_id):
        record = checked_completion(completion, completion_sha256)
        blob.need(type(target) is blob.SelectedTarget and re.fullmatch(blob.GUID, boot_id)
                  and image_name in IMAGE_NAMES and image_id == record['image_id']
                  and all(type(pin) is str and re.fullmatch(blob.HEX, pin)
                          for pin in (inventory_sha256, recipient_sha256)))
        self._target = target
        self._completion = completion
        self._context = dict(scope=SCOPE, vm_id=target.vm_id, vm_instance_id=target.instance_id,
            region=target.region, boot_id=boot_id, image_name=image_name, image_id=image_id,
            completion_sha256=completion_sha256, inventory_sha256=inventory_sha256,
            recipient_sha256=recipient_sha256, ciphertext_sha256=record['ciphertext_sha256'],
            ciphertext_bytes=record['ciphertext_bytes'])

    def _path(self, root):
        return Path(root) / (self._context['completion_sha256'] + '-' + self._context['boot_id'])

    def _check(self, offer, offer_sha256):
        document = checked_document(offer, offer_sha256, 6144)
        blob.need(set(document) == set(self._context) | {'header', 'key', 'created', 'expires'}
                  and all(document[name] == value for name, value in self._context.items())
                  and type(document['created']) is int and type(document['expires']) is int
                  and document['created'] <= int(time.time()) < document['expires'] == document['created'] + LIFETIME)
        aad = decode(document['header'], 4096)
        header = cipher.read_header(io.BytesIO(aad), document['ciphertext_bytes'])
        blob.need(header.aad == aad and header.recipient_sha256 == document['recipient_sha256'])
        return header, recipient_key(decode(document['key'], 1024))

    def offer(self, source, root, *, _boot=boot):
        """Inspect the exact independent copy before reserving a boot-local key."""
        try:
            blob.need(_boot(self._target) == self._context['boot_id'])
            with ExitStack() as guards:
                maximum = self._context['ciphertext_bytes']
                stream, size, unchanged = private_input(source, guards, maximum)
                blob.need(size == maximum)
                header = cipher.read_header(stream, size)
                stream.seek(0)
                blob.need(hashlib.file_digest(stream, 'sha256').hexdigest() == self._context['ciphertext_sha256'])
                unchanged()
                key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
                public = key.public_key().public_bytes(serialization.Encoding.DER,
                                                       serialization.PublicFormat.SubjectPublicKeyInfo)
                now = int(time.time())
                offer = blob.encoded({**self._context, 'header': b64(header.aad), 'key': b64(public),
                                      'created': now, 'expires': now + LIFETIME})
                digest = sha(offer)
                self._check(offer, digest)
                state = blob.Journal(self._path(root), {'offer_sha256': digest}, guards)
                write_at(state.fd, 'recipient.der', key.private_bytes(serialization.Encoding.DER,
                         serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
                write_at(state.fd, 'offer.json', offer)
            return offer
        except Exception:
            raise blob.RetentionRejected('Could not prepare the retained image offer') from None

    def seal(self, offer, offer_sha256, original_key):
        """Unwrap only the matched data key on the operator workstation."""
        try:
            header, recipient = self._check(offer, offer_sha256)
            blob.need(isinstance(original_key, rsa.RSAPrivateKey))
            secret = cipher.unwrap(header, original_key, self._context['ciphertext_sha256'])
            return recipient.encrypt(secret, oaep(offer))
        except Exception:
            raise blob.RetentionRejected('Could not delegate the retained image key') from None

    def load(self, source, root, offer_sha256, envelope, envelope_sha256, *, socket, staging, attempt,
             seconds=600, _boot=boot):
        """Consume the sealed data key once and use the existing authenticated loader."""
        try:
            blob.need(socket is not None and attempt is not None and _boot(self._target) == self._context['boot_id']
                      and type(envelope) is bytes and len(envelope) == 384 and sha(envelope) == envelope_sha256)
            with ExitStack() as guards:
                folder, name = blob.parent(self._path(root) / 'offer.json', guards)
                offer = read_at(folder, name, 6144)
                header, public = self._check(offer, offer_sha256)
                blob.need(read_at(folder, 'intent.json', 4096) == blob.encoded({'offer_sha256': offer_sha256}))
                private = serialization.load_der_private_key(read_at(folder, 'recipient.der', 8192), password=None)
                blob.need(isinstance(private, rsa.RSAPrivateKey)
                          and private.public_key().public_numbers() == public.public_numbers())
                write_at(folder, 'consumed.json', blob.encoded({'envelope_sha256': envelope_sha256}))
                os.unlink('recipient.der', dir_fd=folder)
                os.fsync(folder)
            secret = private.decrypt(envelope, oaep(offer))
            key = cipher.ContentKey(secret, self._context['ciphertext_sha256'], header.sha256, header.recipient_sha256)
            return verify_or_load(source, self._completion, key, staging,
                **{name: self._context[name] for name in ('completion_sha256', 'inventory_sha256',
                                                        'image_name', 'image_id')},
                socket=socket, attempt=attempt, seconds=seconds)
        except Exception:
            raise blob.RetentionRejected('Retained image load rejected or unknown; preserve the journal') from None
