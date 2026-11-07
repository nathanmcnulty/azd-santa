"""Original Unlicense recipient-only setup-link envelope, not sender authentication.

The Azure/host authority and selected deployment binding must be verified by the
caller. No private key or cleartext setup URL is included in the exported object.
"""
import base64
from dataclasses import dataclass
import hashlib
import json
import math
import re
import secrets
import struct
from urllib.parse import urlsplit

ALGORITHM = 'RSA-OAEP-256+A256GCM'
SCOPE = 'azd-santa-sealed-setup'
MAX_ENVELOPE_BYTES = 2600  # Leave room for Run Command's ~4 KiB output framing.


class SealedSetupError(ValueError):
    pass


def require(condition):
    if not condition:
        raise SealedSetupError('Invalid or unsupported sealed setup input')


def target_digest(username, email):
    require(isinstance(username, str) and isinstance(email, str))
    values = [value.encode('utf-8') for value in (username, email)]
    require(all(len(value) <= 2048 for value in values))
    return hashlib.sha256(b''.join(struct.pack('>I', len(value)) + value for value in values)).hexdigest()


def origin(value):
    require(isinstance(value, str) and value.isascii() and len(value) <= 256)
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        raise SealedSetupError('Invalid or unsupported sealed setup input') from None
    require(parsed.scheme == 'https' and parsed.hostname and not parsed.username and not parsed.password
            and not parsed.query and not parsed.fragment and parsed.path in ('', '/')
            and re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', parsed.hostname)
            and (port is None or 1 <= port <= 65535))
    return 'https://' + parsed.hostname.lower() + (':' + str(port) if port and port != 443 else '')


def aad(mode, kid, context, target):
    return ('azd-santa-operator-setup/v1|' + ALGORITHM + '|' + mode + '|' + kid + '|' + context + '|' + target).encode('ascii')


@dataclass(frozen=True)
class Recipient:
    key: object
    kid: str
    context: str
    target: str
    mode: str
    expected_origin: str

    def _encrypt(self, payload):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        key = AESGCM.generate_key(bit_length=256)
        nonce = secrets.token_bytes(12)
        ciphertext = AESGCM(key).encrypt(nonce, json.dumps(payload, separators=(',', ':'), ensure_ascii=False).encode('utf-8'),
                                         aad(self.mode, self.kid, self.context, self.target))
        wrapped = self.key.encrypt(key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        encode = lambda value: base64.b64encode(value).decode('ascii')
        result = dict(scope=SCOPE, version=1, algorithm=ALGORITHM, mode=self.mode,
                      kid_sha256=self.kid, context_sha256=self.context, target_sha256=self.target,
                      wrapped_key_base64=encode(wrapped), nonce_base64=encode(nonce),
                      ciphertext_base64=encode(ciphertext))
        require(len(json.dumps(result, separators=(',', ':')).encode('ascii')) <= MAX_ENVELOPE_BYTES)
        return result

    def seal(self, artifact):
        require(artifact['mode'] == self.mode
                and target_digest(artifact['target']['username'], artifact['target']['email']) == self.target)
        value = artifact['setup_url']
        require(isinstance(value, str) and value.isascii() and len(value) <= 768)
        parsed = urlsplit(value)
        path = re.fullmatch(r'/accounts/reset/(?P<uid>[A-Za-z0-9_-]{1,32})/[0-9a-z]{1,16}-[0-9a-f]{32}/', parsed.path)
        require(origin('https://' + parsed.netloc) == self.expected_origin
                and parsed.scheme == 'https' and not parsed.query and not parsed.fragment
                and path)
        pk, expires = artifact['target']['pk'], artifact['expires_at_unix']
        require(type(pk) is int and 1 <= pk <= 2**63 - 1
                and type(expires) in (int, float) and math.isfinite(expires) and expires > 0)
        uid = path.group('uid')
        require(base64.urlsafe_b64decode(uid + '=' * (-len(uid) % 4)).decode('ascii') == str(pk))
        return self._encrypt(dict(setup_url=value, expires_at_unix=expires, target_pk=pk))


def prepare_recipient(public_key_base64, context_sha256, mode, username, email, setup_origin):
    # All key/algorithm/context/origin checks and a maximum-size encryption check
    # happen before the caller reserves output or changes user security state.
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    require(mode in ('bootstrap', 'recover') and isinstance(context_sha256, str)
            and re.fullmatch(r'[0-9a-f]{64}', context_sha256))
    require(isinstance(public_key_base64, str) and len(public_key_base64) <= 1024)
    try:
        raw = base64.b64decode(public_key_base64, validate=True)
        require(base64.b64encode(raw).decode('ascii') == public_key_base64)
        key = serialization.load_der_public_key(raw)
    except (ValueError, TypeError):
        raise SealedSetupError('Invalid or unsupported recipient public key') from None
    require(isinstance(key, rsa.RSAPublicKey) and key.key_size == 3072
            and key.public_numbers().e == 65537
            and key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) == raw)
    recipient = Recipient(key, hashlib.sha256(raw).hexdigest(), context_sha256,
                          target_digest(username, email), mode, origin(setup_origin))
    # Maximum supported URL/ID/expiry budget, independently of verbose Unicode
    # identity/reason metadata in the private unsealed qualification artifact.
    recipient._encrypt(dict(setup_url='x' * 768, expires_at_unix=9999999999.999999, target_pk=2**63 - 1))
    return recipient
