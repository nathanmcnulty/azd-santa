"""Original Unlicense. Authenticate a sealed capture without releasing plaintext.

This primitive does not extract an archive, restore services or authorize old
backup state. Callers must obtain the expected digest from a trusted external
receipt and enforce an outer process deadline for blocking filesystem I/O.
"""
import base64
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys
import time

MAGIC = b'AZDSANTABACKUP1\n'
CHUNK = 1024 * 1024


def need(value):
    if not value:
        raise ValueError('Sealed backup authentication failed')


def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result)
        result[key] = value
    return result


def decode(value, length):
    need(type(value) is str and len(value) <= 1024)
    raw = base64.b64decode(value, validate=True)
    need(len(raw) == length and base64.b64encode(raw).decode() == value)
    return raw


@dataclass(frozen=True, repr=False)
class Header:
    aad: bytes
    raw: bytes
    recipient_sha256: str
    nonce: bytes
    wrapped: bytes

    @property
    def sha256(self):
        return hashlib.sha256(self.raw).hexdigest()


@dataclass(frozen=True, repr=False)
class ContentKey:
    """One data key, valid only for the pinned ciphertext and envelope header."""

    value: bytes
    ciphertext_sha256: str
    header_sha256: str
    recipient_sha256: str


def read_header(stream, size):
    stream.seek(0)
    prefix = stream.read(len(MAGIC)+4)
    need(len(prefix) == len(MAGIC)+4 and prefix.startswith(MAGIC))
    length = struct.unpack('>I', prefix[-4:])[0]
    need(1 <= length <= 2048 and len(prefix)+length+16 < size)
    raw = stream.read(length)
    need(len(raw) == length)
    value = json.loads(raw, object_pairs_hook=unique)
    need(type(value) is dict and set(value) == {'algorithm','recipient_sha256','nonce','wrapped_key'}
         and value['algorithm'] == 'RSA-OAEP-256+A256GCM'
         and re.fullmatch('[a-f0-9]{64}', value['recipient_sha256'])
         and json.dumps(value, sort_keys=True, separators=(',', ':')).encode() == raw)
    return Header(prefix + raw, raw, value['recipient_sha256'],
                  decode(value['nonce'], 12), decode(value['wrapped_key'], 384))


def unwrap(header, key, ciphertext_sha256):
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    if type(key) is ContentKey:
        need(key.ciphertext_sha256 == ciphertext_sha256 and key.header_sha256 == header.sha256
             and key.recipient_sha256 == header.recipient_sha256)
        secret = key.value
    else:
        need(isinstance(key, rsa.RSAPrivateKey) and key.key_size == 3072
             and key.public_key().public_numbers().e == 65537)
        public = key.public_key().public_bytes(serialization.Encoding.DER,
                                              serialization.PublicFormat.SubjectPublicKeyInfo)
        need(hashlib.sha256(public).hexdigest() == header.recipient_sha256)
        secret = key.decrypt(header.wrapped, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                             algorithm=hashes.SHA256(), label=MAGIC))
    need(type(secret) is bytes and len(secret) == 32)
    return secret


def authenticate(stream, size, expected_sha256, private_key, *, maximum=32*1024**3, seconds=1800):
    """Stream-discard decrypted bytes; return only after digest AND GCM verify."""
    result, _ = _authenticate(stream, size, expected_sha256, private_key, maximum, seconds, 0)
    return result


def authenticate_prefix(stream, size, expected_sha256, private_key, *, prefix_limit, maximum, seconds):
    """Return a bounded plaintext prefix only after verifying the whole seal."""
    need(type(prefix_limit) is int and 1 <= prefix_limit <= CHUNK + 8192)
    return _authenticate(stream, size, expected_sha256, private_key, maximum, seconds, prefix_limit)


def _authenticate(stream, size, expected_sha256, private_key, maximum, seconds, prefix_limit):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    need(type(maximum) is int and CHUNK <= maximum <= 32*1024**3
         and type(size) is int and len(MAGIC)+4+16 < size <= maximum
         and type(seconds) is int and 1 <= seconds <= 7200)
    need(type(expected_sha256) is str and re.fullmatch('[a-f0-9]{64}', expected_sha256))
    deadline = time.monotonic() + seconds
    header = read_header(stream, size)
    key = unwrap(header, private_key, expected_sha256)
    need(time.monotonic() < deadline)
    offset = len(header.aad)
    stream.seek(size-16); tag = stream.read(16); need(len(tag) == 16)
    decryptor = Cipher(algorithms.AES256(key), modes.GCM(header.nonce, tag)).decryptor()
    aad = header.aad
    decryptor.authenticate_additional_data(aad)
    hasher = hashlib.sha256(aad)
    stream.seek(offset)
    remaining = size-offset-16
    plaintext_bytes = 0
    retained = bytearray()
    while remaining:
        need(time.monotonic() < deadline)
        chunk = stream.read(min(CHUNK, remaining))
        need(0 < len(chunk) <= remaining)
        hasher.update(chunk)
        plaintext = decryptor.update(chunk)
        plaintext_bytes += len(plaintext)
        if len(retained) < prefix_limit:
            retained.extend(plaintext[:prefix_limit - len(retained)])
        remaining -= len(chunk)
    need(stream.read(16) == tag and stream.read(1) == b'')
    hasher.update(tag)
    tail = decryptor.finalize()
    plaintext_bytes += len(tail)
    retained.extend(tail[:prefix_limit - len(retained)])
    need(hasher.hexdigest() == expected_sha256 and time.monotonic() < deadline)
    return dict(scope='sealed-backup-ciphertext-authentication-v1', ciphertext_sha256=expected_sha256,
                ciphertext_bytes=size, plaintext_bytes=plaintext_bytes, recipient_sha256=header.recipient_sha256,
                header_sha256=header.sha256, plaintext_released=prefix_limit > 0,
                limitation='No archive/extraction, compatibility, current authority or application restore proof'), bytes(retained)


def identity(info):
    return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_nlink,
            info.st_size,info.st_mtime_ns,info.st_ctime_ns)


def verify_file(path, expected_sha256, private_key, **limits):
    """Linux owner-private regular file, one stable descriptor, no output files."""
    need(sys.platform == 'linux')
    need(os.geteuid() == 0)
    path = Path(path)
    need(path.is_absolute() and path == path.resolve(strict=True))
    for parent in path.parents:
        info = parent.stat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o022)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
             and not before.st_mode & 0o077 and before.st_nlink == 1)
        result = authenticate(stream, before.st_size, expected_sha256, private_key, **limits)
        need(identity(os.fstat(stream.fileno())) == identity(before)
             and identity(path.lstat()) == identity(before))
        return result
