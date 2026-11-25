"""Original Unlicense. Authenticate a sealed capture without releasing plaintext.

This primitive does not extract an archive, restore services or authorize old
backup state. Callers must obtain the expected digest from a trusted external
receipt and enforce an outer process deadline for blocking filesystem I/O.
"""
import base64
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


def authenticate(stream, size, expected_sha256, private_key, *, maximum=32*1024**3, seconds=1800):
    """Stream-discard decrypted bytes; return only after digest AND GCM verify."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    need(type(maximum) is int and CHUNK <= maximum <= 32*1024**3
         and type(size) is int and len(MAGIC)+4+16 < size <= maximum
         and type(seconds) is int and 1 <= seconds <= 7200)
    need(type(expected_sha256) is str and re.fullmatch('[a-f0-9]{64}', expected_sha256))
    need(isinstance(private_key, rsa.RSAPrivateKey) and private_key.key_size == 3072
         and private_key.public_key().public_numbers().e == 65537)
    deadline = time.monotonic() + seconds
    stream.seek(0)
    prefix = stream.read(len(MAGIC)+4)
    need(len(prefix) == len(MAGIC)+4 and prefix.startswith(MAGIC))
    length = struct.unpack('>I', prefix[-4:])[0]
    need(1 <= length <= 2048 and len(prefix)+length+16 < size)
    header = stream.read(length)
    need(len(header) == length)
    document = json.loads(header, object_pairs_hook=unique)
    need(type(document) is dict and set(document) == {'algorithm','recipient_sha256','nonce','wrapped_key'}
         and document['algorithm'] == 'RSA-OAEP-256+A256GCM'
         and json.dumps(document, sort_keys=True, separators=(',', ':')).encode() == header)
    public = private_key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    recipient = hashlib.sha256(public).hexdigest()
    need(document['recipient_sha256'] == recipient)
    nonce = decode(document['nonce'], 12)
    wrapped = decode(document['wrapped_key'], 384)
    key = private_key.decrypt(wrapped, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=MAGIC))
    need(len(key) == 32 and time.monotonic() < deadline)
    offset = len(prefix)+length
    stream.seek(size-16); tag = stream.read(16); need(len(tag) == 16)
    decryptor = Cipher(algorithms.AES256(key), modes.GCM(nonce, tag)).decryptor()
    aad = prefix+header
    decryptor.authenticate_additional_data(aad)
    hasher = hashlib.sha256(aad)
    stream.seek(offset)
    remaining = size-offset-16
    plaintext_bytes = 0
    while remaining:
        need(time.monotonic() < deadline)
        chunk = stream.read(min(CHUNK, remaining))
        need(0 < len(chunk) <= remaining)
        hasher.update(chunk)
        # No callback, output stream, archive parser or plaintext file exists.
        plaintext_bytes += len(decryptor.update(chunk))
        remaining -= len(chunk)
    need(stream.read(16) == tag and stream.read(1) == b'')
    hasher.update(tag)
    plaintext_bytes += len(decryptor.finalize())
    need(hasher.hexdigest() == expected_sha256 and time.monotonic() < deadline)
    return dict(scope='sealed-backup-ciphertext-authentication-v1', ciphertext_sha256=expected_sha256,
                ciphertext_bytes=size, plaintext_bytes=plaintext_bytes, recipient_sha256=recipient,
                header_sha256=hashlib.sha256(header).hexdigest(), plaintext_released=False,
                limitation='No archive/extraction, compatibility, current authority or application restore proof')


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
