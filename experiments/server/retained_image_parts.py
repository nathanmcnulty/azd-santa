"""Original Unlicense. Plan and independently verify ordered encrypted image parts."""

import hashlib
import os
import re
import time

from restore_cipher import CHUNK
from retained_image_archive import ARCHIVE_MAXIMUM, parse
from retained_image_export import encoded
from retention_image_inventory import HEX, IMAGE_ID

PART_BYTES = 512 * 1024**2
MAX_PARTS = 33
MAX_MANIFEST = 32 * 1024
SCOPE = 'azd-santa-retained-image-parts-v1'


class PartsRejected(ValueError):
    pass


def need(condition):
    if not condition:
        raise PartsRejected('Santa image transfer parts rejected; preserve the existing artifacts')


def checked_document(raw, digest, maximum):
    need(type(raw) is bytes and 0 < len(raw) <= maximum and hashlib.sha256(raw).hexdigest() == digest)
    value = parse(raw)
    need(type(value) is dict and encoded(value) == raw)
    return value


def checked_completion(raw, digest):
    value = checked_document(raw, digest, 4096)
    need(set(value) == {'scope', 'image_id', 'intent_sha256', 'archive_bytes', 'archive_sha256',
                       'ciphertext_bytes', 'ciphertext_sha256'}
         and value['scope'] == 'azd-santa-retained-image-export-v1'
         and type(value['image_id']) is str and re.fullmatch(IMAGE_ID, value['image_id']))
    for field in ('intent_sha256', 'archive_sha256', 'ciphertext_sha256'):
        need(type(value[field]) is str and re.fullmatch(HEX, value[field]))
    archive_bytes = value['archive_bytes']
    size = value['ciphertext_bytes']
    need(type(archive_bytes) is int and 1024 <= archive_bytes <= ARCHIVE_MAXIMUM
         and type(size) is int and archive_bytes < size <= archive_bytes + 4096)
    return value


def start(seconds, operation):
    need(type(seconds) is int and 1 <= seconds <= 1800
         and type(operation) is str and re.fullmatch(r'[a-f0-9]{32}', operation))
    return time.monotonic() + seconds


def layout(size, operation):
    count = (size + PART_BYTES - 1) // PART_BYTES
    need(0 < count <= MAX_PARTS)
    for index in range(count):
        offset = index * PART_BYTES
        yield {'index': index, 'offset': offset, 'bytes': min(PART_BYTES, size - offset),
               'object': f'image-artifacts/{operation}/{index:03d}.sealed-part'}


def hash_part(stream, size, whole, deadline, output=None):
    sha256 = hashlib.sha256()
    md5 = hashlib.md5(usedforsecurity=False)
    while size:
        need(time.monotonic() < deadline)
        raw = stream.read(min(size, CHUNK))
        need(type(raw) is bytes and 0 < len(raw) <= min(size, CHUNK))
        sha256.update(raw)
        md5.update(raw)
        whole.update(raw)
        size -= len(raw)
        if output is not None:
            need(output.write(raw) == len(raw))
    return {'sha256': sha256.hexdigest(), 'md5': md5.hexdigest()}


def plan(stream, completion_raw, *, completion_sha256, operation, seconds=600):
    """Read exact ciphertext once, emitting no part files or transfer requests."""
    try:
        deadline = start(seconds, operation)
        record = checked_completion(completion_raw, completion_sha256)
        size = record['ciphertext_bytes']
        whole = hashlib.sha256()
        stream.seek(0)
        parts = [{**part, **hash_part(stream, part['bytes'], whole, deadline)} for part in layout(size, operation)]
        need(stream.read(1) == b'' and whole.hexdigest() == record['ciphertext_sha256']
             and time.monotonic() < deadline)
        manifest = encoded({'scope': SCOPE, 'operation': operation, 'completion_sha256': completion_sha256,
                            'ciphertext_bytes': size, 'ciphertext_sha256': whole.hexdigest(), 'parts': parts})
        need(len(manifest) <= MAX_MANIFEST)
        return manifest
    except (ValueError, KeyError, TypeError, OSError, RecursionError):
        raise PartsRejected('Santa image transfer planning rejected; preserve the original ciphertext') from None


def checked_manifest(manifest_raw, completion_raw, *, manifest_sha256, completion_sha256, operation):
    try:
        start(1, operation)
        record = checked_completion(completion_raw, completion_sha256)
        manifest = checked_document(manifest_raw, manifest_sha256, MAX_MANIFEST)
        size = record['ciphertext_bytes']
        ciphertext_sha256 = record['ciphertext_sha256']
        parts = manifest['parts']
        need(type(parts) is list and manifest == {'scope': SCOPE, 'operation': operation,
             'completion_sha256': completion_sha256, 'ciphertext_bytes': size,
             'ciphertext_sha256': ciphertext_sha256, 'parts': parts})
        expected = list(layout(size, operation))
        need(len(parts) == len(expected))
        for part, binding in zip(parts, expected):
            need(type(part) is dict and set(part) == set(binding) | {'sha256', 'md5'}
                 and all(type(part[key]) is type(value) and part[key] == value for key, value in binding.items())
                 and type(part['sha256']) is str and re.fullmatch(HEX, part['sha256'])
                 and type(part['md5']) is str and re.fullmatch(r'[a-f0-9]{32}', part['md5']))
        return manifest
    except (ValueError, KeyError, TypeError, RecursionError):
        raise PartsRejected('Santa image transfer manifest rejected') from None


def assemble(manifest_raw, completion_raw, destination, open_part, *, manifest_sha256,
             completion_sha256, operation, seconds=900):
    """Use independent trusted pins to assemble one fresh ciphertext file.

    The caller opens each exact object as a confidential binary stream, supplies
    a private destination, and enforces an outer deadline for blocking I/O.
    A failed attempt may leave a partial file and never reuses an existing path.
    """
    try:
        deadline = start(seconds, operation)
        manifest = checked_manifest(manifest_raw, completion_raw, manifest_sha256=manifest_sha256,
                                    completion_sha256=completion_sha256, operation=operation)
        size = manifest['ciphertext_bytes']
        ciphertext_sha256 = manifest['ciphertext_sha256']
        parts = manifest['parts']

        whole = hashlib.sha256()
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as output:
            for part in parts:
                need(time.monotonic() < deadline)
                with open_part(part['object']) as stream:
                    hashes = hash_part(stream, part['bytes'], whole, deadline, output)
                    need(stream.read(1) == b'' and hashes == {key: part[key] for key in hashes})
            need(whole.hexdigest() == ciphertext_sha256 and output.tell() == size)
            output.flush()
            os.fsync(output.fileno())
            need(time.monotonic() < deadline)
        return {'scope': 'azd-santa-retained-image-parts-readback-v1', 'manifest_sha256': manifest_sha256,
                'completion_sha256': completion_sha256, 'ciphertext_bytes': size,
                'ciphertext_sha256': ciphertext_sha256, 'verified_parts': len(parts)}
    except (ValueError, KeyError, TypeError, OSError, RecursionError):
        raise PartsRejected('Santa image transfer readback rejected; preserve the attempted output') from None
