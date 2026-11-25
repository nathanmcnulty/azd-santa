"""Original Unlicense. Verify an encrypted image artifact before any Docker load."""

from contextlib import ExitStack, contextmanager
import hashlib
import math
import os
from pathlib import Path
import re
import stat
import struct
import sys
from tempfile import TemporaryFile
import time

from cryptography.exceptions import InvalidTag

from restore_cipher import CHUNK, authenticate, identity
from restore_quarantine import decrypt_staging
from retained_image_archive import ARCHIVE_MAXIMUM, parse, verify_archive
from retained_image_export import IMAGE_MAGIC, IMAGE_NAMES, encoded
from retention_image_inventory import HEX, IMAGE_ID


class ReadbackRejected(ValueError):
    pass


def need(condition):
    if not condition:
        raise ReadbackRejected('Santa retained image verification rejected')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def remaining_seconds(deadline):
    remaining = math.ceil(deadline - time.monotonic())
    need(remaining > 0)
    return remaining


@contextmanager
def open_verified_image(source_path, completion_raw, private_key, staging_directory, *, completion_sha256,
                        inventory_sha256, image_name, image_id, maximum=ARCHIVE_MAXIMUM, seconds=600):
    """Yield (archive stream positioned at the tar, verification receipt) on Linux.

    Pin the completion digest and selected image outside the downloaded artifact.
    The caller supplies a trusted owner-private staging directory and enforces an
    outer I/O deadline. The stream is anonymous, valid within this context only,
    and must be consumed from its current position. No Docker or cloud action here.
    """
    with ExitStack() as stack:
        try:
            need(sys.platform == 'linux' and type(maximum) is int and 1024 <= maximum <= ARCHIVE_MAXIMUM
                 and type(seconds) is int and 0 < seconds <= 1800 and image_name in IMAGE_NAMES
                 and type(image_id) is str and re.fullmatch(IMAGE_ID, image_id)
                 and type(inventory_sha256) is str and re.fullmatch(HEX, inventory_sha256))
            deadline = time.monotonic() + seconds
            need(type(completion_raw) is bytes and 0 < len(completion_raw) <= 4096
                 and sha(completion_raw) == completion_sha256)
            record = parse(completion_raw)
            need(type(record) is dict and encoded(record) == completion_raw and set(record) == {
                 'scope', 'image_id', 'intent_sha256', 'archive_bytes', 'archive_sha256',
                 'ciphertext_bytes', 'ciphertext_sha256'}
                 and record['scope'] == 'azd-santa-retained-image-export-v1' and record['image_id'] == image_id)
            for field in ('intent_sha256', 'archive_sha256', 'ciphertext_sha256'):
                need(type(record[field]) is str and re.fullmatch(HEX, record[field]))
            size = record['ciphertext_bytes']
            archive_bytes = record['archive_bytes']
            need(type(archive_bytes) is int and 1024 <= archive_bytes <= maximum
                 and type(size) is int and archive_bytes < size <= archive_bytes + 4096)

            path = Path(source_path)
            staging = Path(staging_directory)
            need(path.is_absolute() and path.parent == path.parent.resolve(strict=True)
                 and staging.is_absolute() and staging == staging.resolve(strict=True))
            info = staging.stat()
            need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700)
            fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
            source = stack.enter_context(os.fdopen(fd, 'rb'))
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and before.st_nlink == 1
                 and not before.st_mode & 0o077 and before.st_size == size)
            ciphertext_digest = record['ciphertext_sha256']
            authenticated = authenticate(source, size, ciphertext_digest, private_key,
                                         maximum=max(CHUNK, size), seconds=remaining_seconds(deadline))
            original = identity(before)
            need(identity(os.fstat(fd)) == original and identity(path.lstat()) == original)

            archive = stack.enter_context(TemporaryFile(dir=staging, buffering=0))
            need(os.fstat(archive.fileno()).st_nlink == 0)
            decrypt_staging(source, size, ciphertext_digest, private_key, archive, deadline)
            need(identity(os.fstat(fd)) == original and identity(path.lstat()) == original)
            need(archive.read(len(IMAGE_MAGIC)) == IMAGE_MAGIC)
            length = struct.unpack('>I', archive.read(4))[0]
            need(0 < length <= 2048)
            metadata = archive.read(length)
            need(len(metadata) == length and sha(metadata) == record['intent_sha256'])
            intent = parse(metadata)
            selection = {'scope': 'azd-santa-retained-image-export-intent-v1', 'image': image_name,
                         'image_id': image_id, 'platform': 'linux/amd64', 'inventory_sha256': inventory_sha256,
                         'recipient_sha256': authenticated['recipient_sha256']}
            limit = intent['maximum_archive_bytes']
            need(type(limit) is int and archive_bytes <= limit <= ARCHIVE_MAXIMUM
                 and intent == {**selection, 'maximum_archive_bytes': limit} and encoded(intent) == metadata)
            offset = archive.tell()
            need(os.fstat(archive.fileno()).st_size == offset + archive_bytes == authenticated['plaintext_bytes'])
            result = verify_archive(archive, archive_sha256=record['archive_sha256'], archive_bytes=archive_bytes,
                                    image_id=image_id, maximum=maximum, seconds=remaining_seconds(deadline),
                                    archive_offset=offset)
            verified_fd = os.open(f'/proc/self/fd/{archive.fileno()}', os.O_RDONLY)
            verified = stack.enter_context(os.fdopen(verified_fd, 'rb', buffering=0))
            need(identity(os.fstat(verified_fd)) == identity(os.fstat(archive.fileno())))
            archive.close()
            need(time.monotonic() < deadline)
            verified.seek(offset)
        except (ValueError, TypeError, KeyError, OSError, EOFError, RecursionError, struct.error, InvalidTag):
            raise ReadbackRejected('Santa retained image verification rejected') from None
        yield verified, {**result, 'completion_sha256': completion_sha256, 'inventory_sha256': inventory_sha256,
                        'ciphertext_sha256': ciphertext_digest, 'recipient_sha256': authenticated['recipient_sha256']}
