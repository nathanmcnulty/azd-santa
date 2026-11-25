"""Original Unlicense. Produce a private, encrypted export of one selected image."""

from contextlib import ExitStack, contextmanager
import hashlib
import os
from pathlib import Path
import re
import selectors
import stat
import struct
import subprocess
import sys
import time

from cold_backup import EncryptedSink, encoded, recipient_key
from restore_cipher import CHUNK
from retained_image_archive import ARCHIVE_MAXIMUM
import retained_image_parts as parts
from retention_image_inventory import IMAGE_ID

IMAGE_MAGIC = b'AZDSANTAIMAGE1\n'
IMAGE_NAMES = frozenset(('core', 'postgres', 'redis', 'rabbitmq', 'elasticsearch'))


class ExportRejected(ValueError):
    pass


def need(condition):
    if not condition:
        raise ExportRejected('Santa encrypted image export rejected; preserve any existing intent')


@contextmanager
def docker_archive(image_id, deadline):
    command = ['/usr/bin/docker', '--host', 'unix:///var/run/docker.sock',
               'image', 'save', '--platform', 'linux/amd64', image_id]
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'})
    try:
        with selectors.DefaultSelector() as ready:
            ready.register(process.stdout, selectors.EVENT_READ)

            def chunks():
                while True:
                    remaining = deadline - time.monotonic()
                    need(remaining > 0 and ready.select(remaining))
                    block = os.read(process.stdout.fileno(), CHUNK)
                    if not block:
                        break
                    yield block

            yield chunks()
        need(process.wait(timeout=max(0, deadline - time.monotonic())) == 0)
    finally:
        process.stdout.close()
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)


def new_file(directory, name):
    return os.fdopen(os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                            mode=0o600, dir_fd=directory), 'wb')


def sync(output):
    output.flush()
    os.fsync(output.fileno())


def export_intent(inventory, image_name, inventory_sha256, recipient_sha256, maximum):
    return {'scope': 'azd-santa-retained-image-export-intent-v1', 'image': image_name,
            'image_id': inventory['images'][image_name]['id'], 'platform': 'linux/amd64',
            'inventory_sha256': inventory_sha256, 'recipient_sha256': recipient_sha256,
            'maximum_archive_bytes': maximum}


def export_image(destination, inventory, image_name, recipient_der, *, inventory_sha256,
                 recipient_sha256, maximum=ARCHIVE_MAXIMUM, seconds=600, operation=None):
    """Export by immutable ID using a fresh directory under an owned private parent.

    The caller binds inventory and recipient digests to trusted prior evidence.
    It also supplies a trusted local Docker daemon and an outer process deadline
    for blocking I/O. Existing or incomplete directories are never reused. An
    operation ID also commits a transfer manifest before the completion marker.
    """
    try:
        need(sys.platform == 'linux' and type(maximum) is int and 1024 <= maximum <= ARCHIVE_MAXIMUM
             and type(seconds) is int and 0 < seconds <= 1800 and image_name in IMAGE_NAMES)
        need(type(recipient_der) is bytes and 0 < len(recipient_der) <= 1024
             and hashlib.sha256(recipient_der).hexdigest() == recipient_sha256)
        need(operation is None or type(operation) is str and re.fullmatch(r'[0-9a-f]{32}', operation))
        recipient_key(recipient_der)
        need(type(inventory) is dict and inventory['scope'] == 'azd-santa-retention-image-inventory-v1'
             and inventory['platform'] == 'linux/amd64'
             and hashlib.sha256(encoded(inventory)).hexdigest() == inventory_sha256)
        image_id = inventory['images'][image_name]['id']
        need(type(image_id) is str and re.fullmatch(IMAGE_ID, image_id))
        path = Path(destination)
        need(path.is_absolute() and path.name not in ('', '.', '..')
             and path.parent == path.parent.resolve(strict=True))
        deadline = time.monotonic() + seconds
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        with ExitStack() as stack:
            parent = os.open(path.parent, flags)
            stack.callback(os.close, parent)
            info = os.fstat(parent)
            need(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700)
            os.mkdir(path.name, 0o700, dir_fd=parent)
            directory = os.open(path.name, flags, dir_fd=parent)
            stack.callback(os.close, directory)
            os.fsync(parent)

            intent = export_intent(inventory, image_name, inventory_sha256, recipient_sha256, maximum)
            metadata = encoded(intent)
            with new_file(directory, 'intent.json') as output:
                output.write(metadata)
                sync(output)
            os.fsync(directory)

            digest = hashlib.sha256()
            size = 0
            with new_file(directory, 'image.sealed') as output:
                planned = parts.PlannedOutput(output) if operation is not None else None
                sink = EncryptedSink(output if planned is None else planned, recipient_der, maximum + 4096, deadline)
                sink.write(IMAGE_MAGIC + struct.pack('>I', len(metadata)) + metadata)
                with docker_archive(image_id, deadline) as chunks:
                    for chunk in chunks:
                        size += len(chunk)
                        need(0 < len(chunk) <= CHUNK and size <= maximum)
                        digest.update(chunk)
                        sink.write(chunk)
                need(size >= 1024 and size % 512 == 0)
                sink.finish()
                sync(output)

            result = {'scope': 'azd-santa-retained-image-export-v1', 'image_id': image_id,
                      'intent_sha256': hashlib.sha256(metadata).hexdigest(),
                      'archive_bytes': size, 'archive_sha256': digest.hexdigest(),
                      'ciphertext_bytes': sink.total, 'ciphertext_sha256': sink.hasher.hexdigest()}
            completion = encoded(result)
            if planned is not None:
                with new_file(directory, 'parts.json') as output:
                    output.write(planned.manifest(completion, operation=operation))
                    sync(output)
            with new_file(directory, 'completion.pending') as output:
                output.write(completion)
                sync(output)
            need(time.monotonic() < deadline)
            os.link('completion.pending', 'complete.json', src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)
            return result
    except (ValueError, KeyError, TypeError, OSError, RuntimeError, RecursionError, subprocess.SubprocessError):
        raise ExportRejected('Santa encrypted image export rejected; preserve any existing intent') from None
