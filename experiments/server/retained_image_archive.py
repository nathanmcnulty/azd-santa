"""Original Unlicense. Check an exact retained Docker image archive without loading it."""

import hashlib
import json
import re
import tarfile
import time

from restore_cipher import CHUNK, unique
from retention_image_inventory import HEX, IMAGE_ID

ARCHIVE_MAXIMUM = 16 * 1024**3
METADATA_MAXIMUM = 8 * CHUNK
ENTRY_MAXIMUM = 2048
IMAGE_MANIFEST_TYPES = ('application/vnd.oci.image.manifest.v1+json',
                        'application/vnd.docker.distribution.manifest.v2+json')
IMAGE_INDEX_TYPES = ('application/vnd.oci.image.index.v1+json',
                     'application/vnd.docker.distribution.manifest.list.v2+json')


class ArchiveRejected(ValueError):
    pass


def need(condition):
    if not condition:
        raise ArchiveRejected('Santa retained image archive rejected')


class MetadataReader:
    """Bound tar header and control-file reads, even for PAX headers."""
    def __init__(self, stream, size, deadline, start):
        self.stream, self.size, self.deadline, self.start = stream, size, deadline, start
        self.budget = METADATA_MAXIMUM

    def read(self, size):
        need(0 <= size <= min(self.budget, CHUNK) and time.monotonic() < self.deadline)
        raw = self.stream.read(size)
        self.budget -= len(raw)
        return raw

    def seek(self, offset, whence=0):
        if whence == 1:
            offset += self.tell()
        elif whence == 2:
            offset += self.size
        else:
            need(whence == 0)
        need(0 <= offset <= self.size and time.monotonic() < self.deadline)
        return self.stream.seek(self.start + offset) - self.start

    def tell(self):
        return self.stream.tell() - self.start


def read_metadata(archive, members, name):
    member = members[name]
    need(member.isreg() and 0 < member.size <= CHUNK)
    with archive.extractfile(member) as source:
        raw = source.read(member.size)
    need(len(raw) == member.size)
    return raw


def parse(raw):
    return json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: need(False))


def content_id(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def blob_path(digest):
    need(type(digest) is str and re.fullmatch(IMAGE_ID, digest))
    return 'blobs/sha256/' + digest[7:]


def read_descriptor(archive, members, descriptor, *, require_size=False):
    digest = descriptor['digest']
    raw = read_metadata(archive, members, blob_path(digest))
    need(content_id(raw) == digest)
    if require_size or 'size' in descriptor:
        need(type(descriptor['size']) is int and descriptor['size'] == len(raw))
    document = parse(raw)
    need(type(document) is dict)
    return document


def platform_descriptor(index):
    manifests = index['manifests']
    need(index['schemaVersion'] == 2 and type(manifests) is list and 0 < len(manifests) <= 256)
    candidates = []
    for descriptor in manifests:
        need(type(descriptor) is dict)
        platform = descriptor.get('platform')
        need(platform is None or type(platform) is dict)
        if platform is None:
            # A manifest without platform metadata could also match Linux amd64.
            need(descriptor['mediaType'] not in IMAGE_MANIFEST_TYPES + IMAGE_INDEX_TYPES)
        elif platform['os'] == 'linux' and platform['architecture'] == 'amd64':
            need(not platform.get('variant') and not platform.get('os.version')
                 and not platform.get('os.features') and not platform.get('features')
                 and descriptor['mediaType'] in IMAGE_MANIFEST_TYPES)
            candidates.append(descriptor)
    need(len(candidates) == 1)
    return candidates[0]


def verify_oci_index(archive, members, config_id, selected, diff_ids):
    need(selected['Config'] == blob_path(config_id))
    index = parse(read_metadata(archive, members, 'index.json'))
    manifests = index['manifests']
    need(index['schemaVersion'] == 2 and type(manifests) is list and len(manifests) == 1)
    descriptor = manifests[0]
    media_type = descriptor['mediaType']
    digest = descriptor['digest']
    if media_type in IMAGE_INDEX_TYPES:
        platform_index = read_descriptor(archive, members, descriptor, require_size=True)
        need(platform_index.get('mediaType', media_type) == media_type)
        platform = platform_descriptor(platform_index)
        manifest = read_descriptor(archive, members, platform, require_size=True)
        need(manifest.get('mediaType', platform['mediaType']) == platform['mediaType'])
    else:
        need(media_type in IMAGE_MANIFEST_TYPES)
        manifest = read_descriptor(archive, members, descriptor)
    need(manifest['schemaVersion'] == 2 and manifest['config']['digest'] == config_id)
    need(type(manifest['layers']) is list and len(manifest['layers']) == len(diff_ids))
    for path, descriptor, diff_id in zip(selected['Layers'], manifest['layers'], diff_ids):
        if path != blob_path(descriptor['digest']):
            # The classic Docker store exports uncompressed layers and records
            # the original registry descriptors separately in LayerSources.
            need(path == blob_path(diff_id) and selected['LayerSources'][diff_id]['digest'] == descriptor['digest'])
    return digest


def verify_archive(stream, *, archive_sha256, archive_bytes, image_id,
                   maximum=ARCHIVE_MAXIMUM, seconds=600, archive_offset=0):
    """Check authenticated byte expectations, one image manifest and its config.

    Use a trusted receipt and a stable, owned seekable binary stream. Control
    plane calls, decryption, extraction, and image loading belong elsewhere.
    The archive may follow a bounded authenticated prefix and must end at EOF.
    The caller must enforce an outer deadline for blocking filesystem I/O.
    """
    try:
        need(type(maximum) is int and 1024 <= maximum <= ARCHIVE_MAXIMUM
             and type(archive_bytes) is int and 1024 <= archive_bytes <= maximum
             and type(archive_offset) is int and 0 <= archive_offset <= 8192
             and type(seconds) is int and 0 < seconds <= 1800
             and type(archive_sha256) is str and re.fullmatch(HEX, archive_sha256)
             and type(image_id) is str and re.fullmatch(IMAGE_ID, image_id))
        deadline = time.monotonic() + seconds
        stream.seek(archive_offset)
        remaining = archive_bytes
        digest = hashlib.sha256()
        while remaining:
            need(time.monotonic() < deadline)
            raw = stream.read(min(remaining, CHUNK))
            need(0 < len(raw) <= remaining)
            digest.update(raw)
            remaining -= len(raw)
        need(not stream.read(1) and digest.hexdigest() == archive_sha256)

        stream.seek(archive_offset)
        reader = MetadataReader(stream, archive_bytes, deadline, archive_offset)
        with tarfile.open(fileobj=reader, mode='r:') as archive:
            members = {}
            for member in archive:
                name = member.name
                need(len(members) < ENTRY_MAXIMUM and len(name) <= 256 and name not in members
                     and re.fullmatch(r'[A-Za-z0-9_./-]+', name)
                     and all(part not in ('', '.', '..') for part in name.split('/'))
                     and member.type in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE)
                     and member.sparse is None and 0 <= member.size <= archive_bytes - member.offset_data)
                members[name] = member
            # tarfile accepts a short or malformed footer after valid entries.
            # Require two end blocks and bounded all-zero record padding.
            padding = archive_bytes - archive.offset
            need(1024 <= padding <= 10240 and padding % 512 == 0)
            reader.seek(archive.offset)
            need(reader.read(padding) == bytes(padding))
            manifest = parse(read_metadata(archive, members, 'manifest.json'))
            need(type(manifest) is list and len(manifest) == 1)
            selected = manifest[0]
            need(type(selected) is dict and not selected.get('RepoTags') and not selected.get('Parent'))
            raw_config = read_metadata(archive, members, selected['Config'])
            config_id = content_id(raw_config)
            config = parse(raw_config)
            need(config['os'] == 'linux' and config['architecture'] == 'amd64' and not config.get('variant'))
            layers = selected['Layers']
            diff_ids = config['rootfs']['diff_ids']
            need(type(layers) is list and type(diff_ids) is list and config['rootfs']['type'] == 'layers'
                 and len(layers) == len(diff_ids) <= 256
                 and all(members[name].isreg() and members[name].size > 0 for name in layers)
                 and all(type(value) is str and re.fullmatch(IMAGE_ID, value) for value in diff_ids))
            if 'repositories' in members:
                need(parse(read_metadata(archive, members, 'repositories')) == {})
            manifest_id = None
            if 'index.json' in members:
                manifest_id = verify_oci_index(archive, members, config_id, selected, diff_ids)
            need(image_id in (config_id, manifest_id))
        need(time.monotonic() < deadline)
        return {'scope': 'azd-santa-retained-image-archive-v1', 'image_id': image_id,
                'config_id': config_id,
                'platform': 'linux/amd64', 'archive_sha256': archive_sha256,
                'archive_bytes': archive_bytes, 'image_loaded': False}
    except (ValueError, KeyError, TypeError, OSError, EOFError, RecursionError, tarfile.TarError):
        raise ArchiveRejected('Santa retained image archive rejected') from None
