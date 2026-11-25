"""Original Unlicense. One selected guest export with bounded receipt readback."""

from contextlib import ExitStack
import io
import os
from pathlib import Path
import re
import zipfile

import blob_retention as blob
from retained_image_delivery import read_at
import retained_image_export as export
from retained_image_handoff import b64, decode, sha
import retained_image_parts as parts

ROOT = '/var/lib/azd-santa-qualification/image-exports'
SCOPE = 'azd-santa-retained-image-export-job-v1'
PAGE_BYTES = 1536
MAX_RESPONSE = 3072
REQUEST_FILE = 'export.json'
MAX_SELECTION = 16 * 1024


class ExportJob:
    """Bind one export, its encryption recipient, and metadata to the selected source VM."""

    def __init__(self, source, operation, inventory, image_name, recipient_der, *, inventory_sha256,
                 recipient_sha256, maximum=export.ARCHIVE_MAXIMUM, seconds=600, root=ROOT):
        blob.need(type(source) is blob.SelectedTarget and image_name in export.IMAGE_NAMES
                  and type(operation) is str and re.fullmatch(r'[0-9a-f]{32}', operation)
                  and type(seconds) is int and 0 < seconds <= 1800
                  and type(maximum) is int and 1024 <= maximum <= export.ARCHIVE_MAXIMUM
                  and type(recipient_der) is bytes and 0 < len(recipient_der) <= 1024
                  and sha(recipient_der) == recipient_sha256)
        self.inventory = parts.checked_document(inventory, inventory_sha256, 8192)
        blob.need(self.inventory['scope'] == 'azd-santa-retention-image-inventory-v1'
                  and self.inventory['platform'] == 'linux/amd64')
        self.intent = export.export_intent(self.inventory, image_name, inventory_sha256, recipient_sha256, maximum)
        blob.need(re.fullmatch(parts.IMAGE_ID, self.intent['image_id']))
        export.recipient_key(recipient_der)
        self.source, self.operation, self.recipient = source, operation, recipient_der
        self.image_name, self.maximum, self.seconds = image_name, maximum, seconds
        self.root = Path(root)
        self.directory = self.root / operation
        self.artifact = self.directory / 'artifact'
        self.identity = {'scope': SCOPE, 'operation': operation, 'vm_id': source.vm_id,
                         'vm_instance_id': source.instance_id, 'intent_sha256': sha(blob.encoded(self.intent))}
        self.reservation = {**self.identity, 'seconds': seconds}

    def start(self, *, apply=False):
        blob.need(type(apply) is bool)
        if not apply:
            return {**self.identity, 'state': 'planned'}
        blob.host_identity(self.source)
        with ExitStack() as stack:
            parent, name = blob.parent(self.root, stack)
            try:
                os.mkdir(name, 0o700, dir_fd=parent)
                os.fsync(parent)
            except FileExistsError:
                pass
            blob.Journal(self.directory, self.reservation, stack)
            export.export_image(self.artifact, self.inventory, self.image_name, self.recipient,
                inventory_sha256=self.intent['inventory_sha256'], recipient_sha256=self.intent['recipient_sha256'],
                maximum=self.maximum, seconds=self.seconds, operation=self.operation)
        return self.observe()

    def observe(self, *, page=None, manifest_sha256=None):
        blob.host_identity(self.source)
        with ExitStack() as stack:
            if not self.directory.exists():
                blob.need(page is None and manifest_sha256 is None)
                return {**self.identity, 'state': 'not-attempted'}
            folder, _ = blob.parent(self.directory / 'intent.json', stack)
            blob.need(read_at(folder, 'intent.json', 4096) == blob.encoded(self.reservation))
            try:
                artifact, _ = blob.parent(self.artifact / 'complete.json', stack)
                completion = read_at(artifact, 'complete.json', 4096)
            except FileNotFoundError:
                blob.need(page is None and manifest_sha256 is None)
                return {**self.identity, 'state': 'reserved'}
            metadata = read_at(artifact, 'intent.json', 4096)
            blob.need(metadata == blob.encoded(self.intent))
            completion_sha256 = sha(completion)
            record = parts.checked_completion(completion, completion_sha256)
            blob.need(record['intent_sha256'] == self.identity['intent_sha256']
                      and record['image_id'] == self.intent['image_id'] and record['archive_bytes'] <= self.maximum)
            manifest = read_at(artifact, 'parts.json', parts.MAX_MANIFEST)
            digest = sha(manifest)
            parts.checked_manifest(manifest, completion, manifest_sha256=digest,
                                   completion_sha256=completion_sha256, operation=self.operation)
            pages = (len(manifest) + PAGE_BYTES - 1) // PAGE_BYTES
            if page is None:
                blob.need(manifest_sha256 is None)
                result = {**self.identity, 'state': 'completed', 'export_directory': self.artifact.as_posix(),
                          'completion_sha256': completion_sha256, 'completion': b64(completion),
                          'manifest_sha256': digest, 'pages': pages}
                blob.need(len(blob.encoded(result)) <= MAX_RESPONSE)
                return result
            blob.need(type(page) is int and 0 <= page < pages and manifest_sha256 == digest)
            # Keep the VM/intent binding on the initial receipt. The manifest
            # hash binds all pages and leaves room for transport framing.
            result = {'scope': SCOPE, 'operation': self.operation, 'manifest_sha256': digest,
                      'page': page, 'bytes': b64(manifest[page * PAGE_BYTES:(page + 1) * PAGE_BYTES])}
            blob.need(len(blob.encoded(result)) <= MAX_RESPONSE)
            return result


def collect(receipt, pages):
    """Reassemble bounded metadata against a previously obtained completed receipt."""
    blob.need(receipt['scope'] == SCOPE and receipt['state'] == 'completed'
              and type(receipt['pages']) is int
              and 0 < receipt['pages'] <= (parts.MAX_MANIFEST + PAGE_BYTES - 1) // PAGE_BYTES)
    digest = receipt['manifest_sha256']
    expected = {'scope': SCOPE, 'operation': receipt['operation'], 'manifest_sha256': digest}
    chunks = []
    for index, page in enumerate(pages):
        blob.need(index < receipt['pages'] and page == {**expected, 'page': index, 'bytes': page['bytes']}
                  and type(page['page']) is int)
        chunk = decode(page['bytes'], PAGE_BYTES)
        blob.need(0 < len(chunk) <= PAGE_BYTES and (index + 1 == receipt['pages'] or len(chunk) == PAGE_BYTES))
        chunks.append(chunk)
    blob.need(len(chunks) == receipt['pages'])
    manifest, completion = b''.join(chunks), decode(receipt['completion'], 4096)
    record = parts.checked_completion(completion, receipt['completion_sha256'])
    blob.need(record['intent_sha256'] == receipt['intent_sha256'])
    parts.checked_manifest(manifest, completion, manifest_sha256=digest,
                           completion_sha256=receipt['completion_sha256'], operation=receipt['operation'])
    return completion, manifest


def dispatch(archive_bytes, request_bytes):
    """Entry point for the digest-checked Run Command bootstrap."""
    with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
        entry = archive.getinfo(REQUEST_FILE)
        blob.need(0 < entry.file_size <= MAX_SELECTION)
        raw = archive.read(entry)
    config = parts.checked_document(raw, sha(raw), MAX_SELECTION)
    blob.need(set(config) == {'source', 'operation', 'inventory', 'image_name', 'recipient',
                             'inventory_sha256', 'recipient_sha256', 'maximum', 'seconds'})
    job = ExportJob(blob.SelectedTarget(**config.pop('source')), config.pop('operation'),
        decode(config.pop('inventory'), 8192), config.pop('image_name'), decode(config.pop('recipient'), 1024),
        **config)
    request = parts.checked_document(request_bytes, sha(request_bytes), 1024)
    verb = request['action']
    if verb == 'page':
        blob.need(set(request) == {'action', 'page', 'manifest_sha256'})
        result = job.observe(page=request['page'], manifest_sha256=request['manifest_sha256'])
    else:
        blob.need(set(request) == {'action'} and verb in ('start', 'observe'))
        result = job.start(apply=True) if verb == 'start' else job.observe()
    return {**result, 'batch_sha256': sha(request_bytes)}
