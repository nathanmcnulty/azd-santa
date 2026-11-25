"""Original Unlicense. Provision and run one immutable guest image selection."""

from contextlib import ExitStack
from dataclasses import asdict
import io
import os
from pathlib import Path, PurePosixPath
import zipfile

import blob_retention as blob
import retained_image_delivery as delivery
import retained_image_handoff as handoff
from retained_image_blob import Transfer
from retained_image_parts import MAX_MANIFEST, checked_document

GUEST_ROOT = '/var/lib/azd-santa-qualification/image-delivery'
MAX_ARCHIVE = 512 * 1024
MAX_SELECTION = 48 * 1024
SOURCES = tuple(name + '.py' for name in (
    'backup_store_selection', 'blob_retention', 'cold_backup', 'private_arm_adapter',
    'restore_cipher', 'retained_image_archive', 'retained_image_blob', 'retained_image_delivery',
    'retained_image_export', 'retained_image_handoff', 'retained_image_parts', 'retained_image_runner',
    'retained_image_sas', 'retention_image_inventory'))
SELECTION = 'selection.json'
DRIVER = """import hashlib, os, stat, sys
from pathlib import Path

def handle(request):
    directory = Path(__file__).parent
    archive = directory / 'tools.zip'
    with os.fdopen(os.open(archive, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1 or info.st_mode & 0o077:
            raise ValueError()
        raw = stream.read(ARCHIVE_LIMIT + 1)
    if not 0 < len(raw) <= ARCHIVE_LIMIT or hashlib.sha256(raw).hexdigest() != 'ARCHIVE_SHA256':
        raise ValueError()
    sys.path.insert(0, str(archive))
    try:
        from retained_image_runner import serve
        return serve(directory, raw, request)
    finally:
        sys.path.pop(0)
"""


def driver(digest):
    blob.need(len(digest) == 64 and all(char in '0123456789abcdef' for char in digest))
    return DRIVER.replace('ARCHIVE_SHA256', digest).replace('ARCHIVE_LIMIT', str(MAX_ARCHIVE)).encode('ascii')


def source_file(path, permission):
    if permission == 'r':
        blob.need(path is None)
        return None
    blob.need(type(path) is str and 0 < len(path) <= 1024 and '\0' not in path and not path.startswith('//'))
    selected = PurePosixPath(path)
    blob.need(selected.is_absolute() and str(selected) == path and '..' not in selected.parts)
    return path


def build(tooling, commit, tooling_sha256, transfer, target, permission, *, source_path=None):
    """Create an inert, reproducible archive from the selected reviewed commit."""
    from restore_tooling_bundle import SERVER, verify

    handoff.context(transfer, target, permission)
    source_file(source_path, permission)
    files = verify(tooling, commit=commit, bundle_sha256=tooling_sha256)
    selection = blob.encoded({'source': asdict(transfer.source), 'target': asdict(target),
        'store': asdict(transfer.store), 'pins': transfer.pins, 'permission': permission,
        'manifest': handoff.b64(transfer.manifest), 'completion': handoff.b64(transfer.completion),
        'source_path': source_path})
    blob.need(len(selection) <= MAX_SELECTION)
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w') as archive:
        for name, data in [(name, files[SERVER + name]) for name in SOURCES] + [(SELECTION, selection)]:
            # Outer XZ compresses across source files while the installed ZIP remains importable.
            archive.writestr(zipfile.ZipInfo(name), data)
    raw = output.getvalue()
    blob.need(len(raw) <= MAX_ARCHIVE)
    return raw


def read_selection(raw, digest):
    blob.need(type(raw) is bytes and 0 < len(raw) <= MAX_ARCHIVE and handoff.sha(raw) == digest)
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entries = archive.infolist()
        blob.need(tuple(entry.filename for entry in entries) == (*SOURCES, SELECTION)
                  and all(0 < entry.file_size <= 256 * 1024 and not entry.flag_bits & 1 for entry in entries)
                  and entries[-1].file_size <= MAX_SELECTION)
        data = archive.read(SELECTION)
    selection = checked_document(data, handoff.sha(data), MAX_SELECTION)
    blob.need(set(selection) == {'source', 'target', 'store', 'pins', 'permission',
                                  'manifest', 'completion', 'source_path'})
    source, target = (blob.SelectedTarget(**selection[name]) for name in ('source', 'target'))
    facts = selection['store']
    blob.need(set(facts) == {'blob', 'region', 'owned_subnets', 'ownership_id'}
              and type(facts['owned_subnets']) is list)
    store = blob.Store(blob.Blob(**facts['blob']), facts['region'], tuple(facts['owned_subnets']), facts['ownership_id'])
    transfer = Transfer(handoff.decode(selection['manifest'], MAX_MANIFEST), handoff.decode(selection['completion'], 4096),
                        store, source, **selection['pins'])
    permission = selection['permission']
    handoff.context(transfer, target, permission)
    return transfer, target, permission, source_file(selection['source_path'], permission)


def install(raw, digest, *, root=GUEST_ROOT, apply=False):
    """Provision a fresh guest runner once, under the private qualification root."""
    transfer, target, permission, path = read_selection(raw, digest)
    name = handoff.offer_name(transfer, permission)
    program = driver(digest)
    result = {'scope': 'azd-santa-image-runner-v1', 'runner_sha256': handoff.sha(program),
              'archive_sha256': digest, 'state': 'installed' if apply else 'planned'}
    blob.need(type(apply) is bool)
    if not apply:
        return result
    blob.host_identity(target)
    with ExitStack() as stack:
        if path is not None:
            blob.parent(path, stack)
        base = Path(root)
        parent, leaf = blob.parent(base, stack)
        try:
            os.mkdir(leaf, 0o700, dir_fd=parent)
            os.fsync(parent)
        except FileExistsError:
            pass
        folder = base / name
        journal = blob.Journal(folder, result, stack)
        for child in ('offers', 'staging', 'attempts'):
            os.mkdir(child, 0o700, dir_fd=journal.fd)
        delivery.write_at(journal.fd, 'tools.zip', raw)
        delivery.write_at(journal.fd, 'run.py', program)
    return result


def serve(directory, raw_archive, request):
    """Dispatch only against the reviewed local selection and its saved offer."""
    transfer, target, permission, path = read_selection(raw_archive, handoff.sha(raw_archive))
    name = handoff.offer_name(transfer, permission)
    blob.need(directory.name == name)
    raw = checked_document(request, handoff.sha(request), delivery.MAX_FRAME)
    if raw.get('action') == 'runner':
        expected = {'scope': delivery.SCOPE, 'action': 'runner', 'batch_sha256': transfer.pins['manifest_sha256']}
        blob.need(raw == expected)
        blob.host_identity(target)
        return {'scope': delivery.SCOPE, 'batch_sha256': transfer.pins['manifest_sha256'],
                'state': 'installed', 'archive_sha256': handoff.sha(raw_archive)}
    offer_root = directory / 'offers'
    public_path = offer_root / name / 'offer.json'
    with ExitStack() as stack:
        if raw.get('action') == 'offer':
            expected = {'scope': delivery.SCOPE, 'action': 'offer',
                        'batch_sha256': transfer.pins['manifest_sha256']}
            blob.need(raw == expected)
            if not public_path.exists():
                offer = handoff.create_offer(offer_root, transfer, target, permission, apply=True)
                folder, _ = blob.parent(public_path, stack)
                delivery.write_at(folder, public_path.name, offer)
        folder, _ = blob.parent(public_path, stack)
        offer = delivery.read_at(folder, public_path.name, 4096)
        digest = handoff.sha(offer)
        intent = delivery.read_at(folder, 'intent.json', 4096)
        blob.need(intent == blob.encoded({'offer_sha256': digest, 'permission': permission}))
        if raw.get('action') == 'offer':
            value, _ = handoff.check_offer(offer, digest, transfer, target, permission)
            blob.need(handoff.boot(target) == value['boot_id'])
            try:
                os.stat('consumed', dir_fd=folder, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise blob.RetentionRejected('Santa image delivery offer has already been consumed')
            return {'scope': delivery.SCOPE, 'batch_sha256': transfer.pins['manifest_sha256'],
                    'state': 'offered', 'offer': handoff.b64(offer)}
        guest = delivery.Guest(directory / 'staging', offer_root, offer, digest, transfer, target, permission,
                               directory / 'attempts', source_path=path)
        return guest(request)
