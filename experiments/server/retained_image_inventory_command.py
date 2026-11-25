"""Original Unlicense. Collect the pinned source image inventory through Azure Run Command."""

import argparse
from dataclasses import asdict
import io
import json
import lzma
from pathlib import Path
import uuid
import zipfile

import blob_retention as blob
from retained_image_handoff import b64, sha
from retained_image_operator import read_bytes, selected_store
from retained_image_run_command import ARCHIVE_BOOTSTRAP, SelectedVmCommand
from retained_image_sas import sync_directory, write_record
from restore_tooling_bundle import MAX_BUNDLE, SERVER, verify
import retention_image_inventory as inventory

SCOPE = 'azd-santa-image-inventory-readback-v1'
SOURCES = ('blob_retention.py', 'cold_backup.py', 'restore_cipher.py', 'retention_image_inventory.py')
BOOTSTRAP = ARCHIVE_BOOTSTRAP.replace('ARCHIVE_ACTION', """            from retention_image_inventory import inspect_selected
            request = base64.b64decode(os.environ.pop('SANTA_IMAGE_INVENTORY_REQUEST'), validate=True)
            result = inspect_selected(request)""")


class InventoryCommand(SelectedVmCommand):
    def __init__(self, selection, compatibility, tooling, *, compatibility_sha256, commit, tooling_sha256, cli=None):
        super().__init__(selection, selection.source, cli)
        files = verify(tooling, commit=commit, bundle_sha256=tooling_sha256)
        lock = files[SERVER + 'dependency-images.lock.json']
        self.expected = inventory.expected_images(compatibility, lock, compatibility_sha256=compatibility_sha256,
                                                 dependency_lock_sha256=sha(lock), source=self.target)
        self.request = blob.encoded({'source': asdict(self.target), 'expected': self.expected})
        blob.need(len(self.request) <= 4096)
        output = io.BytesIO()
        with zipfile.ZipFile(output, 'w') as archive:
            for name in SOURCES:
                archive.writestr(zipfile.ZipInfo(name), files[SERVER + name])
        raw = output.getvalue()
        self.exports = (f"export SANTA_IMAGE_ARCHIVE='{b64(lzma.compress(raw, preset=6))}'\n"
                        f"export SANTA_IMAGE_ARCHIVE_SHA='{sha(raw)}'\n"
                        f"export SANTA_IMAGE_INVENTORY_REQUEST='{b64(self.request)}'\n")
        script_bytes = len(self._script(self.exports, BOOTSTRAP, '0' * 32))
        self.plan = {'scope': SCOPE, 'state': 'planned', 'tenant': selection.tenant,
                     'subscription': selection.subscription, 'source': asdict(self.target),
                     'expected_inventory': self.expected, 'tooling_sha256': tooling_sha256, 'tooling_commit': commit,
                     'script_bytes': script_bytes}
        self.plan_sha256 = sha(blob.encoded(self.plan))

    def preview(self):
        return {**self.plan, 'plan_sha256': self.plan_sha256, 'contacts_azure': False}

    def read(self, plan_sha256, destination):
        blob.need(plan_sha256 == self.plan_sha256)
        path = Path(destination)
        blob.need(path.is_absolute() and path.parent == path.parent.resolve(strict=True) and not path.exists())
        nonce = uuid.uuid4().hex
        script = self._script(self.exports, BOOTSTRAP, nonce)
        digest = sha(self.request)
        reply = self._submit(self._read_target(), script, nonce, digest, 180, scope=SCOPE)
        expected = {'scope': SCOPE, 'batch_sha256': digest,
                    'source_vm_instance_id': self.target.instance_id, 'inventory': self.expected}
        blob.need(reply == expected)
        write_record(path, reply['inventory'])
        sync_directory(path.parent)
        return {'scope': SCOPE, 'state': 'collected', 'inventory': str(path),
                'inventory_sha256': sha(blob.encoded(reply['inventory'])), 'image_count': len(self.expected['images'])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('plan', 'read'))
    for name in ('selection', 'operation', 'compatibility', 'compatibility-sha256', 'tooling', 'tooling-sha256', 'commit'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--plan-sha256')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    try:
        receipt = json.loads(read_bytes(args.selection, 8192), object_pairs_hook=blob.unique)
        command = InventoryCommand(selected_store(receipt, args.operation), read_bytes(args.compatibility, 1024 * 1024),
            read_bytes(args.tooling, MAX_BUNDLE), compatibility_sha256=args.compatibility_sha256, commit=args.commit,
            tooling_sha256=args.tooling_sha256)
        result = command.preview() if args.action == 'plan' else command.read(args.plan_sha256, args.output)
        print(blob.encoded(result).decode('ascii'))
    except (OSError, ValueError, TypeError, KeyError, RuntimeError):
        parser.exit(1, 'Santa selected source image inventory read failed or is unknown.\n')


if __name__ == '__main__':
    main()
