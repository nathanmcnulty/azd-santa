"""Original Unlicense. Read the completed native capture record from its selected Azure VM."""

import argparse
from dataclasses import asdict
import json
from pathlib import Path
import uuid

import blob_retention as blob
from native_retention_upload_command import guest_archive, source_script
from native_retention_upload_guest import RECORD_SCOPE, check_record, checked_pins
from retained_image_handoff import sha
from retained_image_operator import journal_root, read_bytes, selected_store
from retained_image_run_command import SelectedVmCommand
from retained_image_sas import sync_directory, write_record
from restore_tooling_bundle import MAX_BUNDLE, verify


class CaptureRecordCommand(SelectedVmCommand):
    def __init__(self, selection, pins, tooling, *, commit, tooling_sha256, cli=None):
        super().__init__(selection, selection.source, cli)
        checked_pins(pins)
        self.pins = dict(pins)
        self.selected = selection.store.blob
        config = blob.encoded({'source': asdict(self.target), 'blob': asdict(self.selected), 'pins': self.pins})
        files = verify(tooling, commit=commit, bundle_sha256=tooling_sha256)
        digest, self.exports = guest_archive(files, config)
        self.request = {'action': 'read-record'}
        maximum = len(source_script(self.exports, self.request, '0' * 32)[0])
        self.plan = {'scope': RECORD_SCOPE, 'state': 'planned', 'source': asdict(self.target),
                     'tenant': selection.tenant, 'subscription': selection.subscription,
                     'operation': self.selected.operation, 'blob_uri': self.selected.uri, 'pins': dict(self.pins),
                     'tooling_commit': commit, 'tooling_sha256': tooling_sha256,
                     'archive_sha256': digest, 'script_bytes': maximum}
        self.plan_sha256 = sha(blob.encoded(self.plan))

    def preview(self):
        return {**self.plan, 'plan_sha256': self.plan_sha256, 'contacts_azure': False}

    def read(self, destination, plan_sha256):
        blob.need(plan_sha256 == self.plan_sha256)
        path = Path(destination)
        journal_root(path.parent)
        blob.need(not path.exists() and not path.is_symlink())
        nonce = uuid.uuid4().hex
        script, digest = source_script(self.exports, self.request, nonce)
        reply = self._submit(self._read_target(), script, nonce, digest, 180, scope=RECORD_SCOPE)
        blob.need(set(reply) == {'scope', 'batch_sha256', 'record', 'record_sha256'})
        record = reply['record']
        check_record(record, self.target, self.selected, self.pins)
        blob.need(sha(blob.encoded(record)) == reply['record_sha256'])
        write_record(path, record)
        sync_directory(path.parent)
        return {'scope': RECORD_SCOPE, 'plan_sha256': self.plan_sha256, 'state': 'collected',
                'capture_record': str(path), 'capture_record_sha256': reply['record_sha256']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('plan', 'read'))
    names = ('request-sha256', 'ciphertext-sha256', 'source-bundle-sha256', 'image-id')
    for name in ('selection', 'operation', 'tooling', 'commit', 'tooling-sha256', *names):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--ciphertext-bytes', type=int, required=True)
    parser.add_argument('--plan-sha256')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    try:
        pins = {key: getattr(args, key) for key in (name.replace('-', '_') for name in (*names, 'ciphertext-bytes'))}
        receipt = json.loads(read_bytes(args.selection, 8192), object_pairs_hook=blob.unique)
        command = CaptureRecordCommand(selected_store(receipt, args.operation), pins, read_bytes(args.tooling, MAX_BUNDLE),
                                       commit=args.commit, tooling_sha256=args.tooling_sha256)
        result = command.preview() if args.action == 'plan' else command.read(args.output, args.plan_sha256)
        print(blob.encoded(result).decode('ascii'))
    except (ValueError, KeyError, OSError, TypeError, RuntimeError):
        parser.exit(1, 'Native capture record read failed or is unknown. Preserve the original evidence.\n')


if __name__ == '__main__':
    main()
