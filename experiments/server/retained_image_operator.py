"""Original Unlicense. Plan, run, and observe one selected Santa recovery transfer."""

import argparse
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat

import blob_retention as blob
from private_arm_adapter import Selection
from retained_image_blob import Transfer
import retained_image_delivery as delivery
import retained_image_handoff as handoff
from retained_image_parts import MAX_MANIFEST, checked_document
from retained_image_sas import ImageSasIssuer
from retained_image_run_command import RunCommand
import retained_image_runner as runner
from restore_tooling_bundle import MAX_BUNDLE

SCOPE = 'azd-santa-image-retention-operator-v1'


def read_bytes(path, maximum):
    with Path(path).open('rb') as stream:
        value = stream.read(maximum + 1)
    blob.need(0 < len(value) <= maximum)
    return value


def journal_root(path):
    root = Path(path)
    blob.need(root.is_absolute() and root == root.resolve(strict=True) and root.is_dir())
    if os.name != 'nt':
        info = root.stat()
        blob.need(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700)
    return root


def journal_read(path):
    blob.need(path.resolve(strict=True) == path and path.is_file())
    raw = read_bytes(path, 8192)
    return checked_document(raw, handoff.sha(raw), 8192)


def selected_store(receipt, operation):
    """Use the existing selection producer's output. Apply refreshes ARM before SAS issuance."""
    expected = {'scope': 'cached-arm-backup-store-selection-v1', 'status': 'selected',
                'cloud_write': False, 'capability_minted': False, 'retention_proven': False,
                'restore_accepted': False, 'requires_fresh_read_before_use': True}
    details = {'tenant_id', 'subscription_id', 'account_id', 'ownership_id', 'region', 'targets', 'observation_sha256'}
    blob.need(set(receipt) == set(expected) | details
              and blob.encoded({name: receipt[name] for name in expected}) == blob.encoded(expected)
              and re.fullmatch(blob.HEX, receipt['observation_sha256']))
    blob.need(type(receipt['targets']) is list and 1 <= len(receipt['targets']) <= 2)
    targets = [blob.SelectedTarget(region=receipt['region'], **target) for target in receipt['targets']]
    store = blob.Store(blob.Blob(receipt['account_id'], operation), receipt['region'],
                       tuple(target.subnet_id for target in targets), receipt['ownership_id'])
    selection = Selection(receipt['tenant_id'], receipt['subscription_id'], store, targets[0],
                          targets[1] if len(targets) == 2 else None)
    selection.intent()
    return selection


class Operation:
    def __init__(self, selection, permission, manifest, completion, tooling, *,
                 operation, manifest_sha256, completion_sha256, commit, tooling_sha256, export_directory=None):
        blob.need(type(selection) is Selection and permission in ('c', 'r') and selection.store.blob.operation == operation)
        store, source = selection.store, selection.source
        target = source if permission == 'c' else selection.verifier
        blob.need(target is not None)
        pins = {'operation': operation, 'manifest_sha256': manifest_sha256, 'completion_sha256': completion_sha256}
        transfer = Transfer(manifest, completion, store, source, **pins)
        source_path = None
        if permission == 'c':
            directory = runner.source_file(export_directory, 'c')
            blob.need(directory != '/')
            source_path = (PurePosixPath(directory) / 'image.sealed').as_posix()
        else:
            blob.need(export_directory is None)
        self.archive = runner.build(tooling, commit, tooling_sha256, transfer, target, permission, source_path=source_path)
        self.archive_sha256 = handoff.sha(self.archive)
        self.runner_sha256 = handoff.sha(runner.driver(self.archive_sha256))
        self.command = RunCommand(selection, transfer, permission, self.runner_sha256)
        self.issuer = ImageSasIssuer(selection, manifest, completion, permission, **pins)
        self.transfer, self.target, self.permission = transfer, target, permission
        self.name = handoff.offer_name(transfer, permission)
        self.plan = {'scope': SCOPE, **pins, 'tenant': selection.tenant, 'subscription': selection.subscription,
                     'source_vm_id': source.vm_id, 'source_vm_instance_id': source.instance_id,
                     'source_export_file': source_path,
                     'target_vm_id': target.vm_id, 'target_vm_instance_id': target.instance_id,
                     'storage_account_id': store.blob.account_id, 'permission': permission,
                     'tooling_commit': commit, 'tooling_sha256': tooling_sha256,
                     'archive_sha256': self.archive_sha256, 'runner_sha256': self.runner_sha256,
                     'part_count': len(transfer.selection['parts']),
                     'provision_script_bytes': self.command.provision(self.archive)['script_bytes']}
        self.plan_sha256 = handoff.sha(blob.encoded(self.plan))

    def preview(self):
        return {**self.plan, 'plan_sha256': self.plan_sha256, 'performs_mutation': False}

    def apply(self, root, plan_sha256):
        blob.need(plan_sha256 == self.plan_sha256)
        root = journal_root(root)
        self.command.provision(self.archive, root, apply=True)
        offer = self.command.offer()
        capabilities = self.issuer.issue(root, apply=True)
        packets = handoff.seal(offer, handoff.sha(offer), capabilities, self.transfer, self.target, self.permission)
        return delivery.send(self.command, root, offer, packets, self.transfer, self.target, self.permission, apply=True)

    def observe(self, root, plan_sha256):
        blob.need(plan_sha256 == self.plan_sha256)
        root = journal_root(root)
        summary = {'scope': SCOPE, 'plan_sha256': plan_sha256, 'permission': self.permission}
        provision = root / (self.name + '-provision')
        if not provision.exists():
            return {**summary, 'state': 'not-attempted'}
        intent = journal_read(provision / 'intent.json')
        blob.need(intent == {'archive_sha256': self.archive_sha256, 'runner_sha256': self.runner_sha256,
                             'vm_instance_id': self.target.instance_id})
        sending = root / (self.name + '-delivery')
        if not sending.exists():
            self.command.observe_install(self.archive_sha256)
            state = 'issuance-attempted' if (root / self.name).exists() else 'runner-installed'
            return {**summary, 'state': state}
        intent = journal_read(sending / 'intent.json')
        digest = intent['batch_sha256']
        blob.need(set(intent) == {'batch_sha256', 'offer_sha256', 'frames', 'permission', 'vm_instance_id'}
                  and re.fullmatch(blob.HEX, digest) and re.fullmatch(blob.HEX, intent['offer_sha256'])
                  and type(intent['frames']) is int and 3 <= intent['frames'] <= self.plan['part_count'] + 2
                  and intent['permission'] == self.permission and intent['vm_instance_id'] == self.target.instance_id)
        reply = self.command(delivery.frame('observe', digest))
        if reply.get('state') == 'finished':
            return delivery.check_result(reply, digest, self.transfer, self.permission)
        expected = {'scope': delivery.SCOPE, 'batch_sha256': digest}
        if reply.get('state') == 'staging':
            staged = reply['staged']
            blob.need(type(staged) is list
                      and all(type(index) is int and 0 <= index < self.plan['part_count'] for index in staged)
                      and staged == sorted(set(staged)) and reply == {**expected, 'state': 'staging', 'staged': staged})
        else:
            blob.need(reply == {**expected, 'state': 'submitted-unknown'})
        return reply


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('plan', 'apply', 'observe'))
    parser.add_argument('--role', choices=('upload', 'verify'), required=True)
    for name in ('selection', 'manifest', 'completion', 'tooling', 'operation', 'manifest-sha256',
                 'completion-sha256', 'commit', 'tooling-sha256'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--export-directory', help='Original encrypted export directory on the selected source VM')
    parser.add_argument('--journal-root', type=Path)
    parser.add_argument('--plan-sha256')
    options = parser.parse_args()
    try:
        selection = json.loads(read_bytes(options.selection, 8192), object_pairs_hook=blob.unique)
        kind = 'c' if options.role == 'upload' else 'r'
        operation = Operation(selected_store(selection, options.operation), kind, read_bytes(options.manifest, MAX_MANIFEST),
            read_bytes(options.completion, 4096), read_bytes(options.tooling, MAX_BUNDLE),
            operation=options.operation, manifest_sha256=options.manifest_sha256,
            completion_sha256=options.completion_sha256, commit=options.commit,
            tooling_sha256=options.tooling_sha256, export_directory=options.export_directory)
        if options.action == 'plan':
            result = operation.preview()
        else:
            blob.need(options.journal_root is not None and options.plan_sha256 is not None)
            action = operation.apply if options.action == 'apply' else operation.observe
            result = action(options.journal_root, options.plan_sha256)
        print(blob.encoded(result).decode('ascii'))
        if options.action == 'apply' and result['result'].get('state') == 'unknown':
            parser.exit(2)
    except (ValueError, OSError, TypeError, KeyError, RuntimeError):
        parser.exit(1, 'Santa image operation rejected or unknown. Preserve the journal and use observe.\n')


if __name__ == '__main__':
    main()
