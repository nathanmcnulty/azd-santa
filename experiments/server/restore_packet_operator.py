"""Plan and deliver one sealed Santa recovery packet to the selected recovery VM."""

import argparse
from contextlib import ExitStack
import json
from pathlib import Path

import blob_retention as blob
from restore_arm_authorization import Selection as Operator
from restore_authority_transaction import Target
from restore_carrier_command import Command, PACKET_PART_BYTES
from restore_guest_job import Job
from restore_input_blob import PacketTransfer
from restore_input_sas import RestoreInputSasIssuer
from restore_quarantine_journal import is_digest
from restore_sealed_inputs import MAX_PACKET, sha
from restore_tooling_bundle import MAX_BUNDLE
from retained_image_delivery import read_at
from retained_image_operator import journal_read, journal_root, read_bytes, selected_store
from retained_image_sas import sync_directory, write_record

SCOPE = 'santa-restore-packet-operation-v1'
CARRIER_ROOT = Path('/run/azd-santa-recovery-carrier')


def delivery_binding(job, plan, plan_sha256, receipt):
    """Verify the approved transport plan and its corresponding receipt."""
    blob.need(type(job) is Job and type(plan) is dict and is_digest(plan_sha256)
              and plan.get('plan_sha256') == plan_sha256 and plan.get('submits_run_command') is False)
    body = {name: value for name, value in plan.items() if name not in ('plan_sha256', 'submits_run_command')}
    blob.need(sha(blob.encoded(body)) == plan_sha256 and plan['scope'] == SCOPE)
    expected = dict(tenant=job.selection.tenant, subscription=job.selection.subscription,
                    receiver=job.selection.vm_instance_id, receiver_boot=job.verified_boot_id,
                    archive_sha256=job.archive_sha256, generation=job.generation)
    blob.need(all(plan[name] == value for name, value in expected.items()))
    capsule, digest, length = (plan[name] for name in ('receiver_capsule', 'packet_sha256', 'packet_bytes'))
    blob.need(is_digest(capsule) and is_digest(digest) and type(length) is int and 0 < length <= MAX_PACKET)
    blob.need(type(receipt) is dict and type(receipt.get('upload_confirmed')) is bool
              and receipt.get('database_applied') is False
              and receipt == dict(scope=SCOPE, state='verified', plan_sha256=plan_sha256,
                                  receiver_capsule=capsule, packet_sha256=digest, packet_bytes=length,
                                  upload_confirmed=receipt['upload_confirmed'], database_applied=False))
    return capsule, digest, length


def received_packet(job, plan, plan_sha256, receipt, *, root=CARRIER_ROOT):
    """Open only the verified ciphertext for the approved receiver capsule."""
    capsule, digest, length = delivery_binding(job, plan, plan_sha256, receipt)
    with ExitStack() as stack:
        directory, name = blob.parent(Path(root) / capsule / 'packet.sealed', stack)
        packet = read_at(directory, name, length)
    blob.need(len(packet) == length and sha(packet) == digest)
    return packet


class Operation:
    def __init__(self, selection, job, packet, tooling, *, commit, tooling_sha256, sender_boot):
        blob.need(type(packet) is bytes)
        self.transfer = PacketTransfer(job, selection.store, selection.verifier, sha(packet), len(packet))
        self._packet = packet
        self._commands = {
            role: Command(selection, self.transfer, role, tooling, commit=commit,
                          tooling_sha256=tooling_sha256, boot_id=boot_id)
            for role, boot_id in (('c', sender_boot), ('r', job.verified_boot_id))
        }
        self._selection = selection
        self.plan = dict(scope=SCOPE, tenant=selection.tenant, subscription=selection.subscription,
                         account_id=selection.store.blob.account_id, operation=selection.store.blob.operation,
                         sender=selection.source.instance_id, receiver=selection.verifier.instance_id,
                         sender_boot=sender_boot, receiver_boot=job.verified_boot_id,
                         archive_sha256=job.archive_sha256, generation=job.generation,
                         packet_sha256=self.transfer.packet_sha256, packet_bytes=self.transfer.packet_bytes,
                         tooling_commit=commit, tooling_sha256=tooling_sha256,
                         sender_capsule=self._commands['c'].capsule, receiver_capsule=self._commands['r'].capsule,
                         packet_frames=(len(packet) + PACKET_PART_BYTES - 1) // PACKET_PART_BYTES)
        self.plan_sha256 = sha(blob.encoded(self.plan))

    def preview(self):
        return {**self.plan, 'plan_sha256': self.plan_sha256, 'submits_run_command': False}

    def _directory(self, root, plan_sha256):
        blob.need(plan_sha256 == self.plan_sha256 == sha(blob.encoded(self.plan)))
        return journal_root(root) / (self.transfer.packet_sha256 + '-restore-packet')

    def _record(self, directory, name, data):
        write_record(directory / (name + '.json'), data)
        sync_directory(directory)

    def _reply(self, state):
        return dict(state=state, packet_sha256=self.transfer.packet_sha256, packet_bytes=self.transfer.packet_bytes)

    def _summary(self, *, state, upload_confirmed=False):
        return dict(scope=SCOPE, plan_sha256=self.plan_sha256, **self._reply(state),
                    receiver_capsule=self.plan['receiver_capsule'],
                    upload_confirmed=upload_confirmed, database_applied=False)

    def apply(self, root, plan_sha256):
        directory = self._directory(root, plan_sha256)
        directory.mkdir(mode=0o700)
        sync_directory(directory.parent)
        self._record(directory, 'intent', self.preview())
        sender, receiver = self._commands['c'], self._commands['r']
        sender.install()
        sender.stage_packet(self._packet)
        receiver.install()
        create_offer = sender.offer()
        read_offer = receiver.offer()
        create = RestoreInputSasIssuer(self._selection, self.transfer, 'c').issue(directory, apply=True)
        self._record(directory, 'upload-attempt', self._reply('attempted'))
        try:
            reply = sender.transfer(create_offer, sha(create_offer), create)
        except Exception:
            # A lost upload acknowledgement can be reconciled by exact readback.
            # Never reissue the create credential or repeat the PUT.
            self._record(directory, 'upload-unconfirmed', self._reply('unconfirmed'))
        else:
            blob.need(reply == self._reply('uploaded'))
            self._record(directory, 'uploaded', reply)
        read = RestoreInputSasIssuer(self._selection, self.transfer, 'r').issue(directory, apply=True)
        self._record(directory, 'read-attempt', self._reply('attempted'))
        received = receiver.transfer(read_offer, sha(read_offer), read)
        blob.need(received == self._reply('verified'))
        self._record(directory, 'verified', received)
        return self.observe(root, plan_sha256)

    def observe(self, root, plan_sha256):
        """Report durable local evidence. Do not make a remote request or repeat a write."""
        directory = self._directory(root, plan_sha256)
        if not directory.exists():
            return self._summary(state='not-attempted')
        blob.need(journal_read(directory / 'intent.json') == self.preview())
        phases = {'upload-attempt': 'attempted', 'upload-unconfirmed': 'unconfirmed',
                  'uploaded': 'uploaded', 'read-attempt': 'attempted', 'verified': 'verified'}
        found = {}
        for name, state in phases.items():
            path = directory / (name + '.json')
            found[name] = path.exists()
            if found[name]:
                blob.need(journal_read(path) == self._reply(state))
        blob.need(not found['verified'] or found['read-attempt'])
        blob.need(not found['read-attempt'] or found['uploaded'] or found['upload-unconfirmed'])
        blob.need(not (found['uploaded'] and found['upload-unconfirmed']))
        blob.need(not any(found[name] for name in phases if name != 'upload-attempt') or found['upload-attempt'])
        state = 'verified' if found['verified'] else 'interrupted'
        return self._summary(state=state, upload_confirmed=found['uploaded'])


def build_operation(selection_bytes, job_bytes, packet, tooling, *, operation, commit, tooling_sha256):
    blob.need(all(type(raw) is bytes and 0 < len(raw) <= 8192 for raw in (selection_bytes, job_bytes)))
    selection = selected_store(json.loads(selection_bytes, object_pairs_hook=blob.unique), operation)
    meta = json.loads(job_bytes, object_pairs_hook=blob.unique)
    blob.need(type(meta) is dict
              and set(meta) == {'operator_account', 'sender_boot', 'receiver', 'target', 'archive_sha256', 'generation'}
              and type(selection.verifier) is blob.SelectedTarget)
    receiver = selection.verifier
    identity = Operator(selection.tenant, selection.subscription, meta['operator_account'],
                        receiver.vm_id, receiver.instance_id, receiver.region)
    job = Job.from_readback(identity, Target(**meta['target']), guest_receipt=meta['receiver'],
                            archive_sha256=meta['archive_sha256'], generation=meta['generation'])
    return Operation(selection, job, packet, tooling, commit=commit, tooling_sha256=tooling_sha256,
                     sender_boot=meta['sender_boot'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('plan', 'apply', 'observe'))
    for name in ('selection', 'job', 'packet', 'tooling', 'operation', 'commit', 'tooling-sha256'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--plan-sha256')
    parser.add_argument('--journal-root', type=Path)
    options = parser.parse_args()
    try:
        operation = build_operation(read_bytes(options.selection, 8192), read_bytes(options.job, 8192),
                                    read_bytes(options.packet, MAX_PACKET), read_bytes(options.tooling, MAX_BUNDLE),
                                    operation=options.operation, commit=options.commit,
                                    tooling_sha256=options.tooling_sha256)
        if options.action == 'plan':
            result = operation.preview()
        else:
            blob.need(options.journal_root is not None and is_digest(options.plan_sha256))
            action = operation.apply if options.action == 'apply' else operation.observe
            result = action(options.journal_root, options.plan_sha256)
        print(json.dumps(result, sort_keys=True))
    except Exception:
        parser.exit(1, 'Santa packet operation rejected or interrupted. Preserve the journal and use observe.\n')


if __name__ == '__main__':
    main()
