"""Plan and deliver one sealed Santa recovery packet to the selected recovery VM."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from dataclasses import replace
import json
from pathlib import Path

import blob_retention as blob
from restore_arm_authorization import Selection as Operator
from restore_authority_transaction import Target
from restore_carrier_command import Command, PACKET_PART_BYTES
from restore_guest_job import Job
from restore_guest_readback import readback
from restore_input_blob import PacketTransfer
from restore_input_sas import RestoreInputSasIssuer
from restore_quarantine_journal import is_digest
from restore_sealed_inputs import BootRecipient, MAX_PACKET, NONCE_BYTES, WRAPPED_BYTES, sha
from restore_tooling_bundle import MAX_BUNDLE, verify
from retained_image_handoff import boot
from retained_image_delivery import read_at, write_at
from retained_image_operator import journal_read, journal_root, read_bytes, selected_store
from retained_image_sas import sync_directory, write_record

SCOPE = 'santa-restore-packet-operation-v1'
LOCAL_SCOPE = 'santa-restore-local-packet-v1'
READBACK_SCOPE = 'santa-restore-packet-readback-v1'
CARRIER_ROOT = Path('/run/azd-santa-recovery-carrier')


def check_plan(plan, plan_sha256, *, scope=SCOPE):
    blob.need(type(plan) is dict and is_digest(plan_sha256)
              and plan.get('plan_sha256') == plan_sha256 and plan.get('submits_run_command') is False)
    body = {name: value for name, value in plan.items() if name not in ('plan_sha256', 'submits_run_command')}
    blob.need(sha(blob.encoded(body)) == plan_sha256 and plan['scope'] == scope)


def receive_identity(job):
    blob.need(type(job) is Job)
    return dict(tenant=job.selection.tenant, subscription=job.selection.subscription,
                receiver=job.selection.vm_instance_id, receiver_boot=job.verified_boot_id,
                archive_sha256=job.archive_sha256, generation=job.generation)


def local_plan(job, digest, length):
    blob.need(is_digest(digest) and type(length) is int and WRAPPED_BYTES + NONCE_BYTES + 16 < length <= MAX_PACKET)
    body = dict(scope=LOCAL_SCOPE, **receive_identity(job), packet_sha256=digest, packet_bytes=length)
    body['receiver_capsule'] = sha(blob.encoded(body))
    return {**body, 'plan_sha256': sha(blob.encoded(body)), 'submits_run_command': False}


def delivery_receipt(plan, *, upload_confirmed):
    return dict(scope=plan['scope'], state='verified', plan_sha256=plan['plan_sha256'],
                receiver_capsule=plan['receiver_capsule'], packet_sha256=plan['packet_sha256'],
                packet_bytes=plan['packet_bytes'], upload_confirmed=upload_confirmed, database_applied=False)


def delivery_binding(job, plan, plan_sha256, receipt):
    """Verify the approved transport plan and its corresponding receipt."""
    blob.need(type(plan) is dict and plan.get('scope') in (SCOPE, LOCAL_SCOPE))
    check_plan(plan, plan_sha256, scope=plan['scope'])
    blob.need(all(plan[name] == value for name, value in receive_identity(job).items()))
    capsule, digest, length = (plan[name] for name in ('receiver_capsule', 'packet_sha256', 'packet_bytes'))
    blob.need(is_digest(capsule) and is_digest(digest) and type(length) is int and 0 < length <= MAX_PACKET)
    blob.need(type(receipt) is dict and type(receipt.get('upload_confirmed')) is bool
              and receipt.get('database_applied') is False
              and receipt == delivery_receipt(plan, upload_confirmed=receipt['upload_confirmed']))
    if plan['scope'] == LOCAL_SCOPE:
        blob.need(plan == local_plan(job, digest, length) and receipt['upload_confirmed'] is False)
    return capsule, digest, length


def stage_local(job, host, packet, *, root=CARRIER_ROOT, _boot=boot):
    """Stage ciphertext sealed on the verified receiver for a later operator signature."""
    BootRecipient._verify_host(job, host, _boot)
    blob.need(type(packet) is bytes)
    plan = local_plan(job, sha(packet), len(packet))
    capsule = plan['receiver_capsule']
    receipt = delivery_receipt(plan, upload_confirmed=False)
    root = Path(root)
    root.mkdir(mode=0o700, exist_ok=True)
    with ExitStack() as stack:
        state = blob.Journal(root / capsule, plan, stack)
        write_at(state.fd, 'packet.sealed', packet)
        readback = read_at(state.fd, 'packet.sealed', len(packet))
        blob.need(len(readback) == len(packet) and sha(readback) == plan['packet_sha256'])
        state.write('verified.json', receipt)
    return plan, receipt


def received_packet(job, plan, plan_sha256, receipt, *, root=CARRIER_ROOT):
    """Open only the verified ciphertext for the approved receiver capsule."""
    capsule, digest, length = delivery_binding(job, plan, plan_sha256, receipt)
    with ExitStack() as stack:
        directory, name = blob.parent(Path(root) / capsule / 'packet.sealed', stack)
        if plan['scope'] == LOCAL_SCOPE:
            blob.need(read_at(directory, 'verified.json', 8192) == blob.encoded(receipt))
        packet = read_at(directory, name, length)
    blob.need(len(packet) == length and sha(packet) == digest)
    return packet


def packet_status(packet_sha256, packet_bytes, state):
    return dict(state=state, packet_sha256=packet_sha256, packet_bytes=packet_bytes)


def phase_evidence(directory, digest, length):
    phases = {'upload-attempt': 'attempted', 'upload-unconfirmed': 'unconfirmed',
              'uploaded': 'uploaded', 'read-attempt': 'attempted', 'verified': 'verified'}
    found = {}
    for name, state in phases.items():
        path = directory / (name + '.json')
        found[name] = path.exists()
        if found[name]:
            blob.need(journal_read(path) == packet_status(digest, length, state))
    blob.need(not found['verified'] or found['read-attempt'])
    blob.need(not found['read-attempt'] or found['uploaded'] or found['upload-unconfirmed'])
    blob.need(not (found['uploaded'] and found['upload-unconfirmed']))
    blob.need(not any(found[name] for name in phases if name != 'upload-attempt') or found['upload-attempt'])
    return found


def record(directory, name, data):
    write_record(directory / (name + '.json'), data)
    sync_directory(directory)


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

    def _reply(self, state):
        return packet_status(self.transfer.packet_sha256, self.transfer.packet_bytes, state)

    def _summary(self, *, state, upload_confirmed=False):
        return dict(scope=SCOPE, plan_sha256=self.plan_sha256, **self._reply(state),
                    receiver_capsule=self.plan['receiver_capsule'],
                    upload_confirmed=upload_confirmed, database_applied=False)

    def _prepare(self, role):
        command = self._commands[role]
        command.install()
        if role == 'c':
            command.stage_packet(self._packet)
        return command.offer()

    def apply(self, root, plan_sha256):
        directory = self._directory(root, plan_sha256)
        directory.mkdir(mode=0o700)
        sync_directory(directory.parent)
        record(directory, 'intent', self.preview())
        sender, receiver = self._commands['c'], self._commands['r']
        with ThreadPoolExecutor(max_workers=2) as guests:
            create_offer, read_offer = guests.map(self._prepare, ('c', 'r'))
        create = RestoreInputSasIssuer(self._selection, self.transfer, 'c').issue(directory, apply=True)
        record(directory, 'upload-attempt', self._reply('attempted'))
        try:
            reply = sender.transfer(create_offer, sha(create_offer), create)
        except Exception:
            # A lost upload acknowledgement can be reconciled by exact readback.
            # Never reissue the create credential or repeat the PUT.
            record(directory, 'upload-unconfirmed', self._reply('unconfirmed'))
        else:
            blob.need(reply == self._reply('uploaded'))
            record(directory, 'uploaded', reply)
        read = RestoreInputSasIssuer(self._selection, self.transfer, 'r').issue(directory, apply=True)
        record(directory, 'read-attempt', self._reply('attempted'))
        received = receiver.transfer(read_offer, sha(read_offer), read)
        blob.need(received == self._reply('verified'))
        record(directory, 'verified', received)
        return self.observe(root, plan_sha256)

    def observe(self, root, plan_sha256):
        """Report durable local evidence. Do not make a remote request or repeat a write."""
        directory = self._directory(root, plan_sha256)
        if not directory.exists():
            return self._summary(state='not-attempted')
        blob.need(journal_read(directory / 'intent.json') == self.preview())
        found = phase_evidence(directory, self.transfer.packet_sha256, self.transfer.packet_bytes)
        state = 'verified' if found['verified'] else 'interrupted'
        return self._summary(state=state, upload_confirmed=found['uploaded'])


def readback_retry(selection, job, tooling, *, root, packet_sha256, plan_sha256, commit, tooling_sha256, sender_boot):
    """Read an interrupted transfer's exact object on a fresh receiver boot."""
    blob.need(is_digest(packet_sha256))
    directory = journal_root(root) / (packet_sha256 + '-restore-packet')
    plan = journal_read(directory / 'intent.json')
    check_plan(plan, plan_sha256)
    receiver = selection.verifier
    expected = dict(tenant=selection.tenant, subscription=selection.subscription,
                    account_id=selection.store.blob.account_id, operation=selection.store.blob.operation,
                    sender=selection.source.instance_id, receiver=receiver.instance_id,
                    sender_boot=sender_boot, receiver_boot=job.verified_boot_id,
                    archive_sha256=job.archive_sha256, generation=job.generation, packet_sha256=packet_sha256,
                    tooling_commit=commit, tooling_sha256=tooling_sha256)
    blob.need(all(plan[name] == value for name, value in expected.items()))
    length = plan['packet_bytes']
    PacketTransfer(job, selection.store, receiver, packet_sha256, length)
    phases = phase_evidence(directory, packet_sha256, length)
    blob.need(phases['upload-attempt'] and not phases['verified'])
    verify(tooling, commit=commit, bundle_sha256=tooling_sha256)

    current = readback(job.selection)
    current_boot = current['boot_id']
    blob.need(current_boot != job.verified_boot_id)
    target = replace(job.target, boot_id=current_boot)
    fresh = Job.from_readback(job.selection, target, guest_receipt=current,
                              archive_sha256=job.archive_sha256, generation=job.generation)
    transfer = PacketTransfer(fresh, selection.store, receiver, packet_sha256, length)
    command = Command(selection, transfer, 'r', tooling, commit=commit, tooling_sha256=tooling_sha256,
                      boot_id=current_boot)
    attempt = directory / (current_boot + '-readback')
    attempt.mkdir(mode=0o700)
    sync_directory(directory)
    proof = dict(scope=READBACK_SCOPE, plan_sha256=plan_sha256, receiver=receiver.instance_id,
                 receiver_boot=current_boot, receiver_capsule=command.capsule, upload_confirmed=phases['uploaded'],
                 upload_repeated=False, database_applied=False)
    record(attempt, 'intent', {**proof, **packet_status(packet_sha256, length, 'planned')})
    command.install()
    offer = command.offer()
    batch = RestoreInputSasIssuer(selection, transfer, 'r').issue(attempt, apply=True)
    record(attempt, 'read-attempt', packet_status(packet_sha256, length, 'attempted'))
    received = command.transfer(offer, sha(offer), batch)
    blob.need(received == packet_status(packet_sha256, length, 'verified'))
    result = {**proof, **received}
    record(attempt, 'verified', result)
    return result


def selected_job(selection_bytes, job_bytes, operation):
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
    return selection, job, meta['sender_boot']


def build_operation(selection_bytes, job_bytes, packet, tooling, *, operation, commit, tooling_sha256):
    selection, job, sender_boot = selected_job(selection_bytes, job_bytes, operation)
    return Operation(selection, job, packet, tooling, commit=commit, tooling_sha256=tooling_sha256,
                     sender_boot=sender_boot)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('plan', 'apply', 'observe', 'readback'))
    for name in ('selection', 'job', 'tooling', 'operation', 'commit', 'tooling-sha256'):
        parser.add_argument('--' + name, required=True)
    packet_input = parser.add_mutually_exclusive_group(required=True)
    packet_input.add_argument('--packet')
    packet_input.add_argument('--packet-sha256')
    parser.add_argument('--plan-sha256')
    parser.add_argument('--journal-root', type=Path)
    options = parser.parse_args()
    try:
        selection_bytes, job_bytes = read_bytes(options.selection, 8192), read_bytes(options.job, 8192)
        tooling = read_bytes(options.tooling, MAX_BUNDLE)
        pins = dict(commit=options.commit, tooling_sha256=options.tooling_sha256)
        if options.action == 'readback':
            selection, job, sender_boot = selected_job(selection_bytes, job_bytes, options.operation)
            result = readback_retry(selection, job, tooling, root=options.journal_root,
                                   packet_sha256=options.packet_sha256, plan_sha256=options.plan_sha256,
                                   sender_boot=sender_boot, **pins)
            print(json.dumps(result, sort_keys=True))
            return
        operation = build_operation(selection_bytes, job_bytes, read_bytes(options.packet, MAX_PACKET), tooling,
                                    operation=options.operation, **pins)
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
