"""Offline retained image SAS issuance with the maintained ARM observation path."""
import base64
from dataclasses import replace
import hashlib
import io
import json
import lzma
from pathlib import Path
import pickle
import sys
from tempfile import TemporaryDirectory
from threading import Barrier
import unittest
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlencode

import test_private_arm_adapter as native
import retained_image_parts as parts
import restore_carrier_command as carrier
import restore_packet_operator as workflow
import restore_tooling_bundle as tooling
from retained_image_sas import ImageSasIssuer
from restore_arm_authorization import Selection as Operator
from restore_authority_transaction import Target
from restore_guest_job import Job
from restore_guest_readback import SCOPE as GUEST_SCOPE
from restore_input_blob import PacketTransfer
from restore_input_sas import RestoreInputSasIssuer

arm = native.arm


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class ImageSasTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        native.CachedArmTests.setUpClass()

    def setUp(self):
        fixture = native.CachedArmTests()
        fixture.setUp()
        self.selection = fixture.selected
        self.operation = self.selection.store.blob.operation
        self.protocol = native.Protocol()
        root = TemporaryDirectory()
        self.addCleanup(root.cleanup)
        self.root = Path(root.name).resolve()
        data = b'x' * 1400
        self.completion = parts.encoded({'scope': 'azd-santa-retained-image-export-v1',
            'image_id': 'sha256:' + 'a'*64, 'intent_sha256': 'b'*64, 'archive_bytes': 1024,
            'archive_sha256': 'c'*64, 'ciphertext_bytes': len(data), 'ciphertext_sha256': sha(data)})
        size = patch.object(parts, 'PART_BYTES', 1024)
        size.start()
        self.addCleanup(size.stop)
        self.manifest = parts.plan(io.BytesIO(data), self.completion, completion_sha256=sha(self.completion),
                                   operation=self.operation)

        def sas(body):
            values = {key: item[0] for key, item in parse_qs(native.Protocol.sas(body)['serviceSasToken']).items()}
            values['sig'] = base64.b64encode(hashlib.sha256(body['canonicalizedResource'].encode()).digest()).decode()
            return {'serviceSasToken': urlencode(values)}

        self.protocol.sas = sas

    def issuer(self, permission='c'):
        return ImageSasIssuer(self.selection, self.manifest, self.completion, permission,
            manifest_sha256=sha(self.manifest), completion_sha256=sha(self.completion), operation=self.operation,
            cli=self.protocol.cli, transport=self.protocol.transport)

    def test_preview_never_reads_cache_or_writes_journal(self):
        plan = self.issuer().issue()
        self.assertEqual(plan['requests_sent'], 0)
        self.assertEqual(len(plan['objects']), 2)
        self.assertFalse(self.protocol.calls or self.protocol.cli_calls or list(self.root.iterdir()))

    def test_exact_role_batch_is_redacted_and_consumable_once(self):
        for permission in ('c', 'r'):
            with self.subTest(permission=permission):
                issuer = self.issuer(permission)
                begin = len(self.protocol.calls)
                batch = issuer.issue(self.root, apply=True)
                target = self.selection.source if permission == 'c' else self.selection.verifier
                self.assertEqual(repr(batch), '<private image SAS batch>')
                self.assertIsNone(issuer._token)
                with self.assertRaises(arm.ArmRejected):
                    pickle.dumps(batch)
                with self.assertRaises(arm.ArmRejected):
                    batch.take(target, permission, '0'*64)
                tokens = batch.take(target, permission, sha(self.manifest))
                with self.assertRaises(arm.ArmRejected):
                    batch.take(target, permission, sha(self.manifest))
                posted = [call for call in self.protocol.calls[begin:] if call[0] == 'POST']
                self.assertEqual(len(posted), 2)
                for _, url, body in posted:
                    self.assertTrue(url.endswith('/listServiceSas?api-version=2025-06-01'))
                    self.assertEqual(body['signedPermission'], permission)
                    self.assertEqual(body['signedResource'], 'b')
                    self.assertEqual(body['signedProtocol'], 'https')
                    self.assertTrue(body['canonicalizedResource'].endswith(tuple(tokens)))
                for path in (self.root / (self.operation + '-' + permission)).iterdir():
                    self.assertNotIn('sig=', path.read_text())

    def test_context_drift_after_first_post_aborts_and_persistent_reservation_prevents_retry(self):
        self.protocol.drift_after_post = True
        issuer = self.issuer()
        with self.assertRaises(arm.ArmRejected):
            issuer.issue(self.root, apply=True)
        journal = self.root / (self.operation + '-c')
        self.assertTrue((journal / 'intent.json').is_file())
        self.assertFalse((journal / 'issued.json').exists())
        calls = list(self.protocol.calls)
        with self.assertRaises(arm.ArmRejected):
            self.issuer().issue(self.root, apply=True)
        self.assertEqual(self.protocol.calls, calls)
        self.assertEqual(sum(method == 'POST' for method, _, _ in calls), 1)
        self.assertIsNone(issuer._token)

    def restore_transfer(self):
        receiver = self.selection.verifier
        operator = Operator(self.selection.tenant, self.selection.subscription, 'operator@example.com',
                            receiver.vm_id, receiver.instance_id, receiver.region)
        boot_id = '55555555-5555-4555-8555-555555555555'
        target = Target('azd_recovery_' + 'b' * 24, 'postgres', '/private/socket', 42, 24,
                        '2026-01-01T00:00:00', boot_id)
        receipt = dict(scope=GUEST_SCOPE, vm_id=receiver.vm_id, vm_instance_id=receiver.instance_id,
                       boot_id=boot_id)
        job = Job.from_readback(operator, target, guest_receipt=receipt, archive_sha256='a' * 64, generation='b' * 64)
        return PacketTransfer(job, self.selection.store, receiver, 'c' * 64, 512)

    def test_restore_issuance_separates_create_and_read_for_the_exact_packet(self):
        transfer = self.restore_transfer()
        self.protocol.context['user']['name'] = 'operator@example.com'
        for permission, target in (('c', self.selection.source), ('r', self.selection.verifier)):
            with self.subTest(permission=permission):
                begin = len(self.protocol.calls)
                issuer = RestoreInputSasIssuer(self.selection, transfer, permission,
                                               cli=self.protocol.cli, transport=self.protocol.transport)
                plan = issuer.issue()
                self.assertEqual(len(self.protocol.calls), begin)
                self.assertEqual(plan['requests_sent'], 0)
                self.assertEqual(plan['objects'], [
                    f'/blob/{transfer.store.blob.account}/native-captures/{self.operation}/restore-inputs/'
                    f'{transfer.packet_sha256}.sealed'])
                batch = issuer.issue(self.root, apply=True)
                with self.assertRaises(arm.ArmRejected):
                    batch.take(target, permission, '0' * 64)
                tokens = batch.take(target, permission, transfer.packet_sha256)
                with self.assertRaises(arm.ArmRejected):
                    batch.take(target, permission, transfer.packet_sha256)
                self.assertEqual(set(tokens), {transfer.object_metadata()['object']})
                posts = [entry for entry in self.protocol.calls[begin:] if entry[0] == 'POST']
                self.assertEqual(len(posts), 1)
                self.assertEqual(posts[0][2]['signedPermission'], permission)
                self.assertEqual(posts[0][2]['canonicalizedResource'], plan['objects'][0])
                for record in (self.root / (transfer.packet_sha256 + '-restore-input-' + permission)).iterdir():
                    self.assertNotIn('sig=', record.read_text())

    def test_restore_issuance_rejects_changed_operator_before_post(self):
        transfer = self.restore_transfer()
        for _ in range(2):
            issuer = RestoreInputSasIssuer(self.selection, transfer, 'c',
                                           cli=self.protocol.cli, transport=self.protocol.transport)
            with self.assertRaises(arm.ArmRejected):
                issuer.issue(self.root, apply=True)
            self.assertIsNone(issuer._token)
        self.assertFalse(self.protocol.calls)
        self.assertTrue((self.root / (transfer.packet_sha256 + '-restore-input-c') / 'intent.json').is_file())

    def test_recovery_command_frames_the_exact_reviewed_capsule_and_opaque_envelope(self):
        import subprocess
        root = Path(__file__).resolve().parents[1]
        commit = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip()
        raw = tooling.build(root, commit, version=13)
        ciphertext = bytes(range(256)) * 3
        transfer = replace(self.restore_transfer(), packet_sha256=sha(ciphertext), packet_bytes=len(ciphertext))
        command = carrier.Command(self.selection, transfer, 'r', raw, commit=commit,
                                  tooling_sha256=sha(raw), boot_id=transfer.job.verified_boot_id)
        envelope = bytes(range(256)) * 12
        offer = b'fixture-offer'
        frames = []

        def submit(_cli, args, script, _nonce, digest, seconds, *, scope):
            line = script.splitlines()[1]
            frame_bytes = base64.b64decode(line.split(b"'", 2)[1], validate=True)
            frame = json.loads(frame_bytes)
            self.assertEqual(sha(frame_bytes), digest)
            self.assertEqual(frame['capsule'], command.capsule)
            self.assertEqual(scope, carrier.SCOPE)
            self.assertLessEqual(len(script), 64 * 1024)
            self.assertEqual(args[args.index('--resource-group') + 1], transfer.target.vm_id.split('/')[4])
            frames.append(frame)
            if frame['action'] == 'stage':
                index = frame['index']
                return dict(state='staged', index=index, installed=index == frame['parts'] - 1)
            if frame['action'] == 'offer':
                return dict(state='offered', offer=carrier.b64(offer))
            return dict(state='verified', packet_sha256=transfer.packet_sha256, packet_bytes=transfer.packet_bytes)

        with patch.object(carrier.operator, 'observe', return_value={'exact_vm_verified': True}), \
             patch.object(carrier, 'submit_action', side_effect=submit), \
             patch.object(command._handoff, 'seal', return_value=envelope) as encrypt:
            command.install()
            self.assertEqual(command.offer(), offer)
            result = command.transfer(offer, sha(offer), object())
            self.assertEqual(result['state'], 'verified')
            encrypt.assert_called_once()
        staged = frames[:-2]
        self.assertGreater(len(staged), 1)
        recovered = lzma.decompress(b''.join(base64.b64decode(frame['bytes']) for frame in staged))
        self.assertEqual(sha(recovered), command.capsule)
        self.assertEqual(frames[-1]['envelope_sha256'], sha(envelope))
        self.assertEqual(set(frames[-1]), {'action', 'capsule', 'offer_sha256', 'envelope_sha256', 'envelope'})
        if sys.platform == 'linux':
            with TemporaryDirectory(dir=Path.home()) as folder:
                guest = Path(folder) / command.capsule
                guest.mkdir(mode=0o700)
                with patch.object(carrier.Handoff, 'offer', return_value=offer) as make_offer:
                    staged_offer = carrier.dispatch(guest, recovered, carrier.blob.encoded(frames[-2]))
                self.assertEqual(staged_offer, dict(state='offered', offer=carrier.b64(offer)))
                make_offer.assert_called_once_with(guest / 'offers')
                with patch.object(carrier.Handoff, 'use', return_value=ciphertext) as use:
                    receipt = carrier.dispatch(guest, recovered, carrier.blob.encoded(frames[-1]))
                use.assert_called_once_with(guest / 'offers', envelope, sha(offer), sha(envelope), packet=None)
                self.assertEqual(receipt, result)
                self.assertEqual((guest / 'packet.sealed').read_bytes(), ciphertext)
                self.assertEqual((guest / 'packet.sealed').stat().st_mode & 0o777, 0o600)

    def test_sender_stages_exact_ciphertext_within_run_command_limit(self):
        import subprocess
        root = Path(__file__).resolve().parents[1]
        commit = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip()
        raw = tooling.build(root, commit, version=14)
        ciphertext = bytes(range(256)) * 200
        transfer = replace(self.restore_transfer(), packet_sha256=sha(ciphertext), packet_bytes=len(ciphertext))
        command = carrier.Command(self.selection, transfer, 'c', raw, commit=commit,
                                  tooling_sha256=sha(raw), boot_id=transfer.job.verified_boot_id)
        frames = []

        def submit(_cli, args, script, _nonce, digest, _seconds, *, scope):
            frame_line, part_line = script.splitlines()[1:3]
            raw_frame = base64.b64decode(frame_line.split(b"'", 2)[1], validate=True)
            part = base64.b64decode(part_line.split(b"'", 2)[1], validate=True)
            frame = json.loads(raw_frame)
            self.assertEqual(sha(raw_frame), digest)
            self.assertEqual(scope, carrier.SCOPE)
            self.assertEqual(frame['part_sha256'], sha(part))
            self.assertLessEqual(len(script), 64 * 1024)
            self.assertEqual(args[args.index('--resource-group') + 1], self.selection.source.vm_id.split('/')[4])
            frames.append((frame, part))
            received = sum(len(body) for _, body in frames)
            return dict(index=frame['index'], received_bytes=received,
                        state='packet-staged' if received == len(ciphertext) else 'packet-part-staged')

        with patch.object(carrier.operator, 'observe', return_value={'exact_vm_verified': True}), \
             patch.object(carrier, 'submit_action', side_effect=submit):
            with self.assertRaises(native.retention.RetentionRejected):
                command.stage_packet(ciphertext[:-1])
            self.assertFalse(frames)
            command.stage_packet(ciphertext)
        self.assertEqual(len(frames), 2)
        self.assertEqual(b''.join(part for _, part in frames), ciphertext)
        if sys.platform == 'linux':
            package = lzma.decompress(b''.join(command._parts))
            with TemporaryDirectory(dir=Path.home()) as folder:
                guest = Path(folder) / command.capsule
                guest.mkdir(mode=0o700)

                def dispatch(frame, part):
                    return carrier.dispatch(guest, package, carrier.blob.encoded(frame), packet_part=part)

                with patch.object(carrier, 'boot', return_value=transfer.job.verified_boot_id):
                    with self.assertRaises(FileNotFoundError):
                        dispatch(*frames[1])
                    first, body = frames[0]
                    with self.assertRaises(native.retention.RetentionRejected):
                        dispatch({**first, 'part_sha256': '0' * 64}, body)
                    self.assertEqual(dispatch(*frames[0])['state'], 'packet-part-staged')
                    self.assertFalse((guest / 'packet.sealed').exists())
                    with self.assertRaises(FileExistsError):
                        dispatch(*frames[0])
                    self.assertEqual(dispatch(*frames[1])['state'], 'packet-staged')
                    self.assertEqual((guest / 'packet.sealed').read_bytes(), ciphertext)
                    self.assertFalse((guest / 'packet.partial').exists())

    def test_guided_transfer_reconciles_only_by_read_and_preserves_interruption(self):
        for mode in ('success', 'lost-upload', 'lost-read', 'failed-stage'):
            with self.subTest(mode=mode):
                calls = []
                root = self.root / mode
                root.mkdir(mode=0o700)
                packet = bytes(range(256)) * 3
                job = self.restore_transfer().job
                create_offer, read_offer = b'create-offer', b'read-offer'
                sender_boot = '66666666-6666-4666-8666-666666666666'
                staging = Barrier(2, timeout=10)

                class Guest:
                    def __init__(_self, _selection, _transfer, role, _tooling, **pins):
                        _self.role = role
                        _self.capsule = ('c' if role == 'c' else 'd') * 64
                        self.assertEqual(pins['boot_id'], sender_boot if role == 'c' else job.verified_boot_id)

                    def install(_self):
                        calls.append('install-' + _self.role)
                        staging.wait()

                    def stage_packet(_self, data):
                        self.assertEqual(data, packet)
                        calls.append('stage-packet')
                        if mode == 'failed-stage':
                            raise ValueError('simulated staging failure')

                    def offer(_self):
                        calls.append('offer-' + _self.role)
                        return create_offer if _self.role == 'c' else read_offer

                    def transfer(_self, offer, digest, issued):
                        self.assertEqual(offer, create_offer if _self.role == 'c' else read_offer)
                        self.assertEqual(digest, sha(offer))
                        self.assertEqual(issued, _self.role)
                        calls.append('transfer-' + _self.role)
                        if (mode, _self.role) in (('lost-upload', 'c'), ('lost-read', 'r')):
                            raise TimeoutError('simulated missing response')
                        return dict(state='uploaded' if _self.role == 'c' else 'verified',
                                    packet_sha256=sha(packet), packet_bytes=len(packet))

                class Issuer:
                    def __init__(_self, _selection, _transfer, role):
                        _self.role = role

                    def issue(_self, directory, *, apply):
                        self.assertTrue(apply and (directory / 'intent.json').is_file())
                        calls.append('issue-' + _self.role)
                        return _self.role

                with patch.object(workflow, 'Command', Guest), patch.object(workflow, 'RestoreInputSasIssuer', Issuer):
                    operation = workflow.Operation(self.selection, job, packet, b'fixture',
                                                   commit='a' * 40, tooling_sha256='b' * 64, sender_boot=sender_boot)
                    pin = operation.preview()['plan_sha256']
                    self.assertEqual(operation.observe(root, pin)['state'], 'not-attempted')
                    self.assertFalse(calls)
                    with self.assertRaises(native.retention.RetentionRejected):
                        operation.apply(root, '0' * 64)
                    if mode == 'failed-stage':
                        with self.assertRaises(ValueError):
                            operation.apply(root, pin)
                        self.assertCountEqual(calls, ['install-c', 'install-r', 'stage-packet', 'offer-r'])
                        self.assertEqual(operation.observe(root, pin)['state'], 'interrupted')
                        continue
                    if mode == 'lost-read':
                        with self.assertRaises(TimeoutError):
                            operation.apply(root, pin)
                        self.assertEqual(operation.observe(root, pin)['state'], 'interrupted')
                    else:
                        result = operation.apply(root, pin)
                        self.assertEqual(result['state'], 'verified')
                        self.assertEqual(result['upload_confirmed'], mode == 'success')
                    self.assertCountEqual(calls[:5], ['install-c', 'stage-packet', 'install-r', 'offer-c', 'offer-r'])
                    self.assertEqual([call for call in calls[:5] if call not in ('install-r', 'offer-r')],
                                     ['install-c', 'stage-packet', 'offer-c'])
                    self.assertLess(calls.index('install-r'), calls.index('offer-r'))
                    self.assertEqual(calls[5:], ['issue-c', 'transfer-c', 'issue-r', 'transfer-r'])
                    with self.assertRaises(FileExistsError):
                        operation.apply(root, pin)
                    self.assertEqual(calls.count('transfer-c'), 1)
                    self.assertEqual(calls.count('transfer-r'), 1)

    def test_readback_retry_reads_only_the_interrupted_object_on_a_fresh_boot(self):
        transfer = self.restore_transfer()
        job = transfer.job
        packet = bytes(range(256)) * 3
        boot = '66666666-6666-4666-8666-666666666666'
        pins = dict(commit='a' * 40, tooling_sha256='b' * 64, sender_boot='77777777-7777-4777-8777-777777777777')
        vm = job.selection
        receipt = dict(scope=GUEST_SCOPE, vm_id=vm.vm_id, vm_instance_id=vm.vm_instance_id, boot_id=boot)
        with patch.object(workflow, 'Command', return_value=Mock(capsule='c' * 64)):
            operation = workflow.Operation(self.selection, job, packet, b'fixture', **pins)
        plan = operation.preview()
        digest, length, plan_pin = plan['packet_sha256'], plan['packet_bytes'], plan['plan_sha256']
        for mode in ('confirmed', 'unknown', 'missing', 'changed-boot', 'changed-instance', 'no-upload'):
            with self.subTest(mode=mode):
                root = self.root / mode
                folder = root / (digest + '-restore-packet')
                root.mkdir(mode=0o700)
                folder.mkdir(mode=0o700)
                workflow.record(folder, 'intent', plan)
                if mode != 'no-upload':
                    workflow.record(folder, 'upload-attempt', workflow.packet_status(digest, length, 'attempted'))
                if mode == 'confirmed':
                    workflow.record(folder, 'uploaded', workflow.packet_status(digest, length, 'uploaded'))
                original = {path.name: path.read_bytes() for path in folder.iterdir()}
                report = receipt.copy()
                if mode == 'changed-boot':
                    report['boot_id'] = job.verified_boot_id
                if mode == 'changed-instance':
                    report['vm_instance_id'] = '88888888-8888-4888-8888-888888888888'
                guest = Mock(capsule='d' * 64)
                guest.offer.return_value = b'read-only offer'
                guest.transfer.return_value = workflow.packet_status(digest, length, 'verified')
                if mode == 'missing':
                    guest.transfer.side_effect = native.retention.RetentionRejected('missing blob')
                issuer = Mock()
                batch = issuer.issue.return_value
                args = dict(root=root, packet_sha256=digest, plan_sha256=plan_pin, **pins)
                with patch.object(workflow, 'Command', return_value=guest) as command, \
                     patch.object(workflow, 'RestoreInputSasIssuer', return_value=issuer) as issue, \
                     patch.object(workflow, 'readback', return_value=report) as probe, patch.object(workflow, 'verify'):
                    for changes in ({'plan_sha256': '0' * 64}, {'tooling_sha256': '1' * 64}):
                        with self.assertRaises(native.retention.RetentionRejected):
                            workflow.readback_retry(self.selection, job, b'fixture', **{**args, **changes})
                    probe.assert_not_called()
                    if mode == 'missing' or mode == 'no-upload':
                        with self.assertRaises(native.retention.RetentionRejected):
                            workflow.readback_retry(self.selection, job, b'fixture', **args)
                    elif mode in ('changed-boot', 'changed-instance'):
                        with self.assertRaises(ValueError):
                            workflow.readback_retry(self.selection, job, b'fixture', **args)
                    else:
                        result = workflow.readback_retry(self.selection, job, b'fixture', **args)
                        self.assertEqual(result['scope'], workflow.READBACK_SCOPE)
                        self.assertEqual(result['receiver_boot'], boot)
                        self.assertEqual(result['upload_confirmed'], mode == 'confirmed')
                        self.assertFalse(result['upload_repeated'] or result['database_applied'])
                        with self.assertRaises(native.retention.RetentionRejected):
                            workflow.delivery_binding(job, plan, plan_pin, result)
                        self.assertEqual(result, workflow.journal_read(folder / (boot + '-readback') / 'verified.json'))
                        with self.assertRaises(FileExistsError):
                            workflow.readback_retry(self.selection, job, b'fixture', **args)
                    if mode in ('confirmed', 'unknown', 'missing'):
                        retry = folder / (boot + '-readback')
                        issue.assert_called_once_with(self.selection, command.call_args.args[1], 'r')
                        self.assertEqual(command.call_args.args[2], 'r')
                        issuer.issue.assert_called_once_with(retry, apply=True)
                        guest.transfer.assert_called_once_with(b'read-only offer', sha(b'read-only offer'), batch)
                        self.assertTrue((retry / 'read-attempt.json').is_file())
                        self.assertEqual((retry / 'verified.json').exists(), mode != 'missing')
                    else:
                        command.assert_not_called()
                        issue.assert_not_called()
                self.assertEqual(original, {path.name: path.read_bytes() for path in folder.iterdir() if path.is_file()})
