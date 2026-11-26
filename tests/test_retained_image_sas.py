"""Offline retained image SAS issuance with the maintained ARM observation path."""
import base64
import hashlib
import io
from pathlib import Path
import pickle
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlencode

import test_private_arm_adapter as native
import retained_image_parts as parts
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
