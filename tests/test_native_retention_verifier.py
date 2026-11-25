"""Separate verifier receive path with real synthetic ciphertext and cached ARM fixtures."""

from dataclasses import replace
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import test_blob_retention as blob_fixtures
import test_private_arm_adapter as arm_fixtures
import native_retention_verifier as relay


class NativeVerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        arm_fixtures.CachedArmTests.setUpClass()

    def setUp(self):
        self.arm = arm_fixtures.CachedArmTests()
        self.addCleanup(self.arm.doCleanups)
        self.arm.setUp()
        self.capture = self.arm.capture
        self.selected = self.arm.selected

    def test_only_independent_vm_is_admitted(self):
        job = relay.Verifier(self.selected, self.capture.record)
        self.assertEqual(job.offer()['permission'], 'r')
        self.assertFalse(job.offer()['performs_mutation'])
        self.assertEqual(job.offer()['target']['instance_id'], self.selected.verifier.instance_id)
        self.assertEqual(self.arm.protocol.calls, [])
        alias = replace(self.selected.verifier, instance_id=self.selected.source.instance_id)
        with self.assertRaises(relay.blob.RetentionRejected):
            relay.Verifier(replace(self.selected, verifier=alias), self.capture.record)

    @unittest.skipUnless(sys.platform == 'linux', 'Linux private verifier filesystem')
    def test_only_one_read_after_issuance_and_lost_reply_is_observable(self):
        with TemporaryDirectory(dir=Path.home()) as folder:
            root = Path(folder)
            job = relay.Verifier(self.selected, self.capture.record, root=root / 'verifier')
            selected_boot = '55555555-5555-4555-8555-555555555555'
            transport = blob_fixtures.Transport(self.capture.raw)
            arm = relay.CachedArm(self.selected, self.capture.record, self.selected.verifier, 'r',
                                   cli=self.arm.protocol.cli, transport=self.arm.protocol.transport)
            with patch.object(relay, 'boot', return_value=selected_boot) as boot, \
                 patch.object(relay.blob, 'host_identity'), patch.object(relay, 'CachedArm', return_value=arm):
                offer = job.offer(apply=True)
                self.assertEqual(job.observe()['offer'], relay.b64(offer))
                preview = job.issue(offer, root)
                self.assertEqual(preview['body']['signedPermission'], 'r')
                self.assertFalse(self.arm.protocol.calls)
                packet = job.issue(offer, root, apply=True)
                with self.assertRaises(FileExistsError):
                    job.issue(offer, root, apply=True)
                posts = [body for method, _, body in self.arm.protocol.calls if method == 'POST']
                self.assertEqual(len(posts), 1)
                self.assertEqual(posts[0]['signedPermission'], 'r')
                self.assertNotIn(b'sig=', packet)
                self.assertNotIn(b'sig=', (root / (self.capture.blob.operation + '-native-read') / 'intent.json').read_bytes())
                with self.assertRaises(relay.blob.RetentionRejected):
                    job.seal(offer, self.capture.cap('c'))
                boot.return_value = '66666666-6666-4666-8666-666666666666'
                with self.assertRaises(relay.blob.RetentionRejected):
                    job.receive(packet, relay.sha(offer), apply=True, transport=transport)
                self.assertEqual(transport.gets, 0)
                boot.return_value = selected_boot
                job.receive(packet, relay.sha(offer), apply=True, transport=transport)
                # Discard the direct response. Read durable evidence only.
                observed = job.observe()
                self.assertEqual(observed['state'], 'verified')
                self.assertTrue(observed['result']['independent_bytes_verified'])
                self.assertFalse(observed['result']['sealed_authenticated'])
                self.assertEqual((job.path / 'download' / 'backup.sealed').read_bytes(), self.capture.raw)
                self.assertFalse((job.path / 'recipient.der').exists())
                with self.assertRaises(FileNotFoundError):
                    job.receive(packet, relay.sha(offer), apply=True, transport=transport)
                self.assertEqual(transport.gets, 1)

    @unittest.skipUnless(sys.platform == 'linux', 'Linux private verifier filesystem')
    def test_corrupt_download_preserved_without_verification_or_replay(self):
        with TemporaryDirectory(dir=Path.home()) as folder:
            job = relay.Verifier(self.selected, self.capture.record, root=Path(folder) / 'verifier')
            bad = self.capture.raw[:-1] + bytes([self.capture.raw[-1] ^ 1])
            transport = blob_fixtures.Transport(bad)
            with patch.object(relay, 'boot', return_value='55555555-5555-4555-8555-555555555555'), \
                 patch.object(relay.blob, 'host_identity'):
                offer = job.offer(apply=True)
                packet = job.seal(offer, self.capture.cap('r'))
                with self.assertRaises(relay.blob.RetentionRejected):
                    job.receive(packet, relay.sha(offer), apply=True, transport=transport)
                self.assertEqual(job.observe(), {'state': 'submitted-unknown'})
                self.assertTrue((job.path / 'download' / 'backup.sealed').exists())
                with self.assertRaises(FileNotFoundError):
                    job.receive(packet, relay.sha(offer), apply=True, transport=transport)
                self.assertEqual(transport.gets, 1)
