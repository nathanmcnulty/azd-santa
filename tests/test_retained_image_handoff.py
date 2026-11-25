"""Independent source and verifier handoff with synthetic HTTP and VM identity."""
import base64
import json
import sys
import unittest
from unittest.mock import patch

import test_retained_image_blob as fixtures
from retained_image_sas import IssuedBatch
import retained_image_handoff as handoff

BOOT = '00000000-0000-4000-8000-000000000001'


@unittest.skipUnless(sys.platform == 'linux', 'Linux selected-host journal contract')
class HandoffTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.TransferTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.transfer = self.fixture.transfer
        self.root = self.fixture.root / 'handoff'
        self.root.mkdir(mode=0o700)
        boot = patch.object(handoff, 'boot', return_value=BOOT)
        self.boot = boot.start()
        self.addCleanup(boot.stop)

    def prepare(self, target, permission):
        offer = handoff.create_offer(self.root, self.transfer, target, permission, apply=True)
        issuer = IssuedBatch(target, permission, self.transfer.pins['manifest_sha256'],
                             self.fixture.tokens(permission), account_id=self.transfer.store.blob.account_id)
        packets = handoff.seal(offer, handoff.sha(offer), issuer, self.transfer, target, permission)
        for packet in packets.values():
            self.assertNotIn(b'sig=', packet)
            self.assertLessEqual(len(packet), handoff.MAX_PACKET)
        with self.assertRaises(handoff.blob.RetentionRejected):
            handoff.seal(offer, handoff.sha(offer), issuer, self.transfer, target, permission)
        return offer, packets

    def receive(self, target, permission, offer, packets):
        root = self.fixture.root if permission == 'c' else self.fixture.read_dir
        return handoff.receive_and_transfer(self.root, offer, handoff.sha(offer), packets, self.transfer,
            target, permission, root, source_path=self.fixture.source_file, apply=True)

    def test_separate_boot_bound_upload_and_readback(self):
        self.assertFalse(handoff.create_offer(self.root, self.transfer, self.fixture.source, 'c')['performs_mutation'])
        self.boot.assert_not_called()
        offer, packets = self.prepare(self.fixture.source, 'c')
        result = self.receive(self.fixture.source, 'c', offer, packets)
        self.assertEqual(result['state'], 'uploaded')
        self.assertEqual(result['confirmed_parts'], 3)
        state = self.root / (fixtures.OPERATION + '-c')
        self.assertEqual({file.name for file in state.iterdir()}, {'consumed', 'intent.json'})
        with self.assertRaises(handoff.blob.RetentionRejected):
            self.receive(self.fixture.source, 'c', offer, packets)
        offer, packets = self.prepare(self.fixture.reader, 'r')
        result = self.receive(self.fixture.reader, 'r', offer, packets)
        self.assertEqual(result['verified_parts'], 3)
        self.assertEqual(len(self.fixture.calls), 6)

    def test_reboot_and_wrong_role_do_not_consume_the_offer(self):
        offer, packets = self.prepare(self.fixture.source, 'c')
        self.boot.return_value = '00000000-0000-4000-8000-000000000002'
        for target, permission in ((self.fixture.reader, 'r'), (self.fixture.source, 'c')):
            with self.assertRaises(handoff.blob.RetentionRejected):
                self.receive(target, permission, offer, packets)
        self.assertEqual(self.fixture.calls, [])
        self.assertTrue((self.root / (fixtures.OPERATION + '-c') / 'recipient.der').exists())

    def test_changed_authenticated_packet_stops_before_blob_and_cannot_replay(self):
        offer, packets = self.prepare(self.fixture.source, 'c')
        name = next(iter(packets))
        changed = json.loads(packets[name])
        data = bytearray(base64.b64decode(changed['ciphertext']))
        data[0] ^= 1
        changed['ciphertext'] = handoff.b64(data)
        for batch in ({**packets, name: handoff.blob.encoded(changed)}, packets):
            with self.assertRaises(handoff.blob.RetentionRejected):
                self.receive(self.fixture.source, 'c', offer, batch)
        self.assertEqual(self.fixture.calls, [])
