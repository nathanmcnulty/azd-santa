"""Local guest/operator protocol tests using synthetic Blob and boot identity."""
import json
import sys
import unittest

import test_retained_image_handoff as fixtures
import retained_image_delivery as delivery
import retained_image_handoff as handoff


class PacketSizingTests(unittest.TestCase):
    def test_maximum_part_count_uses_six_bounded_packets_requests_at_fixture_size(self):
        digest = 'a' * 64
        packets = [bytes([index]) * 1600 for index in range(delivery.MAX_PARTS)]
        commands = list(delivery.packet_commands(digest, packets))
        self.assertEqual(len(commands), 6)
        self.assertLessEqual(max(len(raw) for raw, _ in commands), delivery.MAX_FRAME)
        merged = []
        for raw, ack in commands:
            start, group = delivery.decode_group(json.loads(raw))
            self.assertEqual(ack, {'state': 'staged', 'start': len(merged), 'count': len(group)})
            self.assertEqual(start, len(merged))
            merged.extend(group)
        self.assertEqual(merged, packets)

    def test_maximum_sized_envelopes_can_be_sent_individually(self):
        packets = [b'x' * handoff.MAX_PACKET] * delivery.MAX_PARTS
        frames = list(delivery.packet_commands('a' * 64, packets))
        self.assertEqual(len(frames), delivery.MAX_PARTS)
        self.assertLessEqual(max(len(raw) for raw, _ in frames), delivery.MAX_FRAME)


@unittest.skipUnless(sys.platform == 'linux', 'Linux guest journal protocol')
class DeliveryTests(unittest.TestCase):
    def setUp(self):
        self.handoff = fixtures.HandoffTests()
        self.addCleanup(self.handoff.doCleanups)
        self.handoff.setUp()
        self.fixture = self.handoff.fixture
        self.transfer = self.fixture.transfer
        self.operator = self.fixture.root / 'operator'
        self.operator.mkdir(mode=0o700)
        self.staging = self.fixture.root / 'staging'
        self.staging.mkdir(mode=0o700)

    def prepare(self, target, permission, attempt_root):
        offer, packets = self.handoff.prepare(target, permission)
        guest = delivery.Guest(self.staging, self.handoff.root, offer, handoff.sha(offer), self.transfer,
                               target, permission, attempt_root, source_path=self.fixture.source_file)
        return guest, offer, packets

    def test_bounded_operator_delivery_dispatches_upload_and_independent_readback(self):
        selections = (('c', self.fixture.source, self.fixture.root), ('r', self.fixture.reader, self.fixture.read_dir))
        for permission, target, root in selections:
            guest, offer, packets = self.prepare(target, permission, root)
            seen = []

            def invoke(raw):
                self.assertLessEqual(len(raw), delivery.MAX_FRAME)
                self.assertNotIn(b'sig=', raw)
                seen.append(json.loads(raw)['action'])
                return guest(raw)

            args = (invoke, self.operator, offer, packets, self.transfer, target, permission)
            preview = delivery.send(*args)
            self.assertFalse(preview['performs_mutation'])
            self.assertEqual(seen, [])
            result = delivery.send(*args, apply=True)
            self.assertEqual(seen, ['begin', 'parts', 'finish'])
            self.assertEqual(result, guest(delivery.frame('observe', result['batch_sha256'])))
        self.assertEqual(result['result']['verified_parts'], 3)

    def test_lost_finish_response_is_observed_without_replay(self):
        target = self.fixture.source
        guest, offer, packets = self.prepare(target, 'c', self.fixture.root)
        batch = delivery.build_batch(offer, packets, self.transfer, target, 'c')
        digest = handoff.sha(batch)

        def invoke(raw):
            result = guest(raw)
            if json.loads(raw)['action'] == 'finish':
                raise TimeoutError('synthetic lost response')
            return result

        args = (invoke, self.operator, offer, packets, self.transfer, target, 'c')
        with self.assertRaises(handoff.blob.RetentionRejected):
            delivery.send(*args, apply=True)
        observed = guest(delivery.frame('observe', digest))
        self.assertEqual(observed['result']['state'], 'uploaded')
        with self.assertRaises(handoff.blob.RetentionRejected):
            delivery.send(*args, apply=True)
        with self.assertRaises(handoff.blob.RetentionRejected):
            guest(delivery.frame('finish', digest))
        self.assertEqual(len(self.fixture.calls), 3)

    def test_missing_or_changed_frame_cannot_trigger_transfer(self):
        target = self.fixture.source
        guest, offer, packets = self.prepare(target, 'c', self.fixture.root)
        batch = delivery.build_batch(offer, packets, self.transfer, target, 'c')
        digest = handoff.sha(batch)
        guest(delivery.frame('begin', digest, batch=handoff.b64(batch)))
        first, second, _ = map(handoff.b64, packets.values())
        with self.assertRaises(handoff.blob.RetentionRejected):
            guest(delivery.frame('parts', digest, start=0, packets=[first, first]))
        self.assertEqual(guest(delivery.frame('observe', digest))['staged'], [])
        # An overlapping request cannot write an otherwise valid trailing member.
        guest(delivery.frame('part', digest, index=0, packet=first))
        with self.assertRaises(handoff.blob.RetentionRejected):
            guest(delivery.frame('parts', digest, start=0, packets=[first, second]))
        with self.assertRaises(handoff.blob.RetentionRejected):
            guest(delivery.frame('finish', digest))
        self.assertEqual(guest(delivery.frame('observe', digest))['staged'], [0])
        self.assertEqual(self.fixture.calls, [])

    def test_lost_group_response_stops_before_finish_and_can_be_observed(self):
        target = self.fixture.source
        guest, offer, packets = self.prepare(target, 'c', self.fixture.root)
        actions = []
        batch = delivery.build_batch(offer, packets, self.transfer, target, 'c')
        digest = handoff.sha(batch)

        def invoke(raw):
            action = json.loads(raw)['action']
            actions.append(action)
            result = guest(raw)
            if action == 'parts':
                raise TimeoutError('synthetic lost group response')
            return result

        for _ in range(2):
            with self.assertRaises(handoff.blob.RetentionRejected):
                delivery.send(invoke, self.operator, offer, packets, self.transfer, target, 'c', apply=True)
        self.assertEqual(actions, ['begin', 'parts'])
        self.assertEqual(guest(delivery.frame('observe', digest))['staged'], [0, 1, 2])
        self.assertEqual(self.fixture.calls, [])
