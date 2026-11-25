"""Synthetic part stores and exact ciphertext reassembly."""
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'experiments/server'))
import retained_image_parts as parts
from blob_retention import MAXIMUM as NATIVE_MAXIMUM


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class PartsTests(unittest.TestCase):
    def setUp(self):
        self.operation = 'd' * 32
        self.ciphertext = bytes(range(256)) * 9
        self.completion = parts.encoded({'scope': 'azd-santa-retained-image-export-v1',
            'image_id': 'sha256:' + 'a' * 64, 'intent_sha256': 'b' * 64,
            'archive_bytes': 2048, 'archive_sha256': 'c' * 64,
            'ciphertext_bytes': len(self.ciphertext), 'ciphertext_sha256': sha(self.ciphertext)})
        patcher = patch.object(parts, 'PART_BYTES', 1024)
        patcher.start()
        self.addCleanup(patcher.stop)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.target = Path(temporary.name) / 'image.sealed'

    def plan(self, data=None):
        return parts.plan(io.BytesIO(self.ciphertext if data is None else data), self.completion,
                          completion_sha256=sha(self.completion), operation=self.operation)

    def store(self, raw):
        return {part['object']: self.ciphertext[part['offset']:part['offset'] + part['bytes']]
                for part in json.loads(raw)['parts']}

    def assemble(self, raw, store, **overrides):
        kwargs = dict(manifest_sha256=sha(raw), completion_sha256=sha(self.completion), operation=self.operation)
        kwargs.update(overrides)
        return parts.assemble(raw, self.completion, self.target, lambda name: io.BytesIO(store[name]), **kwargs)

    def test_reassembles_three_parts_in_order_under_trusted_pins(self):
        raw = self.plan()
        self.assertEqual(raw, self.plan())
        self.assertEqual([row['bytes'] for row in json.loads(raw)['parts']], [1024, 1024, 256])
        result = self.assemble(raw, self.store(raw))
        self.assertEqual(result['verified_parts'], 3)
        self.assertEqual(result['ciphertext_sha256'], sha(self.ciphertext))
        self.assertEqual(self.target.read_bytes(), self.ciphertext)
        with self.assertRaises(parts.PartsRejected):
            self.assemble(raw, {})
        self.assertEqual(self.target.read_bytes(), self.ciphertext)

    def test_corrupt_truncated_or_extended_source_does_not_get_a_plan(self):
        for data in (b'x' + self.ciphertext[1:], self.ciphertext[:-1], self.ciphertext + b'x'):
            with self.assertRaises(parts.PartsRejected):
                self.plan(data)

    def test_missing_short_extended_and_changed_parts_never_complete(self):
        raw = self.plan()
        for change in ('missing', 'short', 'extra', 'digest'):
            with self.subTest(change=change):
                self.target = self.target.with_name(change)
                store = self.store(raw)
                name = next(reversed(store))
                if change == 'missing':
                    del store[name]
                elif change == 'short':
                    store[name] = store[name][:-1]
                elif change == 'extra':
                    store[name] += b'x'
                else:
                    store[name] = b'x' + store[name][1:]
                with self.assertRaises(parts.PartsRejected):
                    self.assemble(raw, store)
                self.assertTrue(self.target.exists())

    def test_rejects_untrusted_pins_order_and_object_paths_before_creating_output(self):
        raw = self.plan()
        with self.assertRaises(parts.PartsRejected):
            self.assemble(raw, {}, manifest_sha256='0' * 64)
        for change in ('reorder', 'path'):
            doc = json.loads(raw)
            if change == 'reorder':
                doc['parts'].reverse()
            else:
                doc['parts'][0]['object'] = '../different-object'
            with self.assertRaises(parts.PartsRejected):
                self.assemble(parts.encoded(doc), {})
        self.assertFalse(self.target.exists())

    def test_layout_covers_the_full_image_limit_without_changing_native_bounds(self):
        size = 16 * 1024**3 + 4096
        with patch.object(parts, 'PART_BYTES', 512 * 1024**2):
            planned = list(parts.layout(size, self.operation))
        self.assertEqual(len(planned), 33)
        self.assertEqual(sum(part['bytes'] for part in planned), size)
        self.assertEqual(planned[-1]['bytes'], 4096)
        self.assertEqual(NATIVE_MAXIMUM, 2 * 1024**3)
