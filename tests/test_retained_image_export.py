"""Linux export filesystem, failure and independent ciphertext checks."""
from contextlib import contextmanager
import hashlib
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import time
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'experiments/server'))
import retained_image_export as export
from restore_cipher import authenticate


@unittest.skipUnless(sys.platform == 'linux', 'Linux Docker export filesystem contract')
class ExportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        cls.public = cls.key.public_key().public_bytes(serialization.Encoding.DER,
                                                       serialization.PublicFormat.SubjectPublicKeyInfo)

    def setUp(self):
        folder = TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.destination = Path(folder.name) / 'artifact'
        self.image_id = 'sha256:' + '1' * 64
        self.inventory = {'scope': 'azd-santa-retention-image-inventory-v1', 'platform': 'linux/amd64',
                          'images': {'core': {'id': self.image_id}}}

    def capture(self, **kwargs):
        pins = {'inventory_sha256': hashlib.sha256(export.encoded(self.inventory)).hexdigest(),
                'recipient_sha256': hashlib.sha256(self.public).hexdigest()}
        pins.update(kwargs)
        return export.export_image(self.destination, self.inventory, 'core', self.public, **pins)

    def test_success_is_private_and_bound_to_the_intent(self):
        tar = (b'confidential sentinel' + bytes(1024))[:1024]

        @contextmanager
        def source(image_id, deadline):
            self.assertEqual(image_id, self.image_id)
            self.assertTrue((self.destination / 'intent.json').exists())
            yield iter((tar[:512], tar[512:]))

        with patch.object(export, 'docker_archive', source):
            result = self.capture()
            with self.assertRaises(export.ExportRejected):
                self.capture()
        self.assertEqual(result['archive_sha256'], hashlib.sha256(tar).hexdigest())
        self.assertEqual((self.destination / 'complete.json').read_bytes(), export.encoded(result))
        self.assertEqual(self.destination.stat().st_mode & 0o777, 0o700)
        sealed = self.destination / 'image.sealed'
        self.assertEqual(sealed.stat().st_mode & 0o777, 0o600)
        self.assertNotIn(b'confidential sentinel', sealed.read_bytes())
        with sealed.open('rb') as stream:
            verified = authenticate(stream, result['ciphertext_bytes'], result['ciphertext_sha256'], self.key)
        self.assertEqual(verified['plaintext_bytes'], len(export.IMAGE_MAGIC) + 4 +
                         (self.destination / 'intent.json').stat().st_size + len(tar))

    def test_nonzero_export_and_size_cap_leave_intent_without_completion(self):
        for failure in ('nonzero', 'byte_limit'):
            with self.subTest(failure=failure):
                self.destination = self.destination.with_name(failure)

                @contextmanager
                def source(image_id, deadline):
                    yield iter((bytes(1024), bytes(512)))
                    raise subprocess.CalledProcessError(1, 'synthetic Docker failure')

                with patch.object(export, 'docker_archive', source), self.assertRaises(export.ExportRejected):
                    self.capture(maximum=1024 if failure == 'byte_limit' else 2048)
                self.assertTrue((self.destination / 'intent.json').exists())
                self.assertFalse((self.destination / 'complete.json').exists())

    def test_wrong_pins_fail_before_creating_an_intent(self):
        for pin in ('inventory_sha256', 'recipient_sha256'):
            with self.subTest(pin=pin), self.assertRaises(export.ExportRejected):
                self.capture(**{pin: '0' * 64})
            self.assertFalse(self.destination.exists())

    def test_cancels_stalled_export_process(self):
        actual_popen = subprocess.Popen
        processes = []

        def launch(*args, **kwargs):
            process = actual_popen([sys.executable, '-c', 'import time; time.sleep(60)'], **kwargs)
            processes.append(process)
            return process

        with patch.object(export.subprocess, 'Popen', launch), self.assertRaises(export.ExportRejected):
            with export.docker_archive(self.image_id, time.monotonic() + 0.2) as chunks:
                list(chunks)
        self.assertIsNotNone(processes[0].poll())
