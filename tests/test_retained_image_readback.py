"""Exercise independent retained image readback using private synthetic files."""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import socket
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from test_retained_image_archive import fixture
import retained_image_export as export
import retained_image_load as loader
import retained_image_readback as readback


def sha(data):
    return hashlib.sha256(data).hexdigest()


@unittest.skipUnless(sys.platform == 'linux', 'Linux private staging contract')
class ReadbackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        cls.public = cls.key.public_key().public_bytes(serialization.Encoding.DER,
                                                       serialization.PublicFormat.SubjectPublicKeyInfo)

    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name)
        self.tar, self.image_id = fixture(oci=True, manifest_id=True)
        inventory = {'scope': 'azd-santa-retention-image-inventory-v1', 'platform': 'linux/amd64',
                     'images': {'core': {'id': self.image_id}}}
        self.inventory_sha256 = sha(export.encoded(inventory))

        @contextmanager
        def source(image_id, deadline):
            yield iter((self.tar,))

        with patch.object(export, 'docker_archive', source):
            self.result = export.export_image(self.home / 'export', inventory, 'core', self.public,
                inventory_sha256=self.inventory_sha256, recipient_sha256=sha(self.public))
        self.source = self.home / 'export' / 'image.sealed'

    def verify(self, **overrides):
        raw = export.encoded(self.result)
        options = dict(completion_sha256=sha(raw), inventory_sha256=self.inventory_sha256,
                       image_name='core', image_id=self.image_id)
        options.update(overrides)
        return readback.open_verified_image(self.source, raw, self.key, self.home, **options)

    def test_yields_exact_verified_bytes_from_anonymous_file_and_closes_it(self):
        with self.verify() as (archive, result):
            self.assertEqual(os.fstat(archive.fileno()).st_nlink, 0)
            self.assertFalse(archive.writable())
            self.assertEqual(archive.read(), self.tar)
            self.assertEqual(result['archive_sha256'], sha(self.tar))
            self.assertEqual(result['inventory_sha256'], self.inventory_sha256)
            self.assertFalse(result['image_loaded'])
        self.assertTrue(archive.closed)
        self.assertEqual(set(self.home.iterdir()), {self.home / 'export'})

    def test_external_pins_and_inventory_selection_are_required(self):
        for options in (dict(completion_sha256='0' * 64), dict(image_id='sha256:' + '0' * 64),
                        dict(inventory_sha256='0' * 64), dict(image_name='postgres')):
            with self.subTest(options=options), self.assertRaises(readback.ReadbackRejected), self.verify(**options):
                self.fail('Unexpected plaintext release')

    def test_bad_gcm_tag_never_creates_plaintext_staging_even_with_matching_hash(self):
        ciphertext = self.source.read_bytes()
        corrupted = ciphertext[:-1] + bytes([ciphertext[-1] ^ 1])
        self.source.write_bytes(corrupted)
        self.result['ciphertext_sha256'] = sha(corrupted)
        with patch.object(readback, 'TemporaryFile') as stage:
            with self.assertRaises(readback.ReadbackRejected), self.verify():
                self.fail('Unexpected plaintext release')
            stage.assert_not_called()

    def test_refuses_extra_link_and_truncated_ciphertext(self):
        linked = self.home / 'duplicate'
        os.link(self.source, linked)
        with self.assertRaises(readback.ReadbackRejected), self.verify():
            self.fail('Unexpected plaintext release')
        linked.unlink()
        self.source.write_bytes(self.source.read_bytes()[:-1])
        with self.assertRaises(readback.ReadbackRejected), self.verify():
            self.fail('Unexpected plaintext release')

    def test_rejects_source_changed_after_decryption(self):
        decrypt = readback.decrypt_staging

        def changed(*args):
            decrypt(*args)
            self.source.chmod(0o400)

        with patch.object(readback, 'decrypt_staging', changed):
            with self.assertRaises(readback.ReadbackRejected), self.verify():
                self.fail('Unexpected plaintext release')

    def test_load_transport_failure_keeps_intent_and_blocks_replay(self):
        with TemporaryDirectory(dir=Path.home()) as temporary:
            attempt = Path(temporary) / 'attempt'
            raw = export.encoded(self.result)
            pins = dict(completion_sha256=sha(raw), inventory_sha256=self.inventory_sha256,
                        image_name='core', image_id=self.image_id, socket='/fixture.sock', attempt=attempt)
            with patch.object(loader, 'RecoveryDocker') as docker:
                daemon = docker.return_value
                daemon.path = Path('/fixture.sock')
                daemon.identity = (10, 11)
                daemon.run.side_effect = TimeoutError('synthetic missing load reply')
                with self.assertRaises(TimeoutError):
                    loader.verify_or_load(self.source, raw, self.key, self.home, **pins)
                self.assertEqual(json.loads((attempt / 'intent.json').read_bytes())['state'], 'load-uncertain')
                self.assertFalse((attempt / 'outcome.json').exists())
                with self.assertRaises(FileExistsError):
                    loader.verify_or_load(self.source, raw, self.key, self.home, **pins)
                daemon.run.assert_called_once()
                daemon.confirm_image.assert_not_called()

    def test_recovery_daemon_rejects_socket_replacement(self):
        path = self.home / 'docker.sock'
        with socket.socket(socket.AF_UNIX) as original, socket.socket(socket.AF_UNIX) as replacement:
            original.bind(str(path))
            daemon = loader.RecoveryDocker(path)
            daemon.assert_current()
            path.rename(self.home / 'original.sock')
            replacement.bind(str(path))
            with self.assertRaises(readback.ReadbackRejected):
                daemon.assert_current()
