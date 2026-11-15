"""Offline crypto and irreversible-boundary tests; no Django/cloud side effects."""
import base64
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'experiments/server'))
import pilot_enrollment as pilot
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


class EnrollmentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=3072)

    def request(self):
        return dict(scope=pilot.SCOPE, nonce='a' * 32, deployment_sha256='b' * 64,
                    origin='https://santa.example.invalid', serial='SYNTHETIC123',
                    hardware_uuid='11111111-1111-4111-8111-111111111111', operator_username='synthetic',
                    source_commit=pilot.SOURCE,
                    recipient_public_key=base64.b64encode(self.key.public_key().public_bytes(
                        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).decode())

    def test_real_recipient_crypto_and_context_binding(self):
        request = self.request()
        secret = 'SYNTHETIC_CANARY_NOT_A_CREDENTIAL'
        envelope = pilot.seal(request, secret, 3, 7)
        self.assertNotIn(secret, json.dumps(envelope))
        self.assertLess(len(pilot.canonical(envelope)), 1500)
        clear = self.key.decrypt(base64.b64decode(envelope['ciphertext_base64']),
                                padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        payload = json.loads(clear)
        self.assertEqual(payload, dict(context_sha256=pilot.validate(request)[0], secret=secret,
                                       configuration_id=3, enrollment_id=7))
        changed = dict(request, serial='OTHERDEVICE123')
        self.assertNotEqual(pilot.validate(changed)[0], payload['context_sha256'])

    def test_ciphertext_cannot_be_decrypted_by_other_recipient_or_after_tampering(self):
        envelope = pilot.seal(self.request(), 'SYNTHETIC_CANARY_123', 3, 7)
        cipher = base64.b64decode(envelope['ciphertext_base64'])
        other = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        oaep = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        with self.assertRaises(ValueError):
            other.decrypt(cipher, oaep)
        with self.assertRaises(ValueError):
            self.key.decrypt(bytes([cipher[0] ^ 1]) + cipher[1:], oaep)

    def test_rejects_unbound_malformed_or_broadened_requests(self):
        for changes in ({'source_commit': '0' * 40}, {'serial': '*'},
                        {'hardware_uuid': '00000000-0000-0000-0000-000000000000'},
                        {'hardware_uuid': 'not-a-uuid'}, {'deployment_sha256': ''},
                        {'origin': 'https://santa.example.invalid/?secret=CANARY'},
                        {'origin': 'https://santa.example.invalid:443'},
                        {'origin': 'http://santa.example.invalid'}, {'scope': 'other'},
                        {'nonce': '../other'}, {'recipient_public_key': 'CANARY'}, {'extra': 'CANARY'}):
            with self.subTest(changes=changes), self.assertRaises((ValueError, TypeError)):
                pilot.validate(dict(self.request(), **changes))

    def test_rejects_weak_recipient_and_oversized_secret(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        raw = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        with self.assertRaises(ValueError):
            pilot.validate(dict(self.request(), recipient_public_key=base64.b64encode(raw).decode()))
        with self.assertRaises(ValueError):
            pilot.seal(self.request(), 'x' * 129, 3, 7)

    @unittest.skipIf(os.name == 'nt', 'Production checkpoint permissions are Linux-specific')
    def test_durable_attempt_blocks_replay_and_observe_never_creates(self):
        # Root is private without unsafe /tmp ancestor in the production tree;
        # patch only the ancestor check for this disposable test location.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request = self.request()
            digest, _ = pilot.validate(request)
            folder = root / digest
            folder.mkdir(mode=0o700)
            pilot.write_new(folder / 'request.json', request)
            envelope = pilot.seal(request, 'SYNTHETIC_CANARY_123', 3, 7)
            pilot.write_new(folder / 'sealed.json', envelope)
            from types import SimpleNamespace
            with patch.object(pilot, 'private_directory', side_effect=lambda p: Path(p)), \
                 patch.object(pilot, 'check_runtime'), patch.object(pilot, 'models') as models, \
                 patch.object(pilot, 'projection', return_value=(SimpleNamespace(pk=3), SimpleNamespace(pk=7), None)):
                with self.assertRaises(FileExistsError):
                    pilot.run(request, root, 'create')
                self.assertEqual(pilot.run(request, root, 'observe'), envelope)
                models.assert_not_called()
            self.assertEqual(os.stat(folder / 'sealed.json').st_mode & 0o777, 0o600)

    @unittest.skipIf(os.name == 'nt', 'Production no-follow/permissions are Linux-specific')
    def test_observe_rejects_wrong_persisted_request_and_never_creates(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request = self.request()
            folder = root / pilot.validate(request)[0]
            folder.mkdir(mode=0o700)
            pilot.write_new(folder / 'request.json', dict(request, serial='OTHERDEVICE123'))
            with patch.object(pilot, 'private_directory', side_effect=lambda p: Path(p)), \
                 patch.object(pilot, 'check_runtime'), patch.object(pilot, 'models') as models:
                with self.assertRaises(ValueError):
                    pilot.run(request, root, 'observe')
                models.assert_not_called()


if __name__ == '__main__':
    unittest.main()
