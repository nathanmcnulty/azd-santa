"""Real local cryptographic vectors; no Azure, Django, browser or tenant calls."""
import base64
import copy
import json
from pathlib import Path
import sys
import time
import unittest

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'experiments/server'))
import sealed_setup as sealed


def public(key, format=serialization.PublicFormat.SubjectPublicKeyInfo):
    return base64.b64encode(key.public_key().public_bytes(serialization.Encoding.DER, format)).decode()


def artifact():
    return dict(mode='recover', target=dict(pk=7, username='synthetic-\u00e9', email='synthetic@example.invalid'),
                setup_url='https://santa.example.invalid/accounts/reset/Nw/abcdef-' + 'a' * 32 + '/',
                expires_at_unix=time.time() + 600, reason='\u2603' * 256, removed={'irrelevant': True})


class RealCrypto(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=3072)

    def recipient(self, **changes):
        values = dict(public_key_base64=public(self.key), context_sha256='c' * 64, mode='recover',
                      username='synthetic-\u00e9', email='synthetic@example.invalid', setup_origin='https://santa.example.invalid')
        values.update(changes)
        return sealed.prepare_recipient(**values)

    def decrypt(self, envelope, key=None):
        key = key or self.key
        decode = lambda name: base64.b64decode(envelope[name], validate=True)
        symmetric = key.decrypt(decode('wrapped_key_base64'), padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        data = AESGCM(symmetric).decrypt(decode('nonce_base64'), decode('ciphertext_base64'),
            sealed.aad(envelope['mode'], envelope['kid_sha256'], envelope['context_sha256'], envelope['target_sha256']))
        return json.loads(data)

    def test_minimal_real_roundtrip_bound_and_randomness(self):
        data = artifact(); recipient = self.recipient()
        first, second = recipient.seal(data), recipient.seal(data)
        recovered = self.decrypt(first)
        self.assertEqual(set(recovered), {'setup_url', 'target_pk', 'expires_at_unix'})
        self.assertEqual(recovered['setup_url'], data['setup_url'])
        self.assertEqual(recovered['target_pk'], 7)
        self.assertLessEqual(len(json.dumps(first, separators=(',', ':')).encode()), 2600)
        self.assertNotIn(data['setup_url'], json.dumps(first))
        self.assertNotIn(data['target']['username'], json.dumps(first))
        for name in ('nonce_base64', 'wrapped_key_base64', 'ciphertext_base64'):
            self.assertNotEqual(first[name], second[name])

    def test_key_and_context_validation_precede_use(self):
        keys = ('not base64', public(rsa.generate_private_key(public_exponent=65537, key_size=2048)),
                public(ec.generate_private_key(ec.SECP256R1())),
                public(self.key, serialization.PublicFormat.PKCS1))
        for key in keys:
            with self.subTest(key_type=key[:8]), self.assertRaises(sealed.SealedSetupError):
                self.recipient(public_key_base64=key)
        for context in ('', 'C' * 64, 'f' * 63, 'x' * 64):
            with self.assertRaises(sealed.SealedSetupError):
                self.recipient(context_sha256=context)

    def test_tamper_wrong_recipient_and_aad_fail_real_authentication(self):
        original = self.recipient().seal(artifact())
        for field in ('mode', 'context_sha256', 'target_sha256', 'kid_sha256'):
            envelope = copy.deepcopy(original)
            envelope[field] = 'other' if field == 'mode' else 'f' * 64
            with self.assertRaises(InvalidTag):
                self.decrypt(envelope)
        envelope = copy.deepcopy(original)
        value = bytearray(base64.b64decode(envelope['ciphertext_base64'])); value[-1] ^= 1
        envelope['ciphertext_base64'] = base64.b64encode(value).decode()
        with self.assertRaises(InvalidTag):
            self.decrypt(envelope)
        with self.assertRaises(ValueError):
            self.decrypt(original, rsa.generate_private_key(public_exponent=65537, key_size=3072))

    def test_origin_identity_and_payload_shape_are_closed(self):
        for url in ('http://santa.example.invalid', 'https://user:pass@santa.example.invalid',
                    'https://santa.example.invalid/path', 'https://santa.example.invalid?x=1'):
            with self.assertRaises(sealed.SealedSetupError):
                self.recipient(setup_origin=url)
        for change in ({'setup_url': 'https://outside.invalid/accounts/reset/Nw/abcdef-' + 'a' * 32 + '/'},
                       {'expires_at_unix': float('nan')}, {'mode': 'bootstrap'},
                       {'target': dict(pk=8, username='synthetic-\u00e9', email='synthetic@example.invalid')},
                       {'target': dict(pk=7, username='other', email='synthetic@example.invalid')}):
            data = artifact(); data.update(change)
            with self.assertRaises(sealed.SealedSetupError):
                self.recipient().seal(data)


if __name__ == '__main__':
    if sys.argv[1:] == ['--seal-json']:
        request = json.loads(sys.stdin.buffer.read(8193).decode('utf-8'))
        data = request['artifact']
        recipient = sealed.prepare_recipient(request['public_key_base64'], request['context_sha256'],
            data['mode'], data['target']['username'], data['target']['email'], request['origin'])
        print(json.dumps(recipient.seal(data), separators=(',', ':')))
    else:
        unittest.main()
