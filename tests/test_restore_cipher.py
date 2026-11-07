"""Actual crypto with synthetic bytes; no application restore or guest actions."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]/'experiments/server'
def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT/(name+'.py'))
    value = importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
backup=module('cold_backup');restore=module('restore_cipher')


class Authentication(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        cls.key=rsa.generate_private_key(public_exponent=65537,key_size=3072)
        cls.public=cls.key.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)

    def sealed(self, payload=b'private synthetic event and credential canary'):
        output=io.BytesIO();sink=backup.EncryptedSink(output,self.public,4*backup.CHUNK,time.monotonic()+30)
        for offset in range(0,len(payload),backup.CHUNK):sink.write(payload[offset:offset+backup.CHUNK])
        sink.finish();return output.getvalue()

    def verify(self,raw,**options):
        return restore.authenticate(io.BytesIO(raw),len(raw),hashlib.sha256(raw).hexdigest(),self.key,**options)

    def test_producer_roundtrip_releases_no_plaintext_or_key_and_counts_multiple_chunks(self):
        raw=self.sealed(b'private-canary'*200000)
        result=self.verify(raw)
        self.assertFalse(result['plaintext_released']);self.assertEqual(result['plaintext_bytes'],len(b'private-canary'*200000))
        self.assertNotIn('private-canary',json.dumps(result));self.assertNotIn('wrapped_key',result)

    def test_tag_body_and_authenticated_header_tampering_never_return_a_result(self):
        from cryptography.exceptions import InvalidTag
        raw=self.sealed();offset=len(backup.MAGIC)+4+struct.unpack('>I',raw[len(backup.MAGIC):len(backup.MAGIC)+4])[0]
        for index in (offset, len(raw)-1):
            changed=bytearray(raw);changed[index]^=1
            with self.subTest(index=index),self.assertRaises(InvalidTag):self.verify(bytes(changed))
        changed=raw.replace(b'RSA-OAEP-256+A256GCM',b'RSA-OAEP-256+A128GCM')
        with self.assertRaises(ValueError):self.verify(changed)

    def test_valid_ciphertext_with_wrong_external_digest_is_rejected(self):
        raw=self.sealed()
        with self.assertRaises(ValueError):restore.authenticate(io.BytesIO(raw),len(raw),'0'*64,self.key)

    def test_wrong_recipient_and_small_key_are_rejected(self):
        from cryptography.hazmat.primitives.asymmetric import rsa
        raw=self.sealed()
        for size in (2048,3072):
            wrong=rsa.generate_private_key(public_exponent=65537,key_size=size)
            with self.subTest(size=size),self.assertRaises(ValueError):
                restore.authenticate(io.BytesIO(raw),len(raw),hashlib.sha256(raw).hexdigest(),wrong)

    def test_truncation_extension_and_size_limit_never_return_success(self):
        from cryptography.exceptions import InvalidTag
        raw=self.sealed()
        for value in (raw[:-1],raw+b'extension'):
            with self.subTest(size=len(value)),self.assertRaises(InvalidTag):self.verify(value)
        with self.assertRaises(ValueError):self.verify(raw[:20])
        with self.assertRaises(ValueError):self.verify(self.sealed(b'x'*(backup.CHUNK+1)),maximum=backup.CHUNK)

    def test_duplicate_and_oversized_headers_fail_before_private_key_unwrap(self):
        from cryptography.hazmat.primitives.asymmetric import rsa
        from unittest.mock import MagicMock
        key=MagicMock(spec=rsa.RSAPrivateKey);key.key_size=3072
        key.public_key.return_value.public_numbers.return_value.e=65537
        key.decrypt.side_effect=AssertionError('Invalid header must not unwrap')
        header=b'{"algorithm":"x","algorithm":"x"}'
        raw=backup.MAGIC+struct.pack('>I',len(header))+header+b'x'*32
        with self.assertRaises(ValueError):restore.authenticate(io.BytesIO(raw),len(raw),hashlib.sha256(raw).hexdigest(),key)
        raw=backup.MAGIC+struct.pack('>I',2049)+b'x'*2070
        with self.assertRaises(ValueError):restore.authenticate(io.BytesIO(raw),len(raw),hashlib.sha256(raw).hexdigest(),key)
        key.decrypt.assert_not_called()

    def test_deadline_is_checked_during_stream(self):
        raw=self.sealed()
        with patch.object(restore.time,'monotonic',side_effect=[0,0,2]):
            with self.assertRaises(ValueError):self.verify(raw,seconds=1)

    def test_file_wrapper_rejects_non_linux_before_open(self):
        with patch.object(restore.sys,'platform','win32'),patch.object(restore.os,'open') as opened:
            with self.assertRaises(ValueError):restore.verify_file('/not-a-restore-target','0'*64,self.key)
            opened.assert_not_called()


if __name__=='__main__':unittest.main()
