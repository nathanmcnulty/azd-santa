"""Actual crypto with synthetic bytes; no application restore or guest actions."""
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]/'experiments/server'
def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT/(name+'.py'))
    value = importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
backup=module('cold_backup');restore=module('restore_cipher')
with patch.object(sys, 'path', [str(ROOT), *sys.path]):
    verify_backup = module('verify_retained_backup')


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

    def test_command_authenticates_the_pinned_local_archive_using_the_pinned_key(self):
        raw = self.sealed()
        ciphertext_sha = hashlib.sha256(raw).hexdigest()
        key_sha = 'b' * 64
        arguments = ['--backup', '/private/backup.sealed', '--backup-sha256', ciphertext_sha,
                     '--portable-key', '/private/recovery.der', '--portable-key-sha256', key_sha]
        report = self.verify(raw)
        output = io.StringIO()
        with patch.object(verify_backup.sys, 'platform', 'linux'), \
             patch.object(verify_backup.os, 'geteuid', return_value=0, create=True), \
             patch.object(verify_backup.restore_recipient_key, 'load', return_value=self.key) as load, \
             patch.object(verify_backup.restore_cipher, 'verify_file', return_value=report) as check, \
             redirect_stdout(output):
            verify_backup.main(arguments)
        load.assert_called_once_with('/private/recovery.der', key_sha)
        check.assert_called_once_with('/private/backup.sealed', ciphertext_sha, self.key)
        self.assertEqual(json.loads(output.getvalue()), report)

    def test_command_redacts_key_errors_and_emits_no_success_receipt(self):
        arguments = ['--backup', '/private/backup.sealed', '--backup-sha256', 'a' * 64,
                     '--portable-key', '/private/recovery.der', '--portable-key-sha256', 'b' * 64]
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(verify_backup.sys, 'platform', 'linux'), \
             patch.object(verify_backup.os, 'geteuid', return_value=0, create=True), \
             patch.object(verify_backup.restore_recipient_key, 'load',
                          side_effect=ValueError('/private/recovery.der')) as load, \
             patch.object(verify_backup.restore_cipher, 'verify_file') as check, \
             redirect_stdout(stdout), redirect_stderr(stderr), self.assertRaises(SystemExit) as exit_status:
            verify_backup.main(arguments)
        self.assertEqual(exit_status.exception.code, 1)
        load.assert_called_once()
        check.assert_not_called()
        self.assertEqual(stdout.getvalue(), '')
        self.assertNotIn('/private/recovery.der', stderr.getvalue())

    @unittest.skipUnless(sys.platform == 'linux' and os.geteuid() == 0, 'requires a private Linux root directory')
    def test_linux_command_authenticates_real_portable_inputs(self):
        from cryptography.hazmat.primitives import serialization

        raw = self.sealed()
        digest = hashlib.sha256(raw).hexdigest()
        passphrase = b'test-only Santa recovery passphrase'
        key_der = self.key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption())
        with tempfile.TemporaryDirectory(prefix='santa-recovery-test-', dir='/root') as folder:
            private = Path(folder)
            archive = private / 'backup.sealed'
            original = private / 'original.der'
            portable = private / 'portable.der'
            archive.write_bytes(raw)
            archive.chmod(0o600)
            original.write_bytes(key_der)
            original.chmod(0o600)
            fingerprint = hashlib.sha256(self.public).hexdigest()
            exported = verify_backup.restore_recipient_key.pack(original, portable, fingerprint, passphrase)
            original.unlink()

            def arguments(backup_digest, recipient_digest):
                return ['--backup', str(archive), '--backup-sha256', backup_digest,
                        '--portable-key', str(portable), '--portable-key-sha256', recipient_digest]

            key_digest = exported['encrypted_key_sha256']
            with patch.object(verify_backup.restore_recipient_key, 'passphrase', return_value=passphrase):
                output = io.StringIO()
                with redirect_stdout(output):
                    verify_backup.main(arguments(digest, key_digest))
                report = json.loads(output.getvalue())
                self.assertEqual(report['ciphertext_sha256'], digest)
                self.assertEqual(report['ciphertext_bytes'], len(raw))
                self.assertEqual(report['recipient_sha256'], fingerprint)
                self.assertFalse(report['plaintext_released'])

                for backup_digest, recipient_digest in (('0' * 64, key_digest), (digest, '0' * 64)):
                    with self.subTest(backup_digest=backup_digest, recipient_digest=recipient_digest):
                        stdout, stderr = io.StringIO(), io.StringIO()
                        with redirect_stdout(stdout), redirect_stderr(stderr), self.assertRaises(SystemExit) as failure:
                            verify_backup.main(arguments(backup_digest, recipient_digest))
                        self.assertEqual(failure.exception.code, 1)
                        self.assertEqual(stdout.getvalue(), '')
                        self.assertIn('Santa backup authentication failed', stderr.getvalue())
            self.assertEqual(set(private.iterdir()), {archive, portable})


if __name__=='__main__':unittest.main()
