"""Offline crypto/filesystem/cold-state guards; no guest or container actions."""
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import struct
import sys
import tarfile
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('cold_backup', ROOT / 'experiments/server/cold_backup.py')
backup = importlib.util.module_from_spec(spec); spec.loader.exec_module(backup)


class ColdBackup(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        cls.public = cls.key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

    def decrypt(self, raw, key=None):
        import base64
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        self.assertTrue(raw.startswith(backup.MAGIC))
        offset = len(backup.MAGIC)
        size = struct.unpack('>I', raw[offset:offset+4])[0]
        end = offset + 4 + size
        header = json.loads(raw[offset+4:end])
        secret = (key or self.key).decrypt(__import__('base64').b64decode(header['wrapped_key']),
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=backup.MAGIC))
        return AESGCM(secret).decrypt(base64.b64decode(header['nonce']), raw[end:], raw[:end])

    def test_real_stream_roundtrip_covers_all_five_stores_and_secret_files_without_plaintext_output(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve(); roots = {}
            for name in ('postgres_data', 'redis_data', 'rabbitmq_data', 'elasticsearch_data', 'media_data'):
                path = root / name; path.mkdir(); (path / 'sample').write_bytes((name + '-sentinel').encode())
                roots['volumes/' + name] = path
            secret = b'POSTGRES_PASSWORD=private-canary-password\n'
            env = root / 'migration.env'; env.write_bytes(secret); roots['control/0/migration.env'] = env
            output = io.BytesIO()
            sink = backup.EncryptedSink(output, self.public, 10*backup.CHUNK, time.monotonic()+30)
            signature = backup.signature
            # Windows CRT fstat exposes a different ctime from Path.lstat.
            # Production is Linux-only; this portable crypto fixture excludes
            # that field while retaining actual bytes/other metadata checks.
            def portable_signature(value):
                data = signature(value)
                return data[:7] + data[8:] if os.name == 'nt' else data
            with patch.object(backup.os, 'O_NOFOLLOW', getattr(os, 'O_NOFOLLOW', 0), create=True), patch.object(backup, 'signature', side_effect=portable_signature):
                count = backup.archive(sink, roots, {'scope': 'offline-roundtrip', 'current_authority': 'not_established'}, 100)
            sink.finish(); ciphertext = output.getvalue()
            self.assertNotIn(secret, ciphertext)
            self.assertEqual(backup.digest(ciphertext), sink.hasher.hexdigest())
            self.assertEqual(sink.total, len(ciphertext)); self.assertEqual(count, 11)
            with tarfile.open(fileobj=io.BytesIO(self.decrypt(ciphertext))) as archive:
                self.assertEqual(archive.extractfile('control/0/migration.env').read(), secret)
                for name in ('postgres_data', 'redis_data', 'rabbitmq_data', 'elasticsearch_data', 'media_data'):
                    self.assertEqual(archive.extractfile('volumes/'+name+'/sample').read(), (name+'-sentinel').encode())
                self.assertEqual(json.load(archive.extractfile('backup/capture.json'))['current_authority'], 'not_established')

    def test_ciphertext_header_tag_and_truncation_tampering_fail_authentication(self):
        from cryptography.exceptions import InvalidTag
        output = io.BytesIO(); sink = backup.EncryptedSink(output, self.public, 10000, time.monotonic()+30)
        sink.write(b'private-data'); sink.finish(); raw = output.getvalue()
        for at in (len(raw)-1, len(raw)-20):
            changed = bytearray(raw); changed[at] ^= 1
            with self.assertRaises(InvalidTag): self.decrypt(bytes(changed))
        changed = raw.replace(b'RSA-OAEP-256+A256GCM', b'RSA-OAEP-256+A256GCM'.lower())
        with self.assertRaises(InvalidTag): self.decrypt(changed)
        with self.assertRaises(InvalidTag): self.decrypt(raw[:-1])

    def test_wrong_recipient_cannot_decrypt_and_wrong_key_size_cannot_capture(self):
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        wrong = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public = wrong.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        with self.assertRaises(ValueError): backup.EncryptedSink(io.BytesIO(), public, 10000, time.monotonic()+30)
        output=io.BytesIO(); sink=backup.EncryptedSink(output,self.public,10000,time.monotonic()+30)
        sink.write(b'data'); sink.finish()
        with self.assertRaises(ValueError): self.decrypt(output.getvalue(), wrong)

    def test_output_size_deadline_and_entry_limits_fail_without_success_tag(self):
        for maximum, deadline in ((1, time.monotonic()+30), (10000, time.monotonic()-1)):
            with self.assertRaises(ValueError): backup.EncryptedSink(io.BytesIO(), self.public, maximum, deadline)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'file'; path.write_bytes(b'a')
            output=io.BytesIO(); sink=backup.EncryptedSink(output,self.public,100000,time.monotonic()+30)
            with self.assertRaises(ValueError): backup.archive(sink, {'data':path}, {}, 0)

    def test_links_and_special_files_are_never_archived(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'plain'; path.write_bytes(b'original')
            link=Path(folder)/'hard'; os.link(path, link)
            sink=backup.EncryptedSink(io.BytesIO(),self.public,100000,time.monotonic()+30)
            with self.assertRaises(ValueError): backup.archive(sink, {'data':link}, {}, 10)
            with patch.object(Path,'lstat',return_value=SimpleNamespace(st_mode=0o010600)):
                with self.assertRaises(ValueError): backup.archive(sink, {'data':path}, {}, 10)

    def test_unknown_final_cold_readback_preserves_partial_without_tag_or_completion_and_will_not_overwrite(self):
        from cryptography.exceptions import InvalidTag
        with tempfile.TemporaryDirectory() as folder:
            destination=Path(folder).resolve()
            def fail(): raise ValueError('cold state changed')
            with patch.object(backup.os, 'O_NOFOLLOW', getattr(os, 'O_NOFOLLOW', 0), create=True):
                with self.assertRaisesRegex(ValueError,'cold state changed'):
                    backup.write_capture(destination,self.public,{}, {},100000,10,time.monotonic()+30,fail)
                partial=(destination/'backup.sealed').read_bytes()
                self.assertFalse((destination/'complete.json').exists())
                with self.assertRaises(InvalidTag): self.decrypt(partial)
                with self.assertRaises(FileExistsError):
                    backup.write_capture(destination,self.public,{}, {},100000,10,time.monotonic()+30,lambda:None)
                self.assertEqual((destination/'backup.sealed').read_bytes(),partial)

    def test_actual_source_file_change_during_stream_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'data'; path.write_bytes(b'original')
            original=tarfile.TarFile.addfile
            def changing(output,info,fileobj=None):
                original(output,info,fileobj)
                if info.name=='data':
                    path.write_bytes(b'changed!')
                    stamp=path.stat().st_mtime_ns+1000000000
                    os.utime(path,ns=(stamp,stamp))
            sink=backup.EncryptedSink(io.BytesIO(),self.public,100000,time.monotonic()+30)
            signature=backup.signature
            def portable(value):
                data=signature(value)
                return data[:7]+data[8:] if os.name=='nt' else data
            with patch.object(backup.os,'O_NOFOLLOW',getattr(os,'O_NOFOLLOW',0),create=True), patch.object(backup,'signature',side_effect=portable), patch.object(tarfile.TarFile,'addfile',new=changing):
                with self.assertRaises(ValueError): backup.archive(sink,{'data':path},{},10)

    def selection(self):
        return dict(scope='azd-santa-cold-backup-selection-v1',
            target={'VmId':'/subscriptions/11111111-1111-4111-8111-111111111111/resourceGroups/rg-azd-santa-vm-synthetic/providers/Microsoft.Compute/virtualMachines/vm-santa-lab',
                    'VmInstanceId':'22222222-2222-4222-8222-222222222222'},
            runtime_manifest={'path':'/var/lib/azd-santa-qualification/runtime/runtime-service/manifest.json','sha256':'a'*64},
            controller_sha256=backup.CONTROLLER_SHA, backup_program_sha256=backup.digest(Path(backup.__file__).read_bytes()),
            recipient_sha256=backup.digest(self.public),
            containers={name:format(i+1,'064x') for i,name in enumerate(('db','redis','rabbitmq','elastic','web','workers','celery'))})

    def test_selection_rejects_hash_identity_source_container_and_duplicate_json_drift(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'selection.json'; value=self.selection()
            with patch.object(backup,'checked_file',side_effect=lambda p,**_:Path(p)):
                path.write_bytes(backup.encoded(value)); self.assertEqual(backup.load_selection(path,backup.digest(path.read_bytes())),value)
                for change in (lambda v:v['target'].update(VmId='wrong'), lambda v:v.update(backup_program_sha256='b'*64),
                               lambda v:v['containers'].update(db=v['containers']['web']), lambda v:v.update(controller_sha256='b'*64)):
                    changed=copy.deepcopy(value); change(changed); path.write_bytes(backup.encoded(changed))
                    with self.assertRaises(ValueError): backup.load_selection(path,backup.digest(path.read_bytes()))
                path.write_bytes(backup.encoded(value))
                with self.assertRaises(ValueError): backup.load_selection(path,'f'*64)
                path.write_bytes(b'{"scope":"first","scope":"second"}')
                with self.assertRaises(ValueError): backup.load_selection(path,backup.digest(path.read_bytes()))

    def runtime(self):
        selected=self.selection()['containers']
        state=dict(Status='exited',Running=False,Restarting=False,Paused=False,OOMKilled=False,ExitCode=0,
                   Error='',StartedAt='2026-11-07T01:00:00Z',FinishedAt='2026-11-07T01:01:00Z')
        rows=[dict(Id=cid,State=copy.deepcopy(state),Mounts=[]) for cid in selected.values()]
        unit='LoadState=loaded\nActiveState=inactive\nSubState=dead\nJob=\n'
        runtime=SimpleNamespace(command=['docker','--host','unix:///var/run/docker.sock','compose'],
            binding={'compose':'/var/lib/azd-santa-qualification/runtime/compose.json'},inspect=Mock(return_value=selected))
        responses={'cold-inspect':json.dumps(rows),'unit-cold':unit,'all-containers':'\n'.join(selected.values()),'all-mounts':json.dumps(rows)}
        runtime.call=Mock(side_effect=lambda label,args:SimpleNamespace(stdout=responses[label]))
        return runtime, selected, rows, responses

    def test_cold_state_rejects_running_killed_neverstarted_unitjob_and_foreign_writers(self):
        runtime,selected,rows,responses=self.runtime()
        backup.cold_state(runtime,selected,{'media_data':Path('/docker/selected/_data')})
        for field,value in [('Running',True),('ExitCode',137),('OOMKilled',True),('Status','created'),('StartedAt','0001-01-01')]:
            runtime,selected,rows,responses=self.runtime(); rows[0]['State'][field]=value; responses['cold-inspect']=json.dumps(rows)
            with self.assertRaises(ValueError): backup.cold_state(runtime,selected,{})
        for replacement in ('ActiveState=active','Job=123'):
            runtime,selected,rows,responses=self.runtime()
            responses['unit-cold']=responses['unit-cold'].replace(replacement.split('=')[0]+'='+('inactive' if replacement.startswith('Active') else ''),replacement)
            with self.assertRaises(ValueError): backup.cold_state(runtime,selected,{})
        runtime,selected,rows,responses=self.runtime()
        rows.append(dict(Id='f'*64,Mounts=[{'Source':'/docker/selected/_data'}]))
        responses['all-containers']+='\n'+'f'*64; responses['all-mounts']=json.dumps(rows)
        with self.assertRaises(ValueError): backup.cold_state(runtime,selected,{'media_data':Path('/docker/selected/_data')})

    def test_imds_wrong_instance_and_redirect_are_not_admitted(self):
        target=self.selection()['target']
        reply=Mock(); reply.__enter__=Mock(return_value=reply); reply.__exit__=Mock(return_value=None)
        reply.read.return_value=json.dumps({'resourceId':target['VmId'],'vmId':'f'*36}).encode()
        with patch.object(backup.urllib.request,'build_opener',return_value=SimpleNamespace(open=Mock(return_value=reply))):
            with self.assertRaises(ValueError): backup.host_identity(target)
        self.assertIsNone(backup.NoRedirect().redirect_request(None,None,None,None,None,None))

    def test_component_exposes_no_restore_stop_start_or_cleanup_commands(self):
        source=Path(backup.__file__).read_text()
        for action in ("['start'", "['stop'", "['rm'", 'shutil.rmtree', 'extractall', 'operator_security_store', 'operator_access'):
            self.assertNotIn(action,source)
        self.assertIn('fcntl.LOCK_EX | fcntl.LOCK_NB',source)
        self.assertIn("service.load_manifest(path, manifest['sha256'])",source)
        self.assertIn("not (pgdata / 'postmaster.pid').exists()",source)


if __name__ == '__main__': unittest.main()
