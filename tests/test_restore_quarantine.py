"""Synthetic producer/crypto/archive tests, with separate Linux fd-write cases."""
import base64
from contextlib import contextmanager
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import time
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'experiments/server'))
import cold_backup as producer
import native_snapshot as native
import restore_cipher
import restore_quarantine as quarantine
import restore_recipient_key as recipient_key
import retained_image_compatibility as compatibility


def digest(raw): return hashlib.sha256(raw).hexdigest()


class MemoryWriter:
    """Parser-only sink, not proof of Linux descriptor containment."""
    def __init__(self): self.files = {}; self.directories = set()
    def directory(self, name): self.directories.add(name)
    def file(self, name, chunks):
        if name in self.files: raise FileExistsError()
        self.files[name] = b''.join(chunks)


class Quarantine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        cls.public = cls.key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

    def fixture(self, folder, *, maximum_bytes=4*quarantine.CHUNK, maximum_files=1000):
        base = Path(folder); control = quarantine.ROOT + '/private-runtime-synthetic/runtime-service'
        runtime = str(Path(control).parent).replace('\\', '/')
        source = quarantine.ROOT + '/installers/' + 'a'*64
        operation = control + '/backup-' + 'b'*32
        contents = {}
        for name in ('compose.json', 'conf/base.json', 'db.env', 'rabbitmq.env', 'runtime.env', 'migration.env'):
            contents[runtime + '/' + name] = b'synthetic-private-preservation:' + name.encode()
        selected = {p: digest(raw) for p, raw in contents.items() if not p.endswith('/migration.env')}
        manifest = dict(scope='private-initialized-runtime-service-v1', files=selected,
            controller_sha256=quarantine.PROGRAMS['runtime_service.py'], source_commit=quarantine.COMMIT,
            compose=runtime + '/compose.json', project='santa-zentral-eval-'+'1'*12,
            policy_hashes={name:'e'*64 for name in ('policy','recovery','sealed','admission')},
            worker_hashes={'azd_santa_worker_lifecycle.py':quarantine.PROGRAMS['worker_lifecycle.py'],
                'base/management/commands/runworkers.py':'be379c804120c5a0dd3620bab14adbd5f8a0b89f51ed43ee2284d6eb1f0d9515'},
            helpers_sha256={name:digest((ROOT / 'experiments/server' / name).read_bytes()) for name in
                ('test_live_zentral.py','prepare_zentral_eval.py','cold_backup.py','native_snapshot.py','worker_lifecycle.py')})
        # Runtime.private_write uses spaced JSON. It must not be canonicalized or changed.
        contents[control + '/manifest.json'] = json.dumps(manifest, sort_keys=True).encode()
        containers = {n:format(i+1, '064x') for i,n in enumerate(('web','workers','celery','db','redis','rabbitmq','elastic'))}
        target = dict(VmId='/subscriptions/11111111-1111-4111-8111-111111111111/resourceGroups/rg-azd-santa-vm-synthetic/providers/Microsoft.Compute/virtualMachines/vm-santa-lab',
                      VmInstanceId='22222222-2222-4222-8222-222222222222')
        boot = '33333333-3333-4333-8333-333333333333'
        contents[control + '/container-generation.json'] = producer.encoded(dict(scope='private-runtime-container-generation-v1',
            manifest_sha256=digest(contents[control + '/manifest.json']), project=manifest['project'], image_id='sha256:'+'1'*64,
            generation='2'*32, container_ids=containers))
        contents[control + '/backup-request.json'] = producer.encoded(dict(scope='azd-santa-backup-maintenance-v1',
            operation_id='b'*32, manifest_sha256=digest(contents[control + '/manifest.json']),
            generation_sha256=digest(contents[control + '/container-generation.json']), target=target, boot_id=boot,
            recipient_der_base64=base64.b64encode(self.public).decode(), recipient_sha256=digest(self.public),
            destination=quarantine.ROOT+'/backups/synthetic', maximum_bytes=maximum_bytes,
            maximum_files=maximum_files, seconds=1800, queue_inventory=[], backup_program_sha256=quarantine.PROGRAMS['cold_backup.py'],
            storage_sha256='d'*64, worker_instance={}))
        request_hash = digest(contents[control + '/backup-request.json'])
        plan = native.plan(request_hash, 'b'*32, 'C'*22, '9.2.1', ['santa-events'], 1)
        observed = json.loads((ROOT / 'tests/fixtures/server/native-snapshot-es921-success.json').read_bytes())
        observed['snapshots'][0]['metadata'] = {'azd_santa_binding_sha256': request_hash, 'azd_santa_plan_sha256': native.sha(plan)}
        receipt = native.completed_snapshot(observed, plan)
        native_raw = producer.encoded(receipt)
        selection = dict(scope='azd-santa-native-cold-backup-selection-v1', target=target,
            runtime_manifest={'path': control + '/manifest.json', 'sha256': digest(contents[control + '/manifest.json'])},
            controller_sha256=quarantine.PROGRAMS['runtime_service.py'], backup_program_sha256=quarantine.PROGRAMS['cold_backup.py'],
            recipient_sha256=digest(self.public), containers=containers,
            generation_sha256=digest(contents[control + '/container-generation.json']), maintenance_sha256=request_hash,
            native_snapshot={'path': operation + '/snapshot/native-complete.json', 'sha256': digest(native_raw),
                             'program_sha256': quarantine.PROGRAMS['native_snapshot.py']})
        for name in ('drain-complete.json', 'worker-stop-complete.json', 'stop-complete.json'):
            contents[operation + '/' + name] = producer.encoded({'synthetic': name})
        contents[operation + '/capture-selection.json'] = producer.encoded(selection)
        for name, value in {'plan.json': plan, 'repository-intent.json': {'synthetic': 'repository'},
            'snapshot-intent.json': {'synthetic': 'snapshot'}, 'native-observed.json': observed,
            'native-complete.json': receipt}.items():
            contents[operation + '/snapshot/' + name] = producer.encoded(value)
        for name in ('runtime_service.py', 'cold_backup.py', 'native_snapshot.py', 'worker_lifecycle.py', 'prepare_zentral_eval.py', 'test_live_zentral.py'):
            contents[source + '/' + name] = (ROOT / 'experiments/server' / name).read_bytes()
        contents['/etc/systemd/system/azd-santa-runtime.service'] = b'synthetic-private-unit'
        controls = {}; control_hashes = {}; roots = {}
        for i, (path, raw) in enumerate(sorted(contents.items())):
            name = 'control/' + str(i) + '/' + path.rsplit('/', 1)[1]
            controls[name] = path; control_hashes[name] = digest(raw)
            local = base / ('control-' + str(i)); local.write_bytes(raw); roots[name] = local
        for root in sorted(quarantine.DATA_ROOTS):
            local = base / root.replace('/', '-'); local.mkdir(); roots[root] = local
            if root == 'elasticsearch_snapshot_repository':
                for name in ('snap-' + receipt['snapshot_uuid'] + '.dat', 'meta-' + receipt['snapshot_uuid'] + '.dat', 'index-0'):
                    (local / name).write_bytes(b'native-snapshot-sentinel')
            else: (local / 'historical-record').write_bytes(b'preserve-all-history')
        compatibility = dict(scope='azd-santa-cold-backup-v1', selection=selection, host={**target, 'boot_id':boot},
            images={name:{'reference':'sha256:'+'1'*64,'id':'sha256:'+'1'*64} for name in containers}, postgres_major='18', rabbit_node='rabbit@rabbitmq',
            volumes={n:'/var/lib/docker/volumes/synthetic_' + n + '/_data' for n in
                ('postgres_data','redis_data','rabbitmq_data','elasticsearch_data','media_data','elasticsearch_snapshots')},
            control_files=controls, control_files_sha256=control_hashes, mounts={}, native_snapshot=receipt,
            selected_files_sha256=selected, source_commit=quarantine.COMMIT, crypto_version='synthetic',
            elasticsearch_backup='native-filesystem-snapshot-repository', restore_admission='not_implemented', current_authority='not_established')
        return roots, compatibility

    def plaintext(self):
        with tempfile.TemporaryDirectory() as folder:
            roots, compatibility = self.fixture(folder); output = io.BytesIO()
            signature = producer.signature; directory_entries = producer.directory_entries
            def portable(value):
                parts = signature(value); return parts[:7] + parts[8:] if os.name == 'nt' else parts
            @contextmanager
            def entries(path, before, expected):
                if os.name == 'nt':
                    with os.scandir(path) as selected: yield selected
                else:
                    with directory_entries(path, before, expected) as selected: yield selected
            with patch.object(producer, 'signature', side_effect=portable), patch.object(producer, 'directory_entries', entries), \
                    patch.object(producer.os, 'O_NOFOLLOW', getattr(os, 'O_NOFOLLOW', 0), create=True):
                producer.archive(output, roots, compatibility, 1000)
            return output.getvalue()

    def seal(self, raw):
        output = io.BytesIO(); sink = producer.EncryptedSink(output, self.public, 4*quarantine.CHUNK, time.monotonic()+30)
        for i in range(0, len(raw), quarantine.CHUNK): sink.write(raw[i:i+quarantine.CHUNK])
        sink.finish(); return output.getvalue()

    def parse(self, raw, writer=None, **limits):
        return quarantine.validate_archive(io.BytesIO(raw), writer or MemoryWriter(), maximum=limits.get('maximum', 4*quarantine.CHUNK),
            maximum_member=limits.get('maximum_member', 2*quarantine.CHUNK), maximum_entries=limits.get('maximum_entries', 1000),
            deadline=limits.get('deadline', time.monotonic()+30))

    def rewrite(self, raw, transform):
        output = io.BytesIO()
        with tarfile.open(fileobj=io.BytesIO(raw)) as archive, tarfile.open(fileobj=output, mode='w', format=tarfile.PAX_FORMAT) as result:
            for member in archive:
                data = archive.extractfile(member).read() if member.isfile() else b''
                items = transform(copy.copy(member), data)
                for info, payload in items:
                    info.size = len(payload); result.addfile(info, io.BytesIO(payload) if payload else None)
        return output.getvalue()

    def test_real_producer_roundtrip_retains_every_file_and_original_metadata_inertly(self):
        raw = self.plaintext(); writer = MemoryWriter(); metadata = self.parse(raw, writer)
        with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
            for member in archive:
                name = member.name.rstrip('/')
                if member.isfile(): self.assertEqual(writer.files[name], archive.extractfile(member).read())
                else: self.assertIn(name, writer.directories)
        self.assertTrue(any(m['path'].endswith('historical-record') for m in metadata))
        self.assertNotIn('volumes/elasticsearch_data', writer.directories)

    def test_sealed_producer_authenticate_discard_then_authenticated_staging(self):
        raw = self.plaintext(); sealed = self.seal(raw)
        receipt = restore_cipher.authenticate(io.BytesIO(sealed), len(sealed), digest(sealed), self.key, maximum=4*quarantine.CHUNK)
        self.assertFalse(receipt['plaintext_released'])
        with tempfile.TemporaryFile('w+b') as output:
            quarantine.decrypt_staging(io.BytesIO(sealed), len(sealed), digest(sealed), self.key, output, time.monotonic()+30)
            self.assertEqual(output.read(), raw); output.seek(0)
            self.assertTrue(self.parse(output.read()))

    def test_crypto_tamper_wrong_digest_key_truncation_never_reaches_archive(self):
        sealed = self.seal(self.plaintext()); wrong = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        for data, expected, key in ((sealed[:-1], digest(sealed[:-1]), self.key),
            (sealed[:-1]+bytes([sealed[-1]^1]), digest(sealed[:-1]+bytes([sealed[-1]^1])), self.key),
            (sealed, '0'*64, self.key), (sealed, digest(sealed), wrong)):
            with self.assertRaises(Exception): restore_cipher.authenticate(io.BytesIO(data), len(data), expected, key, maximum=4*quarantine.CHUNK)

    def test_bounded_prefix_is_released_after_full_authentication(self):
        raw = self.plaintext()
        sealed = self.seal(raw)
        receipt, prefix = restore_cipher.authenticate_prefix(io.BytesIO(sealed), len(sealed), digest(sealed), self.key,
            maximum=4*quarantine.CHUNK, seconds=30, prefix_limit=777)
        self.assertEqual(prefix, raw[:777])
        self.assertEqual(receipt['plaintext_bytes'], len(raw))
        self.assertTrue(receipt['plaintext_released'])
        altered = sealed[:-1] + bytes([sealed[-1] ^ 1])
        with self.assertRaises(Exception):
            restore_cipher.authenticate_prefix(io.BytesIO(altered), len(altered), digest(altered), self.key,
                maximum=4*quarantine.CHUNK, seconds=30, prefix_limit=777)

    @unittest.skipUnless(sys.platform == 'linux', 'Linux private descriptor paths')
    def test_collects_only_compatibility_and_refuses_bad_seals_or_first_member(self):
        raw = self.plaintext()
        with tempfile.TemporaryDirectory(dir=Path.home()) as folder:
            source = Path(folder) / 'backup.sealed'
            destination = Path(folder) / 'compatibility.json'
            sealed = self.seal(raw)
            def rename_first(info, data):
                if info.name == 'backup/compatibility.json':
                    info.name = 'backup/wrong.json'
                return [(info, data)]
            changed = self.rewrite(raw, rename_first)
            damaged = sealed[:-1] + bytes([sealed[-1] ^ 1])
            source.touch(mode=0o600)
            for content, expected in ((damaged, digest(damaged)), (sealed, '0'*64)):
                source.write_bytes(content)
                with self.assertRaises(Exception):
                    compatibility.collect(source, expected, self.key, destination)
                self.assertFalse(destination.exists())
            bad_member = self.seal(changed)
            source.write_bytes(bad_member)
            with self.assertRaises(quarantine.QuarantineRejected):
                compatibility.collect(source, digest(bad_member), self.key, destination)
            self.assertFalse(destination.exists())
            source.write_bytes(sealed)
            receipt = compatibility.collect(source, digest(sealed), self.key, destination)
            with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
                original = archive.extractfile('backup/compatibility.json').read()
            self.assertEqual(destination.read_bytes(), original)
            self.assertEqual(receipt['compatibility_sha256'], digest(original))
            self.assertFalse(receipt['restore_accepted'])
            self.assertEqual(set(Path(folder).iterdir()), {source, destination})
            with self.assertRaises(FileExistsError):
                compatibility.collect(source, digest(sealed), self.key, destination)

    @unittest.skipUnless(sys.platform == 'linux', 'Linux private descriptor paths and OpenSSL')
    def test_recovers_capture_metadata_with_only_the_portable_key_file(self):
        password = b'synthetic capture fixture passphrase only'
        with tempfile.TemporaryDirectory(dir=Path.home()) as origin, \
                tempfile.TemporaryDirectory(dir=Path.home()) as recovery:
            private = Path(origin) / 'recipient.der'
            private.touch(mode=0o600)
            private.write_bytes(self.key.private_bytes(serialization.Encoding.DER,
                serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            exported = Path(origin) / 'recipient.encrypted.der'
            report = recipient_key.pack(private, exported, digest(self.public), password)
            encrypted = exported.read_bytes()
            self.assertEqual(report['encrypted_key_sha256'], digest(encrypted))
            self.assertEqual(exported.stat().st_mode & 0o777, 0o600)
            portable = Path(recovery) / exported.name
            portable.touch(mode=0o600)
            portable.write_bytes(encrypted)
            private.unlink()
            with patch.object(recipient_key, 'passphrase') as prompt:
                with self.assertRaises(quarantine.QuarantineRejected):
                    recipient_key.load(portable, '0'*64)
                prompt.assert_not_called()
                prompt.return_value = b'wrong synthetic passphrase'
                with self.assertRaises(ValueError):
                    recipient_key.load(portable, report['encrypted_key_sha256'])
                prompt.return_value = password
                key = recipient_key.load(portable, report['encrypted_key_sha256'])
            sealed = self.seal(self.plaintext())
            source = Path(recovery) / 'backup.sealed'
            source.touch(mode=0o600)
            source.write_bytes(sealed)
            destination = Path(recovery) / 'compatibility.json'
            receipt = compatibility.collect(source, digest(sealed), key, destination)
            self.assertEqual(receipt['compatibility_sha256'], digest(destination.read_bytes()))
            self.assertEqual(set(Path(recovery).iterdir()), {portable, source, destination})

    def test_traversal_absolute_alias_and_unknown_root_reject(self):
        raw = self.plaintext()
        for bad in ('../escape', '/absolute', 'volumes/postgres_data/../escape', 'volumes//postgres_data/x',
                    'volumes/postgres_data/./x', 'volumes/postgres_data/a\\b', 'volumes/elasticsearch_data/raw', 'unknown/root'):
            def transform(info, data):
                if info.name.endswith('historical-record'): info.name = bad
                return [(info, data)]
            with self.assertRaises(Exception): self.parse(self.rewrite(raw, transform))

    def test_duplicates_links_devices_and_unknown_pax_reject(self):
        raw = self.plaintext()
        for kind in ('duplicate', tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.FIFOTYPE,
                     tarfile.GNUTYPE_SPARSE, tarfile.GNUTYPE_LONGNAME, tarfile.XGLTYPE, 'pax'):
            def transform(info, data):
                if info.name.endswith('historical-record'):
                    if kind == 'duplicate': return [(info, data), (copy.copy(info), data)]
                    if kind == 'pax': info.pax_headers = {'GNU.sparse.map': '0,1'}
                    else: info.type = kind; info.linkname = '../escape'
                return [(info, data)]
            with self.assertRaises(Exception): self.parse(self.rewrite(raw, transform))

    def test_pax_duplicate_keys_unknown_keys_truncated_records_and_oversize_reject(self):
        def record(key, value):
            body = key + b'=' + value + b'\n'; length = len(body) + 2
            while len(str(length).encode()) + 1 + len(body) != length:
                length = len(str(length).encode()) + 1 + len(body)
            return str(length).encode() + b' ' + body
        valid = record(b'path', b'volumes/media_data/long-file')
        self.assertEqual(quarantine.pax(valid), {b'path': 'volumes/media_data/long-file'})
        for raw in (valid + valid, record(b'GNU.sparse.map', b'0,1'), valid[:-1], b'0 path=x\n',
                    b'999999 path=x\n', record(b'path', b'\xff'), b'x'*4097):
            with self.assertRaises(Exception): quarantine.pax(raw)

    def test_missing_control_digest_mismatch_or_relabelled_control_reject(self):
        raw = self.plaintext()
        for kind in ('missing', 'bytes', 'unknown-name'):
            def transform(info, data):
                if info.name.endswith('/db.env'):
                    if kind == 'missing': return []
                    if kind == 'bytes': data += b'changed'
                    if kind == 'unknown-name': info.name = info.name.replace('db.env', 'unknown.env')
                return [(info, data)]
            with self.assertRaises(Exception): self.parse(self.rewrite(raw, transform))

    def test_missing_or_empty_native_repository_metadata_reject(self):
        raw = self.plaintext()
        for kind in ('missing', 'empty'):
            def transform(info, data):
                if info.name.startswith('elasticsearch_snapshot_repository/meta-'):
                    if kind == 'missing': return []
                    data = b''
                return [(info, data)]
            with self.assertRaises(Exception): self.parse(self.rewrite(raw, transform))

    def test_capture_count_source_native_or_control_inventory_mismatch_reject(self):
        raw = self.plaintext()
        for kind in ('count', 'source', 'native', 'control-path'):
            def transform(info, data):
                if kind == 'count' and info.name == 'backup/capture.json':
                    value = json.loads(data); value['entries'] -= 1; data = producer.encoded(value)
                if kind != 'count' and info.name == 'backup/compatibility.json':
                    value = json.loads(data)
                    if kind == 'source': value['source_commit'] = 'unknown'
                    if kind == 'native': value['native_snapshot']['state'] = 'PARTIAL'
                    if kind == 'control-path':
                        name = next(iter(value['control_files'])); value['control_files'][name] = '/var/lib/azd-santa-qualification/wrong/' + name.rsplit('/',1)[1]
                    data = producer.encoded(value)
                return [(info, data)]
            with self.assertRaises(Exception): self.parse(self.rewrite(raw, transform))

    def test_truncation_trailing_archive_bad_padding_and_resource_deadlines_reject(self):
        raw = self.plaintext()
        for bad in (raw[:-1], raw[:-1024], raw + raw, raw + b'x', raw[:512] + raw[512:1024][:-1] + b'x' + raw[1024:]):
            with self.assertRaises(Exception): self.parse(bad)
        for kwargs in ({'maximum': 1024}, {'maximum_member': 1}, {'maximum_entries': 1}, {'deadline': 0}):
            with self.assertRaises(Exception): self.parse(raw, **kwargs)

    def test_long_utf8_pax_path_and_setuid_metadata_preserved_without_applying(self):
        raw = self.plaintext()
        name = 'volumes/media_data/' + '\u00e6'*100
        def transform(info, data):
            if info.name == 'volumes/media_data/historical-record':
                info.pax_headers = {}; info.name = name; info.mode = 0o6755; info.uid = 99999999999; info.mtime = 1.25
            return [(info, data)]
        writer = MemoryWriter(); metadata = self.parse(self.rewrite(raw, transform), writer)
        self.assertEqual(writer.files[name], b'preserve-all-history')
        selected = next(m for m in metadata if m['path'] == name)
        self.assertEqual((selected['mode'], selected['uid'], selected['mtime']), (0o6755, 99999999999, 1.25))

    def test_late_failure_retains_private_payload_and_never_returns_completion(self):
        raw = self.plaintext(); writer = MemoryWriter()
        def transform(info, data):
            if info.name == 'backup/capture.json': data = b'{}'
            return [(info, data)]
        with self.assertRaises(Exception): self.parse(self.rewrite(raw, transform), writer)
        self.assertTrue(writer.files); self.assertNotIn('complete.json', writer.files)
        class Interrupted(MemoryWriter):
            def file(self, name, chunks):
                super().file(name, chunks)
                if name.endswith('historical-record'): raise KeyboardInterrupt()
        interrupted = Interrupted()
        with self.assertRaises(KeyboardInterrupt): self.parse(raw, interrupted)
        self.assertTrue(interrupted.files)

    @unittest.skipUnless(sys.platform == 'linux', 'actual fd-relative writes require Linux; parser/crypto tests run separately')
    def test_actual_linux_exclusive_quarantine_preserves_source_and_applies_private_modes(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as folder:
            root = Path(folder); source = root / 'capture.sealed'; sealed = self.seal(self.plaintext())
            source.write_bytes(sealed); source.chmod(0o600); destination = root / 'quarantine'
            result = quarantine.extract(source, digest(sealed), self.key, destination, maximum=4*quarantine.CHUNK, maximum_member=2*quarantine.CHUNK)
            self.assertFalse(result['restore_accepted']); self.assertFalse(result['current_authority_established'])
            self.assertNotIn('synthetic-private', json.dumps(result)); self.assertNotIn(str(source), json.dumps(result))
            self.assertEqual(source.read_bytes(), sealed)
            self.assertTrue((destination / 'complete.json').is_file())
            for path in destination.rglob('*'):
                self.assertEqual(path.stat().st_mode & 0o777, 0o700 if path.is_dir() else 0o600)
            with self.assertRaises(quarantine.QuarantineRejected):
                quarantine.extract(source, digest(sealed), self.key, destination, maximum=4*quarantine.CHUNK, maximum_member=2*quarantine.CHUNK)
            self.assertEqual(source.read_bytes(), sealed)

    @unittest.skipUnless(sys.platform == 'linux', 'actual fd-relative symlink/interruption proof requires Linux')
    def test_actual_linux_bad_cipher_creates_no_quarantine_and_interruption_keeps_partial(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as folder:
            root = Path(folder); source = root / 'capture.sealed'; sealed = self.seal(self.plaintext())
            source.write_bytes(sealed); source.chmod(0o600); destination = root / 'quarantine'
            with self.assertRaises(quarantine.QuarantineRejected):
                quarantine.extract(source, '0'*64, self.key, destination, maximum=4*quarantine.CHUNK, maximum_member=2*quarantine.CHUNK)
            self.assertFalse(destination.exists())
            with patch.object(quarantine.Directory, 'file', side_effect=KeyboardInterrupt):
                with self.assertRaises(KeyboardInterrupt):
                    quarantine.extract(source, digest(sealed), self.key, destination, maximum=4*quarantine.CHUNK, maximum_member=2*quarantine.CHUNK)
            self.assertTrue((destination / 'archive.authenticated.tar').is_file())
            self.assertFalse((destination / 'complete.json').exists())
            outside = root / 'outside'; outside.mkdir(mode=0o700)
            directory = os.open(outside, os.O_RDONLY | os.O_DIRECTORY)
            try:
                (outside / 'alias').symlink_to(root, target_is_directory=True)
                with self.assertRaises(OSError): quarantine.Directory(directory).file('alias/escape', iter((b'no',)))
                self.assertFalse((root / 'escape').exists())
            finally: os.close(directory)


if __name__ == '__main__': unittest.main()
