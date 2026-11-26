"""Check exact Git packaging and independent inert verification."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'experiments/server'))
import restore_tooling_bundle as bundle


def git(root, *args):
    return subprocess.check_output(['git', '-C', str(root), *args], stderr=subprocess.DEVNULL,
                                   timeout=15).strip().decode('ascii')


class BundleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.commit = git(ROOT, 'rev-parse', 'HEAD')
        cls.raw = bundle.build(ROOT, cls.commit)
        cls.digest = bundle.sha(cls.raw)

    def test_current_commit_recreates_exact_bytes_and_stages_inert_source(self):
        self.assertEqual(self.raw, bundle.build(ROOT, self.commit))
        files = bundle.verify(self.raw, commit=self.commit, bundle_sha256=self.digest)
        self.assertEqual(set(files), set(bundle.PATHS))
        for name, contents in files.items():
            if name.endswith('.py'):
                compile(contents, name, 'exec')
        with tempfile.TemporaryDirectory() as folder:
            dest = Path(folder) / 'tooling'
            bundle.stage(self.raw, dest, commit=self.commit, bundle_sha256=self.digest)
            self.assertEqual({file.relative_to(dest).as_posix(): file.read_bytes()
                              for file in dest.rglob('*') if file.is_file()}, files)
            with self.assertRaises(FileExistsError):
                bundle.stage(self.raw, dest, commit=self.commit, bundle_sha256=self.digest)

    def test_rejects_mutable_commit_and_untrusted_pins(self):
        with self.assertRaises(bundle.ToolingRejected):
            bundle.build(ROOT, 'HEAD')
        for commit, digest in ((self.commit, '0' * 64), ('0' * 40, self.digest)):
            with self.assertRaises(bundle.ToolingRejected):
                bundle.verify(self.raw, commit=commit, bundle_sha256=digest)

    def test_authority_version_stages_complete_tools_without_changing_v1(self):
        raw = bundle.build(ROOT, self.commit, version=2)
        pins = {'commit': self.commit, 'bundle_sha256': bundle.sha(raw)}
        files = bundle.verify(raw, **pins)
        self.assertEqual(set(files) - set(bundle.PATHS), {
            'docs/restore-quarantine-design.md',
            bundle.SERVER + 'Export-SantaRecoveryRecipient.ps1',
            bundle.SERVER + 'restore_authority_plan.py',
            bundle.SERVER + 'restore_authority_transaction.py',
        })
        self.assertEqual({path: files[path] for path in bundle.PATHS},
                         bundle.verify(self.raw, commit=self.commit, bundle_sha256=self.digest))
        self.assertEqual(bundle.build(ROOT, self.commit, version=1), self.raw)
        with tempfile.TemporaryDirectory() as folder:
            destination = Path(folder) / 'toolset'
            bundle.stage(raw, destination, **pins)
            completed = subprocess.run([sys.executable, '-B', '-c',
                                        'import restore_authority_plan, restore_authority_transaction'],
                                       cwd=destination / bundle.SERVER, check=False, timeout=10,
                                       capture_output=True)
            self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        for source, scope in ((raw, bundle.SCOPE), (self.raw, bundle.AUTHORITY_SCOPE)):
            doc = json.loads(source)
            doc['scope'] = scope
            changed = bundle.encoded(doc)
            with self.assertRaises(bundle.ToolingRejected):
                bundle.verify(changed, commit=self.commit, bundle_sha256=bundle.sha(changed))

    def test_rewrap_version_extends_authority_inventory_and_stages_adapter(self):
        previous = bundle.build(ROOT, self.commit, version=2)
        raw = bundle.build(ROOT, self.commit, version=3)
        pins = {'commit': self.commit, 'bundle_sha256': bundle.sha(raw)}
        files = bundle.verify(raw, **pins)
        self.assertEqual(set(files) - set(bundle.AUTHORITY_PATHS), {
            'docs/offline-secret-rewrap.md', bundle.SERVER + 'restore_secret_transaction.py',
        })
        self.assertEqual({path: files[path] for path in bundle.AUTHORITY_PATHS},
                         bundle.verify(previous, commit=self.commit, bundle_sha256=bundle.sha(previous)))
        with tempfile.TemporaryDirectory() as folder:
            destination = Path(folder) / 'toolset'
            bundle.stage(raw, destination, **pins)
            completed = subprocess.run([sys.executable, '-B', '-c', 'import restore_secret_transaction'],
                                       cwd=destination / bundle.SERVER, check=False, timeout=10,
                                       capture_output=True)
            self.assertEqual(completed.returncode, 0, completed.stderr.decode())

    def test_rejects_missing_extra_or_mismatched_source_even_with_new_digest(self):
        for change in ('missing', 'extra', 'bytes'):
            with self.subTest(change=change):
                doc = json.loads(self.raw)
                files = doc['files']
                if change == 'missing':
                    del files['LICENSE']
                elif change == 'extra':
                    files['.env'] = files['LICENSE']
                else:
                    files['LICENSE']['base64'] = 'YWJj'
                raw = bundle.encoded(doc)
                with self.assertRaises(bundle.ToolingRejected):
                    bundle.verify(raw, commit=self.commit, bundle_sha256=bundle.sha(raw))

    def test_journal_version_includes_both_adapters_and_exact_journal(self):
        raw = bundle.build(ROOT, self.commit, version=4)
        files = bundle.verify(raw, commit=self.commit, bundle_sha256=bundle.sha(raw))
        path = bundle.SERVER + 'restore_quarantine_journal.py'
        self.assertEqual(set(files) - set(bundle.REWRAP_PATHS), {path})
        compile(files[path], path, 'exec')

    def test_review_version_includes_the_private_census_handoff(self):
        raw = bundle.build(ROOT, self.commit, version=5)
        files = bundle.verify(raw, commit=self.commit, bundle_sha256=bundle.sha(raw))
        path = bundle.SERVER + 'restore_census_review.py'
        self.assertEqual(set(files) - set(bundle.JOURNAL_PATHS), {path})
        compile(files[path], path, 'exec')

    def test_arm_version_includes_the_operator_readback_adapter(self):
        raw = bundle.build(ROOT, self.commit, version=6)
        files = bundle.verify(raw, commit=self.commit, bundle_sha256=bundle.sha(raw))
        path = bundle.SERVER + 'restore_arm_authorization.py'
        self.assertEqual(set(files) - set(bundle.REVIEW_PATHS), {path})
        compile(files[path], path, 'exec')

    def test_guest_version_includes_the_privileged_readback_command(self):
        raw = bundle.build(ROOT, self.commit, version=7)
        files = bundle.verify(raw, commit=self.commit, bundle_sha256=bundle.sha(raw))
        path = bundle.SERVER + 'restore_guest_readback.py'
        self.assertEqual(set(files) - set(bundle.ARM_PATHS), {path})
        compile(files[path], path, 'exec')

    def test_job_version_includes_the_guest_bound_job(self):
        raw = bundle.build(ROOT, self.commit, version=8)
        files = bundle.verify(raw, commit=self.commit, bundle_sha256=bundle.sha(raw))
        path = bundle.SERVER + 'restore_guest_job.py'
        self.assertEqual(set(files) - set(bundle.GUEST_PATHS), {path})
        compile(files[path], path, 'exec')

    def test_input_version_includes_the_private_input_envelope(self):
        raw = bundle.build(ROOT, self.commit, version=9)
        files = bundle.verify(raw, commit=self.commit, bundle_sha256=bundle.sha(raw))
        path = bundle.SERVER + 'restore_sealed_inputs.py'
        self.assertEqual(set(files) - set(bundle.JOB_PATHS), {path})
        compile(files[path], path, 'exec')

    def test_blob_version_includes_the_packet_transport(self):
        raw = bundle.build(ROOT, self.commit, version=10)
        files = bundle.verify(raw, commit=self.commit, bundle_sha256=bundle.sha(raw))
        path = bundle.SERVER + 'restore_input_blob.py'
        self.assertEqual(set(files) - set(bundle.INPUT_PATHS), {path})
        compile(files[path], path, 'exec')

    def test_sas_version_includes_the_packet_issuer(self):
        raw = bundle.build(ROOT, self.commit, version=11)
        files = bundle.verify(raw, commit=self.commit, bundle_sha256=bundle.sha(raw))
        path = bundle.SERVER + 'restore_input_sas.py'
        self.assertEqual(set(files) - set(bundle.BLOB_PATHS), {path})
        compile(files[path], path, 'exec')

    def test_handoff_version_includes_the_boot_bound_sas_delivery(self):
        raw = bundle.build(ROOT, self.commit, version=12)
        files = bundle.verify(raw, commit=self.commit, bundle_sha256=bundle.sha(raw))
        path = bundle.SERVER + 'restore_input_handoff.py'
        self.assertEqual(set(files) - set(bundle.SAS_PATHS), {path})
        compile(files[path], path, 'exec')

    def test_reads_commit_without_packaging_worktree_configuration_or_unapproved_blob(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            git(root, 'init', '-q')
            for name in (*bundle.PATHS, '.env', 'auth-cache.json'):
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(b'committed fixture\n' if name in bundle.PATHS else b'private sentinel\n')
            git(root, 'add', '-f', '--all')
            git(root, '-c', 'core.hooksPath=.git/no-hooks', '-c', 'commit.gpgsign=false',
                '-c', 'user.name=Santa Fixture', '-c', 'user.email=fixture@example.invalid',
                'commit', '-qm', 'Synthetic fixture')
            commit = git(root, 'rev-parse', 'HEAD')
            (root / 'LICENSE').write_bytes(b'worktree-only sentinel')
            raw = bundle.build(root, commit)
            files = bundle.verify(raw, commit=commit, bundle_sha256=bundle.sha(raw))
            with self.assertRaises(bundle.ToolingRejected):
                bundle.build(root, commit, version=2)
            self.assertEqual(set(files), set(bundle.PATHS))
            self.assertEqual(set(files.values()), {b'committed fixture\n'})

    def test_worker_transport_extends_the_retained_image_key_inventory(self):
        raw = bundle.build(ROOT, self.commit, version=22)
        files = bundle.verify(raw, commit=self.commit, bundle_sha256=bundle.sha(raw))
        path = bundle.SERVER + 'restore_worker_transport.py'
        self.assertEqual(set(files) - set(bundle.IMAGE_KEY_PATHS), {path})
        self.assertNotIn(path, bundle.INVENTORIES[bundle.IMAGE_KEY_SCOPE])
        compile(files[path], path, 'exec')

    def test_admin_reissue_extends_the_worker_transport_inventory(self):
        raw = bundle.build(ROOT, self.commit, version=23)
        files = bundle.verify(raw, commit=self.commit, bundle_sha256=bundle.sha(raw))
        path = bundle.SERVER + 'restore_admin_reissue.py'
        self.assertEqual(set(files) - set(bundle.WORKER_TRANSPORT_PATHS), {path})
        compile(files[path], path, 'exec')
