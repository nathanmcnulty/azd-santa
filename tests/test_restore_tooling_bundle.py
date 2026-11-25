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
            self.assertEqual(set(files), set(bundle.PATHS))
            self.assertEqual(set(files.values()), {b'committed fixture\n'})
