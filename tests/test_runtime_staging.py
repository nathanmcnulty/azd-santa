"""Offline dependency/provenance and failed-startup receipt checks."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'experiments/server'))
import lock_dependencies as dependencies
import stage_runtime as runtime


class Staging(unittest.TestCase):
    def test_existing_lock_does_not_contact_docker(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(dependencies.subprocess, 'run') as run:
            path = Path(directory) / 'lock.json'
            path.write_text('keep')
            with self.assertRaises(FileExistsError):
                dependencies.acquire(path)
            run.assert_not_called()
            self.assertEqual(path.read_text(), 'keep')

    def test_acquisition_records_real_inspected_digest_not_tag(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(dependencies.subprocess, 'run'), patch.object(dependencies.subprocess, 'check_output', return_value=json.dumps([{'RepoDigests': ['example.invalid/image@sha256:' + 'a' * 64]}])):
            path = Path(directory) / 'lock.json'
            dependencies.acquire(path)
            lock = json.loads(path.read_text())
            self.assertEqual(set(lock), set(dependencies.IMAGES))
            self.assertTrue(all('@sha256:' in value for value in lock.values()))

    def test_floating_inspection_is_not_written_as_lock(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(dependencies.subprocess, 'run'), patch.object(dependencies.subprocess, 'check_output', return_value=json.dumps([{'RepoDigests': ['redis:latest']}])):
            path = Path(directory) / 'lock.json'
            with self.assertRaises(ValueError):
                dependencies.acquire(path)
            self.assertFalse(path.exists())

    def test_wrong_image_label_never_starts_containers(self):
        with patch.object(runtime.subprocess, 'check_output', return_value=json.dumps([{'Config': {'Labels': {}}}])), patch.object(runtime.subprocess, 'run') as run:
            with self.assertRaises(ValueError):
                runtime.stage('unused', 'unused', 'unused')
            run.assert_not_called()

    def test_real_check_failure_is_not_reported_as_success(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'runtime'
            lock = Path(directory) / 'lock.json'
            lock.write_text('{}')
            metadata = [{'Id': 'sha256:' + 'a' * 64, 'Config': {'Labels': {
                'org.opencontainers.image.revision': runtime.COMMIT,
                'io.azd-santa.variant': 'core-experiment'}}}]
            def run(args, **kwargs):
                failed = args[-1] == 'check'
                return subprocess.CompletedProcess(args, 1 if failed else 0, '', 'private diagnostic' if failed else '')
            with patch.object(runtime.subprocess, 'check_output', return_value=json.dumps(metadata)), patch.object(runtime.subprocess, 'run', side_effect=run), patch.object(runtime, 'prepare', side_effect=lambda *args: path.mkdir()):
                with self.assertRaisesRegex(RuntimeError, 'Actual Django checks failed'):
                    runtime.stage('source', lock, path)
            self.assertEqual((path / 'django-check.log').read_text(), 'private diagnostic')

    def test_django_success_cannot_hide_a_missing_required_store_import(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'runtime'
            lock = Path(directory) / 'lock.json'
            lock.write_text('{}')
            metadata = [{'Id': 'sha256:' + 'a' * 64, 'Config': {'Labels': {
                'org.opencontainers.image.revision': runtime.COMMIT,
                'io.azd-santa.variant': 'core-experiment'}}}]
            def run(args, **kwargs):
                failed = 'import_module' in args[-1]
                return subprocess.CompletedProcess(args, int(failed), '', 'missing required module' if failed else '')
            with patch.object(runtime.subprocess, 'check_output', return_value=json.dumps(metadata)), patch.object(runtime.subprocess, 'run', side_effect=run), patch.object(runtime, 'prepare', side_effect=lambda *args: path.mkdir()):
                with self.assertRaisesRegex(RuntimeError, 'Required event-store provisioner cannot load'):
                    runtime.stage('source', lock, path)
            self.assertEqual((path / 'store-import-check.log').read_text(), 'missing required module')


if __name__ == '__main__':
    unittest.main()
