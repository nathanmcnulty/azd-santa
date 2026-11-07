"""Offline dependency/provenance and failed-startup receipt checks."""
import json
import contextlib
import io
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
import test_zentral_eval as generated


class Staging(unittest.TestCase):
    def setUp(self):
        self.generated = generated.ZentralEvaluation()
        self.generated.setUp()
        self.addCleanup(self.generated.doCleanups)
        self.destination = self.generated.root.resolve() / 'role-stage'
        self.lock = self.generated.root / 'lock.json'
        self.lock.write_text(json.dumps(self.generated.lock))
        self.image = 'sha256:' + 'a' * 64
        self.calls = []
        self.failure = None

    def run_stage(self):
        def prepare(*args):
            with patch.dict(generated.generator.SOURCE_HASHES, self.generated.hashes, clear=True):
                generated.generator.prepare(*args)
        with patch.object(runtime, 'require_host'), \
                patch.object(runtime, 'private_directory'), \
                patch.object(runtime, 'private_file', side_effect=lambda path: Path(path)), \
                patch.object(runtime, 'prepare', side_effect=prepare), \
                patch.object(runtime.subprocess, 'run', side_effect=self.docker):
            return runtime.stage(self.generated.source, self.lock, self.destination, self.image)

    def docker(self, args, **kwargs):
        self.calls.append(args)
        self.assertEqual(args[:3], runtime.DOCKER)
        self.assertFalse(any(key.startswith(('COMPOSE_', 'DOCKER_')) for key in kwargs['env'] if key != 'DOCKER_CONFIG'))
        output, status = '', 0
        if args[3:5] == ['image', 'inspect']:
            labels = {'org.opencontainers.image.revision': runtime.COMMIT, 'io.azd-santa.variant': 'core-experiment'}
            output = json.dumps([{'Id': self.image, 'Config': {'Labels': {} if self.failure == 'image-label' else labels}}])
        elif args[-1] == '--help':
            output = '--env' if self.failure == 'compose-capability' else '--env-from-file'
        elif args[3] == 'ps' and self.failure == 'namespace':
            output = 'f' * 64
        elif args[3:5] == ['volume', 'ls'] and self.failure == 'volume':
            output = json.loads((self.destination / 'compose.json').read_text())['name'] + '_postgres_data'
        elif args[-1] == 'PING':
            output = 'PONG'
        elif '--env-from-file' in args:
            if self.failure and self.failure.startswith('timeout'):
                raise subprocess.TimeoutExpired(args, 600, stderr='private-owner-timeout')
            if self.failure == 'initialize':
                status = 1
            elif self.failure != 'missing-completion':
                (self.destination / 'database-initialization/attempt.json').write_text('{"state":"outcome-requires-inspection"}')
                (self.destination / 'database-initialization/attempt.json.complete').write_text(json.dumps(
                    {'scope': 'fresh-database-initialization', 'state': 'runtime-role-checked'}))
        elif args[3] == 'inspect':
            if self.failure and self.failure.startswith('timeout'):
                name = args[-1]
                project = json.loads((self.destination / 'compose.json').read_text())['name']
                output = json.dumps([{'Id': 'c' * 64, 'Name': '/' + name,
                                      'Image': 'sha256:' + 'b' * 64 if self.failure == 'timeout-wrong-owner' else self.image,
                                      'Config': {'Labels': {'com.docker.compose.project': project,
                                                            'com.docker.compose.service': 'web',
                                                            'com.docker.compose.oneoff': 'True'}}}])
            else:
                status = 1
        elif self.failure == 'django-check' and args[-2:] == ['server/manage.py', 'check']:
            status = 1
        elif self.failure == 'store-import' and 'importlib.import_module' in args[-1]:
            status = 1
        return subprocess.CompletedProcess(args, status, output, 'private-diagnostic-canary' if status else '')
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
        self.failure = 'image-label'
        with self.assertRaises(ValueError): self.run_stage()
        self.assertEqual(len(self.calls), 1)
        self.assertFalse(self.destination.exists())

    def test_real_check_failure_is_not_reported_as_success(self):
        self.failure = 'django-check'
        with self.assertRaisesRegex(RuntimeError, 'django-check'): self.run_stage()
        self.assertFalse((self.destination / 'stage-receipt.json').exists())
        self.assertIn('private-diagnostic-canary', next(self.destination.glob('*-django-check.json')).read_text())

    def test_django_success_cannot_hide_a_missing_required_store_import(self):
        self.failure = 'store-import'
        with self.assertRaisesRegex(RuntimeError, 'store-import-check'): self.run_stage()
        self.assertFalse((self.destination / 'stage-receipt.json').exists())

    def test_fresh_role_job_is_single_root_job_and_normal_checks_have_no_owner_environment(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            result = self.run_stage()
        self.assertFalse(result['listener_started'])
        owners = [args for args in self.calls if '--env-from-file' in args]
        self.assertEqual(len(owners), 1)
        owner = owners[0]
        self.assertEqual(owner[owner.index('--user') + 1], '0')
        self.assertIn(str(self.destination / 'runtime.env') + ':/run/azd-runtime.env:ro', owner)
        self.assertIn('initialize', owner)
        self.assertTrue((self.destination / 'database-initialization/binding.json').exists())
        self.assertTrue((self.destination / 'stage-receipt.json').exists())
        self.assertTrue(any('zentral_owner' in args for args in self.calls if 'pg_isready' in args))
        self.assertFalse(any(args[-1] in ('workers', 'celery', 'web') for args in self.calls if 'up' in args))
        secret = dict(line.split('=', 1) for line in (self.destination / 'migration.env').read_text().splitlines())['POSTGRES_PASSWORD']
        self.assertNotIn(secret, repr(self.calls) + output.getvalue())

    def test_initializer_failure_preserves_unknown_state_and_never_retries(self):
        self.failure = 'initialize'
        with self.assertRaisesRegex(RuntimeError, 'initialize'): self.run_stage()
        self.assertTrue((self.destination / 'database-initialization/binding.json').exists())
        self.assertFalse((self.destination / 'stage-receipt.json').exists())
        count = len(self.calls)
        with self.assertRaises(FileExistsError): self.run_stage()
        self.assertEqual(len(self.calls), count)
        self.assertEqual(sum('--env-from-file' in args for args in self.calls), 1)

    def test_initializer_timeout_stops_only_its_verified_concrete_id(self):
        self.failure = 'timeout'
        with self.assertRaisesRegex(RuntimeError, 'timed out'): self.run_stage()
        stops = [args for args in self.calls if args[3] == 'stop']
        self.assertEqual(stops, [runtime.DOCKER + ['stop', '--time', '5', 'c' * 64]])
        self.assertFalse((self.destination / 'stage-receipt.json').exists())

    def test_zero_exit_without_completion_does_not_admit_runtime(self):
        self.failure = 'missing-completion'
        with self.assertRaises(FileNotFoundError): self.run_stage()
        self.assertFalse(any(args[-2:] == ['operator_database', 'check'] for args in self.calls))

    def test_namespace_collision_prevents_new_container_or_service_creation(self):
        self.failure = 'volume'
        with self.assertRaisesRegex(ValueError, 'namespace already exists'): self.run_stage()
        self.assertFalse(any('run' in args or 'up' in args for args in self.calls))

    def test_missing_owner_job_capability_fails_before_dependency_start(self):
        self.failure = 'compose-capability'
        with self.assertRaisesRegex(ValueError, 'env-from-file'): self.run_stage()
        self.assertFalse(any('up' in args or '--env-from-file' in args for args in self.calls))

    def test_timeout_cleanup_rejects_an_unselected_helper_without_stopping_it(self):
        self.failure = 'timeout-wrong-owner'
        with self.assertRaisesRegex(RuntimeError, 'ownership/outcome'): self.run_stage()
        self.assertFalse(any(args[3] == 'stop' for args in self.calls))

    def test_unprivileged_host_is_rejected_before_docker(self):
        with patch.object(runtime.sys, 'platform', 'linux'), patch.object(runtime.os, 'geteuid', return_value=1000, create=True):
            with self.assertRaisesRegex(ValueError, 'privileged Linux'): runtime.require_host()


if __name__ == '__main__':
    unittest.main()
