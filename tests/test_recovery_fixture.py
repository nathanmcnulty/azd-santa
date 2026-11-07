"""Offline authority/receipt guards; no SQL, container, or live request proof."""
import ast
import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'experiments/server'))
import run_recovery_fixture as host
import recovery_database_fixture as fixture
import test_zentral_eval as generated


class RecoveryFixture(unittest.TestCase):
    def setUp(self):
        self.g = generated.ZentralEvaluation(); self.g.setUp(); self.addCleanup(self.g.doCleanups)
        with patch.dict(generated.generator.SOURCE_HASHES, self.g.hashes, clear=True):
            generated.generator.prepare(self.g.source, self.g.image, self.g.lock, self.g.destination, 'core-experiment')
        self.compose = self.g.destination / 'compose.json'
        self.harness = ROOT / 'experiments/server/test_operator_recovery_live.py'
        self.destination = self.g.root / 'fixture-job'
        self.calls = []
        self.failure = None
        self.timeout = False
        self.accepted = False

    def docker(self, args, **kwargs):
        self.calls.append(args)
        action = 'initialize' if "m.initialize(" in args[-1] else 'teardown'
        if self.timeout:
            raise subprocess.TimeoutExpired(args, 600, output='PRIVATE')
        if self.failure == action:
            return subprocess.CompletedProcess(args, 1, 'PRIVATE-FAILURE', 'SECRET')
        job = self.destination / 'fixture'
        binding = json.loads((job / 'binding.json').read_text())
        if action == 'initialize':
            (job / 'fixture.json').write_text(json.dumps(dict(binding=binding, database_oid=123, owner=fixture.OWNER)))
        else:
            self.assertTrue(self.accepted, 'Owner teardown cannot precede terminal request acceptance')
        return subprocess.CompletedProcess(args, 0, 'PRIVATE', '')

    def request(self, compose, harness, destination, policy, recovery, directory):
        self.assertEqual(self.calls[0][self.calls[0].index('--env-from-file') + 1], str((self.g.destination / 'migration.env').resolve()))
        self.assertEqual(directory, self.destination / 'fixture')
        if self.failure == 'request':
            raise RuntimeError('known failed requests')
        self.accepted = True
        return {'passed': True, 'tests': 13}

    def invoke(self):
        with patch.object(host, 'require_host'), patch.object(host, 'private_directory'), \
             patch.object(host, 'private_file', side_effect=lambda p: Path(p)), \
             patch.object(host, 'runtime_file', side_effect=lambda p: dict(line.split('=', 1) for line in Path(p).read_text().splitlines())), \
             patch.object(host.subprocess, 'run', side_effect=self.docker), \
             patch.object(host, 'requests', side_effect=self.request):
            return host.run(self.compose, self.harness, self.destination, self.g.image, 'a' * 64, 'b' * 64)

    def test_owner_jobs_are_explicit_no_entrypoint_and_source_bound(self):
        main_config = (self.g.destination / 'conf/base.json').read_bytes()
        self.invoke()
        self.assertEqual(len(self.calls), 2)
        for command in self.calls:
            compile(command[-1], '<owner-job>', 'exec')
            self.assertIn('--no-deps', command); self.assertIn('--pull', command)
            self.assertEqual(command[command.index('--entrypoint') + 1], 'python')
            self.assertIn('hashlib.sha256', command[-1])
            self.assertNotIn('operator_database', command)
        binding = json.loads((self.destination / 'fixture/binding.json').read_text())
        self.assertEqual(binding['harness_sha256'], host.digest(self.harness))
        self.assertEqual(binding['runtime_env_sha256'], host.digest(self.g.destination / 'runtime.env'))
        self.assertRegex(binding['database'], r'^azd_recovery_[0-9a-f]{24}$')
        conf = json.loads((self.destination / 'fixture/base.json').read_text())
        self.assertEqual(conf['django']['POSTGRES_NAME'], binding['database'])
        self.assertEqual(main_config, (self.g.destination / 'conf/base.json').read_bytes())
        self.assertNotIn('POSTGRES_PASSWORD', (self.destination / 'receipt.json').read_text())
        with self.assertRaises(FileExistsError): self.invoke()

    def test_unknown_setup_never_runs_request_or_teardown_and_keeps_evidence(self):
        self.timeout = True
        with self.assertRaises(RuntimeError): self.invoke()
        self.assertFalse(self.accepted); self.assertEqual(len(self.calls), 1)
        self.assertTrue((self.destination / 'initialize-timeout.json').exists())
        self.assertTrue((self.destination / 'initialize-attempt.json').exists())

    def test_failed_requests_retain_fixture_without_owner_teardown(self):
        self.failure = 'request'
        with self.assertRaises(RuntimeError): self.invoke()
        self.assertEqual(len(self.calls), 1)
        self.assertTrue((self.destination / 'fixture/fixture.json').exists())
        self.assertFalse((self.destination / 'receipt.json').exists())

    def test_conflicting_image_or_owner_credentials_rejected_before_docker(self):
        data = json.loads(self.compose.read_text()); data['services']['celery']['image'] = 'sha256:' + 'c' * 64
        self.compose.write_text(json.dumps(data))
        with self.assertRaises(ValueError): self.invoke()
        self.assertEqual(self.calls, [])

    def test_shared_owner_runtime_password_is_rejected_before_mutation(self):
        path = self.g.destination / 'migration.env'
        values = dict(line.split('=', 1) for line in path.read_text().splitlines())
        values['POSTGRES_PASSWORD'] = dict(line.split('=', 1) for line in (self.g.destination / 'runtime.env').read_text().splitlines())['POSTGRES_PASSWORD']
        path.write_text(''.join(k + '=' + v + '\n' for k, v in values.items()))
        with self.assertRaises(ValueError): self.invoke()
        self.assertEqual(self.calls, [])

    def test_runtime_owner_identity_is_rejected_before_query_or_cleanup(self):
        binding = {'database': 'azd_recovery_' + 'c' * 24}
        record = dict(binding=binding, database_oid=123, owner=fixture.OWNER)
        connection = types.SimpleNamespace(vendor='postgresql', settings_dict={'NAME': binding['database'], 'USER': fixture.OWNER})
        db = types.ModuleType('django.db'); db.connection = connection; db.connections = {'default': connection}
        with patch.dict(sys.modules, {'django.db': db}), patch.object(fixture, 'read_binding', return_value=binding), \
             patch.object(fixture.Path, 'read_text', return_value=json.dumps(record)):
            with self.assertRaises(ValueError): fixture.runtime_identity('/fixture/fixture.json')

    def test_recovery13_preserves_methods_and_worker_connection_cleanup(self):
        current = ast.parse(self.harness.read_text())
        cls = next(n for n in current.body if isinstance(n, ast.ClassDef))
        self.assertEqual(cls.bases[0].id, 'SimpleTestCase')
        self.assertEqual(host.test_count(self.harness.read_text()), 13)
        methods = [ast.dump(n, include_attributes=False) for n in cls.body if isinstance(n, ast.FunctionDef) and n.name.startswith('test_')]
        self.assertEqual(hashlib.sha256('\n'.join(methods).encode()).hexdigest(), '30bc1c3b0539cfda6c7262e579b2814e34c7dc62b6e32e60ddcdce49a86690c3')
        source = self.harness.read_text()
        self.assertNotIn('setup_databases(', source); self.assertNotIn('teardown_databases(', source)
        self.assertNotIn('reset_sequences', source); self.assertNotIn('TransactionTestCase', source)
        self.assertEqual(source.count('connections.close_all()'), 4)
        self.assertIn('pg_blocking_pids', source)
        self.assertIn("username__startswith=PREFIX + '-'", source)
        self.assertLess(source.index('fixture.runtime_identity(', source.index('def clean_owned_rows')), source.index('User.objects.filter(username__startswith'))

    def test_teardown_rejects_wrong_oid_without_drop(self):
        binding = {'database': 'azd_recovery_' + 'c' * 24}
        fixture_record = dict(binding=binding, database_oid=123, owner=fixture.OWNER)
        class Cursor:
            def __init__(self): self.queries = []; self.rows = iter([(fixture.OWNER, fixture.OWNER), (456, fixture.OWNER)])
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def execute(self, query, params=None): self.queries.append(query)
            def fetchone(self): return next(self.rows)
        cursor = Cursor()
        connection = types.SimpleNamespace(settings_dict={'USER': fixture.OWNER, 'HOST': 'db', 'NAME': binding['database'], 'PASSWORD': 'private'}, close=lambda: None)
        admin = types.SimpleNamespace(cursor=lambda: cursor, close=lambda: None)
        django_db = types.ModuleType('django.db'); django_db.connection = connection
        psycopg = types.ModuleType('psycopg2'); psycopg.connect = lambda **kw: admin; psycopg.sql = types.SimpleNamespace()
        with patch.dict(sys.modules, {'django.db': django_db, 'psycopg2': psycopg}), \
             patch.object(fixture, 'read_binding', return_value=binding), \
             patch.object(fixture.Path, 'read_text', return_value=json.dumps(fixture_record)):
            with self.assertRaises(ValueError): fixture.teardown('/fixture/fixture.json')
        self.assertEqual(len(cursor.queries), 2)
        self.assertFalse(any('DROP' in str(query) for query in cursor.queries))


if __name__ == '__main__': unittest.main()
