"""Process output is untrusted for export even when a private test fails."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'experiments/server'))
import test_live_zentral_harness as harness
import run_operator_mfa_tests as runner


class PrivateExport(unittest.TestCase):
    def setUp(self):
        self.h = harness.Harness(); self.h.setUp(); self.addCleanup(self.h.doCleanups)
        self.script = self.h.root / 'reviewed.py'
        self.script.write_text('class OperatorRequests:\n' + ''.join(f'    def test_case_{i}(self): pass\n' for i in range(14)))
        self.receipt = dict(scope='private-real-django-operator-mfa', namespace='azd-mfa-' + 'a' * 24,
            tests=14, passed=True, skipped=0, failures=[], errors=[],
            harness_sha256=hashlib.sha256(self.script.read_bytes()).hexdigest(), policy_sha256='b' * 64,
            limitation='Synthetic operators, direct Django request client; no real-browser/TLS/native-Mac/restore proof')

    def invoke(self, receipt, destination, recovery=None):
        result = subprocess.CompletedProcess([], 0, 'SECRET-DO-NOT-EXPORT\n' + json.dumps(receipt), 'PRIVATE-STDERR')
        output = io.StringIO()
        fixture_directory = None
        if recovery:
            fixture_directory = self.h.root / 'fixture'
            fixture_directory.mkdir(exist_ok=True)
            (fixture_directory / 'fixture.json').write_text(json.dumps({'binding': {'database': 'azd_recovery_' + 'a' * 24}, 'database_oid': 42}))
            receipt['database_identity'] = dict(database='azd_recovery_' + 'a' * 24, database_oid=42, sql_user='zentral_runtime',
                fixture_sha256=hashlib.sha256((fixture_directory / 'fixture.json').read_bytes()).hexdigest())
            result.stdout = 'SECRET-DO-NOT-EXPORT\n' + json.dumps(receipt)
        with patch.object(runner.subprocess, 'run', return_value=result), contextlib.redirect_stdout(output):
            runner.run(self.h.compose, self.script, destination, 'b' * 64, recovery, fixture_directory)
            self.command = runner.subprocess.run.call_args[0][0]
        return output.getvalue()

    def test_only_bound_receipt_is_exported_and_existing_run_is_not_replaced(self):
        destination = self.h.root / 'run'
        output = self.invoke(self.receipt, destination)
        self.assertIn('SANTA_OPERATOR_MFA_ACCEPTED_REQUESTS', output)
        self.assertNotIn('SECRET-DO-NOT-EXPORT', output)
        self.assertNotIn('PRIVATE-STDERR', output)
        private = (destination / 'private-process-output.json').read_text()
        self.assertIn('SECRET-DO-NOT-EXPORT', private)
        with self.assertRaises(FileExistsError):
            self.invoke(self.receipt, destination)
        self.assertEqual(private, (destination / 'private-process-output.json').read_text())

    def test_partial_or_secret_bearing_receipt_cannot_be_accepted(self):
        for index, change in enumerate(({'tests': 13}, {'skipped': 1}, {'policy_sha256': 'c' * 64}, {'secret': 'PRIVATE'})):
            with self.assertRaises(RuntimeError):
                self.invoke(dict(self.receipt, **change), self.h.root / ('bad-' + str(index)))

    def test_explicit_recovery_source_and_isolated_database_scope_are_bound(self):
        receipt = dict(self.receipt, scope='private-real-django-operator-recovery', recovery_sha256='d' * 64,
                       database_scope='Disposable isolated PostgreSQL test database; audit posting mocked, delivery unproven')
        self.assertIn('recovery', self.invoke(receipt, self.h.root / 'recovery', 'd' * 64))
        self.assertNotIn('--env-from-file', self.command)
        self.assertNotIn('--user', self.command)
        self.assertNotIn('migration.env', json.dumps(self.command))
        self.assertIn(':/run/azd-recovery-conf:ro', json.dumps(self.command))
        self.assertIn('types.ModuleType', self.command[-1])
        for index, change in enumerate(({'recovery_sha256': 'e' * 64}, {'database_scope': 'main database'})):
            with self.assertRaises(RuntimeError):
                self.invoke(dict(receipt, **change), self.h.root / ('wrong-recovery-' + str(index)), 'd' * 64)

    def test_ast_count_rejects_absent_duplicate_or_invalid_tests(self):
        for source in ('pass', 'class OperatorRequests: pass',
                       'class OperatorRequests:\n def test_a(self): pass\n def test_a(self): pass',
                       'class OperatorRequests:\n def test_(self): pass'):
            with self.assertRaises(ValueError):
                runner.test_count(source)
        self.assertEqual(runner.test_count('class OperatorRequests:\n def helper(self): pass\n def test_a(self): pass'), 1)


if __name__ == '__main__':
    unittest.main()
