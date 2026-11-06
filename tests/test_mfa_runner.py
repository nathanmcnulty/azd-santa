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
        self.script = self.h.root / 'reviewed.py'; self.script.write_text('pass\n')
        self.receipt = dict(scope='private-real-django-operator-mfa', namespace='azd-mfa-' + 'a' * 24,
            tests=14, passed=True, skipped=0, failures=[], errors=[],
            harness_sha256=hashlib.sha256(self.script.read_bytes()).hexdigest(), policy_sha256='b' * 64,
            limitation='Synthetic operators, direct Django request client; no real-browser/TLS/native-Mac/restore proof')

    def invoke(self, receipt, destination):
        result = subprocess.CompletedProcess([], 0, 'SECRET-DO-NOT-EXPORT\n' + json.dumps(receipt), 'PRIVATE-STDERR')
        output = io.StringIO()
        with patch.object(runner.subprocess, 'run', return_value=result), contextlib.redirect_stdout(output):
            runner.run(self.h.compose, self.script, destination, 'b' * 64)
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


if __name__ == '__main__':
    unittest.main()
