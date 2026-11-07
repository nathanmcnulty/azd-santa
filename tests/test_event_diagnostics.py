"""Offline diagnostic output boundary; no Docker, network or credentials."""
import contextlib
import importlib.util
import io
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SERVER = Path(__file__).resolve().parents[1] / 'experiments/server'
with patch.object(sys, 'path', [str(SERVER), *sys.path]):
    spec = importlib.util.spec_from_file_location('inspect_events', SERVER / 'inspect_events.py')
    diagnostics = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(diagnostics)


class DiagnosticRedaction(unittest.TestCase):
    def test_app_only_environment_redacts_broker_password_in_worker_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            compose = Path(directory) / 'compose.json'
            queue = 'amqp://zentral:synthetic-broker-password@rabbitmq:5672//'
            (compose.parent / 'runtime.env').write_text(
                'POSTGRES_PASSWORD=synthetic-db-password\nZENTRAL_QUEUE_URL=' + queue + '\n')
            output = io.StringIO()
            with patch.object(diagnostics, 'validate_compose', return_value=(compose, 'digest')), \
                    patch.object(diagnostics, 'load_fixture', return_value={'devices': [{'secret': 'synthetic-device-secret'}]}), \
                    patch.object(diagnostics.subprocess, 'run', side_effect=[
                        SimpleNamespace(returncode=0, stdout='[]', stderr=''),
                        SimpleNamespace(returncode=0, stdout='ERROR synthetic-broker-password ' + queue +
                                        ' synthetic-db-password synthetic-device-secret', stderr='')]), \
                    contextlib.redirect_stdout(output):
                diagnostics.inspect(str(compose), 'synthetic-fixture.json')
            self.assertIn('STORE_RECORD_STATUS 0', output.getvalue())
            self.assertIn('ERROR', output.getvalue())
            for secret in ('synthetic-broker-password', queue, 'synthetic-db-password', 'synthetic-device-secret'):
                self.assertNotIn(secret, output.getvalue())
            self.assertEqual(output.getvalue().count('[REDACTED]'), 4)


if __name__ == '__main__':
    unittest.main()
