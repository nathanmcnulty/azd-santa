"""Offline index receipt checks; no Docker or external HTTP."""
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'experiments/server'))
import verify_indexing as indexing


class IndexReceipt(unittest.TestCase):
    def test_checks_fixture_as_private_path_and_does_not_export_secrets(self):
        fixture = {'devices': [{'serial': 'azd-synthetic-a', 'secret': 'DO-NOT-EXPORT'}]}
        with patch.object(indexing, 'validate_compose', return_value=(Path('/private/compose.json'), 'digest')), patch.object(indexing, 'load_fixture', return_value=fixture) as load, patch.object(indexing.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, '{"count":2}', '')) as run:
            indexing.verify('/private/compose.json', '/private/fixture.json', 2)
            self.assertIsInstance(load.call_args.args[0], Path)
            self.assertNotIn('DO-NOT-EXPORT', str(run.call_args))
            self.assertIn("'type': 'santa_event'", run.call_args.args[0][-1])
            self.assertIn("'machine_serial_number'", run.call_args.args[0][-1])
            self.assertNotIn('_zentral', run.call_args.args[0][-1])

    def test_wrong_count_fails_instead_of_claiming_indexing(self):
        with patch.object(indexing, 'validate_compose', return_value=(Path('/private/compose.json'), 'digest')), patch.object(indexing, 'load_fixture', return_value={'devices': []}), patch.object(indexing.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, '{"count":0}', '')):
            with self.assertRaisesRegex(RuntimeError, 'does not match'):
                indexing.verify('/private/compose.json', '/private/fixture.json', 2)


if __name__ == '__main__':
    unittest.main()
