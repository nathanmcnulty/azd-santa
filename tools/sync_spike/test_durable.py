"""Synthetic local restart/failure tests; no Azure or native Santa execution."""
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from durable import DurableModel, State
from model import Snapshot

RULES = [dict(identifier='a' * 64, policy='BLOCKLIST', rule_type='BINARY')]


class Durability(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'synthetic.db'
        self.state = State(self.path, create=True)
        self.addCleanup(lambda: self.state.close())
        self.state.publish_fixture(Snapshot.fixture(1, RULES))

    def restart(self):
        self.state.close()
        self.state = State(self.path)
        return DurableModel(self.state)

    def complete(self, model):
        body = dict(machine_id='device-a')
        self.assertEqual(model.handle('preflight', 'device-a', body)[0], 200)
        self.assertEqual(model.handle('ruledownload', 'device-a', body)[0], 200)
        return model.handle('postflight', 'device-a', dict(body, rules_received=1, rules_processed=1, syncType='CLEAN'))[0]

    def test_reports_and_snapshots_survive_restart(self):
        self.assertEqual(self.complete(DurableModel(self.state)), 200)
        self.state.publish_fixture(Snapshot.fixture(2, RULES))
        model = self.restart()
        self.assertEqual(model.snapshot.revision, 2)
        self.assertEqual(self.state.device('device-a'), (False, 1))
        self.assertEqual(self.state.device('device-b'), (False, 0))
        self.assertEqual(self.complete(model), 200)
        self.assertEqual(self.state.device('device-a'), (False, 2))

    def test_revocation_survives_new_process_credentials(self):
        DurableModel(self.state).revoke_fixture_device('device-a')
        model = self.restart()
        self.assertEqual(model.handle('preflight', 'device-a', dict(machine_id='device-a'))[0], 403)
        self.assertEqual(model.handle('preflight', 'device-b', dict(machine_id='device-b'))[0], 200)
        with self.assertRaises(ValueError):
            self.state.report_fixture('device-a', 1)
        with self.assertRaises(NotImplementedError):
            model.rotate_fixture_device('device-a')

    def test_restart_invalidates_session_and_tokens(self):
        model = DurableModel(self.state)
        token = next(iter(model.tokens))
        model.handle('preflight', 'device-a', dict(machine_id='device-a'))
        restarted = self.restart()
        self.assertNotIn(token, restarted.tokens)
        self.assertEqual(restarted.handle('postflight', 'device-a', dict(machine_id='device-a'))[0], 409)

    def test_failed_persistence_does_not_acknowledge(self):
        model = DurableModel(self.state)
        with patch.object(self.state, 'report_fixture', side_effect=sqlite3.OperationalError('synthetic disk fault')):
            self.assertEqual(self.complete(model), 503)
        self.assertEqual(self.state.device('device-a'), (False, 0))
        self.assertNotIn('device-a', model.sessions)

    def test_competing_connections_and_rollback(self):
        other = State(self.path)
        self.addCleanup(other.close)
        self.state.publish_fixture(Snapshot.fixture(2, RULES))
        with self.assertRaises(ValueError):
            other.publish_fixture(Snapshot.fixture(2, RULES))
        with self.assertRaises(RuntimeError):
            with other.transaction():
                other.db.execute("INSERT INTO devices VALUES ('device-a',1,0)")
                raise RuntimeError('synthetic interrupted transaction')
        self.assertEqual(self.state.device('device-a'), (False, 0))
        self.assertEqual(other.snapshot().revision, 2)

    def test_sqlite_failure_rolls_back_report_and_revocation_wins(self):
        self.state.db.execute("CREATE TRIGGER reject_report BEFORE INSERT ON devices BEGIN SELECT RAISE(ABORT,'fixture fault'); END")
        self.assertEqual(self.complete(DurableModel(self.state)), 503)
        self.assertEqual(self.state.device('device-a'), (False, 0))
        self.state.db.execute('DROP TRIGGER reject_report')
        other = State(self.path)
        self.addCleanup(other.close)
        other.revoke_fixture('device-a')
        with self.assertRaises(ValueError):
            self.state.report_fixture('device-a', 1)
        self.assertEqual(self.state.device('device-a'), (True, 0))

    def test_process_exit_before_commit_does_not_revoke(self):
        code = "import sqlite3,os,sys; c=sqlite3.connect(sys.argv[1]); c.execute(\"INSERT INTO devices VALUES ('device-a',1,0)\"); os._exit(17)"
        result = subprocess.run([sys.executable, '-c', code, str(self.path)], check=False, timeout=10)
        self.assertEqual(result.returncode, 17)
        self.restart()
        self.assertEqual(self.state.device('device-a'), (False, 0))

    def test_regression_empty_and_invalid_publications_rejected(self):
        for snapshot in (Snapshot.fixture(1, RULES), Snapshot.fixture(2, []), Snapshot(2, (), ''), Snapshot(True, (), 'fixture')):
            with self.assertRaises(ValueError):
                self.state.publish_fixture(snapshot)
        self.state.publish_fixture(Snapshot.fixture(2, RULES))
        self.state.report_fixture('device-a', 2)
        with self.assertRaises(ValueError):
            self.state.report_fixture('device-a', 1)
        with self.assertRaises(ValueError):
            self.state.report_fixture('device-a', 3)

    def test_damaged_or_missing_state_fails_closed(self):
        with self.assertRaises(sqlite3.OperationalError):
            State(Path(self.directory.name) / 'missing.db')
        self.state.db.execute("UPDATE snapshots SET payload=?", (b'{}',))
        with self.assertRaises(ValueError):
            DurableModel(self.state)

    def test_unavailable_state_never_returns_success(self):
        model = DurableModel(self.state)
        self.state.close()
        self.assertEqual(model.handle('preflight', 'device-a', dict(machine_id='device-a'))[0], 503)

    def test_schema_mismatch_is_not_reinitialized(self):
        self.state.db.execute('PRAGMA user_version=99')
        with self.assertRaises(ValueError):
            State(self.path, create=True)
        self.assertEqual(self.state.db.execute('PRAGMA user_version').fetchone()[0], 99)

    def test_selected_local_durability_settings(self):
        self.assertEqual(self.state.db.execute('PRAGMA synchronous').fetchone()[0], 2)
        self.assertEqual(self.state.db.execute('PRAGMA journal_mode').fetchone()[0], 'delete')


if __name__ == '__main__':
    unittest.main()
