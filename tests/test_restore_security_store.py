"""Exercise the quarantine and once-only boundaries of restored Redis setup."""

import os
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import test_restore_admin_reissue as fixture
import restore_quarantine_journal as journal
import restore_security_store as security
import santa_admission as admission


@unittest.skipUnless(os.name == 'posix', 'The private restore journal requires a POSIX host')
class RestoredSecurityStoreTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixture.AdminReissueTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.store_id = '1' * 64
        self.generation = '2' * 32
        self.client = Mock()
        self.client.info.return_value = {'run_id': '3' * 40}
        self.client.dbsize.return_value = 0
        self.check = Mock()
        self.initialize = self.enterContext(patch.object(admission, 'initialize_fresh', return_value=1))
        self.state = Mock(return_value={'generation': self.generation, 'active': 0})
        operator = SimpleNamespace(STORE_MARKER='fixture-marker', _expected_store_id=lambda: self.store_id,
                                   _security_client=lambda: ('cache', self.client), check_security_store=self.check)
        runtime = SimpleNamespace(CONFIG=admission.CONFIG, state=self.state)
        self.enterContext(patch.dict('sys.modules', {'azd_santa_operator': operator, 'azd_santa_admission': runtime}))

    def run_guard(self, **options):
        args = dict(directory=self.fixture.directory, fingerprint_key=self.fixture.key, runtime_sha256='4' * 64,
                    store_id=self.store_id, generation=self.generation)
        return security.run(self.fixture.job, object(), object(), **{**args, **options})

    def test_requires_quarantine_and_empty_database(self):
        with self.assertRaises(journal.JournalRejected):
            self.run_guard()
        self.client.info.assert_not_called()
        self.fixture.quarantine()
        self.client.dbsize.return_value = 1
        with self.assertRaises(journal.JournalRejected):
            self.run_guard()
        self.initialize.assert_not_called()

    def test_authentication_binds_runtime_generation_and_redis_process(self):
        self.fixture.quarantine()
        preview = self.run_guard()
        authorize = Mock(return_value=True)
        options = dict(approved_plan_sha256=preview['plan_sha256'], authorize=authorize)
        with self.assertRaises(journal.JournalRejected):
            self.run_guard(generation='5' * 32, **options)
        self.client.info.return_value = {'run_id': '6' * 40}
        with self.assertRaises(journal.JournalRejected):
            self.run_guard(**options)
        authorize.assert_not_called()
        self.client.info.return_value = {'run_id': '3' * 40}
        committed = self.run_guard(**options)
        self.initialize.assert_called_once_with('cache', self.client, self.store_id, 0, 'fixture-marker',
                                                require_empty_database=True, generation=self.generation)
        self.check.assert_called_once_with()
        self.assertEqual(committed['state'], 'committed')
        self.assertFalse(committed['activation_allowed'])
        with self.assertRaises(journal.JournalRejected):
            self.run_guard(**options)
        self.assertEqual(self.initialize.call_count, 1)

    def test_unknown_redis_initialization_is_not_replayed(self):
        self.fixture.quarantine()
        preview = self.run_guard()
        options = dict(approved_plan_sha256=preview['plan_sha256'], authorize=lambda _: True)
        self.initialize.side_effect = TimeoutError()
        with self.assertRaisesRegex(journal.JournalRejected, 'requires private inspection'):
            self.run_guard(**options)
        with self.assertRaises(journal.JournalRejected):
            self.run_guard(**options)
        self.assertEqual(self.initialize.call_count, 1)
