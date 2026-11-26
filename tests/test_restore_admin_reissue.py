"""Exercise the reissue guard using a private journal and controlled census."""

from dataclasses import replace
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'experiments/server'))

import restore_admin_reissue as reissue
from restore_arm_authorization import Selection
from restore_authority_transaction import Target
from restore_guest_job import Job
import restore_quarantine_journal as journal


@unittest.skipUnless(os.name == 'posix', 'The private restore journal requires a POSIX host')
class AdminReissueTests(unittest.TestCase):
    def setUp(self):
        sub = '00000000-0000-4000-8000-000000000001'
        tenant = '00000000-0000-4000-8000-000000000002'
        instance = '00000000-0000-4000-8000-000000000003'
        boot = '00000000-0000-4000-8000-000000000004'
        vm = f'/subscriptions/{sub}/resourceGroups/rg-azd-santa-vm-fixture/providers/Microsoft.Compute/virtualMachines/vm-santa-lab'
        selection = Selection(tenant, sub, 'restore@example.invalid', vm, instance, 'westus2')
        target = Target('azd_recovery_' + 'a' * 24, 'zentral_owner', '/probe-socket', 1, 2,
                        '2026-01-01T00:00:00', boot)
        self.job = Job(selection, target, 'a' * 64, 'b' * 64, boot)
        self.directory = self.enterContext(TemporaryDirectory())
        self.key = b'k' * 32
        self.quarantine_census = 'c' * 64
        self.read_target = self.enterContext(patch.object(reissue.authority, 'read_target', return_value=target))
        self.collect = self.enterContext(patch.object(reissue.census, 'collect', return_value=SimpleNamespace(
            receipt=dict(complete_supported_data=True, fingerprint=self.quarantine_census))))

    def quarantine(self):
        binding = self.job.binding(self.key)
        with journal.locked(self.directory) as fd:
            for stage, plan in (('rewrap', 'd' * 64), ('quarantine', 'e' * 64)):
                journal.write_record(fd, f'{stage}-intent.json', binding, self.key, plan=plan)
                journal.write_record(fd, f'{stage}-committed.json', binding, self.key,
                                     plan=plan, census=self.quarantine_census)

    def run_guard(self, **changes):
        options = dict(directory=self.directory, fingerprint_key=self.key, username='new-admin',
                       email='new-admin@example.invalid', runtime_sha256='f' * 64, recipient_sha256='1' * 64)
        return self.job.reissue_admin(object(), object(), **{**options, **changes})

    def inspect(self, plan):
        return reissue.inspect(self.job, directory=self.directory, fingerprint_key=self.key,
                               plan_sha256=plan['plan_sha256'])

    def test_requires_exact_completed_quarantine_and_current_target(self):
        with self.assertRaises(journal.JournalRejected):
            self.run_guard()
        self.collect.assert_not_called()
        self.quarantine()
        self.read_target.return_value = replace(self.job.target, database_oid=42)
        with self.assertRaises(journal.JournalRejected):
            self.run_guard()
        self.read_target.return_value = self.job.target
        self.collect.return_value.receipt['fingerprint'] = '7' * 64
        with self.assertRaises(journal.JournalRejected):
            self.run_guard()
        self.assertFalse((Path(self.directory) / reissue.INTENT).exists())

    def test_preview_binds_identity_recipient_and_runtime_then_commits_once(self):
        self.quarantine()
        plan = self.run_guard()
        self.assertEqual(plan, self.run_guard())
        self.assertFalse(plan['activation_allowed'])
        self.assertNotIn('new-admin', str(plan))
        self.assertEqual(self.inspect(plan)['state'], 'pending')
        create = Mock(return_value='2' * 64)
        allow = Mock(return_value=True)
        config = dict(approved_plan_sha256=plan['plan_sha256'], authorize=allow, create=create)
        for different in (dict(email='another@example.invalid'), dict(runtime_sha256='3' * 64),
                          dict(recipient_sha256='4' * 64)):
            with self.assertRaises(journal.JournalRejected):
                self.run_guard(**config, **different)
        allow.assert_not_called()
        create.assert_not_called()
        result = self.run_guard(**config)
        expected_approval = {key: value for key, value in plan.items() if key not in ('state', 'activation_allowed')}
        allow.assert_called_once_with(expected_approval)
        create.assert_called_once_with('new-admin', 'new-admin@example.invalid', expected_approval)
        self.assertEqual(result['state'], 'committed')
        self.assertEqual(result['artifact_sha256'], '2' * 64)
        self.assertFalse(result['activation_allowed'])
        self.assertEqual(self.inspect(plan)['artifact_sha256'], result['artifact_sha256'])
        with self.assertRaises(journal.JournalRejected):
            self.run_guard(**config)
        self.assertEqual(create.call_count, 1)

    def test_denial_is_retryable_and_uncertain_creator_is_not(self):
        self.quarantine()
        plan = self.run_guard()
        create = Mock(side_effect=RuntimeError('creator did not return a receipt'))
        config = dict(approved_plan_sha256=plan['plan_sha256'], create=create)
        with self.assertRaises(journal.JournalRejected):
            self.run_guard(**config, authorize=lambda _: False)
        create.assert_not_called()
        with self.assertRaisesRegex(journal.JournalRejected, 'requires private inspection'):
            self.run_guard(**config, authorize=lambda _: True)
        self.assertTrue((Path(self.directory) / reissue.INTENT).exists())
        self.assertFalse((Path(self.directory) / reissue.COMMITTED).exists())
        self.assertEqual(self.inspect(plan)['state'], 'inspect')
        with self.assertRaises(journal.JournalRejected):
            self.run_guard(**config, authorize=lambda _: True)
        self.assertEqual(create.call_count, 1)
