"""Test the administrator approval with cached ARM readback controlled in-process."""

from dataclasses import replace
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'experiments/server'))

import restore_admin_approval as approval
from restore_arm_authorization import Selection
from restore_authority_transaction import Target
from restore_guest_job import Job


class AdminApprovalTests(unittest.TestCase):
    def setUp(self):
        sub = '00000000-0000-4000-8000-000000000001'
        tenant = '00000000-0000-4000-8000-000000000002'
        instance = '00000000-0000-4000-8000-000000000003'
        boot = '00000000-0000-4000-8000-000000000004'
        vm = f'/subscriptions/{sub}/resourceGroups/rg-azd-santa-vm-fixture/providers/Microsoft.Compute/virtualMachines/vm-santa-lab'
        selection = Selection(tenant, sub, 'operator@example.invalid', vm, instance, 'westus2')
        target = Target('azd_recovery_' + 'a' * 24, 'zentral_owner', '/probe-socket', 1, 2,
                        '2026-01-01T00:00:00', boot)
        self.job = Job(selection, target, 'a' * 64, 'b' * 64, boot)
        self.key = b'k' * 32
        self.signer = Ed25519PrivateKey.generate()
        self.public = self.signer.public_key().public_bytes_raw()
        self.pin = approval.sha(self.public)
        payload = {name: 'c' * 64 for name in approval.FIELDS}
        payload.update(scope=approval.reissue.SCOPE, binding=self.job.binding(self.key))
        self.request = dict(**payload, plan_sha256=approval.sha(approval.encode_record(payload)))
        self.review = dict(**self.request, state='previewed', activation_allowed=False)
        self.readback = dict(scope='santa-restore-arm-readback-v1', vm_instance_id=instance, account_verified=True,
                             exact_vm_verified=True, cloud_write=False)

    def issue(self, **changes):
        options = dict(fingerprint_key=self.key, approved_plan_sha256=self.request['plan_sha256'],
                       signing_key=self.signer, operator_pin=self.pin)
        return approval.issue(self.job, self.review, **{**options, **changes})

    def verify(self, raw, *, job=None, **changes):
        return approval.Verify(job or self.job, self.key, raw,
                               **{**dict(public_key=self.public, operator_pin=self.pin), **changes})

    def test_review_and_cached_arm_must_match_before_signing(self):
        with patch.object(approval.arm, 'observe', return_value=self.readback) as observe:
            for change in (dict(approved_plan_sha256='0' * 64), dict(operator_pin='0' * 64),
                           dict(fingerprint_key=b'0' * 32)):
                with self.assertRaises(approval.ApprovalRejected):
                    self.issue(**change)
            observe.assert_not_called()
            self.issue()
            observe.assert_called_once_with(self.job.selection)
            observe.return_value = {**self.readback, 'exact_vm_verified': False}
            with self.assertRaises(approval.ApprovalRejected):
                self.issue()

    def test_signature_is_pinned_bound_and_single_use(self):
        with patch.object(approval.arm, 'observe', return_value=self.readback):
            raw = self.issue()
        modified = json.loads(raw)
        modified['body']['request']['runtime_sha256'] = '0' * 64
        tampered = approval.encode_record(modified)
        for value, extras in ((raw, dict(operator_pin='0' * 64)),
                              (raw, dict(job=replace(self.job, generation='0' * 64))),
                              (raw, dict(job=replace(self.job,
                                  selection=replace(self.job.selection, account='other@example.invalid')))),
                              (tampered, {}), (raw + b'\n', {})):
            with self.assertRaises(approval.ApprovalRejected):
                self.verify(value, **extras)
        verify = self.verify(raw)
        with self.assertRaises(approval.ApprovalRejected):
            verify({**self.request, 'recipient_sha256': '0' * 64})
        self.assertTrue(verify(self.request))
        with self.assertRaises(approval.ApprovalRejected):
            verify(self.request)

    def test_expiry_is_checked_again_at_consumption(self):
        with patch.object(approval.arm, 'observe', return_value=self.readback), patch.object(approval.time, 'time', return_value=1000):
            raw = self.issue()
            verify = self.verify(raw)
        with patch.object(approval.time, 'time', return_value=1000 + approval.LIFETIME):
            with self.assertRaises(approval.ApprovalRejected):
                self.verify(raw)
            with self.assertRaises(approval.ApprovalRejected):
                verify(self.request)
