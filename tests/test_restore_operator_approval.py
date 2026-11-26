"""Verify signed request assembly, including the local operator CLI entry point."""
from dataclasses import replace
import io
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'experiments/server'))
import blob_retention as blob
from restore_arm_authorization import Selection
from restore_authority_transaction import Target
from restore_database_command import SCOPE as WORKER_SCOPE, parse_request
from restore_guest_job import Job
import restore_operator_approval as approval
from restore_packet_operator import SCOPE as PACKET_SCOPE
from restore_sealed_inputs import Recipient, sha
from retained_image_handoff import b64, decode


class OperatorRequestTests(unittest.TestCase):
    def setUp(self):
        subscription = '00000000-0000-4000-8000-000000000001'
        tenant = '00000000-0000-4000-8000-000000000002'
        instance = '00000000-0000-4000-8000-000000000003'
        boot = '00000000-0000-4000-8000-000000000004'
        group = f'/subscriptions/{subscription}/resourceGroups/rg-azd-santa-vm-fixture/providers/'
        vm = group + 'Microsoft.Compute/virtualMachines/vm-santa-lab'
        self.host = blob.SelectedTarget(vm, instance, group + 'Microsoft.Network/virtualNetworks/vnet/subnets/host', 'westus2')
        identity = Selection(tenant, subscription, 'operator@example.com', vm, instance, 'westus2')
        target = Target('azd_recovery_' + 'b' * 24, 'postgres', '/probe-socket', 42, 24, '2026-01-01T00:00:00', boot)
        self.job = Job(identity, target, 'a' * 64, 'b' * 64, boot)
        self.key = Ed25519PrivateKey.generate()
        self.fingerprint = b's' * 32
        self.public = self.key.public_key().public_bytes_raw()
        self.step = dict(stage='rewrap', binding=self.job.binding(self.fingerprint), review_sha256='c' * 64,
                         plan_digest='d' * 64)
        self.offer = Recipient(self.job, **self.step).offer
        self.plan = dict(scope=PACKET_SCOPE, tenant=tenant, subscription=subscription, receiver=instance,
                         receiver_boot=boot, archive_sha256=self.job.archive_sha256, generation=self.job.generation,
                         receiver_capsule='e' * 64, packet_sha256='f' * 64, packet_bytes=512,
                         account_id='fixture-account', sender='fixture-sender', sender_boot='fixture-boot', operation='1' * 32)
        self.plan_sha = sha(blob.encoded(self.plan))
        self.plan.update(plan_sha256=self.plan_sha, submits_run_command=False)
        self.receipt = dict(scope=PACKET_SCOPE, plan_sha256=self.plan_sha, state='verified', receiver_capsule='e' * 64,
                            packet_sha256='f' * 64, packet_bytes=512, upload_confirmed=False, database_applied=False)

    def request(self, **overrides):
        pins = dict(host=self.host, offer=self.offer, plan=self.plan, receipt=self.receipt, signing_key=self.key,
                    fingerprint_key=self.fingerprint, offer_sha256=sha(self.offer), plan_sha256=self.plan_sha,
                    approved_plan_digest=self.step['plan_digest'], public_key_sha256=sha(self.public))
        return approval.apply_request(self.job, **(pins | overrides))

    def assert_request(self, raw):
        request, job, host = parse_request(raw)
        self.assertEqual((job, host), (self.job, self.host))
        self.assertEqual((request['action'], request['step']), ('apply', self.step))
        self.assertEqual(request['receipt'], self.receipt)
        self.assertEqual(decode(request['public_key'], 32), self.public)
        verify = approval.Verify(self.public, sha(self.public), decode(request['approval'], 4096),
                                 job, self.offer, self.plan, self.plan_sha, self.receipt)
        self.assertTrue(verify(dict(scope=approval.review.SCOPE, **self.step)))
        self.assertNotIn(self.key.private_bytes_raw(), raw)
        self.assertNotIn(self.fingerprint, raw)

    def test_builds_request_only_after_exact_confirmation(self):
        with patch.object(Job, 'confirm', return_value=lambda _: True) as confirm:
            self.assert_request(self.request())
            confirm.assert_called_once_with(fingerprint_key=self.fingerprint, stage='rewrap',
                                            review_sha256=self.step['review_sha256'], plan_digest=self.step['plan_digest'])

    def test_mismatches_fail_before_arm_readback(self):
        wrong = '0' * 64
        for fields in (dict(offer_sha256=wrong), dict(public_key_sha256=wrong), dict(plan_sha256=wrong),
                       dict(approved_plan_digest=wrong), dict(fingerprint_key=b't' * 32),
                       dict(receipt={**self.receipt, 'state': 'interrupted'}),
                       dict(host=replace(self.host, instance_id='00000000-0000-4000-8000-000000000099'))):
            with self.subTest(fields=sorted(fields)), patch.object(Job, 'confirm') as confirm:
                with self.assertRaises(approval.ApprovalRejected):
                    self.request(**fields)
                confirm.assert_not_called()

    def test_cli_accepts_pretty_printed_plan_and_receipt_and_emits_canonical_request(self):
        reply = dict(scope=WORKER_SCOPE, state='offered', stage='rewrap', offer=b64(self.offer),
                     offer_sha256=sha(self.offer), request_sha256='e' * 64)
        selection = SimpleNamespace(verifier=self.host, source=SimpleNamespace(instance_id='fixture-sender'),
                                    store=SimpleNamespace(blob=SimpleNamespace(account_id='fixture-account')))
        with TemporaryDirectory() as directory:
            args = ['operator']
            for name, data in (('selection', {}), ('job', {}), ('offer-reply', reply), ('plan', self.plan),
                               ('receipt', self.receipt)):
                path = Path(directory) / (name + '.json')
                path.write_text(json.dumps(data, indent=2), encoding='utf-8')
                args.extend(('--' + name, str(path)))
            args.extend(('--operation', self.plan['operation'], '--offer-sha256', sha(self.offer),
                         '--plan-sha256', self.plan_sha, '--approved-plan-digest', self.step['plan_digest'],
                         '--public-key-sha256', sha(self.public)))
            source = SimpleNamespace(buffer=io.BytesIO(self.key.private_bytes_raw() + self.fingerprint))
            sink = SimpleNamespace(buffer=io.BytesIO())
            with (patch.object(sys, 'argv', args), patch.object(sys, 'stdin', source), patch.object(sys, 'stdout', sink),
                  patch.object(approval, 'selected_job', return_value=(selection, self.job, 'fixture-boot')),
                  patch.object(Job, 'confirm', return_value=lambda _: True)):
                approval.main()
            self.assert_request(sink.buffer.getvalue())
