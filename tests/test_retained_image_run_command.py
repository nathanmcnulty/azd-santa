"""Run Command boundary with synthetic cached CLI and guest replies."""

import os
from pathlib import Path
import re
import subprocess
import sys
import unittest
from unittest.mock import patch

import test_retained_image_sas as fixtures
import retained_image_blob as storage
import retained_image_delivery as delivery
import retained_image_run_command as relay


class RunCommandTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.ImageSasTests.setUpClass()

    def setUp(self):
        fixture = fixtures.ImageSasTests()
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()
        self.selection = fixture.selection
        self.transfer = storage.Transfer(fixture.manifest, fixture.completion, self.selection.store,
            self.selection.source, manifest_sha256=fixtures.sha(fixture.manifest),
            completion_sha256=fixtures.sha(fixture.completion), operation=fixture.operation)
        self.digest = 'a' * 64
        self.raw = delivery.frame('observe', self.digest)
        self.reply = {'scope': delivery.SCOPE, 'batch_sha256': self.digest, 'state': 'staging', 'staged': []}
        self.calls = []
        self.vm_id = self.selection.verifier.instance_id
        self.tenant = self.selection.tenant
        self.change_output = lambda output: output
        self.runner = relay.RunCommand(self.selection, self.transfer, 'r', 'b' * 64, cli=self.cli)
        target = self.selection.verifier.vm_id.split('/')
        self.target_args = ['--resource-group', target[4], '--name', 'vm-santa-lab',
                            '--subscription', self.selection.subscription]

    def cli(self, args, seconds):
        self.calls.append(args[:3])
        if args[:2] == ['account', 'show']:
            return {'id': self.selection.subscription, 'tenantId': self.tenant,
                    'environmentName': 'AzureCloud', 'state': 'Enabled'}
        if args[:2] == ['vm', 'show']:
            self.assertEqual(args[2:], self.target_args)
            return {'id': self.selection.verifier.vm_id,
                    'location': self.selection.verifier.region, 'vmId': self.vm_id}
        self.assertEqual(args[3:-1], [*self.target_args, '--command-id', 'RunShellScript', '--scripts'])
        self.path = Path(args[-1][1:])
        self.script = self.path.read_text(encoding='ascii')
        request = re.search(r"SANTA_IMAGE_REQUEST='([^']+)'", self.script)[1]
        self.assertEqual(relay.handoff.decode(request, delivery.MAX_FRAME), self.raw)
        self.assertIn(self.transfer.pins['operation'] + '-r/run.py', self.script)
        nonce = re.search(relay.DONE + '([a-f0-9]{32})', self.script)[1]
        output = relay.RECEIPT + storage.blob.encoded(self.reply).decode() + '\n' + relay.DONE + nonce
        return {'value': [{'code': 'ComponentStatus/StdOut/succeeded',
                           'message': self.change_output(output)}]}

    def test_binds_command_to_verifier_and_removes_temporary_script(self):
        self.assertEqual(self.runner(self.raw), self.reply)
        self.assertEqual(len(self.calls), 3)
        self.assertFalse(self.path.exists())

    def test_wrong_tenant_or_replaced_instance_prevents_submission(self):
        self.tenant = '0' * 36
        with self.assertRaises(storage.blob.RetentionRejected):
            self.runner(self.raw)
        self.assertEqual(len(self.calls), 1)
        self.tenant = self.selection.tenant
        self.vm_id = '0' * 36
        with self.assertRaises(storage.blob.RetentionRejected):
            self.runner(self.raw)
        self.assertEqual(len(self.calls), 3)

    def test_missing_duplicate_wrong_or_stale_receipt_has_no_retry(self):
        changes = (lambda s: s.splitlines()[0], lambda s: s + '\n' + s,
                   lambda s: s[:-32] + '0' * 32, lambda s: s.replace(self.digest, 'f' * 64))
        for change in changes:
            with self.subTest(change=change):
                self.calls.clear()
                self.change_output = change
                with self.assertRaises(storage.blob.RetentionRejected):
                    self.runner(self.raw)
                self.assertEqual(len(self.calls), 3)
                self.assertFalse(self.path.exists())

    def test_bad_frame_is_rejected_before_cli_lookup(self):
        with self.assertRaises(storage.blob.RetentionRejected):
            self.runner(delivery.frame('observe', self.digest, other='unexpected'))
        with self.assertRaises(storage.blob.RetentionRejected):
            self.runner(delivery.frame('parts', self.digest, start=delivery.MAX_PARTS - 1,
                                       packets=['eA==', 'eA==']))
        self.assertFalse(self.calls)

    def test_valid_packet_group_reaches_selected_run_command(self):
        self.raw = delivery.frame('parts', self.digest, start=0, packets=['eA==', 'eQ=='])
        self.reply = {'scope': delivery.SCOPE, 'batch_sha256': self.digest, 'state': 'staged',
                      'start': 0, 'count': 2}
        self.assertEqual(self.runner(self.raw), self.reply)
        self.assertEqual(len(self.calls), 3)

    @unittest.skipUnless(sys.platform == 'linux', 'Linux shell')
    def test_missing_installed_runner_emits_no_completion_marker(self):
        with patch.object(relay, 'GUEST_ROOT', '/nonexistent-santa-test'):
            runner = relay.RunCommand(self.selection, self.transfer, 'r', 'b' * 64, cli=self.cli)
        runner(self.raw)
        result = subprocess.run(['/bin/sh'], input=self.script, capture_output=True, text=True, timeout=10,
                                env={'PATH': os.defpath})
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, '')
        self.assertEqual(result.stderr, '')
