"""Exercise the operator workflow with existing receipt and cached ARM fixtures."""

from contextlib import redirect_stdout
import io
import json
import sys
import unittest
from unittest.mock import Mock, patch

import test_retained_image_runner as fixtures
from backup_store_selection import validate
import retained_image_operator as operator
from retained_image_sas import write_record

blob = operator.blob


class OperatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.PackageTests.setUpClass()

    def setUp(self):
        sample = fixtures.PackageTests()
        self.addCleanup(sample.doCleanups)
        sample.setUp()
        self.fixture, self.bundle = sample.fixture, sample.bundle
        self.receipt = validate(**self.fixture.protocol.facts)
        self.selection = operator.selected_store(self.receipt, self.fixture.operation)
        self.assertEqual(self.selection, self.fixture.selection)
        self.pins = dict(operation=self.fixture.operation, manifest_sha256=operator.handoff.sha(self.fixture.manifest),
                         completion_sha256=operator.handoff.sha(self.fixture.completion), commit=self.bundle.commit,
                         tooling_sha256=self.bundle.digest)

    def operation(self, role='r'):
        return operator.Operation(self.selection, role, self.fixture.manifest, self.fixture.completion, self.bundle.raw,
                                  **self.pins, export_directory='/private/export' if role == 'c' else None)

    def test_cli_plan_uses_generated_artifacts_without_cloud_or_journal_writes(self):
        values = {'selection': blob.encoded(self.receipt), 'manifest': self.fixture.manifest,
                  'completion': self.fixture.completion, 'tooling': self.bundle.raw}
        options = []
        for name, value in values.items():
            path = self.fixture.root / name
            path.write_bytes(value)
            options.extend(['--' + name, str(path)])
        for name, value in self.pins.items():
            options.extend(['--' + name.replace('_', '-'), value])
        output = io.StringIO()
        with patch.object(sys, 'argv', ['retained_image_operator.py', 'plan', '--role', 'verify', *options]), \
             patch.object(operator.RunCommand, '_call', side_effect=AssertionError('unexpected Azure command')), \
             redirect_stdout(output):
            operator.main()
        report = json.loads(output.getvalue())
        self.assertEqual(report, self.operation().preview())
        self.assertFalse(report['performs_mutation'])
        self.assertEqual({item.name for item in self.fixture.root.iterdir()}, set(values))

    def test_apply_orders_provision_offer_and_role_scoped_issuance(self):
        for permission in ('c', 'r'):
            with self.subTest(role=permission):
                operation = self.operation(permission)
                operation.issuer = self.fixture.issuer(permission)
                command = Mock()
                operation.command = command

                def installed(archive, root, *, apply):
                    self.assertEqual(self.fixture.protocol.calls, [])
                    self.assertEqual(archive, operation.archive)
                    self.assertTrue(apply)

                def seal(offer, digest, batch, transfer, target, role):
                    posts = [row[2] for row in self.fixture.protocol.calls if row[0] == 'POST']
                    self.assertEqual(len(posts), operation.plan['part_count'])
                    self.assertTrue(all(row['signedPermission'] == permission for row in posts))
                    self.assertEqual(target, operation.target)
                    self.assertEqual(role, permission)
                    command.offer.assert_called_once_with()
                    self.assertNotIn('sig=', repr(batch))
                    return {'synthetic': b'packet'}

                command.provision.side_effect = installed
                command.offer.return_value = b'synthetic-public-offer'
                with patch.object(operator.handoff, 'seal', side_effect=seal), \
                     patch.object(operator.delivery, 'send', return_value={'synthetic': 'receipt'}) as deliver:
                    with self.assertRaises(blob.RetentionRejected):
                        operation.apply(self.fixture.root, '0' * 64)
                    command.provision.assert_not_called()
                    self.assertEqual(operation.apply(self.fixture.root, operation.plan_sha256), {'synthetic': 'receipt'})
                    deliver.assert_called_once()
                self.fixture.protocol.calls.clear()

    def test_observe_validates_terminal_journal_without_reissuing(self):
        operation = self.operation()
        command = Mock()
        operation.command = command
        digest = 'a' * 64
        self.assertEqual(operation.observe(self.fixture.root, operation.plan_sha256)['state'], 'not-attempted')
        self.assertEqual(command.mock_calls, [])
        provision = self.fixture.root / (operation.name + '-provision')
        provision.mkdir()
        write_record(provision / 'intent.json', {'archive_sha256': operation.archive_sha256,
            'runner_sha256': operation.runner_sha256, 'vm_instance_id': operation.target.instance_id})
        self.assertEqual(operation.observe(self.fixture.root, operation.plan_sha256)['state'], 'runner-installed')
        command.observe_install.assert_called_once_with(operation.archive_sha256)
        pending = self.fixture.root / (operation.name + '-delivery')
        pending.mkdir()
        write_record(pending / 'intent.json', {'batch_sha256': digest, 'offer_sha256': 'b' * 64,
            'frames': 3, 'permission': 'r', 'vm_instance_id': operation.target.instance_id})
        command.return_value = {'scope': operator.delivery.SCOPE, 'batch_sha256': digest, 'state': 'staging', 'staged': [0]}
        self.assertEqual(operation.observe(self.fixture.root, operation.plan_sha256)['staged'], [0])
        command.assert_called_once_with(operator.delivery.frame('observe', digest))
        command.provision.assert_not_called()
        command.offer.assert_not_called()
        self.assertEqual(self.fixture.protocol.calls, [])

    def test_roles_require_distinct_valid_selected_targets(self):
        self.assertNotEqual(self.operation('c').preview()['target_vm_id'], self.operation('r').preview()['target_vm_id'])
        receipt = {**self.receipt, 'targets': [self.receipt['targets'][0]] * 2}
        with self.assertRaises(blob.RetentionRejected):
            operator.selected_store(receipt, self.fixture.operation)
