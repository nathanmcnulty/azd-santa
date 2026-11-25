"""Test the source-bound inventory envelope and restricted guest inspection."""

import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock

import test_private_arm_adapter as arm_fixtures
import test_restore_tooling_bundle as tooling_fixtures
import test_retention_image_inventory as image_fixtures
import retained_image_inventory_command as inventory
from retained_image_handoff import sha


class InventoryCommandTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        arm_fixtures.CachedArmTests.setUpClass()
        tooling_fixtures.BundleTests.setUpClass()

    def setUp(self):
        arm = arm_fixtures.CachedArmTests()
        self.addCleanup(arm.doCleanups)
        arm.setUp()
        self.selection = arm.selected
        self.fixture = image_fixtures.InventoryTests()
        self.fixture.setUp()
        source = self.selection.source
        target = {'VmId': source.vm_id, 'VmInstanceId': source.instance_id}
        self.fixture.capture['selection']['target'] = target.copy()
        self.fixture.capture['host'] = {**target, 'boot_id': 'd' * 36}

    def command(self, cli):
        bundle = tooling_fixtures.BundleTests
        raw = image_fixtures.encode(self.fixture.capture)
        return inventory.InventoryCommand(self.selection, raw, bundle.raw,
            compatibility_sha256=sha(raw), commit=bundle.commit, tooling_sha256=bundle.digest, cli=cli)

    def test_plan_and_wrong_capture_host_never_call_azure(self):
        cli = Mock(side_effect=AssertionError('unexpected Azure call'))
        plan = self.command(cli).preview()
        self.assertEqual(plan, self.command(cli).preview())
        self.assertFalse(plan['contacts_azure'])
        self.assertEqual(plan['expected_inventory'], self.fixture.select())
        self.fixture.capture['host']['VmInstanceId'] = self.selection.verifier.instance_id
        with self.assertRaises(inventory.inventory.InventoryRejected):
            self.command(cli)
        cli.assert_not_called()

    @unittest.skipUnless(sys.platform == 'linux', 'Linux bootstrap')
    def test_shell_inspects_exact_ids_and_copies_only_confirmed_inventory(self):
        source = self.selection.source
        with TemporaryDirectory(dir=Path.home()) as folder:
            result_path = Path(folder) / 'inventory.json'
            posted = []

            def cli(args, seconds):
                if args[:2] == ['account', 'show']:
                    return {'id': self.selection.subscription, 'tenantId': self.selection.tenant,
                            'state': 'Enabled', 'environmentName': 'AzureCloud'}
                vm_args = ['--resource-group', source.vm_id.split('/')[4], '--name', 'vm-santa-lab',
                           '--subscription', self.selection.subscription]
                if args[:2] == ['vm', 'show']:
                    self.assertEqual(args[2:], vm_args)
                    return {'id': source.vm_id, 'location': source.region, 'vmId': source.instance_id}
                self.assertEqual(args[3:-1], [*vm_args, '--command-id', 'RunShellScript', '--scripts'])
                posted.append(args[:3])
                raw = [dict(row, Config={'Env': ['PRIVATE_FIXTURE=sentinel']})
                       for row in self.fixture.inspected.values()]
                expected_ids = sorted(self.fixture.inspected)
                script = Path(args[-1][1:]).read_text(encoding='ascii')
                script = script.replace("dir='/run'", f'dir={folder!r}').replace(
                    '            from retention_image_inventory import inspect_selected',
                    f"""            from retention_image_inventory import inspect_selected
            import blob_retention, cold_backup
            from types import SimpleNamespace
            def host(target):
                if target.instance_id != {source.instance_id!r}:
                    raise ValueError()
            def docker(args, env, *, timeout):
                if args[:5] != ['/usr/bin/docker', '--host', 'unix:///var/run/docker.sock', 'image', 'inspect']:
                    raise ValueError()
                if sorted(args[5:]) != {expected_ids!r} or timeout != 25:
                    raise ValueError()
                return SimpleNamespace(stdout={json.dumps(raw)!r})
            blob_retention.host_identity = host
            cold_backup.command = docker""")
                result = subprocess.run(['/bin/sh'], input=script, text=True, capture_output=True, timeout=15)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn('PRIVATE_FIXTURE', result.stdout)
                return {'value': [{'code': 'ComponentStatus/StdOut/succeeded', 'message': result.stdout}]}

            operation = self.command(cli)
            with self.assertRaises(inventory.blob.RetentionRejected):
                operation.read('0' * 64, result_path)
            self.assertEqual(posted, [])
            report = operation.read(operation.plan_sha256, result_path)
            self.assertEqual(report['inventory_sha256'], sha(result_path.read_bytes()))
            self.assertEqual(json.loads(result_path.read_bytes()), self.fixture.select())
            self.assertEqual(report['image_count'], 5)
            with self.assertRaises(inventory.blob.RetentionRejected):
                operation.read(operation.plan_sha256, result_path)
            self.assertEqual(posted, [['vm', 'run-command', 'invoke']])
