"""Run the native verifier command against synthetic ARM and an isolated Linux guest."""

import json
from pathlib import Path
import re
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch

import test_private_arm_adapter as fixtures
import test_restore_tooling_bundle as tooling
import native_retention_verify_command as command


class VerifyCommandTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.CachedArmTests.setUpClass()
        tooling.BundleTests.setUpClass()

    def setUp(self):
        fixture = fixtures.CachedArmTests()
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()
        self.fixture = fixture

    def create(self, cli):
        bundle = tooling.BundleTests
        return command.VerifyCommand(self.fixture.selected, self.fixture.capture.record, bundle.raw,
                                     commit=bundle.commit, tooling_sha256=bundle.digest, cli=cli)

    def test_default_plan_is_bounded_and_keeps_cloud_and_disk_untouched(self):
        cli = Mock(side_effect=AssertionError('unexpected CLI call'))
        plan = self.create(cli).preview()
        self.assertEqual(plan, self.create(cli).preview())
        self.assertFalse(plan['performs_mutation'])
        self.assertEqual(plan['permission'], 'r')
        self.assertEqual(plan['target']['instance_id'], self.fixture.selected.verifier.instance_id)
        cli.assert_not_called()

    @unittest.skipUnless(sys.platform == 'linux', 'Linux guest filesystem and shell')
    def test_completed_get_recovers_from_lost_response_through_observe(self):
        selected = self.fixture.selected
        with TemporaryDirectory(dir=Path.home()) as folder:
            root = Path(folder)
            capture = root / 'fixture.sealed'
            capture.write_bytes(self.fixture.capture.raw)
            guest = root / 'guest'
            received = []

            def cli(args, timeout):
                if args[:2] == ['account', 'show']:
                    return {'id': selected.subscription, 'tenantId': selected.tenant,
                            'state': 'Enabled', 'environmentName': 'AzureCloud'}
                target = selected.verifier
                expected = ['--resource-group', target.vm_id.split('/')[4], '--name', 'vm-santa-lab',
                            '--subscription', selected.subscription]
                if args[:2] == ['vm', 'show']:
                    self.assertEqual(args[2:], expected)
                    return {'id': target.vm_id, 'vmId': target.instance_id, 'location': target.region}
                self.assertEqual(args[3:-1], [*expected, '--command-id', 'RunShellScript', '--scripts'])
                script = Path(args[-1][1:]).read_text(encoding='ascii')
                payload = re.search("SANTA_NATIVE_VERIFY_REQUEST='([^']+)'", script)[1]
                request = json.loads(command.decode(payload, 4096))
                received.append(request['action'])
                self.assertNotIn('sig=', script)
                script = script.replace("dir='/run'", f'dir={folder!r}').replace(
                    '            from native_retention_verifier import dispatch',
                    f"""            import native_retention_verifier as job
            import io
            from types import SimpleNamespace
            original = job.Verifier
            job.Verifier = lambda *args: original(*args, root={str(guest)!r})
            def host(target):
                if target.instance_id != {target.instance_id!r}:
                    raise ValueError()
            job.blob.host_identity = host
            job.boot = lambda target: '55555555-5555-4555-8555-555555555555'
            class Response(io.BytesIO):
                status = 200
                def getheader(self, name):
                    return {{'Content-Length': str(len(self.getvalue())), 'ETag': '"fixture"'}}[name]
            class BlobFixture:
                def get(self, capability, seconds):
                    if capability.permission != 'r' or capability.target.instance_id != {target.instance_id!r}:
                        raise ValueError()
                    with open({str(capture)!r}, 'rb') as source:
                        return SimpleNamespace(close=lambda: None), Response(source.read())
            job.blob.BlobHttp = BlobFixture
            dispatch = job.dispatch""")
                result = subprocess.run(['/bin/sh'], input=script, text=True, capture_output=True, timeout=20)
                self.assertEqual(result.returncode, 0, result.stderr)
                if request['action'] == 'receive':
                    raise TimeoutError('synthetic lost response after GET')
                return {'value': [{'code': 'ComponentStatus/StdOut/succeeded', 'message': result.stdout}]}

            operation = self.create(cli)
            operation.job.path = guest / operation.job.record['operation_id']
            arm = command.verifier.CachedArm(selected, self.fixture.capture.record, selected.verifier, 'r',
                cli=self.fixture.protocol.cli, transport=self.fixture.protocol.transport)
            with patch.object(command.verifier, 'CachedArm', return_value=arm):
                for _ in range(2):
                    with self.assertRaises(command.blob.RetentionRejected):
                        operation.apply(root, operation.plan_sha256)
                self.assertEqual(received, ['offer', 'receive'])
                self.assertEqual(sum(method == 'POST' for method, _, _ in self.fixture.protocol.calls), 1)
                ciphertext = operation.job.path / 'download' / 'backup.sealed'
                self.assertEqual(ciphertext.read_bytes(), self.fixture.capture.raw)
                result = operation.observe(root, operation.plan_sha256)
                self.assertEqual(result['state'], 'verified')
                self.assertEqual(result['verifier_ciphertext'], ciphertext.as_posix())
                self.assertTrue(result['result']['independent_bytes_verified'])
                self.assertFalse(result['result']['sealed_authenticated'])
                self.assertEqual(received, ['offer', 'receive', 'observe'])
