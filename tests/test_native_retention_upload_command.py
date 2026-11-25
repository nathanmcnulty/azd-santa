"""Exercise one source upload submission and read-only recovery after a lost reply."""

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
import native_retention_upload_command as command


class UploadCommandTests(unittest.TestCase):
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
        return command.UploadCommand(self.fixture.selected, self.fixture.capture.record, bundle.raw,
                                     commit=bundle.commit, tooling_sha256=bundle.digest, cli=cli)

    def test_plan_selects_source_without_authentication_or_writes(self):
        cli = Mock(side_effect=AssertionError('unexpected CLI call'))
        plan = self.create(cli).preview()
        self.assertEqual(plan, self.create(cli).preview())
        self.assertFalse(plan['performs_mutation'])
        self.assertEqual(plan['permission'], 'c')
        self.assertEqual(plan['source']['instance_id'], self.fixture.selected.source.instance_id)
        cli.assert_not_called()

    @unittest.skipUnless(sys.platform == 'linux', 'Linux guest filesystem and shell')
    def test_lost_submit_reply_does_not_repeat_mint_or_launch(self):
        selected = self.fixture.selected
        target = selected.source
        received = []
        with TemporaryDirectory(dir=Path.home()) as folder:
            root = Path(folder)
            guest = root / 'guest'
            guest.mkdir(mode=0o700)

            def cli(args, timeout):
                if args[:2] == ['account', 'show']:
                    return {'id': selected.subscription, 'tenantId': selected.tenant,
                            'state': 'Enabled', 'environmentName': 'AzureCloud'}
                expected = ['--resource-group', target.vm_id.split('/')[4], '--name', 'vm-santa-lab',
                            '--subscription', selected.subscription]
                if args[:2] == ['vm', 'show']:
                    self.assertEqual(args[2:], expected)
                    return {'id': target.vm_id, 'vmId': target.instance_id, 'location': target.region}
                self.assertEqual(args[3:-1], [*expected, '--command-id', 'RunShellScript', '--scripts'])
                script = Path(args[-1][1:]).read_text(encoding='ascii')
                payload = re.search("SANTA_NATIVE_UPLOAD_REQUEST='([^']+)'", script)[1]
                request = json.loads(command.relay.decode(payload, maximum=4096))
                received.append(request['action'])
                self.assertNotIn('sig=', script)
                self.assertNotIn('sig=', json.dumps(request))
                shim = f"""
from pathlib import Path
relay.ROOT = Path({str(guest)!r})
relay.guest = lambda: relay.need(Path(relay.__file__).parent.parent == relay.ROOT)
relay.fresh = lambda target: '55555555-5555-4555-8555-555555555555'
relay.capture = lambda *args: {{'fixture': True}}
def launch(intent, digest):
    with (relay.ROOT / 'launch').open('x') as stream:
        stream.write(digest)
relay.launch = launch
relay.unit_state = lambda name: dict(LoadState='loaded', ActiveState='activating', SubState='start',
    Result='success', MainPID='123', ExecMainStatus='0', Job='job', ControlGroup='/system.slice/'+name)
"""
                script = script.replace("dir='/run'", f'dir={folder!r}').replace(
                    '            from native_retention_upload_guest import dispatch',
                    f"""            import native_retention_upload_guest as job
            job.relay.ROOT = Path({str(guest)!r})
            job.blob.host_identity = lambda target: job.blob.need(target.instance_id == {target.instance_id!r})
            job.BRIDGE = job.BRIDGE.replace('import blob_capability_relay as relay', 'import blob_capability_relay as relay\\n' + {shim!r})
            dispatch = job.dispatch""")
                reply = subprocess.run(['/bin/sh'], input=script, text=True, capture_output=True, timeout=20)
                self.assertEqual(reply.returncode, 0, reply.stderr)
                if request['action'] == 'submit':
                    raise TimeoutError('synthetic lost submit response')
                return {'value': [{'code': 'ComponentStatus/StdOut/succeeded', 'message': reply.stdout}]}

            operation = self.create(cli)
            arm = command.CachedArm(selected, self.fixture.capture.record, target, 'c',
                cli=self.fixture.protocol.cli, transport=self.fixture.protocol.transport)
            with patch.object(command, 'CachedArm', return_value=arm):
                for _ in range(2):
                    with self.assertRaises(command.blob.RetentionRejected):
                        operation.apply(root, operation.plan_sha256)
                self.assertEqual(received, ['offer', 'submit'])
                self.assertEqual(sum(method == 'POST' for method, _, _ in self.fixture.protocol.calls), 1)
                observed = operation.observe(root, operation.plan_sha256)
                self.assertEqual(observed['state'], 'in-progress')
                self.assertEqual(observed['intent_sha256'], (guest / 'launch').read_text())
                self.assertFalse(observed['independent_bytes_verified'])
                self.assertEqual(received, ['offer', 'submit', 'observe'])
                self.assertEqual(sum(method == 'POST' for method, _, _ in self.fixture.protocol.calls), 1)
