"""Exercise the export Run Command shell and metadata handoff with a synthetic guest."""

import json
from pathlib import Path
import re
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock

import test_retained_image_runner as fixtures
import test_retained_image_export as export_fixtures
import retained_image_export_command as command
from retained_image_handoff import decode, sha
from retained_image_run_command import MAX_SCRIPT


class ExportCommandTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.PackageTests.setUpClass()
        export_fixtures.ExportTests.setUpClass()

    def setUp(self):
        fixture = fixtures.PackageTests()
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()
        self.selection, self.bundle = fixture.fixture.selection, fixture.bundle
        self.inventory = command.blob.encoded({'scope': 'azd-santa-retention-image-inventory-v1',
            'platform': 'linux/amd64', 'images': {'core': {'id': 'sha256:' + '1' * 64}}})

    def command(self, cli):
        key = export_fixtures.ExportTests.public
        return command.ExportCommand(self.selection, self.inventory, 'core', key, self.bundle.raw,
            inventory_sha256=sha(self.inventory), recipient_sha256=sha(key), commit=self.bundle.commit,
            tooling_sha256=self.bundle.digest, seconds=30, cli=cli)

    def test_plan_is_reproducible_bounded_and_uses_no_cli(self):
        mocked_cli = Mock(side_effect=AssertionError('unexpected Azure CLI call'))
        plan = self.command(mocked_cli).preview()
        self.assertEqual(plan, self.command(mocked_cli).preview())
        self.assertLessEqual(plan['maximum_script_bytes'], MAX_SCRIPT)
        self.assertEqual(plan['vm_id'], self.selection.source.vm_id)
        self.assertFalse(plan['performs_mutation'])
        mocked_cli.assert_not_called()

    @unittest.skipUnless(sys.platform == 'linux', 'Linux isolated bootstrapped guest')
    def test_lost_start_reply_then_collect_recovers_only_metadata(self):
        with TemporaryDirectory(dir=Path.home()) as temporary:
            home = Path(temporary)
            guest = home / 'guest'
            guest.mkdir(mode=0o700)
            operator = home / 'operator'
            operator.mkdir(mode=0o700)
            posts = []
            target = self.selection.source
            intended_args = ['--resource-group', target.vm_id.split('/')[4], '--name', 'vm-santa-lab',
                             '--subscription', self.selection.subscription]

            def cli(arguments, timeout):
                if arguments[:2] == ['account', 'show']:
                    return {'id': self.selection.subscription, 'tenantId': self.selection.tenant,
                            'environmentName': 'AzureCloud', 'state': 'Enabled'}
                if arguments[:2] == ['vm', 'show']:
                    self.assertEqual(arguments[2:], intended_args)
                    return {'id': target.vm_id, 'vmId': target.instance_id, 'location': target.region}
                self.assertEqual(arguments[3:-1], [*intended_args, '--command-id', 'RunShellScript', '--scripts'])
                script = Path(arguments[-1][1:]).read_text(encoding='ascii')
                self.assertLessEqual(len(script), MAX_SCRIPT)
                name = re.search("SANTA_IMAGE_EXPORT_REQUEST='([^']+)'", script)[1]
                request = json.loads(decode(name, 1024))
                posts.append(request['action'])
                # Emulate the guest identity and disk while executing the actual
                # digest-checked archive, dispatcher, and export through bash.
                script = script.replace("dir='/run'", f'dir={str(guest)!r}').replace(
                    '            from retained_image_export_job import dispatch',
                    """            import retained_image_export_job as jobs
            from contextlib import contextmanager
            jobs.blob.host_identity = lambda _: None
            original = jobs.ExportJob
            def selected(*args, **kwargs):
                job = original(*args, root=EXPORT_DIRECTORY, **kwargs)
                return job
            jobs.ExportJob = selected
            @contextmanager
            def fixture(*args):
                yield iter((bytes(1024), bytes(512)))
            jobs.export.docker_archive = fixture
            dispatch = jobs.dispatch""".replace('EXPORT_DIRECTORY', repr(str(guest / 'exports'))))
                result = subprocess.run(['/bin/sh'], input=script, text=True, capture_output=True, timeout=25)
                self.assertEqual(result.returncode, 0, result.stderr)
                if request['action'] == 'start':
                    raise TimeoutError('lost completed export response')
                return {'value': [{'code': 'ComponentStatus/StdOut/succeeded', 'message': result.stdout}]}

            operation = self.command(cli)
            operation.job.artifact = guest / 'exports' / operation.job.operation / 'artifact'
            for _ in range(2):
                with self.assertRaises(command.blob.RetentionRejected):
                    operation.apply(operator, operation.plan_sha256)
            self.assertEqual(posts, ['start'])
            self.assertTrue((operation.job.artifact / 'image.sealed').is_file())
            try:
                receipt = operation.observe(operator, operation.plan_sha256, collect=True)
            except command.blob.RetentionRejected as error:
                raise AssertionError(f'Synthetic export collection failed after {posts}') from error.__context__
            self.assertEqual(posts, ['start', 'observe', 'page'])
            metadata = Path(receipt['metadata_directory'])
            self.assertEqual(sha((metadata / 'complete.json').read_bytes()), receipt['completion_sha256'])
            self.assertEqual(sha((metadata / 'parts.json').read_bytes()), receipt['manifest_sha256'])
            self.assertEqual({item.name for item in metadata.iterdir()}, {'export.json', 'complete.json', 'parts.json'})
            repeated = operation.observe(operator, operation.plan_sha256, collect=True)
            self.assertEqual(repeated, receipt)
