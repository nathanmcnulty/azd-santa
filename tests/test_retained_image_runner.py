"""Exercise the reviewed guest package and dispatch with synthetic Azure and Blob facts."""

import hashlib
import json
import lzma
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import test_restore_tooling_bundle as tooling
import test_retained_image_handoff as fixtures
import test_retained_image_sas as issuer_fixtures
import retained_image_runner as runner
import retained_image_run_command as run_command
import retained_image_parts as parts

from retained_image_blob import Transfer
from retained_image_delivery import frame, send
from retained_image_sas import IssuedBatch

handoff = fixtures.handoff
blob = handoff.blob


class PackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tooling.BundleTests.setUpClass()
        cls.bundle = tooling.BundleTests
        issuer_fixtures.ImageSasTests.setUpClass()

    def setUp(self):
        fixture = issuer_fixtures.ImageSasTests()
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()
        self.fixture = fixture
        selected = fixture.selection
        self.transfer = Transfer(fixture.manifest, fixture.completion, selected.store, selected.source,
            manifest_sha256=handoff.sha(fixture.manifest), completion_sha256=handoff.sha(fixture.completion),
            operation=fixture.operation)

    def build(self):
        return runner.build(self.bundle.raw, self.bundle.commit, self.bundle.digest,
                            self.transfer, self.fixture.selection.verifier, 'r')

    def test_package_plan_is_reproducible_and_writes_nothing(self):
        raw = self.build()
        self.assertEqual(raw, self.build())
        digest = handoff.sha(raw)
        base = self.fixture.root / 'fresh'
        plan = runner.install(raw, digest, root=base)
        self.assertEqual(plan['state'], 'planned')
        self.assertEqual(plan['runner_sha256'], handoff.sha(runner.driver(digest)))
        self.assertFalse(base.exists())
        with self.assertRaises(blob.RetentionRejected):
            runner.install(raw + b'changed', digest, root=base, apply=True)
        self.assertFalse(base.exists())

    def test_module_imports_from_packaged_sources_in_isolated_python(self):
        archive = self.fixture.root / 'tools.zip'
        archive.write_bytes(self.build())
        code = ("import sys; sys.path.insert(0, sys.argv[1]); import retained_image_runner as r; "
                "assert r.__file__.startswith(sys.argv[1]); "
                "assert r.delivery.__file__.startswith(sys.argv[1]); "
                "assert r.handoff.__file__.startswith(sys.argv[1])")
        subprocess.run([sys.executable, '-I', '-B', '-c', code, str(archive)], timeout=10, check=True)

    def test_maximum_part_manifest_fits_complete_provisioning_script(self):
        size = parts.ARCHIVE_MAXIMUM + 4096
        completion = parts.encoded({**json.loads(self.fixture.completion),
                                    'archive_bytes': parts.ARCHIVE_MAXIMUM, 'ciphertext_bytes': size})
        operation = self.fixture.operation
        with patch.object(parts, 'PART_BYTES', 512 * 1024**2):
            rows = [{**part, 'sha256': hashlib.sha256(('sha' + part['object']).encode()).hexdigest(),
                     'md5': hashlib.md5(('md5' + part['object']).encode(), usedforsecurity=False).hexdigest()}
                    for part in parts.layout(size, operation)]
            self.assertEqual(len(rows), parts.MAX_PARTS)
            manifest = parts.encoded({'scope': parts.SCOPE, 'operation': operation,
                'completion_sha256': handoff.sha(completion), 'ciphertext_bytes': size,
                'ciphertext_sha256': json.loads(completion)['ciphertext_sha256'], 'parts': rows})
            selected = self.fixture.selection
            transfer = Transfer(manifest, completion, selected.store, selected.source,
                manifest_sha256=handoff.sha(manifest), completion_sha256=handoff.sha(completion), operation=operation)
            raw = runner.build(self.bundle.raw, self.bundle.commit, self.bundle.digest, transfer, selected.verifier, 'r')
            command = run_command.RunCommand(selected, transfer, 'r', handoff.sha(runner.driver(handoff.sha(raw))))
            planned = command.provision(raw)
        self.assertLessEqual(planned['script_bytes'], run_command.MAX_SCRIPT)
        print(f"Maximum-part runner script: {planned['script_bytes']} bytes.")

    def test_unknown_provisioning_is_observed_without_resubmission(self):
        raw = self.build()
        digest = handoff.sha(raw)
        runner_sha = handoff.sha(runner.driver(digest))
        selected = self.fixture.selection
        posts = []
        delivered = []
        journal = self.fixture.root / (self.fixture.operation + '-r-provision')

        def cli(arguments, timeout):
            if arguments[:2] == ['account', 'show']:
                return {'id': selected.subscription, 'tenantId': selected.tenant,
                        'environmentName': 'AzureCloud', 'state': 'Enabled'}
            target = selected.verifier
            if arguments[:2] == ['vm', 'show']:
                return {'id': target.vm_id, 'vmId': target.instance_id, 'location': target.region}
            self.assertTrue((journal / 'intent.json').is_file())
            self.assertEqual(arguments[:3], ['vm', 'run-command', 'invoke'])
            script = Path(arguments[-1][1:]).read_text(encoding='ascii')
            posts.append(script)
            self.assertLessEqual(len(script), run_command.MAX_SCRIPT)
            nonce = re.search(run_command.DONE + '([a-f0-9]{32})', script)[1]
            if 'SANTA_IMAGE_ARCHIVE=' in script:
                packed = re.search("SANTA_IMAGE_ARCHIVE='([^']+)'", script)[1]
                delivered.append(lzma.decompress(handoff.decode(packed, run_command.MAX_SCRIPT)))
                raise TimeoutError('synthetic missing install response')
            request = re.search("SANTA_IMAGE_REQUEST='([^']+)'", script)[1]
            expected = {'scope': run_command.delivery.SCOPE, 'batch_sha256': self.transfer.pins['manifest_sha256']}
            self.assertEqual(json.loads(handoff.decode(request, 4096)), {**expected, 'action': 'runner'})
            reply = {**expected, 'state': 'installed', 'archive_sha256': digest}
            return {'value': [{'code': 'ComponentStatus/StdOut/succeeded',
                               'message': run_command.RECEIPT + blob.encoded(reply).decode() + '\n'
                               + run_command.DONE + nonce}]}

        commands = run_command.RunCommand(selected, self.transfer, 'r', runner_sha, cli=cli)
        self.assertEqual(commands.provision(raw)['state'], 'planned')
        self.assertEqual(posts, [])
        for _ in range(2):
            with self.assertRaises(blob.RetentionRejected):
                commands.provision(raw, self.fixture.root, apply=True)
        self.assertEqual(len(posts), 1)
        self.assertEqual(delivered, [raw])
        self.assertEqual(commands.observe_install(digest)['state'], 'installed')
        self.assertEqual(len(posts), 2)
        self.assertFalse((journal / 'installed.json').exists())

    @unittest.skipUnless(sys.platform == 'linux', 'Linux shell')
    def test_installer_script_verifies_payload_before_writing_guest_state(self):
        raw = self.build()
        digest = handoff.sha(raw)
        with tempfile.TemporaryDirectory(dir=Path.home()) as folder:
            base = Path(folder) / 'delivery'
            # Use the local filesystem, Azure metadata, and small synthetic part size.
            bootstrap = run_command.INSTALL_BOOTSTRAP.replace("dir='/run'", f"dir={folder!r}").replace(
                'from retained_image_runner import install\n            result = install(raw, digest, apply=True)',
                "import retained_image_runner as module\n            module.blob.host_identity = lambda _: None\n"
                "            import retained_image_parts\n            retained_image_parts.PART_BYTES = 1024\n"
                f"            result = module.install(raw, digest, root={str(base)!r}, apply=True)")
            encoded = handoff.b64(lzma.compress(raw))
            nonce = '1' * 32

            def invoke(pin):
                exports = f"export SANTA_IMAGE_ARCHIVE='{encoded}'\nexport SANTA_IMAGE_ARCHIVE_SHA='{pin}'\n"
                script = run_command.RunCommand._script(exports, bootstrap, nonce)
                return subprocess.run(['/bin/sh'], input=script, capture_output=True, timeout=15)

            bad = invoke('0' * 64)
            self.assertNotEqual(bad.returncode, 0)
            self.assertEqual(bad.stdout, b'')
            self.assertFalse(base.exists())
            good = invoke(digest)
            self.assertEqual(good.returncode, 0, good.stdout.decode())
            reply = run_command.receipt({'value': [{'code': 'ComponentStatus/StdOut/succeeded',
                                                     'message': good.stdout.decode()}]}, nonce, digest)
            self.assertEqual(reply['runner_sha256'], handoff.sha(runner.driver(digest)))
            self.assertEqual((base / (self.fixture.operation + '-r') / 'tools.zip').read_bytes(), raw)


@unittest.skipUnless(sys.platform == 'linux', 'Linux guest state')
class GuestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tooling.BundleTests.setUpClass()
        cls.bundle = tooling.BundleTests

    def test_provision_offer_transfer_and_observe_for_both_roles(self):
        scenario = fixtures.HandoffTests()
        self.addCleanup(scenario.doCleanups)
        scenario.setUp()
        base = scenario.fixture.root / 'image-delivery'
        driver_host = scenario.fixture.host
        transfer = scenario.transfer
        journal = scenario.fixture.root / 'operator'
        journal.mkdir(mode=0o700)
        for permission, target, source_path in (('c', transfer.source, str(scenario.fixture.source_file)),
                                                ('r', scenario.fixture.reader, None)):
            raw = runner.build(self.bundle.raw, self.bundle.commit, self.bundle.digest, transfer,
                               target, permission, source_path=source_path)
            digest = handoff.sha(raw)
            # A failed IMDS preflight cannot install any material.
            driver_host.side_effect = blob.RetentionRejected
            with self.assertRaises(blob.RetentionRejected):
                runner.install(raw, digest, root=base, apply=True)
            driver_host.side_effect = None
            result = runner.install(raw, digest, root=base, apply=True)
            directory = base / handoff.offer_name(transfer, permission)
            if permission == 'c':
                scenario.fixture.upload_attempt_root = directory / 'attempts'
            program = directory / 'run.py'
            self.assertEqual(result['runner_sha256'], handoff.sha(program.read_bytes()))
            with self.assertRaises(FileExistsError):
                runner.install(raw, digest, root=base, apply=True)
            namespace = {'__file__': str(program)}
            exec(compile(program.read_bytes(), str(program), 'exec'), namespace)
            invoke = namespace['handle']
            manifest_digest = transfer.pins['manifest_sha256']
            self.assertEqual(invoke(frame('runner', manifest_digest))['archive_sha256'], digest)
            self.assertFalse(any((directory / 'offers').iterdir()))
            request = frame('offer', manifest_digest)
            public = invoke(request)
            self.assertEqual(invoke(request), public)
            offer = handoff.decode(public['offer'], 4096)
            batch = IssuedBatch(target, permission, transfer.pins['manifest_sha256'],
                                scenario.fixture.tokens(permission), account_id=transfer.store.blob.account_id)
            packets = handoff.seal(offer, handoff.sha(offer), batch, transfer, target, permission)
            outcome = send(invoke, journal, offer, packets, transfer, target, permission, apply=True)
            self.assertEqual(invoke(frame('observe', outcome['batch_sha256'])), outcome)
            self.assertFalse((directory / 'offers' / handoff.offer_name(transfer, permission) / 'recipient.der').exists())
            with self.assertRaises(blob.RetentionRejected):
                invoke(request)
            with patch.object(runner, 'serve') as dispatched:
                (directory / 'tools.zip').write_bytes(raw + b'changed')
                with self.assertRaises(ValueError):
                    invoke(request)
                dispatched.assert_not_called()
        self.assertEqual([method for method, _ in scenario.fixture.calls], ['PUT'] * 3 + ['GET'] * 3)
