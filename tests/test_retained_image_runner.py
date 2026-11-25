"""Exercise the reviewed guest package and dispatch with synthetic Azure and Blob facts."""

import subprocess
import sys
import unittest
from unittest.mock import patch

import test_restore_tooling_bundle as tooling
import test_retained_image_handoff as fixtures
import test_retained_image_sas as issuer_fixtures
import retained_image_runner as runner

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
            request = frame('offer', transfer.pins['manifest_sha256'])
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
