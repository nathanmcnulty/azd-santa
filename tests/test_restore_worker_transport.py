"""Exercise the fixed recovery-worker wire format and no-replay journal."""
import base64
import json
from pathlib import Path
import re
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import test_restore_operator_approval as signing_fixture
import blob_retention as blob
from restore_database_command import SCOPE as WORKER_SCOPE
from restore_tooling_bundle import WORKER_TRANSPORT_SCOPE
import restore_worker_transport as transport
from retained_image_handoff import sha
from retained_image_run_command import DONE, RECEIPT


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.fixture = signing_fixture.OperatorRequestTests()
        self.fixture.setUp()
        with patch.object(signing_fixture.Job, 'confirm', return_value=lambda _: True):
            self.raw = self.fixture.request()
        self.selection = SimpleNamespace(verifier=self.fixture.host, tenant=self.fixture.job.selection.tenant,
                                         subscription=self.fixture.job.selection.subscription)
        self.tooling = blob.encoded(dict(scope=WORKER_TRANSPORT_SCOPE))
        self.calls = []
        self.lose_reply = False
        self.wrong_receiver = False
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name).resolve(strict=True)
        self.root.chmod(0o700)

    def operation(self, **changes):
        options = dict(workspace='a' * 32, image='sha256:' + 'b' * 64, commit='c' * 40,
                       tooling_sha256=sha(self.tooling), config_sha256='d' * 64, cli=self.cli)
        with patch.object(transport, 'verify'):
            return transport.Operation(self.selection, self.raw, self.tooling, **(options | changes))

    def cli(self, args, seconds):
        self.calls.append(args[:3])
        self.assertEqual(args[:3], ['vm', 'run-command', 'invoke'])
        self.assertEqual(args[args.index('--subscription') + 1], self.selection.subscription)
        self.assertEqual(args[args.index('--command-id') + 1], 'RunShellScript')
        script = Path(args[-1].removeprefix('@')).read_text(encoding='ascii')
        frame = re.search(r"SANTA_WORKER_TRANSPORT='([A-Za-z0-9+/=]+)'", script)[1]
        raw_frame = base64.b64decode(frame, validate=True)
        body = json.loads(raw_frame)
        self.assertEqual(base64.b64decode(body['request'], validate=True), self.raw)
        self.assertEqual(body['request_sha256'], sha(self.raw))
        self.assertEqual(body['receiver'], self.fixture.host.instance_id)
        self.assertEqual(body['boot'], self.fixture.job.verified_boot_id)
        self.assertLess(len(f"{transport.WORKSPACE_ROOT}/{body['workspace']}/docker.sock"), 108)
        self.assertLessEqual(seconds, 270)
        if self.lose_reply:
            raise TimeoutError('synthetic lost acknowledgement')
        nonce = re.search(DONE + r'([0-9a-f]{32})', script)[1]
        reply = dict(scope=WORKER_SCOPE, stage='rewrap', request_sha256=sha(self.raw))
        if body['action'] == 'offer':
            reply.update(state='offered', offer=base64.b64encode(self.fixture.offer).decode('ascii'),
                         offer_sha256=sha(self.fixture.offer))
        else:
            reply.update(state='committed', plan_sha256=self.fixture.step['plan_digest'],
                         stages={'rewrap': 'committed', 'quarantine': 'pending'}, database_changed=True,
                         activation_allowed=False, current_authority_established=False)
        if self.wrong_receiver:
            reply['request_sha256'] = '0' * 64
        result = blob.encoded(dict(scope=transport.SCOPE, batch_sha256=sha(raw_frame), reply=reply)).decode('ascii')
        self.assertLessEqual(len(result), 3072)
        return {'value': [{'code': 'ProvisioningState/succeeded', 'message': f'{RECEIPT}{result}\n{DONE}{nonce}'}]}

    def test_reviewed_plan_submits_once_and_validates_the_reply(self):
        operation = self.operation()
        compile(transport.BOOTSTRAP, 'worker-guest-bootstrap', 'exec')
        pin = operation.preview()['plan_sha256']
        self.assertEqual(operation.observe(self.root, pin)['state'], 'not-attempted')
        with patch.object(transport.operator, 'observe', return_value={'stable': True}) as observe:
            with self.assertRaises(blob.RetentionRejected):
                operation.apply(self.root, '0' * 64)
            observe.assert_not_called()
            reply = operation.apply(self.root, pin)
            self.assertEqual(observe.call_count, 2)
            observe.assert_called_with(self.fixture.job.selection, _cli=operation._call)
            self.assertFalse(reply['activation_allowed'])
            self.assertEqual(operation.observe(self.root, pin), reply)
            with self.assertRaises(blob.RetentionRejected):
                self.operation().apply(self.root, pin)
            self.assertEqual(observe.call_count, 2)
        self.assertEqual(len(self.calls), 1)

    def test_rejects_overlong_or_untrusted_workspace_ids(self):
        for workspace in ('a' * 64, '../other', None):
            with self.subTest(workspace=workspace), self.assertRaises(blob.RetentionRejected):
                self.operation(workspace=workspace)

    def test_offer_uses_the_same_transport_without_database_configuration(self):
        applied = json.loads(self.raw)
        fields = {name: applied[name] for name in ('scope', 'job', 'host', 'step')}
        self.raw = blob.encoded(dict(**fields, action='offer', public_key_sha256=sha(self.fixture.public)))
        with self.assertRaises(blob.RetentionRejected):
            self.operation()
        operation = self.operation(config_sha256=None)
        with patch.object(transport.operator, 'observe', return_value={'stable': True}):
            reply = operation.apply(self.root, operation.plan_sha256)
        self.assertEqual(reply['state'], 'offered')
        self.assertEqual(reply['offer_sha256'], sha(self.fixture.offer))
        self.assertEqual(operation.observe(self.root, operation.plan_sha256), reply)

    def test_unknown_transport_is_never_repeated(self):
        self.lose_reply = True
        operation = self.operation()
        pin = operation.plan_sha256
        with patch.object(transport.operator, 'observe', return_value={'stable': True}):
            with self.assertRaises(TimeoutError):
                operation.apply(self.root, pin)
            self.assertEqual(operation.observe(self.root, pin)['state'], 'unknown')
            with self.assertRaises(blob.RetentionRejected):
                self.operation().apply(self.root, pin)
        self.assertEqual(len(self.calls), 1)

    def test_unbound_response_or_drift_retains_only_attempt(self):
        for wrong in (True, False):
            with self.subTest(wrong_reply=wrong), TemporaryDirectory(dir=self.root) as scratch:
                local = Path(scratch)
                self.wrong_receiver = wrong
                operation = self.operation()
                with patch.object(transport.operator, 'observe', side_effect=[{'identity': 1}, {'identity': 2}]):
                    with self.assertRaises(blob.RetentionRejected):
                        operation.apply(local, operation.plan_sha256)
                self.assertEqual(operation.observe(local, operation.plan_sha256)['state'], 'unknown')
