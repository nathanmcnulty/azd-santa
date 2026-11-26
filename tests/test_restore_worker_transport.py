"""Exercise the fixed recovery-worker wire format and no-replay journal."""
import base64
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import subprocess
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import test_restore_operator_approval as signing_fixture
import blob_retention as blob
import restore_census_review as review
import restore_database_command as database
from restore_database_command import SCOPE as WORKER_SCOPE
from restore_tooling_bundle import WORKER_TRANSPORT_SCOPE
from restore_worker import check_worker_image, stage_application
import restore_worker_transport as transport
from retained_image_handoff import sha
from retained_image_run_command import DONE, RECEIPT


class LocalPreviewTests(unittest.TestCase):
    def setUp(self):
        self.fixture = signing_fixture.OperatorRequestTests()
        self.fixture.setUp()
        self.key = b'k' * 32
        self.review = review.encode(dict(scope=review.SCOPE, binding=self.fixture.job.binding(self.key),
            stage='quarantine', census='a' * 64, dispositions={}))
        self.request = database.preview_request(self.fixture.job, self.fixture.host, stage='quarantine',
            review_bytes=self.review, review_sha256=sha(self.review), fingerprint_key=self.key,
            options={'cutoff': datetime(2026, 1, 1, tzinfo=timezone.utc)})

    def test_round_trip_and_local_transport_boundary(self):
        header, job, host, (fingerprint_key, review_bytes, options) = database.parse_preview(self.request)
        self.assertEqual(header['action'], 'preview')
        self.assertEqual(job, self.fixture.job)
        self.assertEqual(host, self.fixture.host)
        self.assertEqual(fingerprint_key, self.key)
        self.assertEqual(review_bytes, self.review)
        self.assertEqual(options['cutoff'].year, 2026)
        with self.assertRaises(ValueError):
            database.parse_request(self.request)

    def test_invalid_private_inputs_and_wrong_boot_reject_before_database_connection(self):
        offset = 4 + int.from_bytes(self.request[:4], 'big')
        wrong_key = self.request[:offset] + b'x' * 32 + self.request[offset + 32:]
        for raw in (b'', self.request[:-1], wrong_key, b'\xff' * 4 + self.request[4:]):
            with self.subTest(size=len(raw)), self.assertRaises(ValueError):
                database.parse_preview(raw)
        with patch.object(database, 'database_connections') as connection:
            with self.assertRaises(ValueError):
                database.preview(self.request, directory=None, _boot=lambda _: 'wrong')
            connection.assert_not_called()


class ApplicationStagingTests(unittest.TestCase):
    def test_copy_failure_removes_the_unstarted_container(self):
        calls = []

        def docker(args, **options):
            calls.append(args)
            if args[0] == 'cp':
                raise subprocess.CalledProcessError(1, args)
            self.assertTrue(options['check'])

        with TemporaryDirectory() as directory, self.assertRaises(subprocess.CalledProcessError):
            stage_application(docker, 'sha256:' + 'f' * 64, 'stage-fixture', Path(directory) / 'application')
        self.assertEqual([args[0] for args in calls], ['create', 'cp', 'rm'])
        self.assertEqual(calls[-1], ['rm', '--force', '--volumes', 'stage-fixture'])


class WorkerImageTests(unittest.TestCase):
    image = 'sha256:' + 'f' * 64

    def test_inspection_accepts_omitted_or_empty_volume_declarations(self):
        record = dict(Id=self.image, Os='linux', Architecture='amd64')
        for config in ({}, {'Volumes': None}, {'Volumes': {}}):
            with self.subTest(config=config):
                check_worker_image(blob.encoded([dict(record, Config=config)]), self.image)

    def test_inspection_rejects_unsafe_or_unexpected_image_metadata(self):
        record = dict(Id=self.image, Os='linux', Architecture='amd64', Config={})
        for results in ([], [record, record], [dict(record, Id='sha256:' + '1' * 64)],
                        [dict(record, Os='windows')], [dict(record, Architecture='arm64')],
                        [dict(record, Config=None)], [dict(record, Config={'Volumes': []})],
                        [dict(record, Config={'Volumes': {'/data': {}}})]):
            with self.subTest(results=results), self.assertRaises(blob.RetentionRejected):
                check_worker_image(blob.encoded(results), self.image)


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
        self.readback_pending = False
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
        action, frame = re.search(r"SANTA_WORKER_(TRANSPORT|READBACK)='([A-Za-z0-9+/=]+)'", script).groups()
        raw_frame = base64.b64decode(frame, validate=True)
        body = json.loads(raw_frame)
        if action == 'READBACK':
            self.assertEqual(set(body), {'vm_id', 'vm_instance_id', 'region', 'boot', 'workspace',
                                         'request_sha256', 'plan_sha256', 'stage'})
            self.assertEqual(body['vm_instance_id'], self.fixture.host.instance_id)
            self.assertEqual(body['plan_sha256'], self.fixture.step['plan_digest'])
            self.assertNotIn('def launch', script)
            self.assertLessEqual(seconds, 180)
        else:
            self.assertEqual(base64.b64decode(body['request'], validate=True), self.raw)
            self.assertEqual(body['receiver'], self.fixture.host.instance_id)
        self.assertEqual(body['request_sha256'], sha(self.raw))
        self.assertEqual(body['boot'], self.fixture.job.verified_boot_id)
        self.assertLess(len(f"{transport.WORKSPACE_ROOT}/{body['workspace']}/docker.sock"), 108)
        self.assertLessEqual(seconds, 270)
        if self.lose_reply:
            raise TimeoutError('synthetic lost acknowledgement')
        nonce = re.search(DONE + r'([0-9a-f]{32})', script)[1]
        reply = dict(scope=WORKER_SCOPE, stage='rewrap', request_sha256=sha(self.raw))
        if body.get('action') == 'offer':
            reply.update(state='offered', offer=base64.b64encode(self.fixture.offer).decode('ascii'),
                         offer_sha256=sha(self.fixture.offer))
        else:
            reply.update(state='committed', plan_sha256=self.fixture.step['plan_digest'],
                         stages={'rewrap': 'committed', 'quarantine': 'pending'}, database_changed=True,
                         activation_allowed=False, current_authority_established=False)
        if self.wrong_receiver:
            reply['request_sha256'] = '0' * 64
        scope = transport.READBACK_SCOPE if action == 'READBACK' else transport.SCOPE
        if action == 'READBACK' and self.readback_pending:
            reply = None
        result = blob.encoded(dict(scope=scope, batch_sha256=sha(raw_frame), reply=reply)).decode('ascii')
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

    def test_pending_readback_retains_unknown_then_recovers_validated_outcome(self):
        operation = self.operation()
        pin = operation.plan_sha256
        with patch.object(transport.operator, 'observe', return_value={'stable': True}):
            self.assertEqual(operation.readback(self.root, pin)['state'], 'not-attempted')
            self.assertEqual(self.calls, [])
            self.lose_reply = True
            with self.assertRaises(TimeoutError):
                operation.apply(self.root, pin)
            self.lose_reply = False
            self.readback_pending = True
            self.assertEqual(operation.readback(self.root, pin)['state'], 'unknown')
            self.assertEqual(operation.observe(self.root, pin)['state'], 'unknown')
            self.readback_pending = False
            reply = operation.readback(self.root, pin)
            self.assertEqual(reply['state'], 'committed')
            self.assertEqual(operation.observe(self.root, pin), reply)
            self.assertEqual(operation.readback(self.root, pin), reply)
            with self.assertRaises(blob.RetentionRejected):
                operation.apply(self.root, pin)
        self.assertEqual(len(self.calls), 3)

    def test_readback_with_wrong_receipt_or_live_arm_drift_leaves_unknown(self):
        operation = self.operation()
        pin = operation.plan_sha256
        self.lose_reply = True
        with patch.object(transport.operator, 'observe', return_value={'stable': True}):
            with self.assertRaises(TimeoutError):
                operation.apply(self.root, pin)
        self.lose_reply = False
        self.wrong_receiver = True
        with patch.object(transport.operator, 'observe', return_value={'stable': True}):
            with self.assertRaises(blob.RetentionRejected):
                operation.readback(self.root, pin)
        self.wrong_receiver = False
        with patch.object(transport.operator, 'observe', side_effect=[{'stable': True}, {'stable': False}]):
            with self.assertRaises(blob.RetentionRejected):
                operation.readback(self.root, pin)
        self.assertEqual(operation.observe(self.root, pin)['state'], 'unknown')

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


class GuestReadbackTests(unittest.TestCase):
    def setUp(self):
        program, _, invocation = transport.READBACK.rpartition('\ntry:\n    readback()')
        self.assertTrue(invocation)
        self.guest = {}
        exec(compile(program, '<worker-readback>', 'exec'), self.guest)
        self.request = dict(boot='4' * 36, workspace='a' * 32, request_sha256='b' * 64,
                            plan_sha256='c' * 64, stage='quarantine')
        self.intent = dict(request_sha256=self.request['request_sha256'], boot=self.request['boot'])
        self.outcome = dict(scope=WORKER_SCOPE, state='committed', request_sha256=self.request['request_sha256'],
                            plan_sha256=self.request['plan_sha256'], stage='quarantine',
                            stages={'rewrap': 'committed', 'quarantine': 'committed'},
                            database_changed=True, activation_allowed=False, current_authority_established=False)

    def test_guest_returns_only_the_required_commit_and_preserves_pending(self):
        paths = []
        self.guest['private_directory'] = paths.append
        view = self.guest['checked_outcome']

        def record(path):
            if path.name == 'intent.json':
                return self.intent
            raise FileNotFoundError()

        self.guest['read_record'] = record
        self.assertIsNone(view(self.request))
        self.assertEqual(paths[-1].name, 'transport-' + self.intent['request_sha256'])
        self.guest['read_record'] = lambda path: self.intent if path.name == 'intent.json' else self.outcome
        self.assertEqual(view(self.request), self.outcome)
        for change in ({'boot': '5' * 36}, {'plan_sha256': 'f' * 64}, {'stage': 'rewrap'}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                view(self.request | change)
        with self.assertRaises(ValueError):
            self.outcome['unexpected'] = 'must not export'
            view(self.request)

    def test_guest_refuses_a_new_boot_before_reading_the_workspace(self):
        self.guest['os'] = SimpleNamespace(geteuid=lambda: 0, environ={
            'SANTA_WORKER_READBACK': base64.b64encode(blob.encoded(self.request | {
                'vm_id': '/selected/vm', 'vm_instance_id': 'fixture', 'region': 'fixture'
            })).decode('ascii'),
        })
        self.guest['selected_boot'] = Mock(return_value='5' * 36)
        self.guest['checked_outcome'] = Mock()
        with self.assertRaises(ValueError):
            self.guest['readback']()
        self.guest['checked_outcome'].assert_not_called()
