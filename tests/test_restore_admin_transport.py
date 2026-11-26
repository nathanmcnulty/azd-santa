"""Exercise the administrator Run Command journal and bounded ciphertext reply."""

import base64
import json
import re
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import test_restore_admin_approval as fixture
import blob_retention as blob
import restore_admin_transport as transport
from retained_image_run_command import DONE, RECEIPT


class AdminTransportTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixture.AdminApprovalTests()
        self.fixture.setUp()
        self.job = self.fixture.job
        self.workspace = '8' * 32
        vm = self.job.selection.vm_id
        network = vm.split('/providers/')[0] + '/providers/Microsoft.Network/virtualNetworks/vnet/subnets/host'
        self.host = blob.SelectedTarget(vm, self.job.selection.vm_instance_id, network, self.job.selection.region)
        self.selection = SimpleNamespace(verifier=self.host, tenant=self.job.selection.tenant,
                                         subscription=self.job.selection.subscription)
        self.root = Path(self.enterContext(TemporaryDirectory())).resolve()
        self.root.chmod(0o700)
        self.result = {}
        self.requests = []
        self.lose_reply = False
        self.enterContext(patch.object(transport.operator, 'observe', return_value=self.fixture.readback))
        self.approval = self.fixture.issue()
        tooling = blob.encoded(dict(files={'experiments/server/restore_admin_transport.py': {}}))
        with patch.object(transport, 'verify'):
            self.operation = transport.Operation(self.selection, self.job, tooling, workspace=self.workspace,
                plan_sha256=self.fixture.request['plan_sha256'], operator_pin=self.fixture.pin, commit='d' * 40,
                tooling_sha256=transport.sha(tooling), cli=self.cli)

    def cli(self, args, seconds):
        self.assertEqual(args[:3], ['vm', 'run-command', 'invoke'])
        self.assertEqual(args[args.index('--subscription') + 1], self.selection.subscription)
        script = Path(args[-1].removeprefix('@')).read_text(encoding='ascii')
        raw = base64.b64decode(re.search(r"SANTA_ADMIN_TRANSPORT='([A-Za-z0-9+/=]+)'", script)[1])
        frame = json.loads(raw)
        self.requests.append(frame)
        if self.lose_reply:
            raise RuntimeError('Response unavailable')
        nonce = re.search(DONE + '([a-f0-9]{32})', script)[1]
        reply = blob.encoded(dict(scope=transport.SCOPE, batch_sha256=transport.sha(raw),
                                 plan_sha256=frame['plan_sha256'], **self.result))
        return {'value': [{'code': 'ComponentStatus/StdOut/succeeded',
                           'message': RECEIPT + reply.decode('ascii') + '\n' + DONE + nonce}]}

    def test_submission_and_readback_never_replay_an_unknown_result(self):
        self.lose_reply = True
        with self.assertRaises(RuntimeError):
            self.operation.apply(self.root, self.approval, self.fixture.public)
        with self.assertRaises(FileExistsError):
            self.operation.apply(self.root, self.approval, self.fixture.public)
        self.assertEqual(len(self.requests), 1)
        self.lose_reply = False
        for state in ('not-submitted', 'pending'):
            self.result = {'state': state}
            self.assertEqual(self.operation.observe(self.root)['state'], state)
        artifact = {'ciphertext_base64': ''}
        artifact['ciphertext_base64'] = 'A' * (transport.MAX_ENVELOPE_BYTES - len(blob.encoded(artifact)))
        self.result = dict(state='committed', artifact=artifact, artifact_sha256=transport.sha(blob.encoded(artifact)),
                           approval_sha256=transport.sha(self.approval))
        self.assertEqual(self.operation.observe(self.root)['artifact'], artifact)
        for field in ('artifact_sha256', 'approval_sha256'):
            original = self.result[field]
            self.result[field] = '0' * 64
            with self.assertRaises(blob.RetentionRejected):
                self.operation.observe(self.root)
            self.result[field] = original
        self.assertEqual({request['action'] for request in self.requests[1:]}, {'readback'})
        self.assertTrue(all('approval' not in request for request in self.requests[1:]))
