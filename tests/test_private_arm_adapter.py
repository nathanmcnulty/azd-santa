"""Offline cached-ARM protocol boundaries; no CLI, auth or network invocation."""
import copy
import io
import json
import os
import pickle
import subprocess
import sys
import tempfile
import time
import threading
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'experiments/server'))
import private_arm_adapter as arm
import blob_retention as retention
import restore_arm_authorization as restore_arm
import restore_census_review as review
import restore_guest_readback as guest
from retained_image_run_command import DONE, RECEIPT
from test_backup_store_selection import fixture, TENANT
import test_blob_retention as retention_tests
from test_blob_retention import Arm


class RestoreArmTests(unittest.TestCase):
    def setUp(self):
        subscription = '1' * 8 + '-1111-1111-1111-' + '1' * 12
        self.group = 'rg-azd-santa-vm-fixture'
        vm_id = (f'/subscriptions/{subscription}/resourceGroups/{self.group}'
                 '/providers/Microsoft.Compute/virtualMachines/vm-santa-lab')
        self.selection = restore_arm.Selection(TENANT, subscription, 'operator@example.com',
                                               vm_id, TENANT, 'westus2')
        self.context = dict(id=subscription, tenantId=TENANT, environmentName='AzureCloud', state='Enabled',
                            user={'type': 'user', 'name': 'operator@example.com'})
        self.vm = dict(id=vm_id, vmId=TENANT, location='westus2', provisioningState='Succeeded',
                       tags={'azd-solution': 'azd-santa', 'purpose': 'synthetic-vm-lab', 'azd-env-name': 'fixture'})
        self.account_command = ['account', 'show', '--subscription', subscription]
        self.vm_command = ['vm', 'show', '--subscription', subscription, '--resource-group', self.group,
                           '--name', 'vm-santa-lab', '--query', restore_arm.VM_QUERY]

    def test_readback_uses_only_selected_cached_user_and_exact_vm(self):
        cli = Mock(side_effect=[self.context, self.vm, self.context])
        result = restore_arm.observe(self.selection, _cli=cli)
        self.assertEqual(result['vm_instance_id'], self.selection.vm_instance_id)
        self.assertTrue(result['account_verified'] and result['exact_vm_verified'])
        self.assertFalse(result['cloud_write'])
        self.assertEqual([call.args[0] for call in cli.call_args_list],
                         [self.account_command, self.vm_command, self.account_command])
        self.assertTrue(all(0 < call.args[1] <= 30 for call in cli.call_args_list))

    def test_denies_account_target_and_context_drift(self):
        other = {**self.context, 'user': {'type': 'user', 'name': 'other@example.com'}}
        principal = {**self.context, 'user': {**self.context['user'], 'type': 'servicePrincipal'}}
        for replies in ([other], [principal], [self.context, {**self.vm, 'vmId': self.selection.subscription}],
                        [self.context, {**self.vm, 'tags': {}}], [self.context, self.vm, other]):
            with self.subTest(replies=replies):
                cli = Mock(side_effect=replies)
                with self.assertRaises(arm.ArmRejected):
                    restore_arm.observe(self.selection, _cli=cli)
                self.assertEqual(cli.call_count, len(replies))

    def test_only_one_matching_confirmed_operation_is_accepted(self):
        operation = dict(stage='rewrap', binding='0' * 64, review_sha256='1' * 64, plan_digest='2' * 64)
        request = {**operation, 'scope': review.SCOPE}
        cli = Mock(side_effect=[self.context, self.vm, self.context])
        readback = Mock(side_effect=lambda target: restore_arm.observe(target, _cli=cli))
        approve = restore_arm.ConfirmedOperation(self.selection, **operation, _observe=readback)
        with self.assertRaises(arm.ArmRejected):
            approve({**request, 'review_sha256': '3' * 64})
        readback.assert_not_called()
        self.assertTrue(approve(request))
        with self.assertRaises(arm.ArmRejected):
            approve(request)
        readback.assert_called_once_with(self.selection)
        fail = Mock(side_effect=RuntimeError('sensitive transport error'))
        approve = restore_arm.ConfirmedOperation(self.selection, **operation, _observe=fail)
        for _ in range(2):
            with self.assertRaises(arm.ArmRejected) as rejected:
                approve(request)
            self.assertNotIn('sensitive', str(rejected.exception))
        fail.assert_called_once_with(self.selection)

        with patch.object(restore_arm.time, 'monotonic', return_value=100):
            expired = restore_arm.ConfirmedOperation(self.selection, **operation, _observe=readback)
        with patch.object(restore_arm.time, 'monotonic', return_value=400), self.assertRaises(arm.ArmRejected):
            expired(request)
        readback.assert_called_once_with(self.selection)

    def test_guest_readback_submits_only_one_probe_and_requires_exact_completion(self):
        for mode in ('complete', 'wrong_nonce', 'wrong_vm', 'account_drift'):
            with self.subTest(mode=mode):
                calls = []
                nonce = 'f' * 32
                script, digest = guest.operation(self.selection, nonce)
                boot = '0' * 8 + '-0000-4000-8000-' + '0' * 12
                reply = dict(scope=guest.SCOPE, batch_sha256=digest, vm_instance_id=self.selection.vm_instance_id,
                             boot_id=boot)
                if mode == 'wrong_vm':
                    reply['vm_instance_id'] = self.selection.subscription
                suffix = '0' * 32 if mode == 'wrong_nonce' else nonce
                response = {'value': [{'code': 'ComponentStatus/StdOut/succeeded',
                    'message': RECEIPT + retention.encoded(reply).decode() + '\n' + DONE + suffix + '\n'}]}

                def cli(args, seconds):
                    calls.append(args[:2])
                    if args == self.account_command:
                        if mode == 'account_drift' and len(calls) > 4:
                            return {**self.context, 'user': {'type': 'user', 'name': 'other@example.com'}}
                        return self.context
                    if args == self.vm_command:
                        return self.vm
                    self.assertEqual(args[:-1], ['vm', 'run-command', 'invoke', '--subscription',
                        self.selection.subscription, '--resource-group', self.group, '--name', 'vm-santa-lab',
                        '--command-id', 'RunShellScript', '--scripts'])
                    self.assertEqual(Path(args[-1][1:]).read_bytes(), script)
                    self.assertEqual(seconds, 180)
                    return response

                with patch.object(guest.uuid, 'uuid4', return_value=Mock(hex=nonce)):
                    if mode == 'complete':
                        result = guest.readback(self.selection, _cli=cli)
                        self.assertEqual(result, dict(scope=guest.SCOPE, vm_instance_id=self.selection.vm_instance_id,
                                                      boot_id=boot))
                    else:
                        with self.assertRaises(arm.ArmRejected):
                            guest.readback(self.selection, _cli=cli)
                self.assertEqual(calls.count(['vm', 'run-command']), 1)


class Protocol:
    def __init__(self):
        self.facts = fixture()
        self.context = dict(self.facts['context_before'], user={'type': 'user', 'name': 'synthetic'})
        self.token = dict(tokenType='Bearer', accessToken='private-synthetic-arm-token', expires_on=int(time.time())+3600,
                          expiresOn='unused local timestamp', tenant=TENANT, subscription=self.context['id'])
        self.calls = []
        self.cli_calls = []
        self.error = False
        self.graph_mutation = None
        self.drift_after_post = False

    def cli(self, args, seconds):
        self.cli_calls.append((args, seconds))
        if args == ['version']:
            return {'azure-cli': '2.80.0'}
        if args[:2] == ['account', 'get-access-token']:
            return copy.deepcopy(self.token)
        result = copy.deepcopy(self.context)
        if self.drift_after_post and any(c[0] == 'POST' for c in self.calls):
            result['name'] = 'changed'
        return result

    def transport(self, method, url, body, token, deadline):
        assert token == self.token['accessToken']
        assert deadline > time.monotonic()
        self.calls.append((method, url, body))
        if method == 'POST':
            if self.error:
                raise RuntimeError('private-synthetic-arm-token secret-SAS')
            return self.sas(body)
        result = copy.deepcopy(self.facts['before'][url])
        if self.graph_mutation:
            self.graph_mutation(url, result)
        return result

    @staticmethod
    def sas(body):
        fake = object.__new__(Arm)
        fake.calls = []
        return fake('POST', 'unused', body)


class CachedArmTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        retention_tests.Retention.setUpClass()

    def setUp(self):
        self.capture = retention_tests.Retention()
        self.capture.setUp()
        self.protocol = Protocol()
        self.selected = arm.Selection(TENANT, self.protocol.context['id'], self.capture.store,
                                      self.capture.source, self.capture.verifier)

    def adapter(self, permission='c', **kw):
        return arm.CachedArm(self.selected, self.capture.record,
            self.capture.source if permission == 'c' else self.capture.verifier, permission,
            cli=self.protocol.cli, transport=self.protocol.transport, **kw)

    def ready(self, permission='c'):
        adapter = self.adapter(permission)
        receipt = adapter.initialize(live=True)
        self.assertFalse(receipt['capability_minted'])
        return adapter

    def test_default_plans_make_no_calls_and_do_not_serialize_private_state(self):
        adapter = self.adapter()
        self.assertFalse(adapter.initialize()['authenticates'])
        self.assertFalse(adapter.mint()['performs_mutation'])
        self.assertEqual(self.protocol.calls + self.protocol.cli_calls, [])
        self.assertEqual(repr(adapter), '<private cached ARM attempt>')
        with self.assertRaises(arm.ArmRejected):
            pickle.dumps(adapter)
        with self.assertRaises(Exception):
            adapter.mint(apply=True)
        self.assertEqual(self.protocol.calls, [])

    def test_exact_source_and_separate_verifier_private_capabilities(self):
        for permission in ('c', 'r'):
            self.protocol = Protocol()
            adapter = self.ready(permission)
            capability = adapter.mint(apply=True)
            self.assertEqual(capability.permission, permission)
            self.assertEqual(capability.target, self.capture.source if permission == 'c' else self.capture.verifier)
            posts = [c for c in self.protocol.calls if c[0] == 'POST']
            self.assertEqual(len(posts), 1)
            self.assertEqual(posts[0][2]['canonicalizedResource'], self.capture.blob.canonical)
            self.assertIsNone(adapter._token)
            self.assertNotIn('synthetic', repr(adapter) + repr(capability))
            args = next(args for args, _ in self.protocol.cli_calls if args[:2] == ['account', 'get-access-token'])
            self.assertNotIn('--tenant', args)
            self.assertEqual(args[-2:], ['--resource', arm.RESOURCE])
            self.assertTrue(all('token' not in str(args) or args[1] == 'get-access-token' for args, _ in self.protocol.cli_calls))
            with self.assertRaises(Exception):
                adapter.mint(apply=True)
            self.assertEqual(len([c for c in self.protocol.calls if c[0] == 'POST']), 1)

    def test_typed_selection_rejects_undeclared_targets_store_or_subscription(self):
        for field, value in [('tenant', 'unknown'), ('subscription', self.capture.store.ownership_id),
                             ('source', self.capture.verifier)]:
            values = vars(self.selected).copy()
            values[field] = value
            with self.subTest(field=field), self.assertRaises(Exception):
                arm.CachedArm(arm.Selection(**values), self.capture.record, self.capture.source, 'c')
        with self.assertRaises(Exception):
            arm.CachedArm(self.selected, self.capture.record, self.capture.source, 'r')
        self.assertEqual(self.protocol.calls, [])

    def test_context_missing_wrong_cloud_disabled_identity_and_tenant_fail_closed(self):
        for key, value in [('tenantId', 'wrong'), ('id', 'wrong'), ('state', 'Disabled'),
                           ('environmentName', 'AzureUSGovernment'), ('user', {}),
                           ('user', {'type': 'user', 'name': 'systemAssignedIdentity'}),
                           ('user', {'type': 'user', 'cloudShellID': 'cloud'})]:
            self.protocol = Protocol()
            self.protocol.context[key] = value
            adapter = self.adapter()
            with self.subTest(key=key, value=value), self.assertRaises(arm.ArmRejected):
                adapter.initialize(live=True)
            self.assertEqual(self.protocol.calls, [])
            self.assertIsNone(adapter._token)

    def test_token_missing_expired_wrong_scope_and_invalid_material_reject(self):
        for key, value in [('tenant', 'wrong'), ('subscription', 'wrong'), ('tokenType', 'Other'),
                           ('expires_on', int(time.time())-1), ('expires_on', 'future'),
                           ('accessToken', 'secret\r\nInjected: header'), ('accessToken', '')]:
            self.protocol = Protocol()
            self.protocol.token[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(arm.ArmRejected):
                self.adapter().initialize(live=True)
            self.assertEqual(self.protocol.calls, [])
        self.protocol = Protocol()
        del self.protocol.token['expires_on']
        with self.assertRaises(arm.ArmRejected):
            self.adapter().initialize(live=True)

    def test_old_cli_or_context_drift_is_not_refreshed_or_retried(self):
        for mode in ('version', 'context'):
            adapter = self.adapter()
            original = self.protocol.cli
            def changed(args, seconds):
                result = original(args, seconds)
                if mode == 'version' and args == ['version']:
                    result['azure-cli'] = '2.53.0'
                if mode == 'context' and len(self.protocol.cli_calls) >= 4:
                    result['name'] = 'drift'
                return result
            adapter._cli = changed
            with self.subTest(mode=mode), self.assertRaises(arm.ArmRejected):
                adapter.initialize(live=True)
            with self.assertRaises(arm.ArmRejected):
                adapter.initialize(live=True)

    def test_existing_ownership_and_graph_validator_are_mandatory(self):
        for mutation in ('owner', 'etag-drift', 'missing-id', 'endpoint'):
            self.protocol = Protocol()
            count = {}
            def change(url, row):
                count[url] = count.get(url, 0) + 1
                if mutation == 'owner' and '/providers/' not in url:
                    row['tags']['azd-santa-backup-owner'] = 'wrong'
                elif mutation == 'etag-drift':
                    row['etag'] = str(count[url])
                elif mutation == 'missing-id':
                    row.pop('id', None)
                elif mutation == 'endpoint' and '/subnets/host?' in url:
                    row['properties']['serviceEndpoints'] = []
            self.protocol.graph_mutation = change
            with self.subTest(mutation=mutation), self.assertRaises(arm.ArmRejected):
                self.adapter().initialize(live=True)
            self.assertFalse(any(c[0] == 'POST' for c in self.protocol.calls))

    def test_exact_url_method_and_get_body_allowlist_before_transport(self):
        for method, suffix, body in [('DELETE', '', None), ('GET', '&extra=1', None),
                                     ('GET', '#fragment', None), ('GET', '', {}),
                                     ('POST', '', {})]:
            self.protocol = Protocol()
            adapter = self.ready()
            count = len(self.protocol.calls)
            with self.subTest(method=method, suffix=suffix), self.assertRaises(arm.ArmRejected):
                adapter(method, next(iter(adapter._urls)) + suffix, body)
            self.assertEqual(len(self.protocol.calls), count)
        for url in ('https://management.azure.com.evil/', 'https://management.azure.com:443/',
                    'http://management.azure.com/', 'https://user@management.azure.com/'):
            adapter = self.ready()
            with self.assertRaises(arm.ArmRejected):
                adapter('GET', url, None)

    def test_post_exact_blob_permission_fields_and_time_bounds(self):
        for key, value in [('canonicalizedResource', '/other'), ('signedPermission', 'rw'),
                           ('signedResource', 'c'), ('signedProtocol', 'http'),
                           ('signedExpiry', '2099-01-01T00:00:00Z'), ('signedStart', '2026-1-1T00:00:00Z'),
                           ('signedIp', '1.2.3.4')]:
            self.protocol = Protocol()
            adapter = self.ready()
            plan = adapter.mint()
            plan['body'][key] = value
            with self.subTest(key=key), self.assertRaises(arm.ArmRejected):
                adapter('POST', plan['url'], plan['body'])
            self.assertFalse(any(c[0] == 'POST' for c in self.protocol.calls))

    def test_unknown_post_and_post_context_drift_fence_all_replay_and_redact(self):
        for field in ('error', 'drift_after_post'):
            self.protocol = Protocol()
            setattr(self.protocol, field, True)
            adapter = self.ready()
            with self.assertRaises(Exception) as caught:
                adapter.mint(apply=True)
            self.assertNotIn('secret', str(caught.exception))
            self.assertNotIn('synthetic', str(caught.exception))
            self.assertIsNone(adapter._token)
            with self.assertRaises(Exception):
                adapter.mint(apply=True)
            with self.assertRaises(Exception):
                adapter.initialize(live=True)
            self.assertEqual(len([c for c in self.protocol.calls if c[0] == 'POST']), 1)

    def test_pre_post_fresh_graph_failure_has_no_post(self):
        adapter = self.ready()
        self.protocol.graph_mutation = lambda url, row: row.update(etag=str(time.monotonic()))
        with self.assertRaises(Exception):
            adapter.mint(apply=True)
        self.assertFalse(any(c[0] == 'POST' for c in self.protocol.calls))

    def test_stable_graph_change_since_initial_selection_rejects(self):
        adapter = self.ready()
        self.protocol.graph_mutation = lambda url, row: row.update(etag='new-stable-etag')
        with self.assertRaises(Exception):
            adapter.mint(apply=True)
        self.assertFalse(any(c[0] == 'POST' for c in self.protocol.calls))

    def test_overlapping_callback_cannot_send_second_post(self):
        adapter = self.ready()
        plan = adapter.mint()
        entered, release = threading.Event(), threading.Event()
        original = self.protocol.transport
        def transport(*args):
            if args[0] == 'POST':
                entered.set()
                self.assertTrue(release.wait(5))
            return original(*args)
        adapter._transport = transport
        result = []
        def first():
            result.append(adapter('POST', plan['url'], plan['body']))
        thread = threading.Thread(target=first)
        thread.start()
        try:
            self.assertTrue(entered.wait(5))
            with self.assertRaises(arm.ArmRejected):
                adapter('POST', plan['url'], plan['body'])
        finally:
            release.set()
            thread.join(5)
        self.assertEqual(len(result), 1)
        self.assertEqual(len([c for c in self.protocol.calls if c[0] == 'POST']), 1)

    def test_deadline_and_response_bounds_fail_closed(self):
        adapter = self.ready()
        adapter._deadline = time.monotonic() - 1
        with self.assertRaises(Exception):
            adapter.mint(apply=True)
        self.assertFalse(any(c[0] == 'POST' for c in self.protocol.calls))
        adapter = self.ready()
        adapter._transport = lambda *args: {'raw': 'x' * arm.BOUND}
        with self.assertRaises(arm.ArmRejected):
            adapter('GET', next(iter(adapter._urls)), None)


class WireTests(unittest.TestCase):
    def application(self):
        path = Path(sys.executable)
        return path, arm.file_identity(path)

    def connection(self, raw=b'{}', status=200, length=None):
        response = Mock(status=status)
        stream = io.BytesIO(raw)
        response.read1.side_effect = stream.read1
        response.getheader.side_effect = lambda key, default=None: str(length) if key == 'Content-Length' and length is not None else default
        connection = Mock()
        connection.getresponse.return_value = response
        return connection

    def test_direct_https_authorization_header_and_no_redirect(self):
        for status in (200, 302, 401, 429, 500):
            connection = self.connection(status=status)
            with patch.object(arm.http.client, 'HTTPSConnection', return_value=connection) as factory:
                if status == 200:
                    self.assertEqual(arm.https('GET', arm.RESOURCE+'exact', None, 'private', time.monotonic()+5), {})
                else:
                    with self.assertRaises(arm.ArmRejected):
                        arm.https('GET', arm.RESOURCE+'exact', None, 'private', time.monotonic()+5)
                self.assertEqual(factory.call_args.args, ('management.azure.com', 443))
                self.assertEqual(connection.request.call_count, 1)
                self.assertEqual(connection.request.call_args.kwargs['headers']['Authorization'], 'Bearer private')
                connection.close.assert_called_once()

    def test_duplicate_invalid_large_truncated_responses_reject(self):
        for raw, length in [(b'{"x":1,"x":2}', None), (b'not-json private', None),
                            (b'{"x":NaN}', None), (b'[]', None), (b'{}', 3), (b'x'*(arm.BOUND+1), None)]:
            connection = self.connection(raw=raw, length=length)
            with patch.object(arm.http.client, 'HTTPSConnection', return_value=connection), self.assertRaises(arm.ArmRejected):
                arm.https('GET', arm.RESOURCE+'exact', None, 'private', time.monotonic()+5)

    def test_connect_deadline_expired_before_request_no_late_post(self):
        connection = self.connection()
        with patch.object(arm.http.client, 'HTTPSConnection', return_value=connection), \
             patch.object(arm.time, 'monotonic', side_effect=[0, 0, 10]), self.assertRaises(arm.ArmRejected):
            arm.https('POST', arm.RESOURCE+'exact', {}, 'private', 5)
        connection.request.assert_not_called()

    def test_cli_fixed_arguments_bounded_stdout_stderr_discard_and_no_shell(self):
        process = Mock(pid=123)
        process.stdout = io.BytesIO(b'{"azure-cli":"2.80.0"}')
        process.wait.return_value = 0
        with patch.object(arm, 'resolve_cli', return_value=self.application()), \
             patch.object(arm.subprocess, 'Popen', return_value=process) as factory:
            self.assertEqual(arm.cached_cli(['version'], 2), {'azure-cli': '2.80.0'})
            self.assertFalse(factory.call_args.kwargs['shell'])
            self.assertEqual(factory.call_args.kwargs['stderr'], arm.subprocess.DEVNULL)
            self.assertNotIn('--debug', factory.call_args.args[0])
            self.assertEqual(factory.call_args.kwargs['env']['AZURE_LOGGING_ENABLE_LOG_FILE'], 'false')
        with patch.object(arm.subprocess, 'Popen') as factory:
            for args in (['login'], ['account', 'get-access-token', '--tenant', TENANT], ['rest', '--url', 'evil']):
                with self.assertRaises(arm.ArmRejected):
                    arm.cached_cli(args, 1)
            factory.assert_not_called()

    def test_cli_overflow_and_timeout_kill_tree_without_raw_error(self):
        for raw in (b'x'*65537, b'private-token-not-json'):
            process = Mock(pid=123)
            process.stdout = io.BytesIO(raw)
            process.wait.return_value = 0
            with patch.object(arm, 'resolve_cli', return_value=self.application()), \
                 patch.object(arm.subprocess, 'Popen', return_value=process), \
                 patch.object(arm.subprocess, 'run'), patch.object(arm.os, 'killpg', create=True), \
                 self.assertRaises(Exception) as caught:
                arm.cached_cli(['version'], 2)
            self.assertNotIn('private-token', str(caught.exception))
            process.kill.assert_called_once()
        process = Mock(pid=123, stdout=io.BytesIO(b'{}'))
        with patch.object(arm, 'resolve_cli', return_value=self.application()), \
             patch.object(arm.subprocess, 'Popen', return_value=process), \
             patch.object(arm.threading.Event, 'wait', return_value=False), \
             patch.object(arm.subprocess, 'run'), patch.object(arm.os, 'killpg', create=True), \
             self.assertRaises(arm.ArmRejected):
            arm.cached_cli(['version'], 2)
        process.kill.assert_called_once()

    def fake_application(self, directory, script):
        folder = Path(directory)
        program = folder / 'fixture.py'
        program.write_text(script, encoding='utf-8', newline='\n')
        path = folder / ('az.cmd' if os.name == 'nt' else 'az')
        if os.name == 'nt':
            path.write_text('@echo off\n"' + sys.executable + '" "' + str(program) + '" %*\n', encoding='utf-8')
        else:
            path.write_text('#!/bin/sh\nexec "' + sys.executable + '" "' + str(program) + '" "$@"\n', encoding='utf-8')
            path.chmod(0o700)
        return path

    def test_actual_owned_launcher_resolution_and_fixed_argv(self):
        with tempfile.TemporaryDirectory(prefix='santa-owned-cli-test-') as directory:
            path = self.fake_application(directory,
                'import sys,json\nprint(json.dumps({"arguments":sys.argv[1:],"synthetic":True}))\n')
            with patch.dict(os.environ, PATH=directory):
                application = arm.resolve_cli()
                self.assertEqual(application[0], path.resolve())
                result = arm.cached_cli(['version'], 5, application=application)
                self.assertEqual(result, {'arguments': ['version', '--only-show-errors', '--output', 'json'], 'synthetic': True})
                # A different launcher at the same path must not inherit the pin.
                path.write_text('changed', encoding='utf-8')
                with self.assertRaises(arm.ArmRejected):
                    arm.cached_cli(['version'], 1, application=application)

    def test_actual_owned_launcher_timeout_terminates_child_tree(self):
        with tempfile.TemporaryDirectory(prefix='santa-owned-cli-timeout-') as directory:
            pidfile = Path(directory) / 'child.pid'
            self.fake_application(directory, 'import pathlib,subprocess,sys,time\n'
                'child=subprocess.Popen([sys.executable,"-c","import time;time.sleep(60)"])\n'
                'pathlib.Path(__file__).with_name("child.pid").write_text(str(child.pid))\n'
                'time.sleep(60)\n')
            child = None
            try:
                with patch.dict(os.environ, PATH=directory), self.assertRaises(arm.ArmRejected):
                    arm.cached_cli(['version'], 2)
                self.assertTrue(pidfile.is_file(), 'fixture child must positively exist before timeout')
                child = int(pidfile.read_text())
                if os.name == 'nt':
                    import ctypes
                    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
                    kernel.OpenProcess.restype = ctypes.c_void_p
                    handle = kernel.OpenProcess(0x1000, False, child)
                    if handle:
                        try:
                            code = ctypes.c_ulong()
                            self.assertTrue(kernel.GetExitCodeProcess(ctypes.c_void_p(handle), ctypes.byref(code)))
                            self.assertNotEqual(code.value, 259, 'owned child must no longer be active')
                        finally:
                            kernel.CloseHandle(ctypes.c_void_p(handle))
                else:
                    # A reaped child is absent; an unreaped killed child can be
                    # a zombie until init reaps it, but cannot execute work.
                    proc = Path('/proc') / str(child) / 'stat'
                    self.assertTrue(not proc.exists() or proc.read_text().split()[2] == 'Z')
            finally:
                if child is not None:
                    if os.name == 'nt':
                        subprocess.run([str(Path(os.environ['SystemRoot'])/'System32/taskkill.exe'), '/PID', str(child), '/T', '/F'],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5, creationflags=subprocess.CREATE_NO_WINDOW)
                    else:
                        try:
                            os.kill(child, 9)
                        except ProcessLookupError:
                            pass

    def test_watchdog_interrupts_slow_header_wait_without_network(self):
        connection = self.connection()
        ended = threading.Event()
        clock = [100.0]
        timer = Mock()
        deadline = 100.05
        connection.sock.shutdown.side_effect = lambda _: ended.set()
        def register_timer(delay, interrupt):
            self.assertAlmostEqual(delay, deadline - clock[0])
            timer.fire = interrupt
            return timer
        def waiting_headers():
            # Positive phase proof: this case must exercise the armed watchdog,
            # not an earlier expiry during platform CA/context initialization.
            timer.start.assert_called_once_with()
            connection.request.assert_called_once()
            self.assertFalse(ended.is_set())
            clock[0] = deadline
            timer.fire()
            self.assertTrue(ended.is_set(), 'deadline callback must shut down the captured socket')
            raise OSError('private header failure')
        connection.getresponse.side_effect = waiting_headers
        with patch.object(arm.ssl, 'create_default_context', return_value=object()), \
             patch.object(arm.http.client, 'HTTPSConnection', return_value=connection), \
             patch.object(arm.time, 'monotonic', side_effect=lambda: clock[0]), \
             patch.object(arm.threading, 'Timer', side_effect=register_timer) as factory, \
             self.assertRaises(arm.ArmRejected):
            arm.https('GET', arm.RESOURCE+'exact', None, 'private', deadline)
        factory.assert_called_once()
        self.assertIs(timer.daemon, True)
        timer.cancel.assert_called_once_with()
        connection.getresponse.assert_called_once_with()
        connection.sock.shutdown.assert_called_once_with(arm.socket.SHUT_RDWR)
        connection.close.assert_called_once_with()

    def test_context_setup_expiring_deadline_rejects_before_request_or_watchdog(self):
        connection = self.connection()
        clock = [100.0]
        def slow_context():
            clock[0] = 101.0
            return object()
        with patch.object(arm.ssl, 'create_default_context', side_effect=slow_context), \
             patch.object(arm.http.client, 'HTTPSConnection', return_value=connection), \
             patch.object(arm.time, 'monotonic', side_effect=lambda: clock[0]), \
             patch.object(arm.threading, 'Timer') as factory, self.assertRaises(arm.ArmRejected):
            arm.https('GET', arm.RESOURCE+'exact', None, 'private', 100.05)
        connection.connect.assert_not_called()
        connection.request.assert_not_called()
        connection.getresponse.assert_not_called()
        connection.sock.shutdown.assert_not_called()
        factory.assert_not_called()
        connection.close.assert_called_once_with()


if __name__ == '__main__':
    unittest.main()
