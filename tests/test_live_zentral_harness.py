"""Offline mocks of the live harness; no upstream, Docker or network execution."""
import contextlib
import ast
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import zlib

PATH = Path(__file__).resolve().parents[1] / 'experiments/server/test_live_zentral.py'
sys.path.insert(0, str(PATH.parent))
SPEC = importlib.util.spec_from_file_location('live_zentral', PATH)
live = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(live)


class Response:
    status = 200

    def __init__(self, body):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def read(self, size):
        return self.body[:size]


class Harness(unittest.TestCase):
    def setUp(self):
        live.reset_http_transport()
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.compose = self.root / 'compose.json'
        services = {key: {'image': 'sha256:' + 'a' * 64} for key in (
            'db', 'redis', 'rabbitmq', 'elastic', 'web', 'workers', 'celery')}
        services['web']['ports'] = ['127.0.0.1:8000:8000']
        self.compose.write_text(json.dumps({'name': 'santa-zentral-eval-' + 'a' * 12, 'services': services}))
        self.compose_hash = hashlib.sha256(self.compose.read_bytes()).hexdigest()
        self.fixture_path = self.root / 'private.json'
        name = 'azd-synthetic-' + 'a' * 24
        self.fixture = dict(scope='synthetic-loopback-only', commit=live.COMMIT,
                            compose_sha256=self.compose_hash, name=name,
                            configuration_id=1, meta_business_unit_id=1,
                            identifiers=[hashlib.sha256((name + ':' + str(i)).encode()).hexdigest()
                                         for i in range(6)],
                            devices=[dict(uuid='00000000-0000-4000-8000-' + str(i + 1) * 12,
                                          serial=name + '-' + str(i), secret=str(i + 1) * 64,
                                          enrollment_id=i + 1, secret_id=i + 1) for i in range(2)])

    def write_fixture(self):
        self.fixture_path.write_text(json.dumps(self.fixture))
        self.fixture_path.chmod(0o600)

    def state(self, committed, counter=0, timestamp='2026-11-06 12:00:00'):
        machines = []
        for device in self.fixture['devices']:
            machine = None
            if committed:
                machine = dict(pk=device['enrollment_id'], preflight=timestamp,
                               postflight=timestamp, sync_session=None,
                               rules=[dict(target__identifier=value, policy=2, version=1,
                                           cursor=None, sync_session=None, staged_removal=False,
                                           committed_policy=None, committed_version=None)
                                      for value in sorted(self.fixture['identifiers'])])
            machines.append(dict(uuid=device['uuid'], request_count=int(committed), machine=machine))
        return dict(configuration_id=1, machines=machines, synthetic_blocked_count=counter)

    def fake_post(self, stage, device, body, credential=None):
        own = next(item for item in self.fixture['devices'] if item['uuid'] == device)
        if credential is None:
            return 401, None
        if credential != own['secret']:
            return 403, None
        if stage == 'preflight':
            return 200, dict(client_mode='MONITOR', sync_type='CLEAN', batch_size=5)
        if stage == 'ruledownload':
            rules = [dict(identifier=value, rule_type='BINARY', policy='BLOCKLIST')
                     for value in sorted(self.fixture['identifiers'])]
            return (200, dict(rules=rules[5:]) if body.get('cursor') else dict(rules=rules[:5], cursor='page2'))
        return 200, {}

    def test_compose_rejects_public_ports_extra_service_socket_and_mutable_web(self):
        original = json.loads(self.compose.read_text())
        for edit in (
                lambda data: data['services']['web'].update(ports=['8000:8000']),
                lambda data: data['services'].update(extra={}),
                lambda data: data['services']['web'].update(volumes=['/var/run/docker.sock:/var/run/docker.sock']),
                lambda data: data['services']['web'].update(privileged=True),
                lambda data: data.update(include=['/outside/compose.json']),
                lambda data: data['services']['web'].update(volumes=['/:/host']),
                lambda data: data['services']['web'].update(image='upstream:latest')):
            data = json.loads(json.dumps(original))
            edit(data)
            self.compose.write_text(json.dumps(data))
            with self.assertRaises(ValueError):
                live.validate_compose(self.compose)

    def test_fixture_refuses_real_identifiers_or_changed_compose(self):
        live.validate_fixture(self.fixture, self.compose_hash)
        self.fixture['devices'][0]['uuid'] = '3a229e76-0356-456f-868d-17ad8cd76c3b'
        with self.assertRaises(ValueError):
            live.validate_fixture(self.fixture, self.compose_hash)
        with self.assertRaises(ValueError):
            live.validate_fixture(self.fixture, 'changed')

    def test_security_redis_binding_rejects_durability_drift_external_or_shared_mount(self):
        from prepare_zentral_eval import REDIS_COMMAND
        data = json.loads(self.compose.read_text())
        data['volumes'] = {'redis_data': {}}
        data['services']['redis'].update(volumes=['redis_data:/data'], command=list(REDIS_COMMAND))
        self.compose.write_text(json.dumps(data))
        live.validate_compose(self.compose)
        for mutate in (
                lambda item: item['services']['redis']['command'].__setitem__(4, 'everysec'),
                lambda item: item['volumes'].__setitem__('redis_data', {'external': True}),
                lambda item: item['services']['web'].update(volumes=['redis_data:/data']),
                lambda item: item['services']['redis'].update(volumes=[])):
            bad = json.loads(json.dumps(data))
            mutate(bad)
            self.compose.write_text(json.dumps(bad))
            with self.assertRaises(ValueError):
                live.validate_compose(self.compose)

    def test_initialize_is_exclusive_and_never_prints_credentials(self):
        self.write_fixture()
        with patch.object(live, 'orm') as orm:
            with self.assertRaises(FileExistsError):
                live.initialize_fixture(self.compose, self.fixture_path, self.compose_hash)
            orm.assert_not_called()

    def test_orm_errors_do_not_echo_private_output(self):
        secret = 'private-do-not-print'
        with patch.object(live.subprocess, 'run', return_value=SimpleNamespace(
                returncode=1, stdout=secret, stderr=secret)), contextlib.redirect_stdout(io.StringIO()) as stdout:
            with self.assertRaises(ValueError) as error:
                live.orm(self.compose, 'private code')
        self.assertNotIn(secret, str(error.exception))
        self.assertEqual(stdout.getvalue(), '')
        audits = list(self.root.glob('private-orm-*.json'))
        self.assertEqual(len(audits), 1)
        self.assertEqual(json.loads(audits[0].read_text())['stdout'], secret)
        if os.name != 'nt':
            self.assertEqual(stat.S_IMODE(audits[0].stat().st_mode), 0o600)

    def test_initialization_uses_restricted_supported_fixture_and_private_file(self):
        def fake_orm(compose, code):
            data = json.loads(ast.literal_eval(ast.parse(code).body[0].value.args[0]))
            data.update(configuration_id=1, meta_business_unit_id=1)
            for i, device in enumerate(data['devices']):
                device.update(secret=str(i + 1) * 64, enrollment_id=i + 1, secret_id=i + 1)
            self.assertIn('client_mode=Configuration.MONITOR_MODE, batch_size=5', code)
            self.assertIn("udids=[device['uuid']], serial_numbers=[device['serial']], quota=1", code)
            return data
        with patch.object(live, 'orm', side_effect=fake_orm):
            fixture = live.initialize_fixture(self.compose, self.fixture_path, self.compose_hash)
        self.assertEqual(json.loads(self.fixture_path.read_text()), fixture)
        self.assertEqual(len(fixture['identifiers']), 6)
        if os.name != 'nt':
            self.assertEqual(stat.S_IMODE(self.fixture_path.stat().st_mode), 0o600)

    def test_orm_forces_local_daemon_and_exact_project_without_context_overrides(self):
        with patch.dict(os.environ, {'DOCKER_HOST': 'tcp://outside.invalid', 'COMPOSE_PROJECT_NAME': 'production'}):
            with patch.object(live.subprocess, 'run', return_value=SimpleNamespace(
                    returncode=0, stdout=live.MARKER + '{}', stderr='')) as command:
                self.assertEqual(live.orm(self.compose, 'print(1)'), {})
        args = command.call_args.args[0]
        self.assertEqual(args[:3], ['docker', '--host', 'unix:///var/run/docker.sock'])
        self.assertEqual(args[args.index('--project-name') + 1], 'santa-zentral-eval-' + 'a' * 12)
        self.assertNotIn('DOCKER_HOST', command.call_args.kwargs['env'])
        self.assertNotIn('COMPOSE_PROJECT_NAME', command.call_args.kwargs['env'])

    def test_http_is_fixed_loopback_zlib_no_proxy_and_no_redirect(self):
        opener = SimpleNamespace(open=lambda request, timeout: Response(b'{}'))
        with patch.object(live.urllib.request, 'build_opener', return_value=opener) as build:
            with patch.object(live.urllib.request, 'Request', wraps=live.urllib.request.Request) as request:
                self.assertEqual(live.post('preflight', self.fixture['devices'][0]['uuid'], {'x': 1}, 'abc'), (200, {}))
        args = request.call_args.args
        self.assertTrue(args[0].startswith('http://127.0.0.1:8000/public/santa/sync/preflight/'))
        self.assertEqual(json.loads(zlib.decompress(args[1])), {'x': 1})
        handlers = build.call_args.args
        self.assertEqual(handlers[0].proxies, {})
        self.assertIsInstance(handlers[1], live.NoRedirect)
        self.assertIsNone(live.NoRedirect().redirect_request(None, None, 302, '', {}, 'https://outside.invalid'))
        with self.assertRaises(ValueError):
            live.post('https://outside.invalid', self.fixture['devices'][0]['uuid'], {})

    def test_http_response_is_bounded(self):
        with patch.object(live.urllib.request, 'build_opener', return_value=SimpleNamespace(
                open=lambda request, timeout: Response(b'x' * 65537))):
            with self.assertRaises(ValueError):
                live.post('preflight', self.fixture['devices'][0]['uuid'], {})
        for payload in (b'null',b'[]',b'true'):
            with patch.object(live.urllib.request,'build_opener',return_value=SimpleNamespace(
                    open=lambda request,timeout:Response(payload))):
                with self.assertRaises(ValueError):live.post('preflight',self.fixture['devices'][0]['uuid'],{})

    def rate_response(self, status, values=None, body=b'{}'):
        result = Response(body); result.status = status
        result.headers = SimpleNamespace(get_all=lambda name: values)
        return result

    def test_429_waits_are_separate_and_retry_exact_request_until_real_denial(self):
        opener = SimpleNamespace(open=Mock(side_effect=[self.rate_response(429,['2']),self.rate_response(403)]))
        clock=[0.0]
        def sleep(seconds):clock[0]+=seconds
        with patch.object(live.urllib.request,'build_opener',return_value=opener), \
             patch.object(live.time,'monotonic',side_effect=lambda:clock[0]),patch.object(live.time,'sleep',side_effect=sleep):
            self.assertEqual(live.post('eventupload',self.fixture['devices'][0]['uuid'],{'events':[]},'invalid'),(403,None))
        requests=[call.args[0] for call in opener.open.call_args_list]
        self.assertIs(requests[0],requests[1])
        self.assertEqual(json.loads(zlib.decompress(requests[1].data)),{'events':[]})
        receipt=live.http_transport().receipt()
        self.assertEqual((receipt['http_attempts'],receipt['semantic_requests'],receipt['completed_requests']),(2,1,1))
        self.assertEqual(receipt['rate_limit_waits'],[dict(request=1,attempt=1,status=429,
            retry_after_seconds=2,wait_completed=True,wait_seconds=2.0)])
        self.assertNotIn('invalid',json.dumps(receipt))

    def test_429_invalid_missing_duplicate_or_oversized_retry_after_never_sleeps(self):
        for values in (None,[],['1','2'],['0'],['01'],['61'],['999999'],['1.5'],['-1'],['Thu, 1 Jan'],[' 1']):
            with self.subTest(values=values):
                live.reset_http_transport()
                opener=Mock();opener.open.return_value=self.rate_response(429,values)
                with patch.object(live.urllib.request,'build_opener',return_value=opener),patch.object(live.time,'sleep') as sleep:
                    with self.assertRaises(ValueError):live.post('preflight',self.fixture['devices'][0]['uuid'],{})
                    sleep.assert_not_called();self.assertEqual(opener.open.call_count,1)

    def test_real_urllib_http_error_429_path_is_closed_then_reaches_final_401(self):
        body=io.BytesIO(b'limited')
        error=live.urllib.error.HTTPError(live.BASE_URL,429,'limited',
            SimpleNamespace(get_all=lambda key:['1']),body)
        opener=Mock();opener.open.side_effect=[error,self.rate_response(401)]
        with patch.object(live.urllib.request,'build_opener',return_value=opener), \
             patch.object(live.time,'sleep') as sleep:
            self.assertEqual(live.post('preflight',self.fixture['devices'][0]['uuid'],{}),(401,None))
        self.assertTrue(body.closed);sleep.assert_called_once_with(1)
        self.assertEqual(opener.open.call_count,2)

    def test_429_attempt_deadline_and_aggregate_wait_limits_fail_without_semantic_result(self):
        clock=[0.0]
        opener=Mock();opener.open.side_effect=lambda *a,**kw:self.rate_response(429,['1'])
        with patch.object(live.urllib.request,'build_opener',return_value=opener), \
             patch.object(live.time,'monotonic',side_effect=lambda:clock[0]), \
             patch.object(live.time,'sleep',side_effect=lambda delay:clock.__setitem__(0,clock[0]+delay)):
            with self.assertRaises(ValueError):live.post('preflight',self.fixture['devices'][0]['uuid'],{})
        self.assertEqual(opener.open.call_count,4)
        self.assertEqual(live.http_transport().receipt()['completed_requests'],0)
        self.assertEqual(sum(row['wait_completed'] for row in live.http_transport().waits),3)
        for state in ('deadline','waits','attempts'):
            live.reset_http_transport();transport=live.http_transport()
            if state=='deadline':transport.started=-1199
            if state=='waits':transport.waits=[dict(retry_after_seconds=600)]
            if state=='attempts':transport.attempts=512
            opener=Mock();opener.open.return_value=self.rate_response(429,['2'])
            with self.subTest(state=state),patch.object(live.urllib.request,'build_opener',return_value=opener), \
                 patch.object(live.time,'monotonic',return_value=0),patch.object(live.time,'sleep') as sleep:
                with self.assertRaises(ValueError):live.post('preflight',self.fixture['devices'][0]['uuid'],{})
                sleep.assert_not_called()

    def test_ambiguous_transport_failure_and_other_statuses_never_replay(self):
        for outcome in (live.urllib.error.URLError('unknown mutation'),self.rate_response(503)):
            live.reset_http_transport();opener=Mock()
            opener.open.side_effect=outcome if isinstance(outcome,Exception) else None
            opener.open.return_value=outcome
            with patch.object(live.urllib.request,'build_opener',return_value=opener),patch.object(live.time,'sleep') as sleep:
                if isinstance(outcome,Exception):
                    with self.assertRaises(live.urllib.error.URLError):live.post('postflight',self.fixture['devices'][0]['uuid'],{})
                else:self.assertEqual(live.post('postflight',self.fixture['devices'][0]['uuid'],{}),(503,None))
                self.assertEqual(opener.open.call_count,1);sleep.assert_not_called()

    def test_transport_refuses_external_legacy_prefix_or_method_before_network(self):
        for url,method in [('https://outside.invalid', 'POST'),(live.BASE_URL+'invalid/preflight/'+self.fixture['devices'][0]['uuid'],'POST'),
                           (live.BASE_URL+'preflight/'+self.fixture['devices'][0]['uuid'],'GET')]:
            with self.subTest(url=url,method=method),patch.object(live.urllib.request,'build_opener') as opener:
                with self.assertRaises(ValueError):live.http_send(live.urllib.request.Request(url,method=method))
                opener.assert_not_called()

    def test_reopen_checks_database_before_any_http_and_does_not_reset(self):
        self.write_fixture()
        with patch.object(live, 'snapshot', return_value=self.state(False)), patch.object(live, 'post') as post:
            with self.assertRaises(ValueError):
                live.run(self.compose, self.fixture_path)
            post.assert_not_called()
        self.assertEqual(json.loads(self.fixture_path.read_text()), self.fixture)

    def test_complete_reopen_receipt_contains_db_evidence_not_credentials(self):
        self.write_fixture()
        with patch.object(live, 'snapshot', side_effect=[self.state(True, 2), self.state(True, 4, '2026-11-06 12:01:00')]), patch.object(live, 'post', side_effect=self.fake_post) as post:
            receipt_path = live.run(self.compose, self.fixture_path)
        receipt = json.loads(receipt_path.read_text())
        self.assertTrue(receipt['reopened'])
        self.assertEqual(receipt['after']['synthetic_blocked_count'], 4)
        self.assertIn('not verified', receipt['event_store_indexing'])
        self.assertEqual(sum(call.args[0] == 'ruledownload' for call in post.call_args_list), 6)
        self.assertEqual(sum(call.args[0] == 'eventupload' for call in post.call_args_list), 6)
        for device in self.fixture['devices']:
            self.assertNotIn(device['secret'], receipt_path.read_text())
        if os.name != 'nt':
            self.assertEqual(stat.S_IMODE(receipt_path.stat().st_mode), 0o600)

    def test_tampered_rules_or_missing_postflight_never_pass(self):
        state = self.state(True)
        state['machines'][0]['machine']['rules'][0]['policy'] = 1
        with self.assertRaises(ValueError):
            live.assert_committed(state, self.fixture)
        state = self.state(True)
        state['machines'][1]['machine']['postflight'] = None
        with self.assertRaises(ValueError):
            live.assert_committed(state, self.fixture)


if __name__ == '__main__':
    unittest.main()
