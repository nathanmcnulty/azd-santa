"""Offline producer fail-closed/read-only scope; no Docker/Azure proof."""
import copy
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('installation_readback', ROOT / 'experiments/server/installation_readback.py')
producer = importlib.util.module_from_spec(spec); spec.loader.exec_module(producer)
spec = importlib.util.spec_from_file_location('host_guard', ROOT / 'experiments/server/operator_setup_host.py')
host_guard = importlib.util.module_from_spec(spec); spec.loader.exec_module(host_guard)


def fixture():
    sub = '11111111-1111-4111-8111-111111111111'
    binding = dict(TenantId='22222222-2222-4222-8222-222222222222', SubscriptionId=sub, EnvironmentName='synthetic',
        ResourceGroup='rg-azd-santa-vm-synthetic', VmName='vm-santa-lab', VmId='/selected/validated/by/host',
        VmInstanceId='33333333-3333-4333-8333-333333333333', ImageId='sha256:' + 'a' * 64,
        ComposePath='/var/lib/azd-santa-qualification/synthetic/compose.json', ComposeSha256='b' * 64,
        Origin='https://santa.example.invalid', SourceCommit='c' * 40, RecoverySha256='d' * 64,
        SealedSha256='e' * 64, RemoteProgramSha256='f' * 64)
    request = dict(context={'binding': binding}, context_sha256='1' * 64)
    services = {name: str(index + 1) * 64 for index, name in enumerate(('web', 'workers', 'celery', 'db', 'redis', 'rabbitmq', 'elastic'))}
    projection = dict(queue='store_events_Elasticsearch', migrations=True, store=True, search=True)
    queues = [dict(name=name, consumers=1) for name in ('store_events_Elasticsearch', 'enrich_events', 'process_events')]
    calls = []
    def docker(args, **kwargs):
        calls.append(args)
        if args[1] == services['web']:
            compile(args[-1], 'original-readonly-initialization-probe', 'exec')
            return b'SANTA_INSTALL_READY:' + host_guard.encoded(projection) + b'\n'
        if args[1] == services['rabbitmq']:
            return host_guard.encoded(queues)
        raise AssertionError('Unselected container ID')
    host = SimpleNamespace(need=host_guard.need, HEX=host_guard.HEX, encoded=host_guard.encoded, loads=host_guard.loads,
        request_from_environment=Mock(return_value=(request, b'unused')), attest_metadata=Mock(),
        attest_runtime=Mock(return_value=services), docker=Mock(side_effect=docker))
    return host, request, projection, queues, calls


class Producer(unittest.TestCase):
    def run_producer(self, host):
        with patch.object(producer.os, 'geteuid', return_value=0, create=True), \
             patch.object(producer.signal, 'signal'), patch.object(producer.signal, 'SIGALRM', 14, create=True), \
             patch.object(producer.signal, 'alarm', create=True):
            return producer.produce_installation(host,
                '/subscriptions/11111111-1111-4111-8111-111111111111/providers/Microsoft.Resources/deployments/azd-synthetic',
                'a' * 64, 'b' * 64)

    def test_produces_only_attested_exact_outputs_after_all_initialized_gates(self):
        host, request, _, _, calls = fixture()
        with patch('sys.stdout', new_callable=io.StringIO) as output:
            result = self.run_producer(host)
        self.assertTrue(output.getvalue().startswith(producer.MARKER))
        self.assertLessEqual(len(output.getvalue().encode()), 3200 + len(producer.MARKER) + 1)
        self.assertEqual(set(result['installation']['outputs']), set(host_guard.BINDINGS) - {'SourceCommit', 'RecoverySha256', 'SealedSha256', 'RemoteProgramSha256'})
        self.assertEqual(result['context_sha256'], request['context_sha256'])
        self.assertEqual(result['readiness'], {key: True for key in producer.READY})
        self.assertEqual(len(calls), 2)
        self.assertTrue(all(args[0] == 'exec' for args in calls))
        self.assertNotIn('operator_access', repr(calls))
        self.assertNotIn('security_store fresh', repr(calls))
        host.attest_metadata.assert_called_once_with(request['context']['binding'])
        host.attest_runtime.assert_called_once_with(request)

    def test_uninitialized_migrations_store_search_or_security_cannot_emit_ready_receipt(self):
        for failure in ('migrations', 'store', 'search', 'security'):
            host, _, projection, _, _ = fixture()
            if failure == 'security':
                host.attest_runtime.side_effect = ValueError('not admitted')
            else:
                projection[failure] = False
            with patch('sys.stdout', new_callable=io.StringIO) as output, self.assertRaises(ValueError):
                self.run_producer(host)
            self.assertEqual(output.getvalue(), '')

    def test_event_consumer_zero_missing_wrong_type_and_duplicate_fail_closed(self):
        for case in ('zero', 'missing', 'type', 'duplicate'):
            host, _, _, queues, _ = fixture()
            if case == 'zero': queues[0]['consumers'] = 0
            if case == 'missing': queues.pop()
            if case == 'type': queues[0]['consumers'] = True
            if case == 'duplicate': queues.append(copy.deepcopy(queues[0]))
            with patch('sys.stdout', new_callable=io.StringIO) as output, self.assertRaises(ValueError):
                self.run_producer(host)
            self.assertEqual(output.getvalue(), '')

    def test_wrong_observed_service_id_rejects_before_readiness_exec(self):
        host, _, _, _, _ = fixture(); host.attest_runtime.return_value['rabbitmq'] = 'rabbitmq'
        with self.assertRaises(ValueError): self.run_producer(host)
        host.docker.assert_not_called()

    def test_probe_does_not_provision_or_initialize_store_backend(self):
        compile(producer.PROBE, 'readonly-installation-probe', 'exec')
        self.assertIn('migration_plan(', producer.PROBE)
        self.assertNotIn('.migrate(', producer.PROBE)
        self.assertNotIn('.save(', producer.PROBE)
        self.assertNotIn('.get_backend(', producer.PROBE)  # Loading that backend can create ES indexes.
        self.assertNotIn('call_command(', producer.PROBE)
        self.assertIn('ProxyHandler({})', producer.PROBE)


if __name__ == '__main__':
    unittest.main()
