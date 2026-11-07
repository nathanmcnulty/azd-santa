"""Offline policy/configuration boundaries; Lua/Redis crash proof is separate."""
import ast
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'experiments/server'))
import test_security_store_live as gate
POLICY = ROOT / 'experiments/server/operator_mfa.py'


def policy_helpers():
    # Extract original dependency-free helpers without importing Django/models.
    # This verifies the actual functions, not a separately implemented cache.
    names = {'STORE_MARKER', 'STORE_SETTINGS', 'STORE_GUARD', 'CHALLENGE_SECONDS',
             '_security_client', '_store_operation', 'check_security_store', '_cache_add', '_budget'}
    names.add('initialize_security_store')
    tree = ast.parse(POLICY.read_text())
    nodes = [node for node in tree.body if
             (isinstance(node, ast.FunctionDef) and node.name in names) or
             (isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id in names for target in node.targets))]
    namespace = {'ImproperlyConfigured': ValueError}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(POLICY), 'exec'), namespace)
    client = Mock()
    client.config_get.return_value = dict(namespace['STORE_SETTINGS'])
    client.info.return_value = {'aof_last_write_status': 'ok'}
    client.eval.return_value = 1
    cache = SimpleNamespace(client=SimpleNamespace(get_client=lambda **kwargs: client),
                            make_key=lambda key: 'private-prefix:1:' + key)
    namespace['caches'] = {'azd_santa_security': cache}
    namespace['_expected_store_id'] = lambda: 'a' * 64
    namespace['_fresh_authority_empty'] = lambda: True
    return namespace, client


class SecurityStore(unittest.TestCase):
    def test_refuses_each_unsafe_persistence_configuration_before_mutation(self):
        for name in ('appendonly', 'appendfsync', 'aof-load-truncated',
                     'maxmemory-policy', 'no-appendfsync-on-rewrite'):
            namespace, client = policy_helpers()
            config = dict(namespace['STORE_SETTINGS'])
            config[name] = 'unsafe'
            client.config_get.return_value = config
            with self.assertRaises(ValueError):
                namespace['_cache_add']('claim', True, 360)
            client.eval.assert_not_called()
        namespace, client = policy_helpers()
        client.info.return_value = {'aof_last_write_status': 'err'}
        with self.assertRaises(ValueError):
            namespace['_budget']('user-budget', 5)
        client.eval.assert_not_called()

    def test_transport_and_marker_errors_propagate_without_fallback_write(self):
        for operation in ('config_get', 'info', 'eval'):
            namespace, client = policy_helpers()
            getattr(client, operation).side_effect = RuntimeError('unavailable')
            with self.assertRaises(RuntimeError):
                namespace['_cache_add']('claim', True, 360)
            self.assertLessEqual(client.eval.call_count, 1)
            self.assertFalse(client.set.called)
            self.assertFalse(client.incr.called)

    def test_claim_is_one_marker_guarded_operation_with_namespaced_keys(self):
        namespace, client = policy_helpers()
        self.assertTrue(namespace['_cache_add']('claim', True, 360))
        script, count, marker, key, store_id, ttl = client.eval.call_args.args
        self.assertTrue(script.startswith(namespace['STORE_GUARD']))
        self.assertIn("redis.call('SET', KEYS[2], '1', 'NX', 'EX', ARGV[2])", script)
        self.assertEqual((count, marker, key, store_id, ttl),
                         (2, 'private-prefix:1:security-store-instance-v1', 'private-prefix:1:claim', 'a' * 64, 360))
        client.eval.return_value = 0
        self.assertFalse(namespace['_cache_add']('claim', True, 360))

    def test_budget_has_no_separate_get_increment_race_and_preserves_rejection(self):
        namespace, client = policy_helpers()
        for value, accepted in ((1, True), (5, True), (6, False)):
            client.eval.return_value = value
            self.assertEqual(namespace['_budget']('budget', 5), accepted)
            script, count, marker, key, store_id, ttl, maximum = client.eval.call_args.args
            self.assertTrue(script.startswith(namespace['STORE_GUARD']))
            self.assertEqual((count, ttl, maximum), (2, 300, 5))
        client.get.assert_not_called()
        client.incr.assert_not_called()

    def test_readiness_never_initializes_a_marker(self):
        namespace, client = policy_helpers()
        namespace['check_security_store']()
        script, count, marker, store_id = client.eval.call_args.args
        self.assertEqual(count, 1)
        self.assertEqual(script, namespace['STORE_GUARD'] + 'return 1')
        self.assertNotIn("redis.call('SET'", script)

    def test_expected_identity_is_private_and_missing_identity_prevents_startup(self):
        tree = ast.parse(POLICY.read_text())
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'install_policy')
        namespace = {'os': SimpleNamespace(environ={}), 're': __import__('re'), 'ImproperlyConfigured': ValueError}
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(POLICY), 'exec'), namespace)
        with self.assertRaisesRegex(ValueError, 'private security-store identity'):
            namespace['install_policy']({})
        namespace['os'].environ = {'AZD_SANTA_SECURITY_STORE_ID': 'a' * 64}
        config = {'CACHES': {'default': {'LOCATION': 'redis://redis:6379/1'}},
                  'MIDDLEWARE': ['realms.middlewares.realm_session_middleware']}
        namespace['install_policy'](config)
        self.assertEqual(config['AZD_SANTA_SECURITY_STORE_ID'], 'a' * 64)
        self.assertFalse(config['CACHES']['azd_santa_security']['OPTIONS']['IGNORE_EXCEPTIONS'])

    def test_fresh_initialization_rejects_existing_authority_before_redis_write(self):
        namespace, client = policy_helpers()
        namespace['_fresh_authority_empty'] = lambda: False
        with self.assertRaisesRegex(ValueError, 'new database'):
            namespace['initialize_security_store']('fresh')
        client.eval.assert_not_called()

    def test_explicit_migration_holds_admission_and_never_overwrites_marker(self):
        namespace, client = policy_helpers()
        for mode in ('migrate', 'unknown'):
            with self.assertRaises(ValueError):
                namespace['initialize_security_store'](mode)
        client.eval.assert_not_called()
        namespace['initialize_security_store']('fresh')
        self.assertEqual(client.eval.call_args.args[-1], 0)
        namespace['initialize_security_store']('migrate', confirm_quiesced=True)
        self.assertEqual(client.eval.call_args.args[-1], 360)
        self.assertIn("redis.call('EXISTS', KEYS[1])", client.eval.call_args.args[0])
        client.eval.return_value = 0
        with self.assertRaisesRegex(ValueError, 'already exists'):
            namespace['initialize_security_store']('migrate', confirm_quiesced=True)
        client.set.assert_not_called()


class LiveGate(unittest.TestCase):
    def test_redis_interruption_requires_explicit_flag_before_any_external_call(self):
        with patch.object(gate.subprocess, 'run') as external:
            with self.assertRaisesRegex(ValueError, 'interruption authorization'):
                gate.run('not-real.json', 'not-real-output', 'a' * 64)
            external.assert_not_called()

    def test_wrong_container_binding_rejects_before_synthetic_claim_or_kill(self):
        import json
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            compose = root / 'compose.json'
            project = 'santa-zentral-eval-' + 'a' * 12
            calls = []
            def external(command, **kwargs):
                calls.append(command)
                if 'inspect' in command:
                    value = json.dumps([{'Config': {'Labels': {'com.docker.compose.project': project,
                        'com.docker.compose.service': 'redis'}}, 'Mounts': [{'Destination': '/data',
                        'Type': 'volume', 'Name': 'unrelated-volume'}]}])
                else:
                    value = 'b' * 64
                return SimpleNamespace(returncode=0, stdout=value, stderr='')
            with patch.object(gate, 'validate_durable_compose', return_value=(compose, 'c' * 64, project)), \
                 patch.object(gate.subprocess, 'run', side_effect=external), patch.object(gate, 'policy_probe') as probe:
                with self.assertRaisesRegex(ValueError, 'binding mismatch'):
                    gate.run(compose, root / 'output', 'a' * 64, allow_redis_restart=True)
                probe.assert_not_called()
            self.assertFalse(any('kill' in command or '--force-recreate' in command for command in calls))
            self.assertTrue(all(command[:3] == ['docker', '--host', 'unix:///var/run/docker.sock'] for command in calls))


if __name__ == '__main__':
    unittest.main()
