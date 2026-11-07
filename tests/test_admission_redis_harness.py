"""Offline adapter/target guards; these do not execute Redis or Docker."""
import ast
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / 'experiments/server/test_admission_redis_live.py'
spec = importlib.util.spec_from_file_location('admission_redis_harness', PATH)
live = importlib.util.module_from_spec(spec); spec.loader.exec_module(live)


class Guards(unittest.TestCase):
    def test_redis_json_success_and_error_are_distinct(self):
        for raw, expected in [('[1,"0"]', [1, '0']), ('1', 1), ('"PONG"', 'PONG'), ('null', None)]:
            self.assertEqual(live.parse_reply(subprocess.CompletedProcess([], 0, raw, '')), expected)
        with self.assertRaises(live.RedisError):
            live.parse_reply(subprocess.CompletedProcess([], 0, 'error:"ERR rejected"', ''))
        for result in [subprocess.CompletedProcess([], 1, '1', ''),
                       subprocess.CompletedProcess([], 0, '1', 'unexpected'),
                       subprocess.CompletedProcess([], 0, 'x' * 65537, '')]:
            with self.assertRaises(ValueError): live.parse_reply(result)

    def valid(self):
        return dict(id='a' * 64, image='sha256:' + 'b' * 64, running=True,
                    network='none', mounts=[dict(Type='tmpfs', Destination='/data')],
                    ports={}, labels={'io.azd-santa.qualification': live.LABEL})

    def test_exact_disposable_target_required_before_commands(self):
        target = live.Target('a' * 64, 'sha256:' + 'b' * 64)
        value = self.valid()
        def inspect(value):
            with patch.object(live.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, json.dumps(value), '')):
                return target.inspect()
        self.assertEqual(inspect(value), value)
        for key, bad in [('id', 'c' * 64), ('image', 'sha256:' + 'c' * 64), ('running', False),
                         ('network', 'bridge'), ('ports', {'6379/tcp': [{}]}), ('labels', {}),
                         ('mounts', [dict(Type='volume', Destination='/data')]),
                         ('mounts', [dict(Type='bind', Destination='/data')]),
                         ('mounts', [dict(Type='tmpfs', Destination='/foreign')])]:
            with self.subTest(key=key, bad=bad):
                with self.assertRaises(ValueError): inspect(dict(value, **{key: bad}))

    def test_command_uses_exact_id_no_host_network_or_lifecycle(self):
        target = live.Target('a' * 64, 'sha256:' + 'b' * 64)
        with patch.object(live.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, '1', '')) as run:
            self.assertEqual(target.eval('return 1', 0), 1)
        self.assertEqual(run.call_args.args[0], ['docker', '--host', 'unix:///var/run/docker.sock',
            'exec', 'a' * 64, 'redis-cli', '--json', 'EVAL', 'return 1', '0'])
        self.assertEqual(run.call_args.kwargs['timeout'], 15)
        source = PATH.read_text()
        self.assertNotIn("command('FLUSH", source)
        self.assertNotIn("['run'", source)
        self.assertNotIn("['stop'", source)

    def test_pins_match_current_product_bytes_and_guard_is_literal(self):
        import hashlib
        for name, digest in live.PINS.items():
            self.assertEqual(hashlib.sha256((PATH.parent / name).read_bytes()).hexdigest(), digest)
        tree = ast.parse((PATH.parent / 'operator_mfa.py').read_text())
        guard = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)
                     and isinstance(n.targets[0], ast.Name) and n.targets[0].id == 'STORE_GUARD')
        self.assertIn("redis.call('TIME')", guard)
        self.assertIn('SECURITY_STORE_UNAVAILABLE', guard)

    def test_every_case_has_unique_prefix_and_production_fresh_initializer(self):
        source = PATH.read_text()
        self.assertIn("self.prefix = 'qualification:' + secrets.token_hex(16)", source)
        self.assertIn('module.initialize_fresh(self, target', source)
        self.assertIn("self.constants['STORE_GUARD'] + script", source)
        for script in ('ACQUIRE', 'RELEASE', 'CHECK', 'EMPTY', 'RECONCILE'):
            self.assertIn('module.' + script, source)


if __name__ == '__main__': unittest.main()
