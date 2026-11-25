"""Offline replay-causality and driver scope guards, not live MFA acceptance."""
import ast
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'experiments/server'))
import run_mfa_restart as driver


def proof_helpers():
    source = ROOT / 'experiments/server/test_mfa_restart_live.py'
    tree = ast.parse(source.read_text())
    names = {'need', 'assert_replay_evidence'}
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    namespace = {}
    exec(compile(ast.Module(body=functions, type_ignores=[]), str(source), 'exec'), namespace)
    return namespace


class Causality(unittest.TestCase):
    def test_requires_actual_false_claim_results_and_exhausted_real_budget(self):
        check = proof_helpers()['assert_replay_evidence']
        valid = {'webauthn-replay': [('challenge', False)],
                 'totp-replay': [('challenge', True), ('totp', False)], 'budget-after': False}
        check(valid, (403, False), (403, False), 429, [1, 2], [1, 2])
        for key, value in (
                ('webauthn-replay', [('challenge', 'error')]),
                ('webauthn-replay', []), ('webauthn-replay', [('challenge', True)]),
                ('totp-replay', [('challenge', False)]), ('totp-replay', []),
                ('totp-replay', [('challenge', True), ('totp', 'error')]),
                ('budget-after', True), ('budget-after', 'error')):
            bad = copy.deepcopy(valid); bad[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(RuntimeError):
                check(bad, (403, False), (403, False), 429, [1, 2], [1, 2])
        for web, totp, status, successes in (
                ((302, False), (403, False), 429, [1, 2]),  # expired/missing challenge
                ((403, False), (200, False), 429, [1, 2]),  # expired/invalid TOTP
                ((403, False), (403, False), 503, [1, 2]),  # unavailable store
                ((403, False), (403, False), 429, [1, 2, 1]),
                ((403, True), (403, False), 429, [1, 2])):
            with self.assertRaises(RuntimeError):
                check(valid, web, totp, status, successes, [1, 2])

    def test_verifiers_authentication_and_clock_are_not_mocked(self):
        tree = ast.parse((ROOT / 'experiments/server/test_mfa_restart_live.py').read_text())
        patched = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr == 'force_login':
                    self.fail('Positive requests cannot use force_login')
                if node.func.attr == 'object' and isinstance(node.func.value, ast.Name) and node.func.value.id == 'patch':
                    patched.append(ast.literal_eval(node.args[1]))
        self.assertEqual(set(patched), {'_challenge', '_cache_add', '_budget', 'post'})
        # These wrappers call originals and observe real results; cryptographic
        # verifier/time patching is forbidden in this actual-request harness.
        text = ast.unparse(tree)
        self.assertIn('result = original_add(key, value, seconds)', text)
        self.assertIn('pyotp.TOTP(seed).verify(code)', text)


class DriverGuards(unittest.TestCase):
    def test_redis_restart_mutates_only_original_id_and_stale_id_never_retargets(self):
        docker = ['docker', '--host', 'unix:///var/run/docker.sock']
        original, replacement = 'a' * 64, 'b' * 64
        calls = []
        driver.restart_bound_redis(lambda label, args: calls.append(args), docker, original)
        self.assertEqual(calls, [docker + ['kill', '--signal', 'KILL', original],
                                 docker + ['start', original]])
        calls.clear()
        def vanished(label, args):
            calls.append(args)
            raise ValueError('Selected Redis ID no longer exists')
        with self.assertRaisesRegex(ValueError, 'no longer exists'):
            driver.restart_bound_redis(vanished, docker, original)
        self.assertEqual(calls, [docker + ['kill', '--signal', 'KILL', original]])
        self.assertFalse(any(replacement in command or 'compose' in command for command in calls))
        calls.clear()
        with self.assertRaisesRegex(ValueError, 'full Redis container ID'):
            driver.restart_bound_redis(lambda label, args: calls.append(args), docker, 'redis')
        self.assertEqual(calls, [])

    def test_generated_ipc_programs_compile_without_executing_them(self):
        tree = ast.parse((ROOT / 'experiments/server/run_mfa_restart.py').read_text())
        run = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'run')
        functions = [node for node in run.body if isinstance(node, ast.FunctionDef) and node.name in ('read_phase', 'release')]
        captured = []
        def capture(label, args, **kwargs):
            captured.append(args)
            return SimpleNamespace(returncode=2, stdout='')
        namespace = {'namespace': 'azd-mfa-restart-' + 'a' * 24, 'command': ['docker'],
                     'context': {'scope': driver.SCOPE}, 'json': json,
                     'execute': capture, 'require': driver.require, 'parse_phase': driver.parse_phase}
        exec(compile(ast.Module(body=functions, type_ignores=[]), 'actual-ipc-builders', 'exec'), namespace)
        self.assertIsNone(namespace['read_phase']('ready.json'))
        namespace['release']()
        for command in captured:
            self.assertEqual(command[-2], '-c')
            compile(command[-1], 'generated-ipc-program', 'exec')
        self.assertIn('os.link(tmp,p)', captured[-1][-1])
        with self.assertRaises(ValueError):
            namespace['read_phase']('../../unexpected')

    def test_explicit_restart_flag_and_exact_hashes_precede_external_operations(self):
        with patch.object(driver.subprocess, 'run') as external:
            with self.assertRaisesRegex(ValueError, 'interruption authorization'):
                driver.run('unused', 'unused', 'unused', 'sha256:' + 'a' * 64, 'b' * 64, 'c' * 64)
            external.assert_not_called()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'harness.py'; path.write_text('pass\n')
            with patch.object(driver.subprocess, 'run') as external:
                with self.assertRaisesRegex(ValueError, 'source differs'):
                    driver.run('unused', path, Path(directory) / 'output', 'sha256:' + 'a' * 64,
                               'b' * 64, 'c' * 64, allow_redis_restart=True)
                external.assert_not_called()

    def test_custom_volume_alias_is_rejected_before_docker_or_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            harness = root / 'harness.py'; harness.write_text('pass\n')
            compose = root / 'compose.json'
            data = {'services': {}, 'volumes': {name: {} for name in (
                'postgres_data', 'redis_data', 'rabbitmq_data', 'elasticsearch_data', 'media_data')}}
            data['volumes']['media_data'] = {'driver_opts': {'device': '/', 'type': 'none', 'o': 'bind'}}
            compose.write_text(json.dumps(data))
            with patch.object(driver, 'validate_durable_compose', return_value=(compose, 'a' * 64, 'project')), \
                 patch.object(driver.subprocess, 'run') as external:
                with self.assertRaisesRegex(ValueError, 'project-local'):
                    driver.run(compose, harness, root / 'output', 'sha256:' + 'a' * 64, 'b' * 64,
                               hashlib.sha256(harness.read_bytes()).hexdigest(), allow_redis_restart=True)
                external.assert_not_called()
            self.assertFalse((root / 'output').exists())

    def test_actual_image_network_and_volume_scope_are_required(self):
        project = 'santa-zentral-eval-' + 'a' * 12
        image = 'sha256:' + 'b' * 64
        valid = {'Config': {'Labels': {'com.docker.compose.project': project, 'com.docker.compose.service': 'web'}},
                 'Image': image, 'State': {'Running': True},
                 'Mounts': [{'Destination': '/var/zentral', 'Type': 'volume', 'Name': project + '_media_data'}],
                 'NetworkSettings': {'Networks': {project + '_default': {}}}}
        driver.container_binding(valid, project, 'web', image, media=True)
        for change in (
                lambda item: item.update(Image='sha256:' + 'c' * 64),
                lambda item: item['State'].update(Running=False),
                lambda item: item['Mounts'][0].update(Name='unrelated_data'),
                lambda item: item['NetworkSettings'].update(Networks={'unrelated_default': {}}),
                lambda item: item['Mounts'].append({'Destination': '/var/run/docker.sock'})):
            bad = copy.deepcopy(valid); change(bad)
            with self.assertRaises(ValueError):
                driver.container_binding(bad, project, 'web', image, media=True)

    def test_ipc_cannot_export_secret_fields_or_claim_partial_success(self):
        context = dict(scope=driver.SCOPE, namespace='azd-mfa-restart-' + 'a' * 24,
                       compose_sha256='b' * 64, policy_sha256='c' * 64, harness_sha256='d' * 64,
                       image_id='sha256:' + 'e' * 64, redis_run_id_sha256='f' * 64)
        result = dict(context, phase='passed', webauthn_nonce_rejected=True, totp_step_rejected=True,
                      budget_exhausted=True, accepted_logins=2, marker_settings_ready=True,
                      redis_restarted=True, limitation=driver.LIMITATION)
        driver.phase_record(result, context, 'passed')
        for change in ({'setup_url': 'secret'}, {'accepted_logins': 3}, {'budget_exhausted': False},
                       {'policy_sha256': 'a' * 64}, {'phase': 'failed'}):
            with self.assertRaises(ValueError):
                driver.phase_record({**result, **change}, context, 'passed')
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            driver.parse_phase('{"phase":"ready","phase":"passed"}')
        with self.assertRaisesRegex(ValueError, 'exceeded bound'):
            driver.parse_phase(' ' * 4097)

    def test_termination_fence_rejects_another_test_namespace(self):
        info = {'Name': '/test', 'Image': 'sha256:' + 'a' * 64, 'Config': {'Labels': {
            'com.docker.compose.project': 'project', 'com.docker.compose.service': 'web',
            'io.azd-santa.mfa-restart': 'namespace'}}}
        driver.owned_test(info, 'project', 'sha256:' + 'a' * 64, 'test', 'namespace')
        with self.assertRaisesRegex(ValueError, 'unrecognized'):
            driver.owned_test(info, 'project', 'sha256:' + 'a' * 64, 'test', 'another-namespace')


if __name__ == '__main__':
    unittest.main()
