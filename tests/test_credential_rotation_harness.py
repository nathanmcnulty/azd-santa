"""No Docker/HTTP/ORM calls; these guards are not real-server acceptance."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import tempfile
from types import SimpleNamespace
import unittest
import uuid
from unittest.mock import MagicMock, patch
import zlib

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('rotation', ROOT / 'experiments/server/test_credential_rotation_live.py')
rotation = importlib.util.module_from_spec(spec); spec.loader.exec_module(rotation)


def fixture():
    return dict(identifiers=['a' * 64, 'b' * 64, 'c' * 64, 'd' * 64, 'e' * 64, 'f' * 64],
                devices=[dict(uuid='00000000-0000-4000-8000-000000000001', serial='synthetic-0', enrollment_id=1, secret='s' * 64),
                         dict(uuid='00000000-0000-4000-8000-000000000002', serial='synthetic-1', enrollment_id=2, secret='t' * 64)])


class Harness(unittest.TestCase):
    def test_embedded_rule_mutation_excludes_only_owned_null_ruleset_and_validates_before_save(self):
        import ast
        import contextlib
        import io
        tree = ast.parse(Path(rotation.__file__).read_text())
        code = next(node.value for node in ast.walk(tree) if isinstance(node, ast.Constant)
                    and isinstance(node.value, str) and 'r=Rule.objects.select_for_update()' in node.value)
        compiled = compile(code, '<actual-rule-mutation>', 'exec')
        data = fixture(); data['configuration_id'] = 3; data['changed_identifier'] = data['identifiers'][0]
        class RuleValue:
            def __init__(self, ruleset=None, validation_error=False):
                self.policy=2; self.version=1; self.ruleset_id=ruleset; self.calls=[]; self.validation_error=validation_error
            def full_clean(self, **kwargs):
                self.calls.append(('validate', kwargs, self.policy, self.version))
                # All original model validation remains enabled. Only the
                # unrelated nullable/nonblank relation is excluded.
                self_test.assertEqual(kwargs, dict(exclude=['ruleset'], validate_unique=True, validate_constraints=True))
                if self.validation_error: raise ValueError('Real validation failure must prevent save')
            def save(self, **kwargs): self.calls.append(('save', kwargs, self.policy, self.version))
        self_test = self
        def execute(rule):
            manager=MagicMock(); manager.select_for_update.return_value.get.return_value=rule
            env=dict(need=rotation.need, fixture=data, json=json,
                     transaction=SimpleNamespace(atomic=contextlib.nullcontext),
                     Rule=SimpleNamespace(objects=manager,Policy=SimpleNamespace(BLOCKLIST=2,ALLOWLIST=1)))
            with contextlib.redirect_stdout(io.StringIO()): exec(compiled, env)
            self.assertEqual(manager.select_for_update.return_value.get.call_args.kwargs,
                dict(configuration_id=3,target__identifier=data['changed_identifier']))
        valid=RuleValue(); execute(valid)
        self.assertEqual([call[0] for call in valid.calls], ['validate','save'])
        self.assertEqual(valid.calls[0][2:], (1,2))
        self.assertEqual(valid.calls[1], ('save',dict(update_fields=['policy','version']),1,2))
        foreign=RuleValue(ruleset=99)
        with self.assertRaises(ValueError): execute(foreign)
        self.assertEqual(foreign.calls, [])
        invalid=RuleValue(validation_error=True)
        with self.assertRaises(ValueError): execute(invalid)
        self.assertEqual([call[0] for call in invalid.calls], ['validate'])

    def test_state_executes_uuid_identity_guard_with_real_uuid_model_values(self):
        # Execute the actual embedded ORM assertion (without importing Django),
        # reproducing UUIDField's Python representation and exact other guards.
        import ast
        source = Path(rotation.__file__).read_text()
        tree = ast.parse(source)
        state_function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'state')
        code = next(node.value for node in ast.walk(state_function) if isinstance(node, ast.Constant)
                    and isinstance(node.value, str) and 'em.hardware_uuid' in node.value)
        orm_tree = ast.parse(code)
        loop = next(node for node in orm_tree.body if isinstance(node, ast.For) and node.target.id == 'em')
        check = next(node for node in loop.body if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
                     and isinstance(node.value.func, ast.Name) and node.value.func.id == 'need')
        compiled = compile(ast.fix_missing_locations(ast.Module(body=[check], type_ignores=[])), '<actual-state-guard>', 'exec')
        device = fixture()['devices'][0]
        model = SimpleNamespace(hardware_uuid=uuid.UUID(device['uuid']), serial_number=device['serial'], client_mode=1)
        def verify():
            exec(compiled, dict(need=rotation.need, str=str, em=model, d=device,
                                Configuration=SimpleNamespace(MONITOR_MODE=1)))
        verify()
        model.hardware_uuid = uuid.UUID(fixture()['devices'][1]['uuid'])
        with self.assertRaises(ValueError): verify()
        model.hardware_uuid = uuid.UUID(device['uuid']); model.serial_number += '-other'
        with self.assertRaises(ValueError): verify()
        model.serial_number = device['serial']; model.client_mode = 2
        with self.assertRaises(ValueError): verify()

    def test_verified_local_helpers_load_without_network_or_docker(self):
        root = ROOT / 'experiments/server'
        helper = hashlib.sha256((root / 'test_live_zentral.py').read_bytes()).hexdigest()
        generator = hashlib.sha256((root / 'prepare_zentral_eval.py').read_bytes()).hexdigest()
        with patch.object(rotation.subprocess, 'run', side_effect=AssertionError('No Docker permitted')), \
             patch.object(rotation.urllib.request, 'urlopen', side_effect=AssertionError('No network permitted')):
            module, hashes = rotation.load_helpers(helper, generator)
            self.assertEqual(module.COMMIT, '88e67b3ce49033aab028029937a6e14f7c489073')
            self.assertEqual(hashes['test_live_zentral'], helper)

    def test_all_selected_helper_hashes_checked_before_any_helper_executes(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve(); generator = root / 'prepare_zentral_eval.py'
            generator.write_text('raise RuntimeError("canary must not execute")\n')
            (root / 'test_live_zentral.py').write_text('# mismatched helper\n')
            with patch.object(rotation, '__file__', str(root / 'harness.py')):
                with self.assertRaises(ValueError): rotation.load_helpers('0' * 64, hashlib.sha256(generator.read_bytes()).hexdigest())

    def test_web_receipt_binds_actual_selected_image_and_exact_private_listener(self):
        cid = 'a' * 64; image = 'sha256:' + 'b' * 64
        binding = [{'HostIp': '127.0.0.1', 'HostPort': '8000'}]
        data = dict(id=cid, image=image, running=True, labels={'com.docker.compose.project': 'selected', 'com.docker.compose.service': 'web'},
                    bindings={'8000/tcp': binding}, ports={'8000/tcp': binding, '443/tcp': None})
        def replies(value): return [SimpleNamespace(returncode=0, stdout=cid), SimpleNamespace(returncode=0, stdout=json.dumps(value))]
        with patch.object(rotation.subprocess, 'run', side_effect=replies(data)):
            self.assertEqual(rotation.attest_web('/private/compose.json', 'selected', image), cid)
        for key, value in [('image', 'sha256:' + 'c' * 64), ('bindings', {'8000/tcp': [{'HostIp': '0.0.0.0', 'HostPort': '8000'}]}),
                           ('ports', {'8000/tcp': binding, '9000/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '9000'}]})]:
            mutated = copy.deepcopy(data); mutated[key] = value
            with self.subTest(key=key), patch.object(rotation.subprocess, 'run', side_effect=replies(mutated)):
                with self.assertRaises(ValueError): rotation.attest_web('/private/compose.json', 'selected', image)

    def test_rejection_requires_each_stage_and_exact_db_invariance(self):
        data = fixture(); observations = []
        with patch.object(rotation, 'state', return_value={'state': 'unchanged'}) as state, \
             patch.object(rotation, 'post', return_value=(403, None)) as post:
            rotation.deny_all('compose', data, data['devices'][0], 'Bearer old', observations, 'revoked', 'cursor')
            self.assertEqual([call.args[0] for call in post.call_args_list], list(rotation.STAGES))
            self.assertEqual(state.call_count, 5)
            self.assertEqual(post.call_args_list[1].args[2], {'cursor': 'cursor'})
            self.assertEqual(len(post.call_args_list[2].args[2]['events']), 1)
        for mutation, status in ((True, 403), (False, 200)):
            with self.subTest(mutation=mutation, status=status), \
                 patch.object(rotation, 'state', side_effect=[{'x': 1}, {'x': 2 if mutation else 1}]), \
                 patch.object(rotation, 'post', return_value=(status, None)) as post:
                with self.assertRaises(ValueError): rotation.deny_all('compose', data, data['devices'][0], 'Bearer old', [], 'negative')
                self.assertEqual(post.call_count, 1)

    def test_rotation_uses_new_bytes_without_changing_original_private_epoch(self):
        data = fixture(); before = copy.deepcopy(data)
        with patch.object(rotation, 'orm', return_value={'changed': True}) as orm:
            result = rotation.change_authority('compose', data, 0, 'rotate')
            self.assertEqual(data, before); self.assertNotEqual(result['devices'][0]['secret'], data['devices'][0]['secret'])
            self.assertRegex(result['devices'][0]['secret'], '^[A-Za-z0-9]{64}$')
            self.assertEqual(result['devices'][1], data['devices'][1])
            self.assertIn('select_for_update', orm.call_args.args[2])
            self.assertIn("need(s.is_revoked or s.is_expired)", orm.call_args.args[2])
        with self.assertRaises(ValueError): rotation.change_authority('compose', data, 3, 'rotate')

    def test_stale_cursor_sync_requires_current_rules_and_fully_committed_ledger(self):
        data = fixture()
        expected = [dict(identifier=value, rule_type='BINARY', policy='ALLOWLIST' if i == 0 else 'BLOCKLIST')
                    for i, value in enumerate(data['identifiers'])]
        ledger = [dict(enrolled_machine_id=10, **{'target__identifier': value}, policy=1 if i == 0 else 2,
                      version=2 if i == 0 else 1, cursor=None, sync_session=None, staged_removal=False,
                      committed_policy=None, committed_version=None) for i, value in enumerate(data['identifiers'])]
        state = dict(machines=[dict(pk=10, enrollment_id=1, sync_session=None, last_postflight_at='time')], rules=ledger)
        replies = [(200, dict(client_mode='MONITOR', sync_type='CLEAN', batch_size=5)),
                   (200, dict(rules=expected[:5], cursor='newcursor')), (200, dict(rules=expected[5:])), (200, {}), (200, {})]
        partial = dict(machines=[dict(pk=10, enrollment_id=1, sync_session='open', sync_session_clean=True, forced_sync_type=None)])
        with patch.object(rotation, 'post', side_effect=replies) as post, patch.object(rotation, 'state', side_effect=[partial, state]):
            observations = []
            rotation.full_sync('compose', data, 0, observations, 'retry', True, stale_cursor='oldcursor', reconcile=True)
            request = post.call_args_list[0].args[2]
            self.assertNotIn('request_clean_sync', request)
            self.assertEqual(request['binary_rule_count'], 6)
            self.assertTrue(all(request[kind + '_rule_count'] == 0 for kind in ('cdhash', 'certificate', 'compiler', 'signingid', 'transitive', 'teamid')))
            self.assertEqual(post.call_args_list[1].args[2], dict(cursor='oldcursor'))
            self.assertTrue(observations[0]['committed_ledger'])
            self.assertTrue(observations[0]['lost_session_reconciliation'])
            self.assertFalse(observations[0]['explicit_clean_requested'])
        stale = copy.deepcopy(state); stale['rules'][0]['policy'] = 2
        with patch.object(rotation, 'post', side_effect=replies), patch.object(rotation, 'state', return_value=stale):
            with self.assertRaises(ValueError): rotation.full_sync('compose', data, 0, [], 'stale', True)

    def test_partial_retry_semantics_allow_new_pks_and_cursor_but_reject_ledger_defects(self):
        data = fixture(); cursor = 'oldpage1'
        page = dict(cursor=cursor, rules=[dict(identifier=value, rule_type='BINARY', policy='BLOCKLIST') for value in data['identifiers'][:5]])
        machine = dict(pk=10, enrollment_id=1, hardware_uuid=data['devices'][0]['uuid'], sync_session='session1',
                       sync_session_clean=True, forced_sync_type=None, last_preflight_at='preflight', last_postflight_at='old')
        rows = [dict(pk=100+i, enrolled_machine_id=10, **{'target__identifier': value}, policy=2, version=1,
                     cursor=cursor if i < 5 else None, sync_session='session1' if i < 5 else None,
                     staged_removal=False, committed_policy=2 if i < 5 else None, committed_version=1 if i < 5 else None)
                for i, value in enumerate(data['identifiers'])]
        before = dict(machines=[machine], rules=rows, authority=[dict(count=1)], counters=[])
        expected = rotation.partial_projection(before, data, 0, page)
        after = copy.deepcopy(before); replay = copy.deepcopy(page); replay['cursor'] = 'newpage1'
        for row in after['rules']:
            row['pk'] += 20
            if row['cursor']: row['cursor'] = replay['cursor']
        self.assertEqual(rotation.partial_projection(after, data, 0, replay), expected)
        for key, value in [('policy', 1), ('version', 2), ('sync_session', 'different'),
                           ('committed_policy', None), ('committed_version', 2), ('cursor', 'wrongpage'),
                           ('staged_removal', True), ('target__identifier', 'f' * 64)]:
            bad = copy.deepcopy(after); bad['rules'][0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): rotation.partial_projection(bad, data, 0, replay)

    def test_fixed_loopback_legacy_header_shape_and_bounded_no_redirect_response(self):
        fake = SimpleNamespace(UUID_PATTERN=re.compile('00000000-0000-4000-8000-[a-f0-9]{12}'),
                               BASE_URL='http://127.0.0.1:8000/public/santa/sync/', NoRedirect=type('NoRedirect', (rotation.urllib.request.HTTPRedirectHandler,), {}))
        response = MagicMock(); response.status = 200; response.read.return_value = b'{}'
        opener = MagicMock(); opener.open.return_value = response
        with patch.object(rotation, 'live', fake), patch.object(rotation.urllib.request, 'build_opener', return_value=opener):
            status, _ = rotation.post('eventupload', fixture()['devices'][0], {'events': []}, 'Bearer replacement', 's' * 64)
            request = opener.open.call_args.args[0]
            self.assertTrue(request.full_url.startswith(fake.BASE_URL + 's' * 64 + '/eventupload/'))
            self.assertEqual(request.get_header('Zentral-authorization'), 'Bearer replacement')
            self.assertEqual(json.loads(zlib.decompress(request.data)), {'events': []})
            self.assertEqual(status, 200)
            with self.assertRaises(ValueError): rotation.post('arbitrary', fixture()['devices'][0], {}, 'Bearer replacement')

    def test_existing_destination_rejects_before_orm_or_fixture_initialization(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve(); compose = root / 'compose.json'
            compose.write_text(json.dumps(dict(services={name: {'image': 'sha256:' + 'a' * 64} for name in ('web', 'workers', 'celery')})))
            fake = MagicMock(); fake.validate_compose.return_value = (compose, 'b' * 64)
            with patch.object(rotation, 'load_helpers', return_value=(fake, {})), \
                 patch.object(rotation.sys, 'platform', 'linux'), patch.object(rotation.os, 'geteuid', return_value=0, create=True):
                with self.assertRaises(ValueError): rotation.run(compose, root, 'sha256:' + 'a' * 64, 'c' * 64, 'd' * 64)
                fake.orm.assert_not_called(); fake.initialize_fixture.assert_not_called()

    def test_private_receipts_refuse_overwrite(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'receipt.json'; rotation.write(path, {'passed': False})
            with self.assertRaises(FileExistsError): rotation.write(path, {'passed': True})
            self.assertFalse(json.loads(path.read_bytes())['passed'])


if __name__ == '__main__': unittest.main()
