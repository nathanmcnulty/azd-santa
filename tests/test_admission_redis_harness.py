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

    def test_expected_redis_error_precedes_nonzero_status_and_remains_consumable(self):
        result=subprocess.CompletedProcess([],1,'error:"ADMISSION_UNAVAILABLE"','private diagnostic')
        # Existing negative-case semantics survive a nonzero redis-cli status.
        live.rejected(lambda: live.parse_reply(result,'EVAL'))
        with self.assertRaises(live.RedisError) as caught: live.parse_reply(result,'EVAL')
        self.assertEqual(live.failure_diagnostic(caught.exception),
                         dict(kind='redis_rejection',operation='EVAL',exit_code=1))

    def test_failure_only_classification_never_exports_raw_process_data(self):
        secret='private-key-token-qualification-secret'
        cases=[(subprocess.CompletedProcess([],137,secret,secret),'command_exit'),
               (subprocess.CompletedProcess([],0,secret,''),'malformed_json'),
               (subprocess.CompletedProcess([],0,'1',secret),'invariant'),
               (subprocess.CompletedProcess([],0,'x'*65537,secret),'output_limit'),
               (subprocess.CompletedProcess([],0,'error:'+secret,''),'malformed_json')]
        for result,kind in cases:
            with self.subTest(kind=kind):
                with self.assertRaises(live.HarnessFailure) as caught: live.parse_reply(result,'EVAL')
                diagnostic=live.failure_diagnostic(caught.exception)
                self.assertEqual(diagnostic,dict(kind=kind,operation='EVAL',exit_code=result.returncode))
                self.assertNotIn(secret,json.dumps(diagnostic)); self.assertNotIn(secret,str(caught.exception))
        self.assertEqual(live.failure_diagnostic(ValueError(secret)),
                         dict(kind='internal_error',operation=None,exit_code=None))
        self.assertEqual(live.failure_diagnostic(live.HarnessFailure(secret,secret,99999)),
                         dict(kind='internal_error',operation=None,exit_code=None))
        self.assertEqual(live.failure_diagnostic(live.HarnessFailure('invariant','SET',True)),
                         dict(kind='invariant',operation='SET',exit_code=None))

    def test_command_timeout_exports_only_static_operation_not_arguments(self):
        target=live.Target('a'*64,'sha256:'+'b'*64)
        with patch.object(live.subprocess,'run',side_effect=subprocess.TimeoutExpired(['secret'],15,output='private')):
            with self.assertRaises(live.HarnessFailure) as caught: target.eval('secret script',0)
        self.assertEqual(live.failure_diagnostic(caught.exception),
                         dict(kind='timeout',operation='EVAL',exit_code=None))

    def test_success_schema_unchanged_and_only_failed_receipt_adds_fixed_diagnostic(self):
        tree=ast.parse(PATH.read_bytes())
        run=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='run')
        writes={}
        for node in ast.walk(run):
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=='write':
                path=node.args[0]
                if (isinstance(path,ast.BinOp) and isinstance(path.right,ast.Constant)
                        and isinstance(node.args[1],ast.Call)):
                    writes[path.right.value]={kw.arg for kw in node.args[1].keywords}
        self.assertNotIn('diagnostic',writes['receipt.json'])
        self.assertEqual(writes['failed.json'],{'passed','completed','diagnostic','action'})
        self.assertEqual(live.OPERATIONS,{'EVAL','EXISTS','TTL','GET','HGET','SET','DEL','LPUSH','HSET',
                                         'EXPIRE','TIME','KEYS','PING','INSPECT'})

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

    def test_readonly_snapshot_uses_absolute_expirations_and_all_case_keys(self):
        self.assertIn("redis.call('PEXPIRETIME',key)", live.SNAPSHOT)
        self.assertIn("redis.call('KEYS',ARGV[1])", live.SNAPSHOT)
        self.assertIn('table.sort(keys)', live.SNAPSHOT)
        self.assertIn('table.sort(fields)', live.SNAPSHOT)
        for write in ('SET', 'DEL', 'EXPIRE', 'HSET', 'HDEL', 'INCR'):
            self.assertNotIn("redis.call('" + write + "'", live.SNAPSHOT)
        case = object.__new__(live.Case); case.prefix='qualification:offline:'
        case.target=unittest.mock.Mock()
        case.target.eval.return_value='[["key","string","1",1234567890123]]'
        self.assertEqual(case.snapshot(), [['key', 'string', '1', 1234567890123]])
        case.target.eval.assert_called_once_with(live.SNAPSHOT, 0, 'qualification:offline:*')

    def test_unchanged_guard_rejects_successful_mutation_or_wrong_result(self):
        from unittest.mock import Mock
        case=Mock(); case.snapshot.side_effect=[[['key','hash',[['0','token']],-1]], []]
        with self.assertRaises(ValueError): live.unchanged(case, lambda: [0,'fence'], expected=[0,'fence'])
        case=Mock(); case.snapshot.return_value=[]
        with self.assertRaises(ValueError): live.unchanged(case, lambda: [1,'fence'], expected=[0,'fence'])
        with self.assertRaises(ValueError): live.unchanged(case, lambda: [0,'fence'], reject=True)
        def redis_error(): raise live.RedisError('rejected')
        live.unchanged(case, redis_error, reject=True)

    def test_production_protocol_adapter_has_full_keys_limits_and_fences(self):
        from unittest.mock import Mock
        case=object.__new__(live.Case); case.module=Mock(); case.config=Mock(window=300,global_max=100)
        case.module.RECONCILE='cas'; case.module.INITIALIZE_QUIESCED='init'
        case.module.READ_STATE='read'; case.module.READ_OR_MISSING='read-missing'
        case.script=Mock(return_value=['result'])
        self.assertEqual(case.reconcile('a'*32,'b'*32), ['result'])
        case.script.assert_called_with('cas', ('sync-global',), (300,100,'a'*32,'b'*32))
        case.reconcile('', 'b'*32, initialize_missing=True)
        case.script.assert_called_with('init', ('sync-global',), (300,100,'','b'*32))
        case.read_state(); case.script.assert_called_with('read', ('sync-global',), (300,100))
        case.read_state(allow_missing=True); case.script.assert_called_with('read-missing', ('sync-global',), (300,100))

    def test_historical_receipt_is_distinct_from_unexecuted_fenced_scope(self):
        doc=(ROOT/'docs/admission-redis-qualification.md').read_text()
        self.assertIn('33a2fd00f8e2c7bee5fb7989325605499e3d181c198ed216c7571d73f55a233b', doc)
        self.assertIn('937ef10433eeb3bf901aaf5b87aaddf37b73b9c4c135a927cb6f9f5e1a0c5235', doc)
        self.assertIn('actual Redis execution pending', doc)
        self.assertIn('disposable-redis-admission-fenced-lua-v2', PATH.read_text())

    def test_receipt_has_exactly_37_unique_nonsecret_observation_families(self):
        import re
        tree=ast.parse(PATH.read_bytes()); names=[]
        exercise=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='exercise')
        mutations=next(n.value for n in exercise.body if isinstance(n,ast.Assign)
                       and isinstance(n.targets[0],ast.Name) and n.targets[0].id=='mutations')
        for node in ast.walk(tree):
            if not (isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute)
                    and isinstance(node.func.value,ast.Name) and node.func.value.id=='record'
                    and node.func.attr=='append'): continue
            value=node.args[0]
            if isinstance(value,ast.Constant): names.append(value.value)
            elif isinstance(value,ast.BinOp) and isinstance(value.op,ast.Add):
                if value.left.id=='name': names.extend(n.elts[0].value+value.right.value for n in mutations.elts)
                elif value.left.id=='kind': names.extend(k+value.right.value for k in ('source','credential','global'))
                else: self.fail('Unreviewed dynamic receipt family')
            else: self.fail('Unreviewed receipt family expression')
        self.assertEqual(len(names),37); self.assertEqual(len(set(names)),37)
        self.assertTrue(all(re.fullmatch('[a-z0-9_]{1,96}', name) for name in names))


if __name__ == '__main__': unittest.main()
