"""Offline fenced recovery protocol/controller tests. No Redis, SQL or Docker.

The Python CAS model is a deliberate transport double, not Lua execution proof.
Actual production-Lua and killed-handler/PG backend faults remain live gates.
"""
import ast
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import ModuleType,SimpleNamespace
import unittest
from unittest.mock import Mock,patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'experiments/server'))
import santa_admission as admission
import runtime_service as service


class FenceModel:
    """Independent protocol double; records the actual production Lua passed."""
    def __init__(self):
        self.generation='c'*32;self.token='opaque-held-permit';self.calls=[];self.corrupt=False
        self.rates={'global':(120,30),'source':(60,29),'credential':(30,28)}
    def __call__(self,script,extra=(),arguments=()):
        self.calls.append((script,extra,arguments))
        if self.corrupt:raise ValueError('invalid existing state')
        if script in (admission.READ_STATE,admission.READ_OR_MISSING):
            if self.generation is None:
                if script==admission.READ_STATE:raise ValueError('missing state')
                return ['missing',0]
            return [self.generation,1 if self.token else 0]
        if script==admission.INITIALIZE_QUIESCED:
            if self.generation is not None:raise ValueError('already exists')
            self.generation=arguments[-1];self.token=None;return [1,self.generation]
        if script==admission.RECONCILE:
            expected,target=arguments[-2:]
            if self.generation==target:return [0,target]
            if self.generation!=expected:raise ValueError('fence conflict')
            self.token=None;self.generation=target;return [1,target]
        raise AssertionError('Unsupported test double operation')


class RedisProtocol(unittest.TestCase):
    def test_exact_production_scripts_and_args_preserve_all_counters_and_fence_stale_clear(self):
        model=FenceModel();rates=copy.deepcopy(model.rates)
        with patch.object(admission,'_eval',side_effect=model):
            before=admission.state();self.assertEqual(before,{'generation':'c'*32,'active':1})
            first=admission.reconcile(expected_generation='c'*32,generation='d'*32)
            self.assertTrue(first['changed']);self.assertEqual(admission.state()['active'],0)
            # Duplicate old command after a later live acquire is a strict NO-OP.
            model.token='new-live-permit'
            self.assertFalse(admission.reconcile(expected_generation='c'*32,generation='d'*32)['changed'])
            self.assertEqual(model.token,'new-live-permit')
            # A still-delayed older epoch cannot clear a different new generation.
            with self.assertRaises(ValueError):admission.reconcile(expected_generation='c'*32,generation='e'*32)
            self.assertEqual(model.token,'new-live-permit');self.assertEqual(model.rates,rates)
        mutation=model.calls[1]
        self.assertIs(mutation[0],admission.RECONCILE)
        self.assertEqual(mutation[1],('sync-global',))
        self.assertEqual(mutation[2],(admission.CONFIG.window,admission.CONFIG.global_max,'c'*32,'d'*32))
        script=admission.RECONCILE
        self.assertIn(admission.VALIDATE,script);self.assertIn(admission.GLOBAL_COUNTER,script)
        self.assertLess(script.index('if generation==ARGV[7]'),script.index("redis.call('HDEL'"))
        self.assertLess(script.index('if generation~=ARGV[6]'),script.index("redis.call('HDEL'"))
        self.assertNotIn("redis.call('SET'",script);self.assertNotIn('EXPIRE',script)
        self.assertNotIn('DEL',script.replace('HDEL',''))

    def test_even_empty_start_advances_fence_and_old_job_cannot_reclaim_new_work(self):
        model=FenceModel();model.token=None
        with patch.object(admission,'_eval',side_effect=model):
            admission.reconcile(expected_generation='c'*32,generation='d'*32)
            model.token='live'
            with self.assertRaises(ValueError):admission.reconcile(expected_generation='c'*32,generation='e'*32)
            self.assertEqual(model.token,'live')

    def test_corrupt_state_and_malformed_readback_never_become_initialization_or_repair(self):
        for result in ([None,0],['not-a-fence',0],['c'*32,True],['c'*32,2],['c'*32,-1],['c'*32]):
            with patch.object(admission,'_eval',return_value=result):
                with self.assertRaises(ValueError):admission.state()
        model=FenceModel();model.corrupt=True
        with patch.object(admission,'_eval',side_effect=model):
            with self.assertRaises(ValueError):admission.reconcile(expected_generation='c'*32,generation='d'*32)
        self.assertEqual(model.generation,'c'*32);self.assertEqual(model.token,'opaque-held-permit')
        with patch.object(admission,'_eval') as evaluate:
            for expected,target in ((None,'d'*32),('c'*32,'c'*32),('bad','d'*32),('c'*32,'bad')):
                with self.assertRaises(ValueError):admission.reconcile(expected_generation=expected,generation=target)
            evaluate.assert_not_called()

    def test_missing_state_requires_explicit_manual_mode_and_never_replaces_existing_hash(self):
        with patch.object(admission,'_eval',return_value=[1,'d'*32]) as evaluate:
            admission.reconcile(expected_generation=None,generation='d'*32,initialize_missing=True)
            self.assertEqual(evaluate.call_args.args[0],admission.INITIALIZE_QUIESCED)
        with patch.object(admission,'_eval') as evaluate:
            with self.assertRaises(ValueError):admission.reconcile(expected_generation='c'*32,generation='d'*32,initialize_missing=True)
            evaluate.assert_not_called()
        for result in ([None,0],['missing',1]):
            with patch.object(admission,'_eval',return_value=result):
                with self.assertRaises(ValueError):admission.state(allow_missing=True)
        self.assertIn("TYPE',KEYS[2]).ok~='none'",admission.INITIALIZE_QUIESCED)
        self.assertIn(admission.GLOBAL_COUNTER,admission.INITIALIZE_QUIESCED)


class Controller(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve();self.lock=(self.root/'supervisor.lock').open('a+b');self.addCleanup(self.lock.close)
        self.ids={name:format(i+1,'064x') for i,name in enumerate((*service.APPS,*service.DEPENDENCIES))}
        self.model=FenceModel();self.failure=None;self.events=[];self.clock=0;self.pending=None;self.observations=0
        self.r=service.Runtime.__new__(service.Runtime)
        for key,value in dict(manifest_path=self.root/'manifest.json',digest='a'*64,evidence=self.root,
                project='santa-zentral-eval-'+'b'*12,command=['docker','--host','unix:///var/run/docker.sock','compose'],data={'services':{'web':{'image':'sha256:'+'b'*64}}},
                binding={'policy_hashes':{'admission':'f'*64}},supervisor_lock_fd=self.lock.fileno(),stopping=False,
                _admission_capability=None).items():setattr(self.r,key,value)
        self.r.inspect=Mock(return_value=self.ids);self.r.call=Mock(side_effect=self.call);self.r.python=Mock(side_effect=self.python)
        self.generation=dict(scope='private-runtime-container-generation-v1',manifest_sha256='a'*64,
            project=self.r.project,image_id='sha256:'+'b'*64,generation='b'*32,container_ids=self.ids)
        (self.root/'container-generation.json').write_text(json.dumps(self.generation))
        self.rows=[dict(Id=self.ids[name],State=dict(Status='exited',Running=False,Paused=False,Restarting=False,
            Pid=0,ExitCode=137,OOMKilled=True)) for name in service.APPS]

    def call(self,label,args,**kw):
        self.events.append(label)
        if label=='admission-quiescence':return SimpleNamespace(stdout=json.dumps(self.rows))
        return SimpleNamespace(stdout='',returncode=0)

    def python(self,label,code,**kw):
        self.events.append(label);compile(code,'<recovery-helper>','exec')
        if label=='admission-database-quiescence':
            if self.failure=='unknown-db':raise ValueError('unknown role visibility')
            value={'quiet':self.failure!='busy-db' and (self.failure!='delayed-db' or self.clock>=4)}
        else:
            self.assertIn('f'*64,code)
            if label=='admission-state':
                if self.failure=='bad-state':raise ValueError('invalid Redis marker/config/counter')
                call=next(node for node in ast.walk(ast.parse(code)) if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=='state')
                with patch.object(admission,'_eval',side_effect=self.model):value=admission.state(**{k.arg:ast.literal_eval(k.value) for k in call.keywords})
            elif label=='admission-recovery-submit':
                call=next(node for node in ast.walk(ast.parse(code)) if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=='reconcile')
                arguments={k.arg:ast.literal_eval(k.value) for k in call.keywords}
                if self.failure=='delayed-submit':self.pending=arguments;raise TimeoutError('unknown EVAL')
                if self.failure=='never-submit':raise TimeoutError('unknown EVAL')
                with patch.object(admission,'_eval',side_effect=self.model):value=admission.reconcile(**arguments)
                if self.failure=='lost-response':raise TimeoutError('lost response after commit')
            elif label=='admission-recovery-observe':
                self.observations+=1
                if self.pending and self.observations==2:
                    with patch.object(admission,'_eval',side_effect=self.model):admission.reconcile(**self.pending)
                    self.pending=None
                with patch.object(admission,'_eval',side_effect=self.model):value=admission.state()
                if self.failure=='malformed-readback':value['active']=False
            else:raise AssertionError(label)
        return SimpleNamespace(stdout='SANTA_ADMISSION_JSON:'+json.dumps(value))

    def recover(self,method=None):
        def sleep(n):self.clock+=n
        with patch.object(service,'load_manifest'),patch.object(service,'checked_path',side_effect=lambda p,**kw:Path(p)),             patch.object(service,'sync_directory'),patch.object(service.secrets,'token_hex',return_value='d'*32),             patch.object(service.time,'monotonic',side_effect=lambda:self.clock),patch.object(service.time,'sleep',side_effect=sleep):
            (method or self.r._recover_admission_locked)()

    def test_dead_original_handler_and_readonly_db_drain_recover_once_without_manual_work(self):
        self.failure='delayed-db';rates=copy.deepcopy(self.model.rates);self.recover()
        self.assertEqual(self.model.generation,'d'*32);self.assertIsNone(self.model.token);self.assertEqual(self.model.rates,rates)
        self.assertEqual(self.events.count('admission-recovery-submit'),1)
        self.assertLess(self.events.index('admission-database-quiescence'),self.events.index('admission-recovery-submit'))
        intent=json.loads((self.root/'admission-recovery-intent.json').read_bytes())
        self.assertEqual(intent['container_ids'],self.ids);self.assertFalse(intent['initialize_missing'])
        self.assertTrue(intent['runtime_database_no_other_sessions']);self.assertEqual(intent['target_generation'],'d'*32)
        self.assertIsNone(self.r._admission_capability)

    def test_lost_or_delayed_mutation_response_is_only_observed_not_resubmitted(self):
        self.failure='lost-response';self.recover()
        self.assertEqual(self.events.count('admission-recovery-submit'),1)
        self.assertTrue(json.loads((self.root/'admission-reconciled.json').read_text())['submission_was_unknown'])
    def test_delayed_old_generation_with_held_slot_is_readonly_observed_until_commit(self):
        self.failure='delayed-submit';self.recover()
        self.assertEqual(self.observations,2);self.assertEqual(self.events.count('admission-recovery-submit'),1)

    def test_unknown_uncommitted_job_retains_intent_without_second_submission_or_admission(self):
        self.failure='never-submit'
        with self.assertRaises(ValueError):self.recover()
        self.assertEqual(self.events.count('admission-recovery-submit'),1)
        self.assertEqual(self.model.generation,'c'*32);self.assertIsNotNone(self.model.token)
        self.assertTrue((self.root/'admission-recovery-intent.json').exists())
        self.assertFalse((self.root/'admission-reconciled.json').exists())

    def test_boolean_zero_readback_never_confirms_recovery(self):
        self.failure='malformed-readback'
        with self.assertRaises(ValueError):self.recover()
        self.assertFalse((self.root/'admission-reconciled.json').exists())

    def test_explicit_missing_migration_remains_separate_and_refuses_existing_hash(self):
        with self.assertRaises(ValueError):self.recover(lambda:self.r._recover_admission_locked(initialize_missing=True))
        self.assertNotIn('admission-recovery-submit',self.events)
        self.model.generation=None;self.model.token=None
        self.recover(lambda:self.r._recover_admission_locked(initialize_missing=True))
        self.assertEqual(self.model.generation,'d'*32)
        self.assertTrue(any(script==admission.INITIALIZE_QUIESCED for script,_,_ in self.model.calls))

    def test_live_paused_restarting_or_unknown_original_state_never_reaches_lua(self):
        for field,value in [('Running',True),('Paused',True),('Restarting',True),('Pid',77),('Pid',False),('Status','dead')]:
            changed=copy.deepcopy(self.rows);changed[0]['State'][field]=value
            with patch.object(self.r,'call',return_value=SimpleNamespace(stdout=json.dumps(changed))):
                with self.assertRaises(ValueError):self.recover()
            self.r.python.assert_not_called()

    def test_consistent_replacement_or_lock_loss_cannot_reclaim(self):
        self.r.inspect.return_value={**self.ids,'web':'9'*64}
        with self.assertRaises(ValueError):self.recover()
        self.r.python.assert_not_called();self.r.inspect.return_value=self.ids
        self.r.supervisor_lock_fd=None
        with self.assertRaises(ValueError):self.recover()
        self.r.python.assert_not_called()

    def test_pg_busy_deadline_and_unknown_visibility_keep_capacity_unchanged(self):
        for failure in ('busy-db','unknown-db'):
            self.failure=failure
            with self.assertRaises((TimeoutError,ValueError)):self.recover()
            self.assertEqual(self.model.generation,'c'*32);self.assertEqual(self.model.token,'opaque-held-permit')
            self.assertNotIn('admission-recovery-submit',self.events)

    def test_invalid_marker_state_or_counter_is_not_repaired(self):
        self.failure='bad-state'
        with self.assertRaises(ValueError):self.recover()
        self.assertNotIn('admission-recovery-submit',self.events)
        self.assertFalse((self.root/'admission-recovery-intent.json').exists())

    def test_app_becoming_live_after_readback_is_rejected_before_cas(self):
        original=self.python
        def changed(label,code,**kw):
            result=original(label,code,**kw)
            if label=='admission-state':self.rows[0]['State'].update(Running=True,Pid=99)
            return result
        self.r.python=Mock(side_effect=changed)
        with self.assertRaises(ValueError):self.recover()
        self.assertNotIn('admission-recovery-submit',self.events)

    def test_expired_or_foreign_process_capability_cannot_authorize_a_later_clear(self):
        cap=service._AdmissionQuiescence(self.r,self.ids,self.generation,service._ADMISSION_KEY)
        with self.assertRaises(ValueError):cap.verify()
        self.r._admission_capability=cap
        with patch.object(service.os,'getpid',return_value=cap.pid+1):
            with self.assertRaises(ValueError):cap.verify()
        with self.assertRaises(ValueError):service._AdmissionQuiescence(self.r,self.ids,self.generation,object())

    def test_pg_helper_exercises_own_role_visibility_and_excludes_only_its_current_backend(self):
        class Cursor:
            def __init__(self,other,visible):self.other=other;self.visible=visible;self.queries=[];self.reads=0
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def execute(self,query):self.queries.append(query)
            def fetchone(self):return (7,'zentral_runtime','zentral')
            def fetchall(self):
                self.reads+=1
                if self.reads==1:return [(7,'zentral_runtime','zentral','active' if self.visible else None,object())]
                return self.other
        for other,visible,want in (([],True,True),([(9,'active',object())],True,False),([],False,None)):
            cursor=Cursor(other,visible);db=ModuleType('django.db');db.connection=SimpleNamespace(cursor=lambda:cursor)
            role=ModuleType('azd_santa_database_roles');role.check_runtime=Mock()
            def actual_helper(label,code,**kw):
                output=io.StringIO()
                with patch.dict(sys.modules,{'django.db':db,'azd_santa_database_roles':role}),contextlib.redirect_stdout(output):
                    exec(compile(code,'<actual-readonly-PG-helper>','exec'),{})
                return SimpleNamespace(stdout=output.getvalue())
            self.r.python=Mock(side_effect=actual_helper)
            if want is None:
                with self.assertRaises(AssertionError):self.r._runtime_database_quiet(5)
            else:self.assertEqual(self.r._runtime_database_quiet(5),want)
            role.check_runtime.assert_called_once()
            self.assertTrue(all(query.startswith('SELECT ') for query in cursor.queries))
            if want is not None:self.assertIn('pid<>pg_backend_pid()',cursor.queries[-1])
            self.assertFalse(any('pg_cancel' in q or 'pg_terminate' in q for q in cursor.queries))

    def test_actual_start_orders_recovery_before_workers_listener_and_empty_check(self):
        implementation=self.r._recover_admission_locked
        self.r._recover_admission_locked=lambda:self.recover(implementation)
        self.r.binding['policy_hashes']={name:'f'*64 for name in service.POLICIES}
        self.r.rendered={'services':{'db':{'environment':{'POSTGRES_USER':'owner','POSTGRES_DB':'zentral'}}}}
        self.r.backing_data=Mock();self.r.start_ids=lambda label,names:self.events.append(label)
        self.r.wait=lambda *args,**kwargs:None
        self.r.oneoff=lambda label,*args,**kwargs:self.events.append(label)
        original=self.python
        def helper(label,code,**kw):
            if label in ('source-schema-store','sync-admission','search'):
                self.events.append(label)
                if label=='sync-admission':self.assertEqual(self.model.generation,'d'*32);self.assertIsNone(self.model.token)
                return SimpleNamespace(stdout='')
            return original(label,code,**kw)
        self.r.python=Mock(side_effect=helper)
        with patch.object(service,'checked_path',side_effect=lambda p,**kw:Path(p)),patch.object(service.Path,'read_text',return_value='1048576'),patch.object(service,'compose_helper',return_value=SimpleNamespace(NoRedirect=service.urllib.request.HTTPRedirectHandler)):
            self.r.start()
        for before,after in [('close-admission','admission-quiescence'),('admission-database-quiescence','admission-recovery-submit'),
                             ('admission-recovery-observe','sync-admission'),('sync-admission','workers'),('workers','listener')]:
            self.assertLess(self.events.index(before),self.events.index(after))

    def test_public_manual_wrapper_cannot_enter_while_other_supervisor_owns_lock(self):
        fcntl=ModuleType('fcntl');fcntl.LOCK_EX=1;fcntl.LOCK_NB=2
        fcntl.flock=Mock(side_effect=BlockingIOError('already held'))
        self.r._recover_admission_locked=Mock()
        with patch.dict(sys.modules,{'fcntl':fcntl}):
            with self.assertRaises(BlockingIOError):self.r.reconcile_admission()
        self.r._recover_admission_locked.assert_not_called();self.r.python.assert_not_called()

    def test_pending_backup_blocks_start_before_selection_or_recovery(self):
        (self.root/'backup-request.json').write_text('pending')
        self.r.backup_module=Mock(return_value=SimpleNamespace(startup_allowed=Mock(side_effect=ValueError('pending backup'))))
        with self.assertRaises(ValueError):self.r.start()
        self.r.inspect.assert_not_called();self.r.python.assert_not_called();self.r.call.assert_not_called()

    def test_supervisor_interval_bounds_three_worst_case_starts(self):
        unit=service.unit_text(service.PurePosixPath('/var/lib/azd-santa-qualification/runtime_service.py'),
            service.PurePosixPath('/var/lib/azd-santa-qualification/runtime-service/manifest.json'),'a'*64)
        values=dict(line.split('=',1) for line in unit.splitlines() if '=' in line)
        self.assertEqual(values['StartLimitBurst'],'3');self.assertEqual(values['RestartSec'],'30')
        self.assertGreaterEqual(int(values['StartLimitIntervalSec']),3*(int(values['TimeoutStartSec'])+int(values['RestartSec'])))


if __name__=='__main__':unittest.main()
