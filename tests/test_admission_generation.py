"""Offline machine-generation producer/consumer; no Docker or lifecycle operations."""
import copy
import json
from pathlib import Path
import sys
import tempfile
from types import ModuleType,SimpleNamespace
import unittest
from unittest.mock import Mock,patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'experiments/server'))
import runtime_service as service
import test_runtime_service as fixtures


class Generation(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.Lifecycle();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.root=self.fixture.root
        self.runtime,self.rows=self.fixture.inspection_fixture()
        self.runtime.manifest_path=self.root/'manifest.json';self.runtime.digest='a'*64
        self.runtime.evidence=self.root;self.runtime.python=Mock()
        self.runtime.helpers=set();self.runtime.phase='prepared';self.runtime.stopping=False;self.runtime.supervisor_lock_fd=None
        self.fcntl=ModuleType('fcntl');self.fcntl.LOCK_EX=1;self.fcntl.LOCK_NB=2;self.fcntl.flock=Mock()

    def anchor(self,selected):
        value=dict(scope='private-runtime-container-generation-v1',manifest_sha256=self.runtime.digest,
            project=self.runtime.project,image_id=self.runtime.data['services']['web']['image'],generation='b'*32,container_ids=selected)
        (self.root/'container-generation.json').write_text(json.dumps(value))
        return value

    def supervise_case(self, case):
        original=self.runtime.inspect(running=False)
        if case != 'missing':
            value=self.anchor(original)
            if case=='mismatched':
                value['manifest_sha256']='f'*64
                (self.root/'container-generation.json').write_text(json.dumps(value))
            elif case=='replacement':self.rows[-1]['Id']='f'*64
        self.runtime.ids=[]
        original_call=self.runtime.call.side_effect
        labels=[]
        def call(label,args,**kwargs):
            labels.append((label,args))
            if label=='cleanup-selection':return SimpleNamespace(stdout='\n'.join(r['Id'] for r in self.rows))
            if label=='stop':return SimpleNamespace(stdout='')
            return original_call(label,args,**kwargs)
        self.runtime.call=Mock(side_effect=call)
        with patch.dict(sys.modules,{'fcntl':self.fcntl}),patch.object(service.signal,'signal'), \
             patch.object(service,'checked_path',side_effect=lambda p,**kw:Path(p)):
            with self.assertRaises((ValueError,FileNotFoundError)):self.runtime.supervise()
        self.assertNotIn('stop',[label for label,_ in labels])
        self.assertNotIn('cleanup-selection',[label for label,_ in labels])

    def test_supervise_missing_anchor_never_stops_unbound_inspected_ids(self):self.supervise_case('missing')
    def test_supervise_mismatched_anchor_never_stops_unbound_inspected_ids(self):self.supervise_case('mismatched')
    def test_supervise_consistent_replacement_never_stops_new_selected_ids(self):self.supervise_case('replacement')

    def authorized_supervise_failure(self, cancelled):
        original=self.runtime.inspect(running=False);self.anchor(original);self.runtime.ids=[]
        original_call=self.runtime.call.side_effect;calls=[]
        self.runtime.backing_data=Mock()
        def call(label,args,**kwargs):
            calls.append((label,args))
            if label=='close-admission':
                if cancelled:raise service.Cancelled('cancelled after authorization')
                return SimpleNamespace(stdout='')
            if label=='compose-config':return SimpleNamespace(stdout='')
            if label=='dependencies':raise RuntimeError('partial authorized start failed')
            if label=='cleanup-selection':return SimpleNamespace(stdout='\n'.join([*original.values(),'f'*64]))
            if label=='stop':return SimpleNamespace(stdout='')
            return original_call(label,args,**kwargs)
        self.runtime.call=Mock(side_effect=call)
        with patch.dict(sys.modules,{'fcntl':self.fcntl}),patch.object(service.signal,'signal'), \
             patch.object(service,'checked_path',side_effect=lambda p,**kw:Path(p)), \
             patch.object(service.Path,'read_text',return_value='1048576'),patch.object(service,'load_manifest'):
            if cancelled:self.runtime.supervise()
            else:
                with self.assertRaisesRegex(RuntimeError,'partial authorized'):self.runtime.supervise()
        stopped=[args for label,args in calls if label=='stop']
        self.assertEqual(len(stopped),1)
        self.assertEqual(set(stopped[0][6:]),set(original.values()))
        self.assertNotIn('f'*64,stopped[0])
        if cancelled:self.assertTrue((self.root/'cancelled.json').exists())
        else:self.assertIn('dependencies',[label for label,_ in calls])

    def test_full_supervise_cancellation_retains_authorized_generation_cleanup(self):self.authorized_supervise_failure(True)
    def test_full_supervise_partial_start_retains_authorized_generation_cleanup(self):self.authorized_supervise_failure(False)

    def test_independent_helper_cleanup_runs_when_container_cleanup_is_unarmed(self):
        self.runtime.ids=['f'*64]
        self.runtime.stop_helpers=Mock();self.runtime.call=Mock(side_effect=AssertionError('Unbound stop'))
        self.runtime.stop()
        self.runtime.stop_helpers.assert_called_once();self.runtime.call.assert_not_called()

    def test_consistent_replacement_passes_live_inspection_but_cannot_reconcile_anchor(self):
        original=self.runtime.inspect(running=False)
        self.anchor(original)
        self.rows[-1]['Id']='f'*64
        self.runtime.ids=[]  # New controller instance has no in-memory old IDs.
        replacement=self.runtime.inspect(running=False)
        self.assertNotEqual(original,replacement)
        with patch.object(service,'checked_path',side_effect=lambda p,**kw:Path(p)),patch.dict(sys.modules,{'fcntl':self.fcntl}):
            with self.assertRaisesRegex(ValueError,'generation'):
                self.runtime.reconcile_admission()
        self.runtime.python.assert_not_called()
        self.assertFalse((self.root/'admission-reconciled.json').exists())

    def test_missing_anchor_fails_before_quiescence_or_clear(self):
        with patch.object(service,'checked_path',side_effect=lambda p,**kw:Path(p)),patch.dict(sys.modules,{'fcntl':self.fcntl}):
            with self.assertRaises(FileNotFoundError):self.runtime.reconcile_admission()
        self.runtime.python.assert_not_called()
        self.assertNotIn('admission-quiescence',[c.args[0] for c in self.runtime.call.call_args_list])

    def test_missing_generation_blocks_start_before_any_stop_or_start(self):
        with patch.object(service,'checked_path',side_effect=lambda p,**kw:Path(p)):
            with self.assertRaises(FileNotFoundError):self.runtime.start()
        labels=[c.args[0] for c in self.runtime.call.call_args_list]
        self.assertNotIn('close-admission',labels)
        self.assertNotIn('dependencies',labels)

    def test_exact_seven_map_and_manifest_binding_are_required(self):
        selected=self.runtime.inspect(running=False);value=self.anchor(selected)
        for mutate in (lambda v:v['container_ids'].pop('redis'),lambda v:v.update(manifest_sha256='c'*64),
                       lambda v:v['container_ids'].update(redis=v['container_ids']['db']),lambda v:v.update(generation='not-a-generation')):
            bad=copy.deepcopy(value);mutate(bad)
            (self.root/'container-generation.json').write_text(json.dumps(bad))
            with patch.object(service,'checked_path',side_effect=lambda p,**kw:Path(p)):
                with self.assertRaises(ValueError):self.runtime.container_generation(selected)

    def fresh(self,started=False):
        selected=self.runtime.inspect(running=False)
        states=[]
        for name,cid in selected.items():
            app=name in service.APPS
            state=dict(Status='created' if app else 'running',Running=not app,Paused=False,Restarting=False,
                OOMKilled=False,Pid=0 if app else 123,StartedAt='0001-01-01' if app else '2026-11-07T00:00:00Z')
            if started and app:state.update(Status='exited',StartedAt='2026-11-07T00:00:00Z')
            states.append(dict(Id=cid,State=state))
        self.runtime.inspect=Mock(return_value=selected)
        self.runtime.call=Mock(return_value=SimpleNamespace(stdout=json.dumps(states)))
        self.runtime.backing_data=Mock()
        return selected

    def test_machine_producer_records_all7_then_refuses_rebinding(self):
        selected=self.fresh()
        with patch.dict(sys.modules,{'fcntl':self.fcntl}),patch.object(service,'UNIT',self.root/'absent-unit'), \
             patch.object(service,'load_manifest'),patch.object(service,'sync_directory') as sync:
            path=self.runtime.bind_admission_fresh()
            value=json.loads(path.read_text())
            self.assertEqual(value['container_ids'],selected);self.assertEqual(len(value['container_ids']),7)
            self.assertEqual(value['manifest_sha256'],self.runtime.digest)
            self.assertRegex(value['generation'],'^[a-f0-9]{32}$')
            self.runtime.backing_data.assert_called_once();sync.assert_called_once_with(path.parent)
            with self.assertRaises(ValueError):self.runtime.bind_admission_fresh()

    def test_started_apps_or_existing_unit_cannot_create_an_anchor(self):
        self.fresh(started=True)
        with patch.dict(sys.modules,{'fcntl':self.fcntl}),patch.object(service,'UNIT',self.root/'absent-unit'):
            with self.assertRaises(ValueError):self.runtime.bind_admission_fresh()
        self.assertFalse((self.root/'container-generation.json').exists())
        unit=self.root/'existing-unit';unit.write_text('preserve')
        self.fresh()
        with patch.dict(sys.modules,{'fcntl':self.fcntl}),patch.object(service,'UNIT',unit):
            with self.assertRaises(ValueError):self.runtime.bind_admission_fresh()
        self.assertFalse((self.root/'container-generation.json').exists())


if __name__=='__main__':unittest.main()
