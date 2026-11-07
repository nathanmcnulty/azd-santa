"""Offline controller-maintenance flow; every container/IMDS action is mocked."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace,ModuleType
import unittest
from unittest.mock import Mock,patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'experiments/server'))
import cold_backup as backup
import native_snapshot as native
import runtime_service as service


class Maintenance(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve();self.control=self.root/'runtime-service';self.control.mkdir()
        self.lock=(self.control/'supervisor.lock').open('w+b');self.addCleanup(self.lock.close)
        self.ids={name:format(i+1,'064x') for i,name in enumerate(('db','redis','rabbitmq','elastic','web','workers','celery'))}
        self.events=[];self.failure=None
        self.states={cid:dict(Status='running',Running=True,Paused=False,Restarting=False,OOMKilled=False,
            Pid=123,ExitCode=0,Error='',StartedAt='2026-11-07T01:00:00Z',FinishedAt='0001-01-01T00:00:00Z') for cid in self.ids.values()}
        self.runtime=SimpleNamespace(manifest_path=self.control/'manifest.json',digest='a'*64,
            project='santa-zentral-eval-'+'b'*12,environment={},stopping=True,backup_ready=True,
            supervisor_lock_fd=self.lock.fileno(),cleanup_ids=tuple(self.ids.values()),helpers=set(),
            command=['docker','--host','unix:///var/run/docker.sock','compose'],
            data={'services':{'web':{'image':'sha256:'+'c'*64}}},
            inspect=Mock(return_value=self.ids),container_generation=Mock(),stop_helpers=Mock())
        self.runtime.call=self.call
        self.request=dict(scope='azd-santa-backup-maintenance-v1',operation_id='d'*32,manifest_sha256='a'*64,
            generation_sha256='e'*64,target={'VmId':'selected','VmInstanceId':'selected'},boot_id='f'*36,
            recipient_sha256='1'*64,destination=str(self.root/'absent-output'),maximum_bytes=1000000,
            maximum_files=100,seconds=60,storage_sha256='3'*64,queue_inventory=[dict(name='events',durable=True,auto_delete=False,messages_ready=0,messages_unacknowledged=0)])
        (self.control/'backup-request.json').write_text('machine fixture')
        self.native_path=ROOT/'experiments/server/native_snapshot.py'
        self.writer=native.write_new
        if os.name=='nt':
            def portable(path,value):
                with path.open('xb') as f:f.write(native.encoded(value));f.flush();os.fsync(f.fileno())
            self.writer=portable

    def call(self,label,args,**kwargs):
        self.events.append(label)
        if label=='resume-unit':return SimpleNamespace(stdout='LoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=0\nResult=success\n')
        if label.startswith('close-'):
            for cid in args[6:]:
                name=next(n for n,v in self.ids.items() if v==cid)
                self.states[cid].update(Status='exited',Running=False,Pid=0,ExitCode=(143 if name=='elastic' or (name=='workers' and self.failure=='abrupt-worker') else 0),FinishedAt='2026-11-07T01:01:00Z')
        if label=='selected-states':return SimpleNamespace(stdout=json.dumps([dict(Id=cid,State=self.states[cid]) for cid in args[4:]]))
        if label=='queue-inventory':
            if self.failure=='unknown-queue':return SimpleNamespace(stdout=json.dumps([dict(name='foreign',messages_ready=0,messages_unacknowledged=0)]))
            return SimpleNamespace(stdout=json.dumps([dict(name='events',messages_ready=0,messages_unacknowledged=0)]))
        return SimpleNamespace(stdout='',returncode=0)

    def snapshot_job(self,runtime,checkpoint,path,request_sha,operation,maximum):
        self.events.append('snapshot-submit')
        self.assertFalse(self.states[self.ids['web']]['Running']);self.assertFalse(self.states[self.ids['celery']]['Running'])
        self.assertFalse(self.states[self.ids['workers']]['Running']);self.assertTrue(self.states[self.ids['elastic']]['Running'])
        self.writer(checkpoint/'snapshot-intent.json',{'retained':True})
        if self.failure=='unknown-snapshot':raise TimeoutError('unknown')
        selected=native.plan(request_sha,operation,'A'*22,'9.2.1',['events'],1)
        response={'snapshots':[dict(snapshot=selected['snapshot'],uuid='B'*22,version_id=9039001,version='9.2.0-9.2.1',state='SUCCESS',include_global_state=True,
            failures=[],indices=['events'],shards={'total':1,'successful':1,'failed':0},
            metadata={'azd_santa_binding_sha256':request_sha,'azd_santa_plan_sha256':native.sha(selected)})]}
        self.writer(checkpoint/'native-complete.json',native.completed_snapshot(response,selected))

    def capture(self,runtime,source,selection,path,public,destination,maximum,files,deadline,nmodule,npath,receipt,rpath,cap):
        self.events.append('encrypted-capture')
        self.assertTrue(all(not s['Running'] for s in self.states.values()))
        self.assertEqual(cap.states,self.states);cap.verify(runtime,self.ids)
        self.assertEqual(selection['maintenance_sha256'],'2'*64)
        output=Path(destination);output.mkdir();(output/'backup.sealed').write_bytes(b'synthetic encrypted fixture')
        (output/'complete.json').write_text('{}')
        return output/'backup.sealed'

    def run_flow(self):
        real_drain=native.drain;clock=[0]
        def drain(*args,**kwargs):
            return real_drain(*args,**kwargs,clock=lambda:clock[0],sleep=lambda n:clock.__setitem__(0,clock[0]+n))
        with patch.object(backup,'_request',return_value=(self.request,'2'*64,b'public')), \
             patch.object(backup,'host_identity',return_value={'boot_id':'f'*36}), \
             patch.object(backup,'_native_module',return_value=(native,self.native_path)), \
             patch.object(backup,'_bounded_calls',side_effect=lambda r,d:r.call), \
             patch.object(backup,'_dedicated'),patch.object(backup,'volume_paths',return_value={}), \
             patch.object(backup,'storage_fingerprint',return_value='3'*64), \
             patch.object(backup,'checked_file',side_effect=lambda p,**kw:Path(p)), \
             patch.object(backup,'load_controller',return_value=SimpleNamespace()), \
             patch.object(backup,'_snapshot_job',side_effect=self.snapshot_job), \
             patch.object(backup,'_worker_join_proof',side_effect=lambda *a: (_ for _ in ()).throw(ValueError('held')) if self.failure=='missing-worker-proof' else {'offline_mock_only':True}), \
             patch.object(backup,'_capture_locked',side_effect=self.capture), \
             patch.object(native,'archive_roots',return_value={}),patch.object(native,'write_new',side_effect=self.writer), \
             patch.object(native,'drain',side_effect=drain),patch.object(backup.signal,'signal'), \
             patch.object(backup.signal,'SIGALRM',getattr(backup.signal,'SIGALRM',14),create=True),patch.object(backup.signal,'alarm',create=True):
            return backup.stop_capture(self.runtime)

    def test_ordered_native_backup_binds_originals_and_mints_only_process_local_capture_capability(self):
        self.assertTrue(self.run_flow())
        self.assertLess(self.events.index('close-web-celery'),self.events.index('queue-inventory'))
        self.assertLess(self.events.index('close-workers'),self.events.index('snapshot-submit'))
        self.assertLess(self.events.index('snapshot-submit'),self.events.index('close-elastic'))
        self.assertLess(self.events.index('close-rabbitmq-redis-db'),self.events.index('encrypted-capture'))
        operation=self.control/('backup-'+'d'*32)
        self.assertTrue((operation/'drain-complete.json').exists());self.assertTrue((operation/'stop-complete.json').exists())
        self.assertTrue((operation/'maintenance-complete.json').exists())
        with self.assertRaises(ValueError):backup._MaintenanceCapability(self.runtime,self.ids,self.states,'2'*64,object())

    def test_unknown_snapshot_retains_intent_never_captures_or_resubmits_on_reentry(self):
        self.failure='unknown-snapshot'
        with self.assertRaises(TimeoutError):self.run_flow()
        operation=self.control/('backup-'+'d'*32)
        self.assertTrue((operation/'snapshot/snapshot-intent.json').exists())
        self.assertFalse((operation/'maintenance-complete.json').exists());self.assertNotIn('encrypted-capture',self.events)
        submits=self.events.count('snapshot-submit')
        with self.assertRaises(FileExistsError):self.run_flow()
        self.assertEqual(self.events.count('snapshot-submit'),submits)

    def test_unknown_queue_cannot_advance_to_worker_stop_snapshot_or_capture(self):
        self.failure='unknown-queue'
        with self.assertRaises(ValueError):self.run_flow()
        self.assertNotIn('close-workers',self.events);self.assertNotIn('snapshot-submit',self.events)
        self.assertFalse(Path(self.request['destination']).exists())

    def test_abrupt_worker_parent_exit_blocks_native_submission_and_capture(self):
        self.failure='abrupt-worker'
        with self.assertRaises(ValueError):self.run_flow()
        self.assertIn('close-workers',self.events)
        self.assertNotIn('snapshot-submit',self.events);self.assertNotIn('encrypted-capture',self.events)
        self.assertFalse((self.control/('backup-'+'d'*32)/'worker-stop-complete.json').exists())

    def test_zero_exit_without_reviewed_child_join_proof_still_blocks_native_snapshot(self):
        self.failure='missing-worker-proof'
        with self.assertRaises(ValueError):self.run_flow()
        self.assertNotIn('snapshot-submit',self.events);self.assertNotIn('encrypted-capture',self.events)
        with self.assertRaisesRegex(ValueError,'not integrated'):
            backup._worker_join_proof(self.runtime,self.ids['workers'],self.states[self.ids['workers']],'2'*64)

    def test_pending_startup_is_blocked_without_minting_completion_or_resume(self):
        with patch.object(backup,'_request',return_value=(self.request,'2'*64,b'public')),patch.object(backup,'checked_file',side_effect=lambda p,**kw:Path(p)):
            with self.assertRaises(FileNotFoundError):backup.startup_allowed(self.runtime)
        self.assertFalse((self.control/'resume-authorized.json').exists())

    def test_normal_stop_without_request_keeps_authorized_cleanup_and_never_loads_backup(self):
        r=service.Runtime.__new__(service.Runtime);r.stopping=True;r.backup_ready=True;r.supervisor_lock_fd=7
        r.manifest_path=self.control/'manifest.json';r.cleanup_ids=('1'*64,);r.stop_helpers=Mock();r.backup_module=Mock()
        r.call=Mock(return_value=SimpleNamespace(stdout='1'*64))
        (self.control/'backup-request.json').unlink();r.stop()
        r.backup_module.assert_not_called();self.assertEqual(r.call.call_args.args[0],'stop')

    def test_failed_maintenance_preserves_authorized_stop_cleanup(self):
        r=service.Runtime.__new__(service.Runtime);r.stopping=True;r.backup_ready=True;r.supervisor_lock_fd=7
        r.manifest_path=self.control/'manifest.json';r.cleanup_ids=('1'*64,);r.stop_helpers=Mock()
        r.backup_module=Mock(return_value=SimpleNamespace(stop_capture=Mock(side_effect=TimeoutError('unknown'))))
        r.call=Mock(return_value=SimpleNamespace(stdout='1'*64))
        with self.assertRaises(TimeoutError):r.stop()
        self.assertEqual(r.call.call_args.args[0],'stop');self.assertEqual(r.call.call_args.args[1][6:],['1'*64])

    def test_native_helper_uses_only_bound_image_and_checkpoint_source_mounts_then_checks_cleanup(self):
        class PathInput:
            def __init__(self,value):self.value=value
            def __str__(self):return self.value
            def read_bytes(self):return b'reviewed stdlib-only source'
        r=self.runtime;r.call=Mock(return_value=SimpleNamespace(stdout=''));r.stop_helpers=Mock()
        r.binding={'helpers_sha256':{'native_snapshot.py':backup.digest(b'reviewed stdlib-only source')}}
        backup._snapshot_job(r,PathInput('/private/checkpoint'),PathInput('/private/native.py'),'a'*64,'b'*32,1000000)
        args=r.call.call_args.args[1];mounts=[args[i+1] for i,v in enumerate(args) if v=='--mount']
        self.assertEqual(len(mounts),2);self.assertIn('readonly',mounts[1])
        self.assertNotIn('migration.env',' '.join(args));self.assertNotIn('runtime.env',' '.join(args))
        self.assertIn('--cap-drop',args);self.assertIn('--read-only',args);self.assertIn('-S',args)
        r.stop_helpers.assert_called_once()

    def test_resume_requires_matching_completed_ciphertext_and_is_not_automatically_replayed(self):
        import hashlib
        operation=self.control/('backup-'+'d'*32);operation.mkdir()
        output=Path(self.request['destination']);output.mkdir();body=b'only synthetic ciphertext'
        (output/'backup.sealed').write_bytes(body)
        receipt=dict(maintenance_sha256='2'*64,generation_sha256='e'*64,ciphertext_sha256=hashlib.sha256(body).hexdigest(),ciphertext_bytes=len(body))
        (output/'complete.json').write_bytes(backup.encoded(receipt))
        complete=dict(request_sha256='2'*64,generation_sha256='e'*64,ciphertext_receipt_sha256=backup.digest((output/'complete.json').read_bytes()))
        (operation/'maintenance-complete.json').write_bytes(backup.encoded(complete))
        for name,cid in self.ids.items():self.states[cid].update(Status='exited',Running=False,Pid=0,ExitCode=(143 if name=='elastic' or (name=='workers' and self.failure=='abrupt-worker') else 0))
        (operation/'stop-complete.json').write_bytes(backup.encoded({'states':self.states}))
        unit=self.control/'unit';unit.write_text('reviewed-unit')
        source=SimpleNamespace(UNIT=unit,__file__='/private/runtime_service.py',unit_text=lambda *a:'reviewed-unit')
        fcntl=ModuleType('fcntl');fcntl.flock=Mock();fcntl.LOCK_EX=1;fcntl.LOCK_NB=2
        with patch.object(backup,'_request',return_value=(self.request,'2'*64,b'public')), \
             patch.object(backup,'checked_file',side_effect=lambda p,**kw:Path(p)), \
             patch.object(backup,'_native_module',return_value=(native,self.native_path)),patch.object(native,'write_new',side_effect=self.writer), \
             patch.object(backup,'load_controller',return_value=source),patch.object(backup,'_bounded_calls',side_effect=lambda r,d:r.call), \
             patch.dict(sys.modules,{'fcntl':fcntl}),patch.object(backup.signal,'signal'),patch.object(backup.signal,'alarm',create=True), \
             patch.object(backup.signal,'SIGALRM',getattr(backup.signal,'SIGALRM',14),create=True):
            (output/'backup.sealed').write_bytes(b'changed')
            with self.assertRaises(ValueError):backup.resume_original(self.runtime)
            self.assertNotIn('explicit-backup-resume',self.events)
            self.assertFalse((operation/'resume-authorized.json').exists())
            (output/'backup.sealed').write_bytes(body)
            backup.resume_original(self.runtime)
            self.assertEqual(self.events.count('explicit-backup-resume'),1)
            with self.assertRaises(FileExistsError):backup.resume_original(self.runtime)
            self.assertEqual(self.events.count('explicit-backup-resume'),1)


if __name__=='__main__':unittest.main()
