"""Synthetic exact-case recovery protocol; no real systemd/Docker/IMDS/cgroups."""
import base64
import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from types import ModuleType,SimpleNamespace
import unittest
from unittest.mock import Mock,patch

REPO=Path(__file__).resolve().parents[1]
def module(name):
    spec=importlib.util.spec_from_file_location('test_'+name,REPO/'experiments/server'/(name+'.py'))
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
r=module('presnapshot_recovery')


class Recovery(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name).resolve()
        self.h=module('helper_upgrade');self.recoveries=self.root/'presnapshot-recoveries';self.recoveries.mkdir()
        self.control=self.root/'private-runtime-synthetic/runtime-service';self.control.mkdir(parents=True)
        self.manifest=self.control/'manifest.json';self.unitfile=self.root/'runtime.service';self.unitfile.write_bytes(b'old unit')
        self.ids={name:format(i+1,'064x') for i,name in enumerate(('web','workers','celery','db','redis','rabbitmq','elastic'))}
        self.target={'EnvironmentName':'synthetic','VmId':'synthetic-vm','VmInstanceId':'synthetic-instance'}
        self.generation_token='d'*32;self.enabled='enabled';self.boot=r.BOOT;self.fs='cgroup2fs';self.actions=[];self.fail=None
        self.data=self.root/'preserved-history';self.data.write_bytes(b'keep every original historical record')
        self.cg=self.root/'cgroup';(self.cg/'system.slice').mkdir(parents=True)
        for base in (self.cg,self.cg/'system.slice'):
            (base/'cgroup.controllers').write_bytes(b'cpuset cpu io memory hugetlb pids rdma misc dmem\n')
        (self.cg/'system.slice/cgroup.events').write_bytes(b'populated 1\nfrozen 0\n')
        (self.cg/'system.slice/cgroup.type').write_bytes(b'domain\n')
        self.volumes={name:self.root/name for name in ('postgres_data','redis_data','rabbitmq_data','elasticsearch_data','media_data','elasticsearch_snapshots')}
        for path in self.volumes.values():path.mkdir()
        self.local_mounts={name:{'device':123,'inode':i+1,'mount':{'id':28,'parent':1,'point':'/','root':'/','filesystem':'ext4','source':'/dev/root','optional':['shared:1']}} for i,name in enumerate(self.volumes)}
        self.oldbytes=b'# synthetic known old helper';old_hash=r.sha(self.oldbytes)
        body={'controller_sha256':r.CONTROLLER,'helpers_sha256':{'cold_backup.py':old_hash},'files':{'config':'unchanged'},
              'worker_hashes':{'worker':'unchanged'},'policy_hashes':{'security':'unchanged'},'project':'original-project'}
        self.manifest.write_bytes(r.encoded(body));mfhash=r.sha(self.manifest.read_bytes())
        generation={'manifest_sha256':mfhash,'generation':self.generation_token,'container_ids':self.ids,'project':'original-project','image_id':'sha256:'+'e'*64}
        self.anchor=self.control/'container-generation.json';self.anchor.write_bytes(r.encoded(generation));genhash=r.sha(self.anchor.read_bytes())
        (self.control/'supervisor.lock').write_bytes(b'')
        self.request={'scope':'azd-santa-backup-maintenance-v1','operation_id':r.BACKUP_OPERATION,'boot_id':r.BOOT,
            'target':{'VmId':self.target['VmId'],'VmInstanceId':self.target['VmInstanceId']},'manifest_sha256':mfhash,
            'generation_sha256':genhash,'backup_program_sha256':old_hash,'storage_sha256':'a'*64,
            'destination':str(self.root/'ciphertext-cold3-20261114'),'worker_instance':{'container_id':self.ids['workers'],'started_at':'original-start'},
            'recipient_sha256':'f'*64,'maximum_bytes':2147483648,'maximum_files':100000,'seconds':1800}
        self.request_path=self.control/'backup-request.json';self.request_path.write_bytes(r.encoded(self.request));reqhash=r.sha(self.request_path.read_bytes())
        self.backup_op=self.control/('backup-'+r.BACKUP_OPERATION);self.backup_op.mkdir()
        intent={'generation_sha256':genhash,'request_sha256':reqhash}
        failed={'request_sha256':reqhash,'error_type':'ValueError','automatic_replay':False}
        (self.backup_op/'maintenance-intent.json').write_bytes(r.encoded(intent));(self.backup_op/'maintenance-failed.json').write_bytes(r.encoded(failed))
        self.failed_files={name:r.sha((self.backup_op/name).read_bytes()) for name in r.FAILED_FILES}
        job=self.root/'native-backup-cold3-20261114';job.mkdir();self.context_path=job/'context.json';self.recorder=job/'record-terminal.py'
        context=dict(destination=self.request['destination'],generation_sha256=genhash,manifest=str(self.manifest),manifest_sha256=mfhash,
            maximum_bytes=2147483648,recipient_sha256='f'*64,scope='privatehook3-native-backup-job-v1',seconds=1800,
            unit=r.CALLER,vm_id=self.target['VmId'],vm_instance_id=self.target['VmInstanceId'])
        self.context_path.write_bytes(r.encoded(context));self.recorder.write_bytes(b'# terminal-only fixture')
        self.fragment=b'known immutable caller fragment'
        base=dict(MainPID='0',Result='exit-code',ExecMainCode='1',ExecMainStatus='1',ExecStart='fixed-source-command',ExecStopPost='fixed-recorder',
            LoadState='loaded',ActiveState='failed',SubState='failed',FragmentPath='/run/systemd/transient/'+r.CALLER,DropInPaths='',Job='',
            InvocationID=r.CALLER_INVOCATION,ControlGroup='',Slice='system.slice',KillMode='control-group',Delegate='no',Restart='no',Type='oneshot')
        self.caller=base.copy();self.runtime_state={**base,'FragmentPath':str(self.unitfile),'InvocationID':r.RUNTIME_INVOCATION,
            'Restart':'on-failure','Type':'notify','NoNewPrivileges':'yes','PrivateTmp':'yes','ProtectHome':'yes'}
        self.rows=[dict(Id=cid,State=dict(Status='exited',Running=False,Paused=False,Restarting=False,OOMKilled=False,Error='',Pid=0,
            ExitCode=1 if name=='workers' else 143 if name=='elastic' else 0,StartedAt='original-start',FinishedAt='original-stop')) for name,cid in self.ids.items()]
        files=module('private_install_transport').FILES
        bodies={name:(REPO/'experiments/server'/name).read_bytes() for name in files};bodies['cold_backup.py']=self.oldbytes
        self.package={'scope':'private-azd-source-v1','files':self.entries(bodies)};oldraw=r.encoded(self.package);old_bundle=r.sha(oldraw)
        self.oldfolder=self.root/'helper-upgrades/bundles'/old_bundle;self.oldfolder.mkdir(parents=True)
        (self.oldfolder/'bundle.json').write_bytes(oldraw)
        for name,raw in bodies.items():(self.oldfolder/name).write_bytes(raw)
        newbodies={**bodies,'cold_backup.py':(REPO/'experiments/server/cold_backup.py').read_bytes()}
        self.newpackage={'scope':self.package['scope'],'files':self.entries(newbodies)};newraw=r.encoded(self.newpackage)
        self.folder=self.oldfolder.parent/r.sha(newraw);self.folder.mkdir();(self.folder/'bundle.json').write_bytes(newraw)
        for name,raw in newbodies.items():(self.folder/name).write_bytes(raw)
        self.old_upgrade={'container_ids':self.ids,'generation':self.generation_token,'image_id':generation['image_id']}
        self.controller=SimpleNamespace(UNIT=self.unitfile,DOCKER=['docker','--host','unix:///var/run/docker.sock'],
            Runtime=self.runtime,load_manifest=self.load_manifest,
            unit_text=lambda script,manifest,digest:'unit '+str(script)+' '+str(manifest)+' '+digest)
        self.backup=SimpleNamespace(_request=self.read_request,host_identity=lambda target:{'boot_id':self.boot},
            storage_fingerprint=lambda runtime:'a'*64,volume_paths=lambda runtime:self.volumes,mount_snapshot=lambda paths:copy.deepcopy(self.local_mounts))
        self.original_read=self.h.read
        self.patches=[patch.object(r,'ROOT',self.root),patch.object(r,'RECOVERIES',self.recoveries),patch.object(r,'ACTIVE',self.recoveries/'active.json'),
            patch.object(r,'CGROUP',self.cg),patch.object(r,'OLD',old_hash),patch.object(r,'OLD_BUNDLE',old_bundle),
            patch.object(r,'OLD_MANIFEST',mfhash),patch.object(r,'OLD_GENERATION',genhash),patch.object(r,'OLD_UNIT',r.sha(self.unitfile.read_bytes())),
            patch.object(r,'REQUEST',reqhash),patch.object(r,'FAILED_FILES',self.failed_files),patch.object(r,'CALLER_FRAGMENT',r.sha(self.fragment)),
            patch.object(r,'CALLER_CONTEXT',r.sha(self.context_path.read_bytes())),patch.object(r,'RECORDER',r.sha(self.recorder.read_bytes())),
            patch.object(r,'CALLER_PROFILE',r.sha(r.encoded({k:self.caller[k] for k in r.PROFILE_FIELDS}))),
            patch.object(r,'library',return_value=self.h),patch.object(r,'historical_upgrade',return_value=(self.old_upgrade,self.oldfolder,self.package)),
            patch.object(self.h,'ROOT',self.root),patch.object(self.h,'checked',side_effect=lambda p,**k:Path(p)),patch.object(self.h,'sync'),
            patch.object(self.h,'read',side_effect=self.read),patch.object(self.h,'load',side_effect=lambda folder,name:self.backup if name=='cold_backup' else self.controller),
            patch.object(self.h,'history_unchanged'),patch.object(self.h,'command',side_effect=self.command),
            patch.object(self.h.os,'O_NOFOLLOW',getattr(os,'O_NOFOLLOW',0),create=True)]
        for p in self.patches:p.start();self.addCleanup(p.stop)
        fcntl=ModuleType('fcntl');fcntl.LOCK_EX=1;fcntl.LOCK_NB=2;fcntl.flock=lambda *args:self.actions.append('flock')
        p=patch.dict(sys.modules,{'fcntl':fcntl});p.start();self.addCleanup(p.stop)

    def entries(self,bodies):return {name:{'sha256':r.sha(body),'base64':base64.b64encode(body).decode()} for name,body in bodies.items()}
    def read_request(self,runtime):
        raw=self.request_path.read_bytes();return json.loads(raw),r.sha(raw),b'public fixture'
    def runtime(self,path,digest):
        self.load_manifest(path,digest)
        return SimpleNamespace(inspect=lambda **kw:self.ids,container_generation=lambda ids:json.loads(self.anchor.read_bytes()))
    def load_manifest(self,path,digest):
        r.need(r.sha(Path(path).read_bytes())==digest)
    def read(self,path,maximum=2*1024**2):
        path=Path(path)
        if path.name==r.CALLER:return self.fragment
        if path.name=='cmdline':
            return b'python3\0'+b'\0'.join(str(v).encode() for v in ('-I',self.folder/'runtime_service.py','run','--manifest',str(self.manifest),'--sha256',r.sha(self.manifest.read_bytes())) )+b'\0'
        return self.original_read(path,maximum)
    def command(self,args,timeout=30):
        if args[0]=='/usr/bin/stat':return self.fs+'\n'
        if args[0]=='docker':
            if 'ps' in args:return '\n'.join(self.ids.values())
            if 'inspect' in args:return json.dumps(self.rows)
        if args[:2]==['systemctl','show']:
            if '--value' in args:return self.enabled+'\n'
            values=self.caller if args[2]==r.CALLER else self.runtime_state
            fields=next(v.split('=',1)[1].split(',') for v in args if v.startswith('--property='))
            return '\n'.join(k+'='+values[k] for k in fields if k in values)
        self.actions.append(args[1])
        if self.fail==args[1]:raise TimeoutError('injected unknown result')
        if args[:2]==['systemctl','disable']:self.enabled='disabled'
        if args[:2]==['systemctl','enable']:self.enabled='enabled'
        if args[:2]==['systemctl','reset-failed']:self.runtime_state.update(ActiveState='inactive',SubState='dead',Result='success')
        if args[:2]==['systemctl','start']:
            self.runtime_state.update(ActiveState='active',SubState='running',MainPID='43',InvocationID='e'*32,Result='success')
            for row in self.rows:row['State'].update(Status='running',Running=True,Pid=100)
        return ''

    def test_exact_positive_eligibility_is_stopped_process_proof_not_clean_worker_backup(self):
        proof,_=r.eligibility(self.h,self.target)
        self.assertEqual(proof['stopped_states'][self.ids['workers']]['ExitCode'],1)
        self.assertEqual({p.name for p in self.backup_op.iterdir()},set(self.failed_files));self.assertEqual(self.actions,[])

    def test_missing_manager_fields_or_wrong_invocation_never_become_no_pending_work(self):
        for key,value in (('Job',None),('MainPID','3'),('InvocationID','f'*32),('ActiveState','activating'),('ExecStopPost','different recorder')):
            old=copy.deepcopy(self.caller)
            if value is None:self.caller.pop(key)
            else:self.caller[key]=value
            with self.assertRaises(ValueError):r.eligibility(self.h,self.target)
            self.caller=old
        self.assertEqual(self.actions,[])

    def test_missing_or_non_kernel_cgroup_and_populated_descendants_reject(self):
        self.fs='tmpfs'
        with self.assertRaises(ValueError):r.eligibility(self.h,self.target)
        self.fs='cgroup2fs';(self.cg/'cgroup.controllers').unlink()
        with self.assertRaises(FileNotFoundError):r.eligibility(self.h,self.target)
        (self.cg/'cgroup.controllers').write_bytes(b'cpuset cpu io memory hugetlb pids rdma misc dmem\n')
        group=self.cg/'system.slice'/r.CALLER;group.mkdir();(group/'cgroup.events').write_bytes(b'populated 1\n')
        self.caller['ControlGroup']='/system.slice/'+r.CALLER
        with self.assertRaises(ValueError):r.eligibility(self.h,self.target)

    def test_nonroot_hierarchy_attestation_and_empty_unit_group_are_positive_proof(self):
        self.assertFalse((self.cg/'cgroup.events').exists())
        group=self.cg/'system.slice'/r.CALLER;group.mkdir()
        (group/'cgroup.events').write_bytes(b'populated 0\nfrozen 0\n')
        self.caller['ControlGroup']='/system.slice/'+r.CALLER
        r.failed_unit(self.h,r.CALLER,r.CALLER_INVOCATION,'no')
        (self.cg/'system.slice/cgroup.type').write_bytes(b'threaded\n')
        with self.assertRaises(ValueError):r.failed_unit(self.h,r.CALLER,r.CALLER_INVOCATION,'no')

    def test_boot_request_fingerprint_or_unknown_process_state_rejects(self):
        self.boot='different-boot'
        with self.assertRaises(ValueError):r.eligibility(self.h,self.target)
        self.boot=r.BOOT;self.backup.storage_fingerprint=lambda runtime:'b'*64
        with self.assertRaises(ValueError):r.eligibility(self.h,self.target)
        self.backup.storage_fingerprint=lambda runtime:'a'*64;self.rows[0]['State']['OOMKilled']=True
        with self.assertRaises(ValueError):r.eligibility(self.h,self.target)

    def test_any_native_checkpoint_or_repository_content_or_cipher_outcome_rejects(self):
        snapshot=self.backup_op/'snapshot';snapshot.mkdir()
        with self.assertRaises(ValueError):r.eligibility(self.h,self.target)
        snapshot.rmdir();entry=self.volumes['elasticsearch_snapshots']/'unexpected';entry.write_bytes(b'do not discard')
        with self.assertRaises(ValueError):r.eligibility(self.h,self.target)
        entry.unlink();Path(self.request['destination']).mkdir()
        with self.assertRaises(ValueError):r.eligibility(self.h,self.target)
        self.assertTrue(self.request_path.exists());self.assertEqual(self.actions,[])

    def test_derive_preserves_all_other_fields_and_original_generation_token(self):
        old=self.manifest.read_bytes();gen=self.anchor.read_bytes();new,newgen=r.derive(json.loads(old),json.loads(gen))
        restored=json.loads(new);restored['helpers_sha256']['cold_backup.py']=r.OLD
        self.assertEqual(r.encoded(restored),old)
        restored_gen=json.loads(newgen);restored_gen['manifest_sha256']=r.OLD_MANIFEST
        self.assertEqual(r.encoded(restored_gen),gen)

    def test_candidate_rejects_any_second_source_change_before_retirement(self):
        intent={'candidate':str(self.folder),'bundle_sha256':self.folder.name}
        r.verify_candidate(self.h,intent)
        (self.folder/'runtime_service.py').write_bytes(b'unknown controller')
        with self.assertRaises(ValueError):r.verify_candidate(self.h,intent)
        self.assertEqual(self.actions,[]);self.assertTrue(self.request_path.exists())

    def prepared(self):
        intent=r.prepare(self.h,self.target,self.folder);operation=Path(intent['operation'])
        return intent,operation,r.sha((operation/'intent.json').read_bytes())

    def test_one_explicit_retirement_no_second_stop_no_backup_resume_preserves_all_bytes(self):
        original=self.request_path.read_bytes();failed={p.name:p.read_bytes() for p in self.backup_op.iterdir()}
        intent,operation,digest=self.prepared();r.execute(operation/'intent.json',digest)
        self.assertFalse(self.request_path.exists());self.assertEqual((operation/'retired-request.json').read_bytes(),original)
        self.assertEqual((operation/'request-preserved.json').read_bytes(),original)
        self.assertEqual({p.name:p.read_bytes() for p in self.backup_op.iterdir()},failed)
        self.assertEqual(self.data.read_bytes(),b'keep every original historical record')
        self.assertEqual(json.loads(self.anchor.read_bytes())['generation'],self.generation_token)
        self.assertNotIn('stop',self.actions);self.assertEqual(self.actions.count('start'),1)
        self.assertLess(self.actions.index('disable'),self.actions.index('flock'))
        self.assertLess(self.actions.index('flock'),self.actions.index('reset-failed'))
        self.assertTrue((operation/'complete.json').exists());self.assertFalse((operation/'terminal-success.json').exists())
        receipt=json.loads((operation/'complete.json').read_bytes())
        self.assertFalse(receipt['old_backup_completed']);self.assertFalse(receipt['clean_worker_proof']);self.assertFalse(receipt['new_backup_requested'])

    def test_interruption_after_retirement_retains_disabled_hold_and_never_replays(self):
        intent,operation,digest=self.prepared();replace=self.h.replace_bound
        def interrupted(path,old,raw):
            if path.name=='container-generation.json':raise OSError('fault after manifest')
            return replace(path,old,raw)
        with patch.object(self.h,'replace_bound',side_effect=interrupted):
            with self.assertRaises(OSError):r.execute(operation/'intent.json',digest)
        self.assertEqual(self.enabled,'disabled');self.assertTrue((operation/'retired-request.json').exists())
        self.assertFalse((operation/'complete.json').exists());self.assertNotIn('start',self.actions)
        with self.assertRaises(ValueError):r.execute(operation/'intent.json',digest)
        self.assertEqual(self.actions.count('disable'),1)

    def test_corrupt_snapshot_or_new_evidence_blocks_before_any_mutation(self):
        intent,operation,digest=self.prepared();(operation/'new-generation.json').write_bytes(b'corrupt')
        with self.assertRaises(ValueError):r.execute(operation/'intent.json',digest)
        self.assertEqual(self.actions,[]);self.assertTrue(self.request_path.exists())

    def test_retirement_failure_keeps_canonical_request_and_never_promotes_or_starts(self):
        intent,operation,digest=self.prepared()
        with patch.object(r.os,'rename',side_effect=OSError('rename unknown')):
            with self.assertRaises(OSError):r.execute(operation/'intent.json',digest)
        self.assertTrue(self.request_path.exists());self.assertTrue((operation/'request-preserved.json').exists())
        self.assertEqual(self.enabled,'disabled');self.assertNotIn('start',self.actions)

    def test_unknown_start_keeps_new_tuple_but_has_no_success_or_replay(self):
        intent,operation,digest=self.prepared();self.fail='start'
        with self.assertRaises(TimeoutError):r.execute(operation/'intent.json',digest)
        self.assertEqual(self.actions.count('start'),1);self.assertFalse((operation/'complete.json').exists())
        with self.assertRaises(ValueError):r.execute(operation/'intent.json',digest)
        self.assertEqual(self.actions.count('start'),1)

    def test_terminal_success_requires_actual_environment_and_typed_non_backup_receipt(self):
        intent,operation,digest=self.prepared();r.execute(operation/'intent.json',digest)
        env={'SERVICE_RESULT':'success','EXIT_CODE':'exited','EXIT_STATUS':'0','INVOCATION_ID':'f'*32}
        with patch.dict(os.environ,{**env,'EXIT_STATUS':'1'}):
            with self.assertRaises(ValueError):r.record_terminal(operation/'intent.json',digest)
        with patch.dict(os.environ,env):r.record_terminal(operation/'intent.json',digest)
        self.assertTrue((operation/'terminal-success.json').exists())

    def test_observer_hard_failure_and_completion_without_terminal_proof_stay_closed(self):
        intent,operation,digest=self.prepared()
        (operation/'complete.json').write_bytes(r.encoded(r.completion(intent,digest)))
        fields=('LoadState','ActiveState','SubState','Result','ExecMainStatus','MainPID','InvocationID','Job')
        values=dict(LoadState='loaded',ActiveState='inactive',SubState='dead',Result='success',ExecMainStatus='0',MainPID='0',InvocationID='f'*32,Job='')
        with patch.object(r,'unit',return_value=values):self.assertEqual(r.observe(self.h,self.target,self.folder.name)['state'],'unknown')
        (operation/'terminal-success.json').write_bytes(r.encoded(dict(scope='exact-presnapshot-recovery-terminal-v1',intent_sha256=digest,
            completion_sha256=r.sha((operation/'complete.json').read_bytes()),invocation='f'*32)))
        with patch.object(r,'unit',return_value={**values,'Result':'timeout','ActiveState':'failed'}):
            self.assertEqual(r.observe(self.h,self.target,self.folder.name)['state'],'failed')
        with patch.object(r,'unit',return_value=values),patch.object(r,'current_binding') as binding:
            self.assertEqual(r.observe(self.h,self.target,self.folder.name)['state'],'completed');binding.assert_called_once()


class Pins(unittest.TestCase):
    def test_exact_reviewed_source_pins_and_no_generic_gate_bypass(self):
        self.assertEqual(r.sha((REPO/'experiments/server/helper_upgrade.py').read_bytes()),r.LIBRARY_SHA)
        self.assertEqual(r.sha((REPO/'experiments/server/cold_backup.py').read_bytes()),r.NEW)
        self.assertEqual(r.sha((REPO/'experiments/server/runtime_service.py').read_bytes()),r.CONTROLLER)
        source=(REPO/'experiments/server/presnapshot_recovery.py').read_text()
        self.assertNotIn("['systemctl','stop'",source)
        self.assertNotIn('bind_admission_fresh(',source);self.assertNotIn('startup_allowed=',source)
        self.assertLessEqual(len(source.encode()),32768)


if __name__=='__main__':unittest.main()
