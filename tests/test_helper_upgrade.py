"""Offline upgrade protocol tests; systemd/Docker/IMDS/ownership are doubles."""
import base64
import copy
import gzip
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('helper_upgrade', ROOT/'experiments/server/helper_upgrade.py')
upgrade = importlib.util.module_from_spec(spec); spec.loader.exec_module(upgrade)


class Upgrade(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve(); self.upgrades = self.root/'helper-upgrades'; self.upgrades.mkdir()
        self.control = self.root/'private-runtime-test/runtime-service'; self.control.mkdir(parents=True)
        self.old = self.root/'installers'/('a'*64); self.old.mkdir(parents=True)
        self.candidate = self.upgrades/'bundles'/('b'*64); self.candidate.mkdir(parents=True)
        self.unit = self.root/'runtime.service'; self.unit.write_bytes(b'old-unit')
        self.ids = {n:format(i+1,'064x') for i,n in enumerate(('web','workers','celery','db','redis','rabbitmq','elastic'))}
        self.target = {'VmId':'synthetic-vm','VmInstanceId':'synthetic-instance'}
        self.manifest = dict(controller_sha256=upgrade.CONTROLLER, helpers_sha256={'cold_backup.py':upgrade.OLD},
            files={'config':'preserved'}, policy_hashes={'policy':'unchanged'}, project='preserved-project', worker_hashes={'worker':'same'})
        self.manifest_path = self.control/'manifest.json'; self.manifest_path.write_bytes(upgrade.encoded(self.manifest))
        self.generation = dict(manifest_sha256=upgrade.sha(upgrade.encoded(self.manifest)), generation='c'*32,
            container_ids=self.ids, image_id='sha256:'+'d'*64, project='preserved-project')
        (self.control/'container-generation.json').write_bytes(upgrade.encoded(self.generation))
        (self.control/'supervisor.lock').write_bytes(b'')
        self.data = self.root/'original-data'; self.data.write_bytes(b'complete historical sentinel')
        self.state = dict(LoadState='loaded',ActiveState='active',SubState='running',MainPID='42',Result='success',Job='')
        self.events = []; self.fail = None
        self.enabled='enabled'
        self.snapshot = dict(target=self.target, boot_id='boot', old_bundle_sha256=self.old.name,
            manifest_path=str(self.manifest_path), old_manifest_sha256=upgrade.sha(self.manifest_path.read_bytes()),
            old_generation_sha256=upgrade.sha((self.control/'container-generation.json').read_bytes()),
            old_unit_sha256=upgrade.sha(self.unit.read_bytes()), container_ids=self.ids, generation='c'*32,
            image_id=self.generation['image_id'], project='preserved-project', old_main_pid='42',old_unit_enabled='enabled',
            historical_sha256={str(self.data):upgrade.sha(self.data.read_bytes())})
        self.controller = SimpleNamespace(UNIT=self.unit, DOCKER=['docker','--host','unix:///var/run/docker.sock'],
            unit_text=lambda script,manifest,digest:'unit '+str(script)+' '+str(manifest)+' '+digest,
            Runtime=self.runtime)
        self.patches = [patch.object(upgrade,'ROOT',self.root), patch.object(upgrade,'UPGRADES',self.upgrades),
            patch.object(upgrade,'ACTIVE',self.upgrades/'active.json'), patch.object(upgrade,'checked',side_effect=lambda p,**k:Path(p)),
            patch.object(upgrade,'sync'), patch.object(upgrade.os,'O_NOFOLLOW',getattr(os,'O_NOFOLLOW',0),create=True),
            patch.object(upgrade,'load',return_value=self.controller), patch.object(upgrade,'baseline',return_value=self.snapshot),
            patch.object(upgrade,'candidate_matches',side_effect=lambda intent:self.events.append('candidate-check')),
            patch.object(upgrade,'command',side_effect=self.command), patch.object(upgrade,'unit_state',side_effect=lambda:self.state.copy())]
        self.patches.append(patch.object(upgrade,'unit_enabled',side_effect=lambda:self.enabled))
        self.patches.append(patch.object(upgrade,'effective_unit'))
        for p in self.patches: p.start(); self.addCleanup(p.stop)
        fcntl = ModuleType('fcntl'); fcntl.LOCK_EX=1; fcntl.LOCK_NB=2
        fcntl.flock=lambda *args:self.events.append('flock')
        self.modules=patch.dict(sys.modules,{'fcntl':fcntl}); self.modules.start();self.addCleanup(self.modules.stop)
        self.intent = upgrade.reserve(self.target,self.candidate,Path(upgrade.__file__))
        self.operation=Path(self.intent['operation']); self.intent_path=self.operation/'intent.json'
        self.intent_sha=upgrade.sha(self.intent_path.read_bytes())

    def runtime(self,path,digest):
        self.assertEqual(upgrade.sha(Path(path).read_bytes()),digest)
        return SimpleNamespace(inspect=Mock(return_value=self.ids),
            container_generation=lambda ids:json.loads((self.control/'container-generation.json').read_bytes()),
            call=lambda *a,**k:SimpleNamespace(stdout=json.dumps([dict(Id=cid,State=dict(Running=False,Paused=False,Restarting=False,Pid=0)) for cid in self.ids.values()])))

    def command(self,args,timeout=30):
        self.events.append(args[1] if args[0]=='systemctl' else args[0])
        if args[:2]==['systemctl','disable']:self.enabled='disabled'
        if args[:2]==['systemctl','enable']:self.enabled='enabled'
        if args[:2]==['systemctl','stop']:
            if self.fail=='stop': raise TimeoutError('unknown stop')
            self.state.update(ActiveState='inactive',SubState='dead',MainPID='0')
            if self.fail=='backup-race': (self.control/'backup-request.json').write_bytes(b'preserve request')
        if args[:2]==['systemctl','daemon-reload'] and self.fail=='reload': raise RuntimeError('reload failed')
        if args[:2]==['systemctl','start']:
            self.state.update(ActiveState='active',SubState='running',MainPID='43')
            if self.fail=='start': raise TimeoutError('unknown start')
        return ''

    def execute(self):
        original=upgrade.read
        def read(path,maximum=2*1024**2):
            if Path(path).name=='cmdline':
                return b'python3\0'+b'\0'.join(str(v).encode() for v in ('-I',self.candidate/'runtime_service.py','run','--manifest',str(self.manifest_path),'--sha256',self.intent['new_manifest_sha256']))+b'\0'
            return original(path,maximum)
        with patch.object(upgrade,'read',side_effect=read): upgrade.execute(self.intent_path,self.intent_sha)

    def test_exact_transition_preserves_every_other_field_and_generation_token(self):
        before=copy.deepcopy((self.manifest,self.generation))
        raw,anchor=upgrade.derive_transition(self.manifest,self.generation,upgrade.NEW)
        changed=json.loads(raw); changed['helpers_sha256']['cold_backup.py']=upgrade.OLD
        self.assertEqual(changed,self.manifest)
        bound=json.loads(anchor); bound['manifest_sha256']=self.generation['manifest_sha256']
        self.assertEqual(bound,self.generation);self.assertEqual((self.manifest,self.generation),before)
        for digest in ('unknown',upgrade.OLD):
            with self.assertRaises(ValueError): upgrade.derive_transition(self.manifest,self.generation,digest)

    def test_one_stop_then_lock_then_promote_then_one_start_preserves_originals(self):
        self.execute()
        self.assertEqual(self.events.count('stop'),1);self.assertEqual(self.events.count('start'),1)
        self.assertLess(self.events.index('stop'),self.events.index('flock'))
        self.assertLess(self.events.index('disable'),self.events.index('stop'))
        self.assertLess(self.events.index('flock'),self.events.index('daemon-reload'))
        self.assertLess(self.events.index('daemon-reload'),self.events.index('start'))
        self.assertLess(self.events.index('daemon-reload'),self.events.index('enable'))
        self.assertEqual(self.enabled,'enabled')
        self.assertEqual(json.loads((self.control/'container-generation.json').read_bytes())['generation'],'c'*32)
        self.assertEqual(json.loads((self.control/'container-generation.json').read_bytes())['container_ids'],self.ids)
        self.assertEqual(self.data.read_bytes(),b'complete historical sentinel')
        self.assertEqual((self.operation/'old-manifest.json').read_bytes(),upgrade.encoded(self.manifest))
        self.assertTrue((self.operation/'complete.json').is_file());self.assertFalse((self.operation/'terminal-success.json').exists())

    def test_stop_timeout_never_promotes_starts_or_repeats_stop(self):
        self.fail='stop'
        with self.assertRaises(TimeoutError):self.execute()
        self.assertEqual(self.manifest_path.read_bytes(),upgrade.encoded(self.manifest))
        with self.assertRaises(ValueError):self.execute()
        self.assertEqual(self.events.count('stop'),1);self.assertNotIn('start',self.events)
        self.assertTrue((self.operation/'failed.json').is_file())
        self.assertEqual(self.enabled,'disabled')

    def test_backup_request_race_blocks_promotion_without_bypassing_or_deleting(self):
        self.fail='backup-race'
        with self.assertRaises(ValueError):self.execute()
        self.assertEqual((self.control/'backup-request.json').read_bytes(),b'preserve request')
        self.assertEqual(self.manifest_path.read_bytes(),upgrade.encoded(self.manifest));self.assertNotIn('start',self.events)

    def test_corrupt_staged_snapshot_is_rejected_before_stop(self):
        (self.operation/'new-generation.json').write_bytes(b'corrupt')
        with self.assertRaises(ValueError):self.execute()
        self.assertNotIn('stop',self.events);self.assertNotIn('start',self.events)

    def test_partial_promotion_is_retained_closed_without_rollback_or_start(self):
        original=upgrade.replace_bound
        def replace(path,digest,raw):
            if path.name=='container-generation.json':raise OSError('fault')
            return original(path,digest,raw)
        with patch.object(upgrade,'replace_bound',side_effect=replace):
            with self.assertRaises(OSError):self.execute()
        self.assertEqual(upgrade.sha(self.manifest_path.read_bytes()),self.intent['new_manifest_sha256'])
        self.assertEqual((self.control/'container-generation.json').read_bytes(),upgrade.encoded(self.generation))
        self.assertNotIn('start',self.events);self.assertTrue((self.operation/'failed.json').exists())
        self.assertEqual(self.enabled,'disabled')

    def test_reload_or_unknown_start_never_reports_completion_or_retries(self):
        self.fail='reload'
        with self.assertRaises(RuntimeError):self.execute()
        self.assertNotIn('start',self.events);self.assertFalse((self.operation/'complete.json').exists())

    def test_unknown_start_keeps_valid_new_tuple_but_never_claims_terminal_success(self):
        self.fail='start'
        with self.assertRaises(TimeoutError):self.execute()
        self.assertEqual(self.events.count('stop'),1);self.assertEqual(self.events.count('start'),1)
        self.assertEqual(upgrade.sha(self.manifest_path.read_bytes()),self.intent['new_manifest_sha256'])
        self.assertFalse((self.operation/'complete.json').exists());self.assertTrue((self.operation/'failed.json').exists())

    def test_replace_rejects_changed_input_without_overwriting_it(self):
        self.manifest_path.write_bytes(b'changed by other actor')
        with self.assertRaises(ValueError):upgrade.replace_bound(self.manifest_path,self.snapshot['old_manifest_sha256'],b'new')
        self.assertEqual(self.manifest_path.read_bytes(),b'changed by other actor')

    def test_terminal_proof_requires_actual_success_exit_and_binds_invocation(self):
        self.execute()
        env={'SERVICE_RESULT':'success','EXIT_CODE':'exited','EXIT_STATUS':'0','INVOCATION_ID':'f'*32}
        with patch.dict(os.environ,{**env,'EXIT_STATUS':'1'}):
            with self.assertRaises(ValueError):upgrade.record_terminal(self.intent_path,self.intent_sha)
        with patch.dict(os.environ,env):upgrade.record_terminal(self.intent_path,self.intent_sha)
        proof=json.loads((self.operation/'terminal-success.json').read_bytes())
        self.assertEqual(proof['completion_sha256'],upgrade.sha((self.operation/'complete.json').read_bytes()))

    def observation(self,*,result='success',active='inactive',sub='dead',proof=False,loaded='loaded'):
        if proof:
            (self.operation/'complete.json').write_bytes(upgrade.encoded(upgrade.completion(self.intent,self.intent_sha)))
            (self.operation/'terminal-success.json').write_bytes(upgrade.encoded(dict(scope='azd-santa-helper-upgrade-terminal-v1',
                intent_sha256=self.intent_sha,completion_sha256=upgrade.sha((self.operation/'complete.json').read_bytes()),invocation='f'*32)))
        output='\n'.join(k+'='+v for k,v in dict(LoadState=loaded,ActiveState=active,SubState=sub,Result=result,ExecMainStatus='0',InvocationID='f'*32).items())
        with patch.object(upgrade,'command',return_value=output),patch.object(upgrade,'current_binding') as binding:
            state=upgrade.observe(self.target,self.candidate.name)
            if state['state']=='completed':binding.assert_called_once()
            else:binding.assert_not_called()
        return state

    def test_hard_kill_timeout_or_failed_unit_wins_even_without_failure_file(self):
        for result in ('signal','timeout','exit-code'):
            self.assertEqual(self.observation(result=result,active='failed')['state'],'failed')
        self.assertEqual(self.observation(result='timeout',active='failed',proof=True)['state'],'failed')

    def test_completion_file_alone_missing_unit_and_still_running_recorder_stay_unconfirmed(self):
        (self.operation/'complete.json').write_bytes(upgrade.encoded({'intent_sha256':self.intent_sha}))
        self.assertEqual(self.observation()['state'],'unknown')
        self.assertEqual(self.observation(loaded='not-found')['state'],'unknown')
        self.assertEqual(self.observation(active='deactivating',sub='stop-post',proof=True)['state'],'in-progress')
        self.assertEqual(self.observation(proof=True)['state'],'completed')

    def test_existing_durable_reservation_turns_request_into_observation_only(self):
        with patch.object(upgrade.sys,'platform','linux'),patch.object(upgrade.os,'geteuid',return_value=0,create=True),\
                patch.object(upgrade,'observe',return_value={'state':'unknown'}) as observe,patch.object(upgrade,'history') as history:
            self.assertEqual(upgrade.run({'mode':'request','target':self.target,'bundle_sha256':self.candidate.name}),{'state':'unknown'})
            observe.assert_called_once();history.assert_not_called()

    def test_frozen_exact_source_pins_are_present_and_no_fresh_install_replay(self):
        self.assertEqual(upgrade.sha((ROOT/'experiments/server/cold_backup.py').read_bytes()),upgrade.NEW)
        self.assertEqual(upgrade.sha((ROOT/'experiments/server/runtime_service.py').read_bytes()),upgrade.CONTROLLER)
        source=(ROOT/'experiments/server/helper_upgrade.py').read_text()
        self.assertNotIn('bind_admission_fresh(',source);self.assertNotIn('install_unit(',source)


class Bundles(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name).resolve()
        self.old=self.root/'old';self.old.mkdir();self.upgrades=self.root/'upgrades';self.upgrades.mkdir()
        self.bodies={'cold_backup.py':b'# old helper','runtime_service.py':b'# same controller','other.py':b'# same source'}
        for name,body in self.bodies.items():(self.old/name).write_bytes(body)
        self.package={'scope':'private-azd-source-v1','files':self.entries(self.bodies)}
        for p in (patch.object(upgrade,'UPGRADES',self.upgrades),patch.object(upgrade,'checked',side_effect=lambda p,**k:Path(p)),
            patch.object(upgrade,'sync'),patch.object(upgrade.os,'O_NOFOLLOW',getattr(os,'O_NOFOLLOW',0),create=True),
            patch.object(upgrade,'NEW',upgrade.sha(b'# reviewed new helper')),
            patch.object(upgrade,'history',return_value=(self.old,self.package,{}))):
            p.start();self.addCleanup(p.stop)

    def entries(self,bodies):return {n:{'sha256':upgrade.sha(b),'base64':base64.b64encode(b).decode()} for n,b in bodies.items()}

    def upload(self,bodies=None,raw=None):
        if raw is None:raw=upgrade.encoded({'scope':'private-azd-source-v1','files':self.entries(bodies)})
        compressed=gzip.compress(raw);bundle=upgrade.sha(raw);archive=upgrade.sha(compressed)
        path=self.upgrades/'uploads'/bundle/archive;path.mkdir(parents=True)
        text=base64.b64encode(compressed);chunks=[text[i:i+24576] for i in range(0,len(text),24576)]
        for i,chunk in enumerate(chunks):(path/str(i)).write_bytes(chunk)
        return bundle,archive,len(chunks)

    def test_stages_only_one_reviewed_change_immutably_without_touching_originals(self):
        bodies={**self.bodies,'cold_backup.py':b'# reviewed new helper'}
        bundle,archive,count=self.upload(bodies)
        candidate=upgrade.stage_bundle({},bundle,archive,count)
        self.assertEqual((candidate/'cold_backup.py').read_bytes(),b'# reviewed new helper')
        for name,body in self.bodies.items():self.assertEqual((self.old/name).read_bytes(),body)
        self.assertEqual(upgrade.stage_bundle({},bundle,archive,count),candidate)

    def test_other_code_unknown_files_wrong_helper_or_bomb_reject_without_staging(self):
        variants=[{**self.bodies,'cold_backup.py':b'# unreviewed'},
            {**self.bodies,'cold_backup.py':b'# reviewed new helper','runtime_service.py':b'changed controller'},
            {**self.bodies,'cold_backup.py':b'# reviewed new helper','extra.py':b'unknown'}]
        for bodies in variants:
            bundle,archive,count=self.upload(bodies)
            with self.assertRaises(ValueError):upgrade.stage_bundle({},bundle,archive,count)
            self.assertFalse((self.upgrades/'bundles'/bundle).exists())
        bundle,archive,count=self.upload(raw=b'x'*(2*1024**2+1))
        with self.assertRaises(ValueError):upgrade.stage_bundle({},bundle,archive,count)

    def test_effective_unit_rejects_dropins_or_policy_drift(self):
        values=dict(FragmentPath=str(self.root/'runtime.service'),DropInPaths='',Type='notify',
            Restart='on-failure',NoNewPrivileges='yes',PrivateTmp='yes',ProtectHome='yes')
        for change in ({},{'DropInPaths':'/etc/unknown.conf'},{'Type':'simple'},{'NoNewPrivileges':'no'}):
            text='\n'.join(k+'='+v for k,v in {**values,**change}.items())
            with patch.object(upgrade,'command',return_value=text):
                if change:
                    with self.assertRaises(ValueError):upgrade.effective_unit(Path(values['FragmentPath']))
                else:upgrade.effective_unit(Path(values['FragmentPath']))


class History(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name).resolve()
        def module(name):
            path=ROOT/'experiments/server'/(name+'.py');spec=importlib.util.spec_from_file_location('history_'+name,path)
            selected=importlib.util.module_from_spec(spec);spec.loader.exec_module(selected);return selected
        self.relay=module('private_install_transport');self.installer=module('private_install')
        bodies={name:(ROOT/'experiments/server'/name).read_bytes() for name in self.relay.FILES}
        package={'scope':'private-azd-source-v1','files':{name:{'sha256':upgrade.sha(body),'base64':base64.b64encode(body).decode()} for name,body in bodies.items()}}
        bundle_raw=upgrade.encoded(package);self.bundle=upgrade.sha(bundle_raw);self.folder=self.root/'installers'/self.bundle;self.folder.mkdir(parents=True)
        for name,body in bodies.items():(self.folder/name).write_bytes(body)
        (self.folder/'bundle.json').write_bytes(bundle_raw)
        self.target={'TenantId':'22222222-2222-4222-8222-222222222222','SubscriptionId':'11111111-1111-4111-8111-111111111111',
            'EnvironmentName':'synthetic','ResourceGroup':'rg-azd-santa-vm-synthetic','VmName':'vm-santa-lab',
            'VmId':'/subscriptions/11111111-1111-4111-8111-111111111111/resourceGroups/rg-azd-santa-vm-synthetic/providers/Microsoft.Compute/virtualMachines/vm-santa-lab',
            'VmInstanceId':'33333333-3333-4333-8333-333333333333'}
        raw=upgrade.encoded(dict(scope='private-azd-install-v1',bundle_sha256=self.bundle,target=self.target))
        (self.root/'private-azd-install.json').write_bytes(raw);(self.folder/'context.json').write_bytes(raw)
        complete=upgrade.encoded(dict(scope='private-azd-install-complete',bundle_sha256=self.bundle,outputs=self.target,limitation='synthetic'))
        (self.folder/'complete.json').write_bytes(complete)
        self.proof=dict(scope='private-azd-install-terminal-success',context_sha256=upgrade.sha(raw),bundle_sha256=self.bundle,
            completion_sha256=upgrade.sha(complete),invocation='f'*32,service_result='success',exit_code='exited',exit_status='0')
        self.writeproof()
        self.unit=dict(LoadState='loaded',ActiveState='inactive',SubState='dead',Result='success',ExecMainStatus='0',InvocationID='f'*32)
        self.relay.ROOT=self.root;self.relay.ACTIVE=self.root/'private-azd-install.json';self.relay.secure=lambda *args:None
        self.relay.command=lambda args:'\n'.join(k+'='+v for k,v in self.unit.items()) if args[1]=='show' else ''
        self.backup=SimpleNamespace(host_identity=Mock(return_value={'boot_id':'boot'}))
        modules={'private_install_transport':self.relay,'private_install':self.installer,'cold_backup':self.backup}
        for p in (patch.object(upgrade,'ROOT',self.root),patch.object(upgrade,'checked',side_effect=lambda p,**k:Path(p)),
            patch.object(upgrade,'OLD',upgrade.sha(bodies['cold_backup.py'])),patch.object(upgrade,'load',side_effect=lambda folder,name:modules[name])):
            p.start();self.addCleanup(p.stop)

    def writeproof(self):(self.folder/'terminal-success.json').write_bytes(upgrade.encoded(self.proof))

    def test_requires_real_original_relay_terminal_validation_before_imds(self):
        folder,package,identity=upgrade.history(self.target)
        self.assertEqual(folder,self.folder);self.assertEqual(identity,{'boot_id':'boot'});self.backup.host_identity.assert_called_once()

    def test_missing_malformed_invocation_failed_or_mismatched_loaded_installer_reject(self):
        original=copy.deepcopy(self.proof)
        for variant in ('missing','malformed','failed','mismatch'):
            self.proof=copy.deepcopy(original);self.unit.update(Result='success',InvocationID='f'*32)
            if variant=='missing':self.proof.pop('invocation')
            if variant=='malformed':self.proof['invocation']='not-an-invocation'
            if variant=='failed':self.unit['Result']='exit-code'
            if variant=='mismatch':self.unit['InvocationID']='e'*32
            self.writeproof();self.backup.host_identity.reset_mock()
            with self.assertRaises((ValueError,KeyError)):upgrade.history(self.target)
            self.backup.host_identity.assert_not_called()


if __name__=='__main__':unittest.main()
