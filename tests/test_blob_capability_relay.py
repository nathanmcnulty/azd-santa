"""Real crypto with controlled guest/systemd/HTTP adapters; no Azure or VM calls."""
import base64
import copy
import datetime as dt
import io
import json
import os
from types import SimpleNamespace
from pathlib import Path,PurePosixPath
import stat
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock,patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'experiments/server'))
import blob_capability_relay as relay
import test_blob_retention as fixtures
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

class MemoryState:
    stores={}
    def __init__(self,selected,create=False):
        relay.operation(selected);self.operation=selected;self.path=relay.ROOT/'blob-relay-v1'/selected
        if create:
            if selected in self.stores:raise FileExistsError()
            self.stores[selected]={}
        self.values=self.stores[selected]
    def exists(self,name):return name in self.values
    def read(self,name,maximum=relay.MAX_PACKET):
        raw=self.values[name];relay.need(len(raw)<=maximum);return raw
    def write(self,name,raw):
        if name in self.values:raise FileExistsError()
        relay.need(type(raw)is bytes and len(raw)<=relay.MAX_PACKET);self.values[name]=raw
    def __enter__(self):return self
    def __exit__(self,*args):pass

class Relay(unittest.TestCase):
    @classmethod
    def setUpClass(cls):fixtures.Retention.setUpClass()
    def setUp(self):
        self.fixture=fixtures.Retention();self.fixture.setUp();f=self.fixture
        self.source=f.source;self.record=f.record;self.selected=f.blob.operation;self.raw=f.raw
        self.cap=f.cap();self.boot='55555555-5555-4555-8555-555555555555';self.now=int(dt.datetime.now(dt.timezone.utc).timestamp())
        self.proof=dict(path='/synthetic/ciphertext-native/backup.sealed',file_identity=[1,2,3],manifest_sha256='d'*64,
            request_sha256=self.record['complete']['maintenance_sha256'],generation_sha256='b'*64,completion_sha256='c'*64,maintenance_sha256='a'*64)
        self.transport=fixtures.Transport(self.raw);self.upload_calls=0;MemoryState.stores={}
        self.manager=dict(LoadState='loaded',ActiveState='activating',SubState='start',Result='success',MainPID=str(os.getpid()),
            InvocationID='e'*32,ExecMainStatus='0',Job='',ControlGroup='')
        self.patches=[patch.object(relay,'guest'),patch.object(relay,'fresh',side_effect=self.identity),
            patch.object(relay,'capture',side_effect=self.capture),patch.object(relay,'State',MemoryState),
            patch.object(relay,'launch'),patch.object(relay,'absent_cgroup',return_value=True),patch.object(relay,'unit_state',side_effect=lambda name:copy.deepcopy(self.manager)),
            patch.object(relay,'read_file',side_effect=self.read_file),patch.object(relay.blob,'upload_file',side_effect=self.upload),
            patch.object(relay.time,'time',side_effect=lambda:self.now),patch.dict(os.environ,{'INVOCATION_ID':'e'*32})]
        for p in self.patches:p.start();self.addCleanup(p.stop)
    def identity(self,target):
        relay.need(target==self.source);return self.boot
    def capture(self,environment,target,record):
        relay.need(environment=='source' and target==self.source and record==self.record);return copy.deepcopy(self.proof)
    def read_file(self,path,*args,**kwargs):
        path=Path(path)
        for selected,files in MemoryState.stores.items():
            prefix=relay.ROOT/'blob-relay-v1'/selected
            if path.is_relative_to(prefix):return files[path.relative_to(prefix).as_posix()]
        raise FileNotFoundError()
    def upload(self,path,record,capability,attempt,**kwargs):
        self.upload_calls+=1;self.assertTrue(kwargs['apply']);self.assertEqual(path,self.proof['path'])
        self.assertEqual(capability.blob,self.fixture.blob);self.assertEqual(capability.target,self.source);self.assertEqual(capability.permission,'c')
        state=MemoryState(self.selected)
        class Journal:
            def write(_,name,value):state.write('put/'+name,relay.encoded(value))
        journal=Journal();journal.write('intent.json',dict(record,attempt='one-create-only-put'))
        stream=io.BytesIO(self.raw);deadline=time.monotonic()+30
        md5=relay.blob.fingerprint(stream,record,deadline)
        return relay.blob.put_once(stream,record,capability,journal,lambda:None,md5,deadline,self.transport)
    def offered(self):
        return relay.create_offer('source',self.source,self.record,self.fixture.blob,apply=True)
    def reserved(self):
        offer=self.offered();packet=relay.seal_offer(offer,self.cap,self.record)
        result=relay.submit(self.selected,relay.sha(relay.encoded(offer)),packet,apply=True)
        return offer,packet,result['intent_sha256']
    def execute(self,digest):return relay.execute(self.selected,digest,apply=True)
    def terminal(self,digest,result='success',status='0'):
        with patch.dict(os.environ,{'SERVICE_RESULT':result,'EXIT_CODE':'exited','EXIT_STATUS':status}):
            relay.record_terminal(self.selected,digest)
    def finished(self):self.manager.update(ActiveState='inactive',SubState='dead',MainPID='0')
    def test_defaults_do_not_touch_guest_identity_keys_files_or_transport(self):
        plan=relay.create_offer('source',self.source,self.record,self.fixture.blob)
        self.assertFalse(plan['performs_mutation']);self.assertEqual(MemoryState.stores,{})
        relay.guest.assert_not_called();relay.fresh.assert_not_called();relay.capture.assert_not_called()
        self.assertFalse(relay.observe(self.selected)['performs_mutation'])
    def test_real_envelope_private_key_offer_binding_and_secret_redaction(self):
        offer=self.offered();packet=relay.seal_offer(offer,self.cap,self.record)
        with MemoryState(self.selected) as state:cap=relay.decrypt(state,packet,offer,self.record)
        self.assertEqual(cap._token,self.cap._token);self.assertEqual(cap.blob,self.cap.blob)
        private=MemoryState(self.selected).read('private-key.der');self.assertNotIn(relay.encode(private),json.dumps(packet))
        self.assertNotIn(self.cap._token,json.dumps(offer)+json.dumps(packet)+repr(cap))
        self.assertEqual(relay.sha(base64.b64decode(offer['public_key_base64'])),offer['kid_sha256'])
        self.assertLessEqual(len(relay.encoded(offer)),4096);self.assertLessEqual(len(relay.encoded(packet)),relay.MAX_PACKET)
    def test_packet_crypto_tamper_unknown_fields_and_wrong_private_key_reject_before_intent(self):
        offer=self.offered();original=relay.seal_offer(offer,self.cap,self.record)
        for field in ('wrapped_key_base64','nonce_base64','ciphertext_base64','offer_sha256','version','extra'):
            packet=copy.deepcopy(original)
            if field=='extra':packet[field]='secret-must-not-appear'
            elif field=='version':packet[field]=True
            elif field.endswith('sha256'):packet[field]='0'*64
            else:
                raw=bytearray(base64.b64decode(packet[field]));raw[-1]^=1;packet[field]=relay.encode(bytes(raw))
            with self.subTest(field=field),self.assertRaises(relay.RelayRejected) as caught:
                relay.submit(self.selected,relay.sha(relay.encoded(offer)),packet,apply=True)
            self.assertNotIn('secret',str(caught.exception));self.assertFalse(MemoryState(self.selected).exists('submit-intent.json'))
        wrong=rsa.generate_private_key(public_exponent=65537,key_size=3072)
        MemoryState.stores[self.selected]['private-key.der']=wrong.private_bytes(serialization.Encoding.DER,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
        with self.assertRaises(relay.RelayRejected):relay.submit(self.selected,relay.sha(relay.encoded(offer)),original,apply=True)
    def test_cross_vm_verifier_read_permission_and_different_blob_are_not_source_upload(self):
        offer=self.offered()
        for capability in (self.fixture.cap('r'),relay.blob.Capability(self.cap.blob,self.fixture.verifier,'c',self.cap.ciphertext_sha256,self.cap.expires,self.cap._token),
            relay.blob.Capability(relay.blob.Blob(self.cap.blob.account_id,'b'*32),self.source,'c',self.cap.ciphertext_sha256,self.cap.expires,self.cap._token)):
            with self.assertRaises(relay.RelayRejected):relay.seal_offer(offer,capability,self.record)
        bad=copy.deepcopy(offer);bad['target']['instance_id']='77777777-7777-4777-8777-777777777777'
        with self.assertRaises(relay.RelayRejected):relay.seal_offer(bad,self.cap,self.record)
    def test_cross_boot_expiry_capture_drift_and_expected_offer_mismatch_are_closed(self):
        offer=self.offered();packet=relay.seal_offer(offer,self.cap,self.record);original=self.boot
        for change in ('boot','expiry','capture','offer'):
            expected=relay.sha(relay.encoded(offer))
            if change=='boot':self.boot='66666666-6666-4666-8666-666666666666'
            elif change=='expiry':self.now=offer['expires']
            elif change=='capture':self.proof['file_identity']=[9]
            else:expected='0'*64
            with self.subTest(change=change),self.assertRaises(relay.RelayRejected):relay.submit(self.selected,expected,packet,apply=True)
            self.boot=original;self.now=offer['created'];self.proof['file_identity']=[1,2,3]
        self.assertEqual(self.upload_calls,0);self.assertFalse(MemoryState(self.selected).exists('submit-intent.json'))
    def test_capability_payload_rejects_arm_tokens_unknown_sas_fields_and_expired_expiry(self):
        offer=self.offered()
        for token in ('eyJhbGciOiJSUzI1NiJ9.private-arm-token',self.cap._token+'&sip=192.0.2.1',self.cap._token+'&sp=c'):
            cap=relay.blob.Capability(self.cap.blob,self.source,'c',self.cap.ciphertext_sha256,self.cap.expires,token)
            with self.assertRaises(relay.RelayRejected) as caught:relay.seal_offer(offer,cap,self.record)
            self.assertNotIn(token,str(caught.exception))
        self.now=int(self.cap.expires.timestamp())
        with self.assertRaises(relay.RelayRejected):relay.seal_offer(offer,self.cap,self.record)
    def test_once_reservation_one_job_and_one_create_only_put_with_real_ciphertext(self):
        offer,packet,digest=self.reserved();relay.launch.assert_called_once()
        self.assertEqual(self.execute(digest)['state'],'uploaded');self.assertEqual(self.transport.puts,1)
        self.assertEqual(self.transport.sent,self.raw)
        with self.assertRaises(relay.RelayRejected):self.execute(digest)
        result=relay.submit(self.selected,relay.sha(relay.encoded(offer)),packet,apply=True)
        self.assertNotEqual(result['state'],'uploaded-unverified');relay.launch.assert_called_once();self.assertEqual(self.upload_calls,1)
        self.terminal(digest);self.finished();result=relay.observe(self.selected,read_guest=True)
        self.assertEqual(result['state'],'uploaded-unverified');self.assertFalse(result['independent_bytes_verified'])
        self.assertFalse(result['restore_accepted']);self.assertFalse(result['current_authority'])
        persisted=b'\n'.join(v for name,v in MemoryState.stores[self.selected].items() if name!='private-key.der')
        self.assertNotIn(self.cap._token.encode(),persisted)
    def test_unknown_launch_response_keeps_one_intent_and_cannot_resubmit(self):
        offer=self.offered();packet=relay.seal_offer(offer,self.cap,self.record)
        relay.launch.side_effect=TimeoutError('private-token-must-not-log')
        with self.assertRaises(relay.RelayRejected) as caught:relay.submit(self.selected,relay.sha(relay.encoded(offer)),packet,apply=True)
        self.assertNotIn('private-token',str(caught.exception))
        relay.submit(self.selected,relay.sha(relay.encoded(offer)),packet,apply=True)
        relay.launch.assert_called_once();self.assertTrue(MemoryState(self.selected).exists('submit-intent.json'))
    def test_ambiguous_http_failure_is_unknown_no_retry_or_overwrite(self):
        for error,status in ((TimeoutError('sig=confidential'),201),(None,412)):
            self.setUp();offer,packet,digest=self.reserved();self.transport.error=error;self.transport.status=status
            with self.assertRaises(relay.RelayRejected) as caught:self.execute(digest)
            self.assertNotIn('confidential',str(caught.exception));self.assertEqual(self.transport.puts,1)
            self.assertEqual(relay.parsed(MemoryState(self.selected).read('body.json'))['state'],'unknown')
            with self.assertRaises(relay.RelayRejected):self.execute(digest)
            self.terminal(digest,'exit-code','1');self.finished();self.manager.update(Result='exit-code',ExecMainStatus='1')
            self.assertEqual(relay.observe(self.selected,read_guest=True)['state'],'unknown')
    def test_body_file_alone_and_hard_kill_without_terminal_never_mean_success(self):
        offer,packet,digest=self.reserved();self.execute(digest);self.finished()
        self.assertEqual(relay.observe(self.selected,read_guest=True)['state'],'unknown')
        self.terminal(digest);self.manager.update(Result='timeout',ActiveState='failed',ExecMainStatus='1')
        self.assertEqual(relay.observe(self.selected,read_guest=True)['state'],'unknown')
    def test_wrong_invocation_and_post_offer_reboot_do_not_inherit_terminal_success(self):
        offer,packet,digest=self.reserved();self.execute(digest);self.terminal(digest);self.finished()
        self.manager['InvocationID']='f'*32
        self.assertEqual(relay.observe(self.selected,read_guest=True)['state'],'unknown')
        self.boot='66666666-6666-4666-8666-666666666666'
        with self.assertRaises(relay.RelayRejected):relay.observe(self.selected,read_guest=True)
    def test_gc_loadstate_never_overrides_negative_active_or_pending_manager_facts(self):
        offer,packet,digest=self.reserved();self.execute(digest);self.terminal(digest);self.finished()
        self.manager.update(LoadState='not-found',InvocationID='')
        baseline=self.manager.copy()
        mutations=[dict(ActiveState='failed',SubState='failed',Result='timeout',MainPID='27',ExecMainStatus='1',Job='queued'),
            dict(ActiveState='active'),dict(ActiveState='activating'),dict(ActiveState='deactivating'),dict(SubState='start'),
            dict(Result='timeout'),dict(Result='signal'),dict(MainPID='27'),dict(ExecMainStatus='1'),dict(Job='queued'),
            dict(InvocationID='e'*32),dict(ControlGroup='/system.slice/another.service')]
        for changes in mutations:
            self.manager.clear();self.manager.update(baseline);self.manager.update(changes)
            relay.absent_cgroup.reset_mock()
            with self.subTest(changes=changes):self.assertEqual(relay.observe(self.selected,read_guest=True)['state'],'unknown')
            relay.absent_cgroup.assert_not_called()
        self.manager.clear();self.manager.update(baseline)
        self.assertEqual(relay.observe(self.selected,read_guest=True)['state'],'uploaded-unverified')
        relay.absent_cgroup.assert_called_once_with('azd-santa-blob-relay-'+offer['offer_id']+'.service')
        self.assertEqual(self.upload_calls,1);relay.launch.assert_called_once()

    def test_gc_and_loaded_success_both_require_absent_cgroup_and_execution_proof(self):
        offer,packet,digest=self.reserved();self.execute(digest);self.terminal(digest);self.finished()
        for state,invocation in (('loaded','e'*32),('not-found','')):
            self.manager.update(LoadState=state,InvocationID=invocation)
            relay.absent_cgroup.return_value=False
            self.assertEqual(relay.observe(self.selected,read_guest=True)['state'],'unknown')
            relay.absent_cgroup.return_value=True
            self.assertEqual(relay.observe(self.selected,read_guest=True)['state'],'uploaded-unverified')
        MemoryState.stores[self.selected].pop('execution-intent.json')
        with self.assertRaises(relay.RelayRejected):relay.observe(self.selected,read_guest=True)

    def test_missing_manager_fields_are_never_synthesized_as_gc_defaults(self):
        offer,packet,digest=self.reserved();self.execute(digest);self.terminal(digest);self.finished()
        self.manager.update(LoadState='not-found',InvocationID='');self.manager.pop('ControlGroup')
        with self.assertRaises(relay.RelayRejected):relay.observe(self.selected,read_guest=True)
        relay.absent_cgroup.assert_not_called()

    def test_completed_observation_survives_capability_offer_expiry_without_reusing_it(self):
        offer,packet,digest=self.reserved();self.execute(digest);self.terminal(digest);self.finished();self.now=offer['expires']+1
        self.assertEqual(relay.observe(self.selected,read_guest=True)['state'],'uploaded-unverified')
        with self.assertRaises(relay.RelayRejected):relay.seal_offer(offer,self.cap,self.record)
    def test_same_offer_readback_recovers_lost_response_without_new_key(self):
        offer=self.offered();before=copy.deepcopy(MemoryState.stores)
        self.assertEqual(relay.get_offer(self.selected,read_guest=True),offer)
        self.assertEqual(before,MemoryState.stores)
        packet=relay.seal_offer(offer,self.cap,self.record)
        relay.submit(self.selected,relay.sha(relay.encoded(offer)),packet,apply=True)
        with self.assertRaises(relay.RelayRejected):relay.get_offer(self.selected,read_guest=True)

    def test_interrupt_after_once_marker_keeps_unknown_evidence_and_never_replays(self):
        offer,packet,digest=self.reserved();self.transport.error=KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):self.execute(digest)
        self.assertEqual(relay.parsed(MemoryState(self.selected).read('body.json'))['state'],'unknown')
        with self.assertRaises(relay.RelayRejected):self.execute(digest)
        self.assertEqual(self.transport.puts,1)
        MemoryState.stores[self.selected].pop('body.json')  # Model hard kill before body fsync.
        self.manager.update(ActiveState='failed',SubState='failed',MainPID='0',Result='signal',ExecMainStatus='9')
        self.assertEqual(relay.observe(self.selected,read_guest=True)['state'],'unknown')
        relay.submit(self.selected,relay.sha(relay.encoded(offer)),packet,apply=True)
        relay.launch.assert_called_once()

    def test_duplicate_offer_never_regenerates_or_overwrites_key_or_history(self):
        self.offered();before=copy.deepcopy(MemoryState.stores)
        with self.assertRaises(relay.RelayRejected):self.offered()
        self.assertEqual(before,MemoryState.stores)
    def test_terminal_environment_and_single_execution_invocation_are_required(self):
        offer,packet,digest=self.reserved()
        self.manager['InvocationID']='f'*32
        with self.assertRaises(relay.RelayRejected):self.execute(digest)
        self.assertFalse(MemoryState(self.selected).exists('execution-intent.json'))
        self.manager['InvocationID']='e'*32;self.execute(digest)
        with self.assertRaises(relay.RelayRejected):self.terminal(digest,'success','1')
        self.assertFalse(MemoryState(self.selected).exists('terminal.json'))

class KernelCgroupContract(unittest.TestCase):
    def setUp(self):
        self.unit='azd-santa-blob-relay-'+('a'*32)+'.service'
        self.fs='cgroup2fs';self.present=False
        self.files={'cgroup.type':b'domain\n','cgroup.events':b'populated 1\nfrozen 0\n','cgroup.controllers':b'cpuset cpu io memory pids\n'}
        self.command=patch.object(relay,'command',side_effect=lambda args:self.fs+'\n').start()
        self.reader=patch.object(relay,'read_file',side_effect=lambda path,maximum:self.files[path.name]).start()
        self.lstat=patch.object(Path,'lstat',side_effect=self.stat).start()
        self.addCleanup(patch.stopall)
    def stat(self,*args,**kwargs):
        if not self.present:raise FileNotFoundError()
        return SimpleNamespace(st_mode=stat.S_IFDIR|0o755)
    def test_absence_requires_positive_kernel_hierarchy_before_exact_name_probe(self):
        self.assertTrue(relay.absent_cgroup(self.unit));self.lstat.assert_called_once()
        self.command.assert_called_once()
        self.assertEqual(self.command.call_args.args[0][:3],['/usr/bin/stat','--file-system','--format=%T'])
        self.present=True;self.assertFalse(relay.absent_cgroup(self.unit))
        self.lstat.side_effect=None;self.lstat.return_value=SimpleNamespace(st_mode=stat.S_IFLNK|0o777)
        self.assertFalse(relay.absent_cgroup(self.unit))
    def test_missing_or_untrusted_hierarchy_never_becomes_absence_proof(self):
        cases=(('fs','tmpfs'),('cgroup.type',b'threaded\n'),('cgroup.events',b''),
            ('cgroup.events',b'populated 0\npopulated 0\n'),('cgroup.controllers',b''),('cgroup.controllers',b'cpu cpu pids\n'))
        for key,value in cases:
            old=self.fs if key=='fs' else self.files[key]
            if key=='fs':self.fs=value
            else:self.files[key]=value
            self.lstat.reset_mock()
            with self.subTest(key=key,value=value),self.assertRaises(relay.RelayRejected):relay.absent_cgroup(self.unit)
            self.lstat.assert_not_called()
            if key=='fs':self.fs=old
            else:self.files[key]=old
        self.files.pop('cgroup.events')
        with self.assertRaises(KeyError):relay.absent_cgroup(self.unit)
    def test_alias_unit_name_is_rejected_before_any_probe(self):
        with self.assertRaises(relay.RelayRejected):relay.absent_cgroup('../'+self.unit)
        self.command.assert_not_called();self.reader.assert_not_called();self.lstat.assert_not_called()
    def test_scalar_manager_parser_requires_controlgroup_and_every_field_once(self):
        fields=dict(LoadState='not-found',ActiveState='inactive',SubState='dead',Result='success',MainPID='0',InvocationID='',ExecMainStatus='0',Job='',ControlGroup='')
        self.command.side_effect=None;self.command.return_value='\n'.join(k+'='+v for k,v in fields.items())
        self.assertEqual(relay.unit_state(self.unit),fields)
        for raw in (self.command.return_value+'\nControlGroup=',self.command.return_value.replace('ControlGroup=',''),self.command.return_value+'\nUnexpected=bad'):
            self.command.return_value=raw
            with self.assertRaises(relay.RelayRejected):relay.unit_state(self.unit)


class CaptureSelector(unittest.TestCase):
    def setUp(self):
        for p in (patch.object(relay,'ROOT',PurePosixPath('/var/lib/azd-santa-qualification')),patch.object(relay,'Path',PurePosixPath)):
            p.start();self.addCleanup(p.stop)
    @classmethod
    def setUpClass(cls):fixtures.Retention.setUpClass()
    def fixture(self,destination=None):
        f=fixtures.Retention();f.setUp();record=copy.deepcopy(f.record)
        control=relay.ROOT/'private-runtime-source/runtime-service';manifest=control/'manifest.json'
        manifest_raw=relay.encoded({'fixture':'read-only manifest'});digest=relay.sha(manifest_raw)
        generation=relay.encoded({'image_id':record['image_id']});gen_sha=relay.sha(generation)
        record['complete']['generation_sha256']=gen_sha
        request=dict(operation_id=record['operation_id'],target={'VmId':f.source.vm_id,'VmInstanceId':f.source.instance_id},
            destination=str(destination or relay.ROOT/'ciphertext-native-test'),generation_sha256=gen_sha)
        runtime=("def unit_text(script,path,digest):\n return 'ExecStart=/usr/bin/python3 -I '+str(script)+' run --manifest '+str(path)+' --sha256 '+digest+'\\n'\n"
                 "def load_manifest(path,digest): return ({},{})\n").encode()
        backup=("import json\ndef _request(runtime): return json.loads("+repr(json.dumps(request))+
            "), "+repr(record['complete']['maintenance_sha256'])+", b'public'\n").encode()
        bodies={'runtime_service.py':runtime,'cold_backup.py':backup,**{'fixture'+str(i)+'.py':b'# preserved source fixture' for i in range(23)}}
        bundle=relay.encoded({'scope':'private-azd-source-v1','files':{name:{'sha256':relay.sha(value),'base64':relay.encode(value)} for name,value in bodies.items()}})
        bundle_sha=relay.sha(bundle);record['source_bundle_sha256']=bundle_sha
        folder=relay.ROOT/'helper-upgrades/bundles'/bundle_sha;script=folder/'runtime_service.py'
        unit=('ExecStart=/usr/bin/python3 -I '+str(script)+' run --manifest '+str(manifest)+' --sha256 '+digest+'\n').encode()
        destination=Path(request['destination']);complete=relay.encoded(record['complete'])
        files={manifest:manifest_raw,Path('/etc/systemd/system/azd-santa-runtime.service'):unit,folder/'bundle.json':bundle,
            **{folder/name:value for name,value in bodies.items()},destination/'complete.json':complete,
            control/'container-generation.json':generation,
            control/('backup-'+record['operation_id'])/'maintenance-complete.json':relay.encoded(dict(
                request_sha256=record['complete']['maintenance_sha256'],generation_sha256=gen_sha,ciphertext_receipt_sha256=relay.sha(complete)))}
        return f,record,files,relay.sha(runtime)
    def run_capture(self,fixture,path):
        f,record,files,controller_sha=fixture
        actual_open=os.open;actual_stat=os.stat
        def opened(name,flags,**kwargs):
            self.assertEqual(name,'backup.sealed');return actual_open(path,os.O_RDONLY)
        def stated(name,*args,**kwargs):
            if 'dir_fd' in kwargs:return actual_stat(path)
            return actual_stat(name,*args,**kwargs)
        with patch.object(relay,'read_file',side_effect=lambda selected,*a,**k:next(value for name,value in files.items() if str(name).replace('\\','/')==str(selected).replace('\\','/'))), \
             patch.object(relay,'CONTROLLER_SHA',controller_sha),patch.object(relay.blob,'parent',return_value=(42,'backup.sealed')), \
             patch.object(relay.os,'open',side_effect=opened),patch.object(relay.os,'stat',side_effect=stated), \
             patch.object(relay.os,'O_NOFOLLOW',getattr(os,'O_NOFOLLOW',0),create=True), \
             patch.object(relay.os,'O_NONBLOCK',getattr(os,'O_NONBLOCK',0),create=True), \
             patch.object(relay.blob,'identity',side_effect=lambda info:(1,2,3,0,0,1,info.st_size,4,5)),patch.object(relay.State,'file'):
            return relay.capture('source',f.source,record)
    def test_actual_selector_checks_complete_bindings_and_real_cipher_fingerprint(self):
        fixture=self.fixture()
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'backup.sealed';path.write_bytes(fixture[0].raw)
            proof=self.run_capture(fixture,path)
            self.assertEqual(proof['completion_sha256'],relay.sha(relay.encoded(fixture[1]['complete'])))
            self.assertEqual(proof['path'],str(relay.ROOT/'ciphertext-native-test/backup.sealed'))
            self.assertEqual(proof['file_identity'][6],len(fixture[0].raw))
            path.write_bytes(fixture[0].raw[:-1]+b'x')
            with self.assertRaises(Exception):self.run_capture(fixture,path)
    def test_selector_rejects_arbitrary_paths_and_missing_or_changed_capture_evidence(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'backup.sealed'
            for destination in (relay.ROOT/'arbitrary',Path('/unrelated/ciphertext-native-test')):
                fixture=self.fixture(destination);path.write_bytes(fixture[0].raw)
                with self.assertRaises(relay.RelayRejected):self.run_capture(fixture,path)
            fixture=self.fixture();path.write_bytes(fixture[0].raw)
            file=next(p for p in fixture[2] if p.name=='maintenance-complete.json')
            fixture[2][file]=relay.encoded({'unknown':'do not infer completed'})
            with self.assertRaises(relay.RelayRejected):self.run_capture(fixture,path)


class PrivateFiles(unittest.TestCase):
    def test_owner_mode_links_and_regular_file_guards(self):
        with patch.object(os,'geteuid',return_value=1000,create=True):
            for changes in ({'st_uid':0},{'st_nlink':2},{'st_mode':stat.S_IFREG|0o644},{'st_mode':stat.S_IFIFO|0o600}):
                value=dict(st_uid=1000,st_nlink=1,st_mode=stat.S_IFREG|0o600);value.update(changes)
                with self.assertRaises(relay.RelayRejected):relay.State.file(type('Info',(),value))
    @unittest.skipUnless(sys.platform=='linux','Actual Linux descriptor-relative private files required')
    def test_real_exclusive_private_files_and_symlink_rejection(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as folder,patch.object(relay,'ROOT',Path(folder)):
            os.chmod(folder,0o700)
            with relay.State('a'*32,create=True) as state:
                state.write('private-key.der',b'private-test-key');self.assertEqual(state.read('private-key.der'),b'private-test-key')
                self.assertEqual(stat.S_IMODE((state.path/'private-key.der').stat().st_mode),0o600)
                with self.assertRaises(FileExistsError):state.write('private-key.der',b'overwrite')
                os.symlink('private-key.der',state.path/'alias')
                with self.assertRaises(OSError):state.read('alias')
            with self.assertRaises(FileExistsError):relay.State('a'*32,create=True)

if __name__=='__main__':unittest.main()
