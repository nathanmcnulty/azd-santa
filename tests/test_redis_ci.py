"""Offline CI boundary tests; no Docker, registry, Redis or root execution."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import MagicMock, patch

REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('redis_ci', REPO/'scripts/ci/qualify_redis.py')
ci = importlib.util.module_from_spec(spec); spec.loader.exec_module(ci)
CID = 'a'*64
IMAGE = 'sha256:'+'b'*64
REFERENCE = 'redis@sha256:'+'c'*64
TOKEN = 'd'*32


def row(running=True):
    return dict(id=CID,image=IMAGE,labels={'io.azd-santa.qualification':ci.LABEL,'io.azd-santa.ci-owner':TOKEN},
        user='999:999',running=running,ports={'6379/tcp':None},mounts=[dict(Type='tmpfs',Destination='/data',RW=True)],
        host=dict(ReadonlyRootfs=True,NetworkMode='none',PortBindings={},PublishAllPorts=False,
            Memory=ci.MEMORY,MemorySwap=ci.MEMORY,NanoCpus=500000000,PidsLimit=32,RestartPolicy={'Name':'no'},
            CapDrop=['ALL'],CapAdd=None,Privileged=False,PidMode='',Devices=[],SecurityOpt=['no-new-privileges:true'],
            LogConfig={'Type':'none'},Tmpfs={'/data':ci.TMPFS}))


def private_receipt(hashes):
    return dict(scope='disposable-redis-admission-lua-v1',container_id=CID,image_id=IMAGE,
        harness_sha256=hashes[ci.FILES[0]],sources={name:hashes[name] for name in ci.FILES[1:]},
        passed=True,observations=['actual_case_'+str(index) for index in range(27)],limitation='PRIVATE DIAGNOSTIC CANARY')


class Boundaries(unittest.TestCase):
    def test_lock_requires_exact_redis_repository_and_digest(self):
        self.assertEqual(ci.redis_reference(json.dumps({'redis':REFERENCE})),REFERENCE)
        for value in ('redis:latest','foreign@sha256:'+'c'*64,'redis@sha256:short',None):
            with self.subTest(value=value),self.assertRaises(ValueError):ci.redis_reference(json.dumps({'redis':value}))

    def test_repo_digest_and_actual_architecture_image_id_required(self):
        image=dict(Id=IMAGE,RepoDigests=[REFERENCE],Os='linux',Architecture='amd64')
        self.assertEqual(ci.image_identity([image],REFERENCE),IMAGE)
        for key,value in [('Id','redis:latest'),('RepoDigests',[]),('RepoDigests',['redis@sha256:'+'e'*64]),
                          ('Architecture','arm64'),('Os','windows')]:
            with self.subTest(key=key),self.assertRaises(ValueError):ci.image_identity([dict(image,**{key:value})],REFERENCE)

    def test_all_actual_container_bounds_fail_closed_on_drift(self):
        ci.isolated(row(),CID,IMAGE,TOKEN)
        edits=[('NetworkMode','bridge'),('ReadonlyRootfs',False),('PortBindings',{'6379/tcp':[{}]}),
            ('Memory',0),('MemorySwap',0),('NanoCpus',0),('PidsLimit',0),('CapDrop',[]),
            ('CapAdd',['SYS_ADMIN']),('Privileged',True),('PidMode','host'),('Devices',[{}]),
            ('SecurityOpt',[]),('Tmpfs',{}),('LogConfig',{'Type':'json-file'}),('RestartPolicy',{'Name':'always'})]
        for key,value in edits:
            value_row=row();value_row['host'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):ci.isolated(value_row,CID,IMAGE,TOKEN)
        for key,value in [('user','0'),('ports',{'6379/tcp':[{'HostIp':'0.0.0.0'}]}),
                          ('mounts',[dict(Type='volume',Destination='/data',RW=True)])]:
            with self.subTest(key=key),self.assertRaises(ValueError):ci.isolated(dict(row(),**{key:value}),CID,IMAGE,TOKEN)

    def test_both_docker_tmpfs_representations_require_exact_bounded_host_map(self):
        for mounts in ([],[dict(Type='tmpfs',Destination='/data',RW=True)]):
            fixture=dict(row(),mounts=mounts)
            ci.isolated(fixture,CID,IMAGE,TOKEN)
            for host_map in ({},{'/foreign':ci.TMPFS},{'/data':'rw'},
                             {'/data':ci.TMPFS,'/foreign':ci.TMPFS}):
                bad=copy.deepcopy(fixture);bad['host']['Tmpfs']=host_map
                with self.subTest(mounts=mounts,host_map=host_map),self.assertRaises(ValueError):
                    ci.isolated(bad,CID,IMAGE,TOKEN)
        for mounts in ([dict(Type='bind',Destination='/data',RW=True)],
                       [dict(Type='volume',Destination='/data',RW=True)],
                       [dict(Type='tmpfs',Destination='/foreign',RW=True)],
                       [dict(Type='tmpfs',Destination='/data',RW=False)],
                       [dict(Type='tmpfs',Destination='/data',RW=True)]*2):
            with self.subTest(mounts=mounts),self.assertRaises(ValueError):
                ci.isolated(dict(row(),mounts=mounts),CID,IMAGE,TOKEN)

    def test_only_matching_owned_container_can_be_stopped(self):
        for cid,image,token in [('e'*64,IMAGE,TOKEN),(CID,'sha256:'+'e'*64,TOKEN),(CID,IMAGE,'e'*32)]:
            with self.assertRaises(ValueError):ci.owned(row(),cid,image,token)

    def test_success_artifact_whitelists_nonsecret_fields_and_binds_all_sources(self):
        hashes={name:'f'*64 for name in ci.FILES};receipt=private_receipt(hashes)
        public=ci.public_receipt(receipt,CID,IMAGE,hashes,'e'*40,REFERENCE)
        self.assertNotIn('PRIVATE DIAGNOSTIC CANARY',json.dumps(public))
        self.assertEqual(public['observations'],receipt['observations'])
        fenced=dict(receipt,scope='disposable-redis-admission-fenced-lua-v2',
                    observations=['actual_fenced_case_'+str(index) for index in range(37)])
        self.assertEqual(ci.public_receipt(fenced,CID,IMAGE,hashes,'e'*40,REFERENCE)['harness_scope'],fenced['scope'])
        for edit in (lambda r:r.update(secret='MUST NEVER EXPORT'),lambda r:r.update(passed=False),
                     lambda r:r.update(harness_sha256='0'*64),lambda r:r['sources'].update({'operator_mfa.py':'0'*64}),
                     lambda r:r.update(scope='unknown-version'),lambda r:r['observations'].pop(),
                     lambda r:r.update(observations=['error: private data']),lambda r:r.update(observations=['duplicate','duplicate'])):
            bad=copy.deepcopy(receipt);edit(bad)
            with self.assertRaises(ValueError):ci.public_receipt(bad,CID,IMAGE,hashes,'e'*40,REFERENCE)

    def exercise(self,fail=False):
        with tempfile.TemporaryDirectory() as name:
            base=Path(name).resolve();source=base/'checkout';(source/'experiments/server').mkdir(parents=True)
            for filename in ci.FILES:(source/'experiments/server'/filename).write_bytes(filename.encode())
            (source/'experiments/server/dependency-images.lock.json').write_text(json.dumps({'redis':REFERENCE}))
            private=base/'private';private.mkdir()
            root=MagicMock();root.__truediv__.side_effect=lambda child:private/child
            root.stat.return_value=SimpleNamespace(st_uid=0,st_mode=0o700)
            hashes={filename:hashlib.sha256(filename.encode()).hexdigest() for filename in ci.FILES}
            phases=[];commands=[];runner=MagicMock()
            def call(phase,args,**kwargs):
                phases.append(phase);commands.append((phase,args,kwargs))
                if phase=='image':return json.dumps([dict(Id=IMAGE,RepoDigests=[REFERENCE],Os='linux',Architecture='amd64')])
                if phase=='create':return CID
                if phase.startswith('ready-'):return '"PONG"'
                if phase=='harness':
                    if fail:raise TimeoutError('Unknown synthetic result')
                    (private/'evidence').mkdir();(private/'evidence/receipt.json').write_text(json.dumps(private_receipt(hashes)))
                    return 'SANTA_ADMISSION_REDIS_LUA_OK\n'
                return CID
            runner.call.side_effect=call
            runner.inspect.side_effect=lambda phase,cid:row(running=phase not in ('created','cleanup-stopped'))
            def write(path,value):
                # Portable exclusive writes only; Linux owner/mode is NOT proven.
                with path.open('xb') as stream:stream.write(value if isinstance(value,bytes) else json.dumps(value).encode())
            with patch.object(ci,'ROOT',root),patch.object(ci,'Runner',return_value=runner),patch.object(ci,'write',side_effect=write),\
                 patch.object(ci,'read_source',side_effect=lambda path:path.read_bytes()),\
                 patch.object(ci.sys,'platform','linux'),patch.object(ci.sys,'flags',SimpleNamespace(isolated=True)),\
                 patch.object(ci.os,'geteuid',return_value=0,create=True),patch.object(ci.secrets,'token_hex',return_value=TOKEN):
                if fail:
                    with self.assertRaises(TimeoutError):ci.run(source,'e'*40)
                else:self.assertTrue(ci.run(source,'e'*40)['passed'])
            self.assertEqual(sorted(path.name for path in (private/'sources').iterdir()),sorted(ci.FILES))
            stop=next(command for phase,command,_ in commands if phase=='stop-owned')
            self.assertEqual(stop,ci.DOCKER+['stop','--time','5',CID])
            self.assertEqual(phases.count('create'),1);self.assertEqual(phases.count('harness'),1)
            harness=next((args,options) for phase,args,options in commands if phase=='harness')
            self.assertEqual(harness[1]['timeout'],240)
            self.assertEqual(harness[0][:2],['/usr/bin/python3','-I'])
            self.assertEqual(harness[0][harness[0].index('--container-id')+1],CID)
            self.assertEqual(harness[0][harness[0].index('--expected-image')+1],IMAGE)
            self.assertEqual(runner.inspect.call_args.args,('cleanup-stopped',CID))

    def test_once_only_pipeline_stages_exact_files_and_cleans_owned_id_before_success(self):self.exercise()
    def test_unknown_harness_outcome_never_retries_and_still_stops_owned_id(self):self.exercise(fail=True)

    def test_workflow_token_artifact_and_trigger_contract(self):
        workflow=(REPO/'.github/workflows/qualify-redis-lua.yml').read_text()
        self.assertIn('contents: read',workflow);self.assertIn('persist-credentials: false',workflow)
        self.assertIn('runs-on: ubuntu-24.04',workflow);self.assertIn('timeout-minutes: 10',workflow)
        for value in ('pull_request_target','id-token:','secrets.','azure/login','az login','self-hosted'):
            self.assertNotIn(value,workflow)
        self.assertIn('actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1',workflow)
        self.assertIn('actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9',workflow)
        self.assertIn('path: ${{ runner.temp }}/santa-redis-lua-receipt.json',workflow)
        self.assertIn('if: success()',workflow);self.assertIn('env -i PATH=',workflow)
        for value in ('test_admission_redis_live.py','santa_admission.py','operator_mfa.py','dependency-images.lock.json','qualify-redis-lua.yml'):
            self.assertIn(value,workflow)
        self.assertIn('pull_request:',workflow);self.assertIn('push:',workflow);self.assertIn('workflow_dispatch:',workflow)


if __name__=='__main__':unittest.main()
