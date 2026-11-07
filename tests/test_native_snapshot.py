"""Pure protocol/metadata guards; no HTTP, Redis, Docker, mounts or guests."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('native_snapshot',ROOT/'experiments/server/native_snapshot.py')
native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)


class NativeSnapshot(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory();self.addCleanup(self.directory.cleanup)
        self.root=Path(self.directory.name).resolve()
        self.plan=native.plan('a'*64,'b'*32,'C'*22,'9.2.1',['santa-events'],1)
        # Source-derived complete API shape, not a live snapshot receipt.
        self.result=json.loads((ROOT/'tests/fixtures/server/native-snapshot-es921-success.json').read_bytes())
        self.assertEqual(self.result['snapshots'][0]['metadata']['azd_santa_plan_sha256'],native.sha(self.plan))
        if os.name=='nt':
            # Real exclusive file writes on Windows. Directory fsync/ownership
            # are Linux gates, not inferred from this portable protocol test.
            def write(path,value):
                with path.open('xb') as stream:
                    stream.write(native.encoded(value));stream.flush();os.fsync(stream.fileno())
            self.writer=patch.object(native,'write_new',side_effect=write)
            self.writer.start();self.addCleanup(self.writer.stop)

    def transport(self,*,timeout=False):
        state={'repository':None,'snapshot':None};calls=[]
        def api(method,path,body):
            calls.append((method,path,body))
            if method=='GET':
                if path=='/':return {'cluster_uuid':'C'*22,'version':{'number':'9.2.1'}}
                if path==native.INDICES_PATH:return [{'index':'santa-events','status':'open','pri':'1'}]
                return state['snapshot'] if path.endswith('/'+self.plan['snapshot']) else state['repository']
            self.assertTrue((self.root/('repository-intent.json' if body.get('type')=='fs' else 'snapshot-intent.json')).exists())
            if body.get('type')=='fs':
                state['repository']={self.plan['repository']:{'type':'fs','settings':{'location':self.plan['location']}}}
                return {'acknowledged':True}
            state['snapshot']=copy.deepcopy(self.result)
            if timeout:raise TimeoutError('unknown snapshot submission')
            return {'accepted':True}
        return api,state,calls

    def test_single_submission_records_intents_before_mutation_and_returns_exact_native_success(self):
        api,state,calls=self.transport()
        receipt=native.submit(self.root,self.plan,api)
        self.assertEqual(receipt['snapshot_uuid'],'D'*22)
        self.assertEqual(receipt['plan_sha256'],native.sha(self.plan))
        puts=[call for call in calls if call[0]=='PUT'];self.assertEqual(len(puts),2)
        self.assertTrue(puts[1][2]['include_global_state']);self.assertFalse(puts[1][2]['partial'])
        self.assertFalse(puts[1][2]['ignore_unavailable'])
        self.assertEqual(puts[1][2]['indices'],'*')
        self.assertEqual(puts[1][2]['expand_wildcards'],'all')
        self.assertNotIn('feature_states',puts[1][2])

    def test_system_indices_use_all_features_not_forbidden_explicit_names_and_remain_required_in_result(self):
        fixture=json.loads((ROOT/'tests/fixtures/server/native-snapshot-es921-system-indices.json').read_bytes())
        self.plan=native.plan('a'*64,'b'*32,'C'*22,'9.2.1',[r['index'] for r in fixture['inventory']],2)
        self.result=fixture['snapshot_response']
        self.assertEqual(self.result['snapshots'][0]['metadata']['azd_santa_plan_sha256'],native.sha(self.plan))
        transport,state,calls=self.transport()
        def api(method,path,body):
            if path==native.INDICES_PATH:return fixture['inventory']
            if method=='PUT' and 'indices' in body:
                # Source-derived request admission: explicit system names fail.
                self.assertEqual(body['indices'],'*');self.assertEqual(body['expand_wildcards'],'all')
                self.assertTrue(body['include_global_state']);self.assertNotIn('feature_states',body)
            return transport(method,path,body)
        result=native.submit(self.root,self.plan,api)
        self.assertEqual(result['plan']['indices'],['.geoip_databases','santa-events'])
        self.assertEqual(result['plan']['primary_shards'],2)
        for change in (lambda s:s.update(indices=['santa-events']),
                       lambda s:s['shards'].update(total=1,successful=1),
                       lambda s:s.update(indices=['.geoip_databases','santa-events','unexpected'])):
            altered=copy.deepcopy(self.result);change(altered['snapshots'][0])
            with self.assertRaises(ValueError):native.completed_snapshot(altered,self.plan)

    def test_ambiguous_snapshot_only_observes_same_identity_never_replays_or_changes_names(self):
        api,state,calls=self.transport(timeout=True)
        with self.assertRaises(TimeoutError):native.submit(self.root,self.plan,api)
        self.assertTrue((self.root/'snapshot-intent.json').exists())
        calls.clear();receipt=native.observe(self.root,self.plan,api)
        self.assertEqual(receipt['state'],'SUCCESS');self.assertTrue(all(c[0]=='GET' for c in calls))
        calls.clear()
        with self.assertRaises(FileExistsError):native.submit(self.root,self.plan,api)
        self.assertEqual(calls,[])
        state['snapshot']=None;self.assertIsNone(native.observe(self.root,self.plan,api))
        self.assertTrue(all(c[0]=='GET' for c in calls))

    def test_missing_repository_after_unknown_is_not_permission_to_submit_again(self):
        (self.root/'plan.json').write_bytes(native.encoded(self.plan))
        calls=[]
        def api(method,path,body):
            calls.append(method)
            return {'cluster_uuid':'C'*22,'version':{'number':'9.2.1'}} if path=='/' else None
        self.assertIsNone(native.observe(self.root,self.plan,api));self.assertEqual(calls,['GET','GET'])

    def test_failed_partial_wrong_uuid_version_metadata_index_or_shard_results_cannot_complete(self):
        changes=(lambda s:s.update(state='PARTIAL'),lambda s:s.update(state='FAILED'),lambda s:s.update(uuid='bad'),
            lambda s:s.update(version='different'),lambda s:s.update(version='9.2.1'),
            lambda s:s.update(version_id=9039000),lambda s:s.update(version_id=True),lambda s:s.update(include_global_state=False),
            lambda s:s.update(failures=[{'reason':'unavailable'}]),lambda s:s.update(indices=[]),
            lambda s:s['metadata'].update(azd_santa_binding_sha256='f'*64),
            lambda s:s['shards'].update(failed=1),lambda s:s['shards'].update(total=2),lambda s:s['shards'].update(successful=True))
        for change in changes:
            value=copy.deepcopy(self.result);change(value['snapshots'][0])
            with self.assertRaises(ValueError):native.completed_snapshot(value,self.plan)

    def test_node_release_must_remain_exact_despite_snapshot_index_release_range(self):
        with self.assertRaises(ValueError):native.plan('a'*64,'b'*32,'C'*22,'9.2.0',['santa-events'],1)
        api,state,calls=self.transport()
        native.submit(self.root,self.plan,api)
        def changed(method,path,body):
            return {'cluster_uuid':'C'*22,'version':{'number':'9.2.0'}} if path=='/' else api(method,path,body)
        calls.clear()
        with self.assertRaises(ValueError):native.observe(self.root,self.plan,changed)
        self.assertFalse(any(call[0]=='PUT' for call in calls))

    def test_in_progress_is_read_only_and_inventory_changes_fail_completion(self):
        api,state,calls=self.transport();native.submit(self.root,self.plan,api)
        state['snapshot']['snapshots'][0]['state']='IN_PROGRESS'
        calls.clear();self.assertIsNone(native.observe(self.root,self.plan,api));self.assertTrue(all(c[0]=='GET' for c in calls))
        for rows in ([{'index':'santa-events','status':'close','pri':'1'}],
                     [{'index':'santa-events','status':'open','pri':'2'}],
                     [{'index':'santa-events','status':'open','pri':'1'},{'index':'hidden','status':'open','pri':'1'}]):
            with self.assertRaises(ValueError):native.inventory_matches(rows,self.plan)

    def test_repository_must_match_fixed_location_type_and_write_owner(self):
        for repository in ({'type':'url','settings':{'location':self.plan['location']}},
                           {'type':'fs','settings':{'location':'/elsewhere'}},
                           {'type':'fs','settings':{'location':self.plan['location'],'readonly':True}},
                           {'type':'fs','settings':{'location':self.plan['location'],'readonly':0}}):
            with self.assertRaises(ValueError):native.repository_matches({self.plan['repository']:repository},self.plan)

    def publishers(self):
        ids={'web':'1'*64,'celery':'2'*64}
        rows=[dict(Id=v,State=dict(Running=False,Paused=False,Restarting=False,Pid=0,ExitCode=0,Status='exited',OOMKilled=False,Error='')) for v in ids.values()]
        return ids,rows

    def test_drain_requires_closed_original_publishers_and_two_complete_zero_samples(self):
        ids,rows=self.publishers();clock=[0];samples=[1,0,0]
        def queues():return [dict(name='santa-events',messages_ready=samples.pop(0),messages_unacknowledged=0)]
        result=native.drain('a'*64,ids,['santa-events'],lambda:rows,queues,clock=lambda:clock[0],sleep=lambda n:clock.__setitem__(0,clock[0]+n))
        self.assertEqual(result['zero_samples'],2);self.assertEqual(clock[0],4)
        for change in (lambda r:r[0]['State'].update(Running=True),lambda r:r[0].update(Id='f'*64),lambda r:r[0]['State'].update(ExitCode=143)):
            changed=copy.deepcopy(rows);change(changed)
            with self.assertRaises(ValueError):native.publisher_quiescence(changed,ids)

    def test_drain_rejects_unknown_missing_duplicate_corrupt_queues_and_times_out_without_success(self):
        ids,rows=self.publishers()
        bad=([],[dict(name='foreign',messages_ready=0,messages_unacknowledged=0)],
             [dict(name='santa-events',messages_ready=True,messages_unacknowledged=0)])
        for values in bad:
            with self.assertRaises(ValueError):native.drain('a'*64,ids,['santa-events'],lambda:rows,lambda:values)
        clock=[0]
        with self.assertRaises(TimeoutError):native.drain('a'*64,ids,['santa-events'],lambda:rows,
            lambda:[dict(name='santa-events',messages_ready=0,messages_unacknowledged=1)],seconds=2,
            clock=lambda:clock[0],sleep=lambda n:clock.__setitem__(0,clock[0]+n))

    def test_restorable_roots_include_entire_completed_repository_and_never_raw_es_data(self):
        volumes={name:self.root/name for name in ('postgres_data','redis_data','rabbitmq_data','elasticsearch_data','media_data','elasticsearch_snapshots')}
        repository=volumes['elasticsearch_snapshots']/self.plan['operation_id'];repository.mkdir(parents=True)
        for name in ('snap-'+'D'*22+'.dat','meta-'+'D'*22+'.dat','index-0'):(repository/name).write_bytes(b'necessary metadata')
        receipt=native.completed_snapshot(self.result,self.plan)
        roots=native.archive_roots(volumes,receipt,'a'*64)
        self.assertEqual(roots['elasticsearch_snapshot_repository'],repository)
        self.assertNotIn(volumes['elasticsearch_data'],roots.values());self.assertNotIn(volumes['elasticsearch_snapshots'],roots.values())
        (repository/('snap-'+'D'*22+'.dat')).unlink()
        with self.assertRaises((ValueError,FileNotFoundError)):native.archive_roots(volumes,receipt,'a'*64)
        with self.assertRaises(ValueError):native.archive_roots({k:v for k,v in volumes.items() if k!='elasticsearch_snapshots'},receipt,'a'*64)


    def run_client(self, *, unknown=False, oversized=False):
        import urllib.request
        calls=[];state={'repository':None,'snapshot':None}
        class Response:
            def __init__(self,value):self.raw=native.encoded(value)
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def read(self,limit):
                self_test.assertEqual(limit,1024*1024+1)
                return self.raw[:limit]
        self_test=self
        def open_request(request,timeout):
            self.assertTrue(request.full_url.startswith('http://elastic:9200/'))
            self.assertGreater(timeout,0);self.assertLessEqual(timeout,5)
            method=request.get_method();path=request.full_url.removeprefix('http://elastic:9200')
            calls.append((method,path))
            if method=='PUT':
                body=json.loads(request.data)
                if body.get('type')=='fs':
                    state['repository']={self.plan['repository']:{'type':'fs','settings':{'location':self.plan['location']}}}
                    return Response({'acknowledged':True})
                state['snapshot']=self.result
                if unknown:raise TimeoutError('submission outcome unknown')
                return Response({'accepted':True})
            if path=='/':return Response({'cluster_uuid':'C'*22,'version':{'number':'9.2.1'}})
            if path.startswith('/_stats/'):return Response({'_all':{'primaries':{'store':{'size_in_bytes':200000000 if oversized else 1}}}})
            if path==native.INDICES_PATH:return Response([{'index':'santa-events','status':'open','pri':'1'}])
            value=state['snapshot'] if path.endswith('/'+self.plan['snapshot']) else state['repository']
            if value is None:
                import urllib.error
                raise urllib.error.HTTPError(request.full_url,404,'missing',{},None)
            return Response(value)
        opener=SimpleNamespace(open=open_request)
        with patch.object(urllib.request,'build_opener',return_value=opener) as builder:
            native.run_reserved(self.root,'a'*64,'b'*32,maximum_bytes=128*1024**2)
        self.assertEqual(len(builder.call_args.args),2)  # no proxy, no redirect
        return calls

    def test_bounded_private_client_persists_full_native_readback_after_one_submission(self):
        calls=self.run_client()
        self.assertEqual(len([c for c in calls if c[0]=='PUT']),2)
        self.assertEqual(json.loads((self.root/'native-observed.json').read_bytes()),self.result)
        self.assertEqual(json.loads((self.root/'native-complete.json').read_bytes())['state'],'SUCCESS')

    def test_private_client_unknown_submission_retains_intent_without_replay_or_completion(self):
        with self.assertRaises(TimeoutError):self.run_client(unknown=True)
        self.assertTrue((self.root/'snapshot-intent.json').exists())
        self.assertFalse((self.root/'native-complete.json').exists())
        with self.assertRaises(FileExistsError):self.run_client()

    def test_private_client_source_size_over_budget_blocks_repository_and_snapshot_mutation(self):
        with self.assertRaises(ValueError):self.run_client(oversized=True)
        self.assertFalse((self.root/'repository-intent.json').exists())
        self.assertFalse((self.root/'snapshot-intent.json').exists())


if __name__=='__main__':unittest.main()
