"""Synthetic protocol/crypto tests; real Linux descriptor cases are separate."""
import base64
import copy
import datetime as dt
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
import urllib.parse
from unittest.mock import Mock, patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'experiments/server'))
import blob_retention as retention
import cold_backup
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

SUB='11111111-1111-4111-8111-111111111111'
OWNER='22222222-2222-4222-8222-222222222222'
def resource(environment,provider,name):
    return f'/subscriptions/{SUB}/resourceGroups/rg-azd-santa-vm-{environment}/providers/{provider}/{name}'
def target(environment,instance):
    return retention.SelectedTarget(resource(environment,'Microsoft.Compute','virtualMachines/vm-santa-lab'),
        instance,resource(environment,'Microsoft.Network','virtualNetworks/vnet-santa-lab/subnets/host'),'westus2')


class Arm:
    def __init__(self,store,targets):
        self.calls=[]; self.responses={}
        self.responses[store.blob.account_id]=dict(id=store.blob.account_id,location=store.region,kind='StorageV2',sku={'name':'Standard_LRS'},
            tags={'azd-santa-backup-owner':store.ownership_id,'azd-santa-backup-store':'independent-v1'},properties=dict(
            allowBlobPublicAccess=False,allowSharedKeyAccess=True,supportsHttpsTrafficOnly=True,minimumTlsVersion='TLS1_2',
            publicNetworkAccess='Enabled',accessTier='Hot',isHnsEnabled=False,networkAcls=dict(defaultAction='Deny',bypass='None',ipRules=[],
                virtualNetworkRules=[{'id':s,'action':'Allow','state':'Succeeded'} for s in store.owned_subnets])))
        self.responses[store.blob.account_id+'/blobServices/default/containers/native-captures']=dict(
            id=store.blob.account_id+'/blobServices/default/containers/native-captures',properties={'publicAccess':'None'})
        for t in targets:
            env=t.vm_id.split('/resourceGroups/rg-azd-santa-vm-')[1].split('/')[0]
            tags={'azd-solution':'azd-santa','purpose':'synthetic-vm-lab','azd-env-name':env}
            nsg=resource(env,'Microsoft.Network','networkSecurityGroups/nsg-santa-lab')
            self.responses[t.subnet_id]=dict(id=t.subnet_id,properties=dict(defaultOutboundAccess=False,
                serviceEndpoints=[{'service':'Microsoft.Storage','provisioningState':'Succeeded'}],networkSecurityGroup={'id':nsg}))
            self.responses[t.subnet_id.rsplit('/subnets/',1)[0]]=dict(location=t.region,tags=tags)
            nic=resource(env,'Microsoft.Network','networkInterfaces/nic-santa-lab')
            self.responses[t.vm_id]=dict(id=t.vm_id,location=t.region,tags=tags,properties=dict(vmId=t.instance_id,
                networkProfile={'networkInterfaces':[{'id':nic}]}))
            self.responses[nic]=dict(properties={'ipConfigurations':[{'properties':{'subnet':{'id':t.subnet_id}}}]})
            self.responses[nsg]=dict(properties={'securityRules':[{'properties':dict(priority=100,direction='Inbound',access='Deny',protocol='*',
                sourcePortRange='*',destinationPortRange='*',sourceAddressPrefix='*',destinationAddressPrefix='*')}]})

    def __call__(self,method,url,body):
        self.calls.append((method,url,body))
        if method=='GET':
            path=urllib.parse.urlsplit(url).path.casefold()
            return copy.deepcopy(next(v for k,v in self.responses.items() if k.casefold()==path))
        values=dict(sv='2015-04-05',sr=body['signedResource'],sp=body['signedPermission'],spr=body['signedProtocol'],
            st=body['signedStart'][:-1]+'.0000000Z',se=body['signedExpiry'][:-1]+'.0000000Z',
            sig=base64.b64encode(b's'*32).decode())
        return {'serviceSasToken':urllib.parse.urlencode(values)}


class Journal:
    def __init__(self):self.values={}
    def write(self,name,value):
        if name in self.values:raise FileExistsError()
        self.values[name]=copy.deepcopy(value)


class Response(io.BytesIO):
    def __init__(self,raw,status=200,length=None,etag='"0xabc"'):
        super().__init__(raw);self.status=status;self.headers={'Content-Length':str(len(raw) if length is None else length),'ETag':etag}
    def getheader(self,name):return self.headers.get(name)


class Transport:
    def __init__(self,raw,status=201,error=None):self.raw=raw;self.status=status;self.error=error;self.puts=0;self.gets=0
    def put(self,capability,reader,length,md5,seconds):
        self.puts+=1
        if self.error:raise self.error
        self.sent=b''
        if self.status==201:
            while True:
                raw=reader.read(8192)
                if not raw:break
                self.sent+=raw
        return self.status,'"0xabc"'
    def get(self,capability,seconds):
        self.gets+=1;return Mock(),Response(self.raw)


class Retention(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        key=rsa.generate_private_key(public_exponent=65537,key_size=3072)
        public=key.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
        stream=io.BytesIO();sink=cold_backup.EncryptedSink(stream,public,retention.MAXIMUM,time.monotonic()+30)
        sink.write(b'synthetic-private-application-data'*2000);sink.finish();cls.raw=stream.getvalue()
        cls.complete=dict(scope='azd-santa-cold-backup-ciphertext-v1',ciphertext_sha256=hashlib.sha256(cls.raw).hexdigest(),
            ciphertext_bytes=len(cls.raw),recipient_sha256=hashlib.sha256(public).hexdigest(),entries=40,
            restore_admission='not_implemented',current_authority='not_established',maintenance_sha256='a'*64,generation_sha256='b'*64)

    def setUp(self):
        self.source=target('source','33333333-3333-4333-8333-333333333333')
        self.verifier=target('restore','44444444-4444-4444-8444-444444444444')
        self.blob=retention.Blob(f'/subscriptions/{SUB}/resourceGroups/independent-backups/providers/Microsoft.Storage/storageAccounts/santatestbackup','a'*32)
        self.store=retention.Store(self.blob,'westus2',(self.source.subnet_id,self.verifier.subnet_id),OWNER)
        self.maintenance=dict(scope='azd-santa-backup-maintenance-v1',operation_id=self.blob.operation,
            manifest_sha256='d'*64,generation_sha256=self.complete['generation_sha256'],
            target={'VmId':self.source.vm_id,'VmInstanceId':self.source.instance_id},boot_id='55555555-5555-4555-8555-555555555555',
            recipient_der_base64='public-key-checked-by-producer',recipient_sha256=self.complete['recipient_sha256'],
            destination='/var/lib/azd-santa-qualification/backup',maximum_bytes=retention.MAXIMUM,maximum_files=100000,
            seconds=1800,queue_inventory=[],backup_program_sha256='c'*64,storage_sha256='d'*64,worker_instance={})
        self.maintenance_raw=json.dumps(self.maintenance,sort_keys=True).encode()
        complete=dict(self.complete,maintenance_sha256=hashlib.sha256(self.maintenance_raw).hexdigest())
        self.record=retention.capture_record(self.blob,complete,self.source,maintenance_request=self.maintenance_raw,
            image_id='sha256:'+'e'*64,source_bundle_sha256='f'*64)
        self.arm=Arm(self.store,(self.source,self.verifier))

    def cap(self,permission='c'):
        return retention.mint_capability(self.arm,self.record,self.blob,self.store,self.source if permission=='c' else self.verifier,permission,apply=True)

    def test_default_plans_do_no_arm_imds_network_or_file_operations(self):
        plan=retention.mint_capability(self.arm,self.record,self.blob,self.store,self.source,'c')
        self.assertEqual(self.arm.calls,[]);self.assertFalse(plan['performs_mutation'])
        self.assertEqual(plan['body']['signedPermission'],'c');self.assertNotIn('signedIp',plan['body'])
        self.assertEqual(plan['body']['signedResource'],'b');self.assertEqual(plan['body']['signedProtocol'],'https')
        start=dt.datetime.fromisoformat(plan['body']['signedStart']);end=dt.datetime.fromisoformat(plan['body']['signedExpiry'])
        self.assertEqual((end-start).total_seconds(),1800)
        with patch.object(retention,'parent',side_effect=AssertionError),patch.object(retention,'host_identity',side_effect=AssertionError):
            self.assertFalse(retention.upload_file('absent',self.record,None,'absent')['performs_mutation'])
            self.assertFalse(retention.verify_download('absent',self.record,None,'absent')['performs_mutation'])

    def test_exact_arm_selection_blob_sas_scope_and_redacted_capability(self):
        cap=self.cap();method,url,body=self.arm.calls[-1]
        self.assertEqual(method,'POST');self.assertEqual(url,'https://management.azure.com'+self.blob.account_id+'/listServiceSas?api-version=2025-06-01')
        self.assertEqual(body['canonicalizedResource'],self.blob.canonical)
        self.assertTrue(all(m=='GET' for m,_,_ in self.arm.calls[:-1]))
        self.assertEqual(cap.permission,'c');self.assertIn('&api-version=2023-11-03',cap.path())
        self.assertNotIn('sig=',repr(cap));self.assertNotIn(cap._token,repr(cap))
        with self.assertRaises(retention.RetentionRejected):self.capability_for_source_read()

    def capability_for_source_read(self):
        return retention.mint_capability(self.arm,self.record,self.blob,self.store,self.source,'r',apply=True)

    def test_unrelated_or_broadened_store_networks_and_policies_reject_before_mint(self):
        account=self.arm.responses[self.blob.account_id]
        for change in ('owner','env-tag','public','allow-all','bypass','ip','shared-key','policy','private-endpoint','subnet-missing'):
            arm=Arm(self.store,(self.source,self.verifier));item=arm.responses[self.blob.account_id]
            if change=='owner':item['tags']['azd-santa-backup-owner']='different'
            elif change=='env-tag':item['tags']['azd-env-name']='source'
            elif change=='public':item['properties']['allowBlobPublicAccess']=True
            elif change=='allow-all':item['properties']['networkAcls']['defaultAction']='Allow'
            elif change=='bypass':item['properties']['networkAcls']['bypass']='AzureServices'
            elif change=='ip':item['properties']['networkAcls']['ipRules']=[{'value':'203.0.113.1'}]
            elif change=='shared-key':item['properties']['allowSharedKeyAccess']=False
            elif change=='policy':item['properties']['sasPolicy']={'expirationAction':'Block'}
            elif change=='private-endpoint':item['properties']['privateEndpointConnections']=[{'id':'unreviewed-network'}]
            else:arm.responses[self.source.subnet_id]['properties']['serviceEndpoints']=[]
            with self.subTest(change=change),self.assertRaises(retention.RetentionRejected):
                retention.mint_capability(arm,self.record,self.blob,self.store,self.source,'c',apply=True)
            self.assertTrue(all(m=='GET' for m,_,_ in arm.calls))

    def test_vm_nic_subnet_ownership_and_inbound_rules_are_rechecked(self):
        for change in ('instance','tags','nic','subnet','inbound'):
            arm=Arm(self.store,(self.source,self.verifier));vm=arm.responses[self.source.vm_id]
            if change=='instance':vm['properties']['vmId']='5'*36
            elif change=='tags':vm['tags']['azd-solution']='unrelated'
            elif change=='nic':vm['properties']['networkProfile']['networkInterfaces']=[]
            elif change=='subnet':arm.responses[resource('source','Microsoft.Network','networkInterfaces/nic-santa-lab')]['properties']['ipConfigurations'][0]['properties']['subnet']['id']=self.verifier.subnet_id
            else:arm.responses[resource('source','Microsoft.Network','networkSecurityGroups/nsg-santa-lab')]['properties']['securityRules'][0]['properties']['access']='Allow'
            with self.subTest(change=change),self.assertRaises(retention.RetentionRejected):
                retention.mint_capability(arm,self.record,self.blob,self.store,self.source,'c',apply=True)
            self.assertTrue(all(m=='GET' for m,_,_ in arm.calls))

    def test_same_region_public_ip_or_external_operator_mode_has_no_fallback(self):
        bad=retention.SelectedTarget(self.source.vm_id,self.source.instance_id,self.source.subnet_id,'eastus')
        with self.assertRaises(retention.RetentionRejected):retention.mint_capability(self.arm,self.record,self.blob,self.store,bad,'c',apply=True)
        with self.assertRaises(retention.RetentionRejected):retention.SelectedTarget('203.0.113.1',self.source.instance_id,self.source.subnet_id,'westus2')
        self.assertEqual(self.arm.calls,[])

    def test_same_vm_case_alias_is_not_an_independent_verifier_before_any_transfer(self):
        alias=self.source.vm_id.replace('rg-azd-santa-vm-source','RG-AZD-SANTA-VM-SOURCE').replace('vm-santa-lab','VM-SANTA-LAB')
        same=retention.SelectedTarget(alias,self.source.instance_id,self.source.subnet_id,self.source.region)
        with self.assertRaises(retention.RetentionRejected):
            retention.mint_capability(self.arm,self.record,self.blob,self.store,same,'r',apply=True)
        self.assertEqual(self.arm.calls,[])
        # Relay-supplied capabilities must be checked again at the filesystem boundary.
        cap=retention.Capability(self.blob,same,'r',self.complete['ciphertext_sha256'],
            dt.datetime.now(dt.timezone.utc)+dt.timedelta(minutes=5),'synthetic-private-relay-capability')
        transport=Transport(self.raw)
        with patch.object(retention,'host_identity') as metadata,patch.object(retention,'parent') as filesystem:
            with self.assertRaises(retention.RetentionRejected):
                retention.verify_download('unused',self.record,cap,'unused',apply=True,transport=transport)
        metadata.assert_not_called();filesystem.assert_not_called();self.assertEqual(transport.gets,0)
        # Case aliases remain the same source for a correctly scoped create operation.
        cap=retention.mint_capability(self.arm,self.record,self.blob,self.store,same,'c',apply=True)
        self.assertEqual(cap.permission,'c')

    def test_mixed_case_azd_ownership_tags_and_duplicate_aliases_reject(self):
        for key in ('AZD-ENV-NAME','AzD-EnV-NaMe','AZD-SERVICE-NAME','AzD-SeRvIcE-NaMe'):
            arm=Arm(self.store,(self.source,self.verifier));arm.responses[self.blob.account_id]['tags'][key]='source'
            with self.subTest(key=key),self.assertRaises(retention.RetentionRejected):
                retention.mint_capability(arm,self.record,self.blob,self.store,self.source,'c',apply=True)
            self.assertTrue(all(method=='GET' for method,_,_ in arm.calls))
        for key in ('AZD-SANTA-BACKUP-OWNER','AZD-SANTA-BACKUP-STORE','PURPOSE'):
            arm=Arm(self.store,(self.source,self.verifier));tags=arm.responses[self.blob.account_id]['tags']
            tags[key.lower()]=tags.get(key.lower(),'encrypted-native-backup');tags[key]=tags[key.lower()]
            with self.subTest(duplicate=key),self.assertRaises(retention.RetentionRejected):
                retention.mint_capability(arm,self.record,self.blob,self.store,self.source,'c',apply=True)
            self.assertTrue(all(method=='GET' for method,_,_ in arm.calls))
        # Accepted key casing never changes the case-sensitive marker or ownership value.
        owner='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
        store=retention.Store(self.blob,self.store.region,self.store.owned_subnets,owner)
        arm=Arm(store,(self.source,self.verifier));account=arm.responses[self.blob.account_id]
        account['tags']={key.upper():value for key,value in account['tags'].items()}
        self.assertEqual(retention.mint_capability(arm,self.record,self.blob,store,self.source,'c',apply=True).permission,'c')
        for key,value in (('AZD-SANTA-BACKUP-OWNER',owner.upper()),('AZD-SANTA-BACKUP-STORE','INDEPENDENT-V1')):
            bad=Arm(store,(self.source,self.verifier));bad.responses[self.blob.account_id]['tags'][key.lower()]=value
            with self.subTest(value_key=key),self.assertRaises(retention.RetentionRejected):
                retention.mint_capability(bad,self.record,self.blob,store,self.source,'c',apply=True)

    def test_resource_id_case_aliases_match_network_facts_but_duplicate_subnets_reject(self):
        alias=self.source.subnet_id.replace('rg-azd-santa-vm-source','RG-AZD-SANTA-VM-SOURCE').replace('vnet-santa-lab','VNET-SANTA-LAB')
        store=retention.Store(self.blob,self.store.region,(alias,self.verifier.subnet_id),OWNER)
        arm=Arm(store,(self.source,self.verifier))
        self.assertEqual(retention.mint_capability(arm,self.record,self.blob,store,self.source,'c',apply=True).permission,'c')
        with self.assertRaises(retention.RetentionRejected):
            retention.Store(self.blob,self.store.region,(alias,self.source.subnet_id),OWNER)

    def test_sas_permission_protocol_ip_expiry_duplicates_and_raw_errors_are_redacted(self):
        base=self.arm
        for change in ('write','ip','protocol','expiry','nonzero-fraction','duplicate','raw-error'):
            def call(method,url,body):
                value=base(method,url,body)
                if method=='GET':return value
                if change=='raw-error':raise RuntimeError('synthetic-secret-SAS-token')
                pairs=urllib.parse.parse_qsl(value['serviceSasToken']);values=dict(pairs)
                if change=='write':values['sp']='cw'
                elif change=='ip':values['sip']='203.0.113.1'
                elif change=='protocol':values['spr']='https,http'
                elif change=='expiry':values['se']='2099-01-01T00:00:00Z'
                elif change=='nonzero-fraction':values['se']=values['se'][:-2]+'1Z'
                raw=urllib.parse.urlencode(values)
                if change=='duplicate':raw+='&sp=c'
                return {'serviceSasToken':raw}
            with self.subTest(change=change),self.assertRaises(retention.RetentionRejected) as caught:
                retention.mint_capability(call,self.record,self.blob,self.store,self.source,'c',apply=True)
            self.assertNotIn('synthetic-secret',str(caught.exception))

    def test_completed_cipher_bounds_source_and_recoverability_claims_are_strict(self):
        for change in ('scope','size','bool','extra','image-claim','uri-secret'):
            record=copy.deepcopy(self.record)
            if change=='scope':record['complete']['scope']='image-export'
            elif change=='size':record['complete']['ciphertext_bytes']=retention.MAXIMUM+1
            elif change=='bool':record['complete']['ciphertext_bytes']=True
            elif change=='extra':record['complete']['unreviewed']='value'
            elif change=='image-claim':record['exact_image_retained']=True
            else:record['blob_uri']+='?sig=synthetic-secret'
            with self.subTest(change=change),self.assertRaises(retention.RetentionRejected):retention.checked_record(record)

    def test_capture_operation_target_generation_and_key_bind_to_actual_request_bytes(self):
        for change in ('hash','operation','target','generation','recipient','duplicate'):
            request=copy.deepcopy(self.maintenance)
            if change=='operation':request['operation_id']='b'*32
            elif change=='target':request['target']['VmId']=self.verifier.vm_id
            elif change=='generation':request['generation_sha256']='c'*64
            elif change=='recipient':request['recipient_sha256']='c'*64
            raw=json.dumps(request,sort_keys=True).encode()
            if change=='duplicate':raw=raw[:-1]+b',"operation_id":"'+self.blob.operation.encode()+b'"}'
            complete=dict(self.complete,maintenance_sha256=hashlib.sha256(raw).hexdigest())
            if change=='hash':complete['maintenance_sha256']='e'*64
            with self.subTest(change=change),self.assertRaises(retention.RetentionRejected):
                retention.capture_record(self.blob,complete,self.source,maintenance_request=raw,image_id='sha256:'+'e'*64,source_bundle_sha256='f'*64)

    def test_actual_producer_envelope_fingerprint_and_plaintext_rejection(self):
        self.assertTrue(retention.fingerprint(io.BytesIO(self.raw),self.record,time.monotonic()+30))
        for raw in (b'plaintext',self.raw[:-1],self.raw+b'extra'):
            with self.assertRaises(Exception):retention.fingerprint(io.BytesIO(raw),self.record,time.monotonic()+30)
        with self.assertRaises(retention.RetentionRejected):retention.fingerprint(io.BytesIO(self.raw),self.record,0)

    def test_one_put_success_and_unknown_412_timeout_expiry_or_descriptor_change(self):
        cap=self.cap()
        for status,error,changed in ((201,None,False),(412,None,False),(201,TimeoutError('synthetic-private-url'),False),(201,None,True)):
            stream=io.BytesIO(self.raw);md5=retention.fingerprint(stream,self.record,time.monotonic()+30);journal=Journal();transport=Transport(self.raw,status,error)
            def unchanged():retention.need(not changed)
            result=retention.put_once(stream,self.record,cap,journal,unchanged,md5,time.monotonic()+30,transport)
            self.assertEqual(transport.puts,1);self.assertFalse(result['automatic_replay']);self.assertFalse(result['independent_bytes_verified'])
            self.assertEqual(result['state'],'uploaded' if status==201 and error is None and not changed else 'unknown')
            self.assertEqual(result['http_status'],None if error else status)
            self.assertNotIn(cap._token,json.dumps(journal.values));self.assertNotIn('synthetic-private-url',json.dumps(result))
        expired=retention.Capability(cap.blob,cap.target,'c',cap.ciphertext_sha256,dt.datetime.now(dt.timezone.utc)-dt.timedelta(seconds=1),cap._token)
        transport=Transport(self.raw);stream=io.BytesIO(self.raw)
        result=retention.put_once(stream,self.record,expired,Journal(),lambda:None,'unused',time.monotonic()+30,transport)
        self.assertEqual(result['state'],'unknown');self.assertEqual(transport.puts,0)

    def test_interrupted_or_changed_stream_keeps_unknown_without_second_put(self):
        cap=self.cap();stream=io.BytesIO(self.raw);md5=retention.fingerprint(stream,self.record,time.monotonic()+30);journal=Journal()
        interrupted=Transport(self.raw,error=KeyboardInterrupt())
        with self.assertRaises(KeyboardInterrupt):
            retention.put_once(stream,self.record,cap,journal,lambda:None,md5,time.monotonic()+30,interrupted)
        self.assertEqual(interrupted.puts,1);self.assertEqual(journal.values['outcome.json']['state'],'unknown')
        stream=io.BytesIO(self.raw);md5=retention.fingerprint(stream,self.record,time.monotonic()+30)
        stream.seek(-1,2);stream.write(bytes([self.raw[-1]^1]));stream.seek(0);transport=Transport(self.raw)
        result=retention.put_once(stream,self.record,cap,Journal(),lambda:None,md5,time.monotonic()+30,transport)
        self.assertEqual(result['state'],'unknown');self.assertEqual(transport.puts,1)

    def test_http_wire_uses_create_only_headers_modern_query_and_no_redirect_retry(self):
        cap=self.cap();connection=Mock();response=Mock();response.read.return_value=b'';response.status=201;response.getheader.return_value='"0xabc"';connection.getresponse.return_value=response
        with patch.object(retention.BlobHttp,'connection',return_value=connection):
            status,_=retention.BlobHttp().put(cap,io.BytesIO(self.raw),len(self.raw),'md5',30)
        args,kw=connection.request.call_args;self.assertEqual(args[0],'PUT');self.assertIn('api-version=2023-11-03',args[1])
        self.assertEqual(kw['headers']['If-None-Match'],'*');self.assertEqual(kw['headers']['Content-Length'],str(len(self.raw)))
        self.assertEqual(kw['headers']['x-ms-blob-type'],'BlockBlob');self.assertEqual(status,201);self.assertEqual(connection.request.call_count,1);connection.close.assert_called_once()

    def test_independent_download_requires_exact_length_sha_and_200_response(self):
        output=io.BytesIO();count,digest=retention.download_bytes(Response(self.raw),output,self.record,time.monotonic()+30)
        self.assertEqual((count,digest),(len(self.raw),self.complete['ciphertext_sha256']));self.assertEqual(output.getvalue(),self.raw)
        for response in (Response(self.raw,status=302),Response(self.raw,length=len(self.raw)+1),Response(self.raw[:-1]),Response(self.raw+b'x'),Response(b'x'*len(self.raw))):
            with self.subTest(status=response.status),self.assertRaises(retention.RetentionRejected):
                retention.download_bytes(response,io.BytesIO(),self.record,time.monotonic()+30)
        with self.assertRaises(retention.RetentionRejected):retention.download_bytes(Response(self.raw),io.BytesIO(),self.record,0)

    def test_host_metadata_exact_vm_instance_region_without_redirects(self):
        metadata=dict(resourceId=self.source.vm_id,vmId=self.source.instance_id,location=self.source.region)
        for bad in (False,True):
            value=dict(metadata)
            if bad:value['vmId']=self.verifier.instance_id
            response=Mock();response.__enter__=Mock(return_value=io.BytesIO(json.dumps(value).encode()));response.__exit__=Mock(return_value=False)
            opener=Mock();opener.open.return_value=response
            with patch.object(retention.urllib.request,'build_opener',return_value=opener):
                if bad:
                    with self.assertRaises(retention.RetentionRejected):retention.host_identity(self.source)
                else:retention.host_identity(self.source)
                request=opener.open.call_args.args[0];self.assertTrue(request.full_url.startswith('http://169.254.169.254/'))

    @unittest.skipUnless(sys.platform=='linux','actual private descriptor and journal guards require Linux')
    def test_linux_upload_is_exclusive_preserves_source_and_records_unknown_without_replay(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as folder:
            root=Path(folder);source=root/'backup.sealed';source.write_bytes(self.raw);source.chmod(0o600);before=source.read_bytes();cap=self.cap();transport=Transport(self.raw,status=412)
            with patch.object(retention,'host_identity'):
                result=retention.upload_file(source,self.record,cap,root/'attempt',apply=True,transport=transport)
                self.assertEqual(result['state'],'unknown');self.assertEqual(transport.puts,1)
                with self.assertRaises(retention.RetentionRejected):retention.upload_file(source,self.record,cap,root/'attempt',apply=True,transport=transport)
            self.assertEqual(transport.puts,1);self.assertEqual(source.read_bytes(),before)
            self.assertTrue((root/'attempt/intent.json').is_file());self.assertTrue((root/'attempt/outcome.json').is_file())
            alias=root/'alias';alias.symlink_to(root,target_is_directory=True)
            with patch.object(retention,'host_identity'),self.assertRaises(retention.RetentionRejected):retention.upload_file(alias/'backup.sealed',self.record,cap,root/'other',apply=True,transport=transport)
            self.assertEqual(transport.puts,1)

    @unittest.skipUnless(sys.platform=='linux','actual independent private download guards require Linux')
    def test_linux_independent_download_verifies_bytes_without_restore_claim_and_preserves_partial(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as folder:
            root=Path(folder);cap=self.cap('r');source_cap=self.cap();destination=root/'backup.sealed'
            with patch.object(retention,'host_identity'):
                result=retention.verify_download(destination,self.record,cap,root/'verify',apply=True,transport=Transport(self.raw))
                self.assertTrue(result['independent_bytes_verified']);self.assertFalse(result['sealed_authenticated']);self.assertFalse(result['restore_accepted']);self.assertFalse(result['exact_image_retained'])
                self.assertEqual(destination.read_bytes(),self.raw);self.assertEqual(destination.stat().st_mode&0o777,0o600)
                with self.assertRaises(retention.RetentionRejected):retention.verify_download(destination,self.record,cap,root/'second',apply=True,transport=Transport(self.raw))
                with self.assertRaises(retention.RetentionRejected):retention.verify_download(root/'unused',self.record,source_cap,root/'third',apply=True,transport=Transport(self.raw))
            self.assertEqual(destination.read_bytes(),self.raw);self.assertFalse((root/'second/verified.json').exists())


if __name__=='__main__':unittest.main()
