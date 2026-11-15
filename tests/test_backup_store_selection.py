import copy
import json
from pathlib import Path
import subprocess
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'experiments/server'))
import backup_store_selection as selection
from test_blob_retention import Arm, SUB, OWNER

TENANT='55555555-5555-4555-8555-555555555555'

def fixture():
    intent=dict(tenant=TENANT,subscription=SUB,region='westus2',store_group='independent-backups',
        store_name='santatestbackup',owner=OWNER,
        source=dict(environment='source',instance='33333333-3333-4333-8333-333333333333'),
        verifier=dict(environment='restore',instance='44444444-4444-4444-8444-444444444444'))
    store,targets,urls=selection.plan(intent)
    arm=Arm(store,targets)
    rg=store.blob.account_id.split('/providers/')[0]
    arm.responses[rg]=dict(id=rg,location=store.region,properties={'provisioningState':'Succeeded'},
        tags={'azd-santa-backup-owner':OWNER,'azd-santa-backup-store':'independent-v1','purpose':'encrypted-native-backup'})
    arm.responses[store.blob.account_id]['properties']['provisioningState']='Succeeded'
    for t in targets:
        group=t.vm_id.split('/providers/')[0]
        tags=arm.responses[t.vm_id]['tags']
        arm.responses[group]=dict(tags=tags,properties={})
        for path,row in list(arm.responses.items()):
            if path.startswith(group):
                row['id']=path
                if path!=t.subnet_id:row.update(location=t.region,tags=copy.deepcopy(tags))
                row.setdefault('properties',{})['provisioningState']='Succeeded'
        nic=group+'/providers/Microsoft.Network/networkInterfaces/nic-santa-lab'
        arm.responses[nic]['properties']['virtualMachine']={'id':t.vm_id}
    before={url:arm('GET',url,None) for url in urls}
    context=dict(id=SUB,tenantId=TENANT,state='Enabled',environmentName='AzureCloud')
    return dict(intent=intent,context_before=context,context_after=copy.deepcopy(context),before=before,after=copy.deepcopy(before))

class StoreSelection(unittest.TestCase):
    def test_matching_preexisting_store_get_only_plan_and_observation(self):
        f=fixture();receipt=selection.validate(**f)
        self.assertEqual(receipt['status'],'selected')
        for key in ('cloud_write','capability_minted','retention_proven','restore_accepted'):self.assertIs(receipt[key],False)
        self.assertTrue(receipt['requires_fresh_read_before_use'])
        self.assertEqual(len(receipt['observation_sha256']),64)
        _,_,urls=selection.plan(f['intent'])
        self.assertEqual(len(urls),15)
        self.assertTrue(all(u.startswith('https://management.azure.com/subscriptions/'+SUB+'/') for u in urls))
        self.assertFalse(any('listServiceSas' in u or 'listKeys' in u for u in urls))

    def test_unrelated_managed_or_azd_store_groups_reject(self):
        for mutation in ('owner','marker','purpose','managed','AZD-ENV-NAME','aZd-SeRvIcE-nAmE','alias'):
            f=fixture();url=next(u for u in f['before'] if '/providers/' not in u)
            row=f['before'][url]
            if mutation=='owner':row['tags']['azd-santa-backup-owner']='66666666-6666-4666-8666-666666666666'
            elif mutation=='marker':row['tags']['azd-santa-backup-store']='different'
            elif mutation=='purpose':row['tags']['purpose']='different'
            elif mutation=='managed':row['managedBy']='/unrelated'
            elif mutation=='alias':row['tags']['AzD-SaNtA-BaCkUp-OwNeR']=OWNER
            else:row['tags'][mutation]='source'
            f['after']=copy.deepcopy(f['before'])
            with self.subTest(mutation=mutation),self.assertRaises(Exception):selection.validate(**f)

    def test_store_group_equals_source_and_verifier_aliases_reject_without_reads(self):
        for group in ('RG-AZD-SANTA-VM-SOURCE','rg-azd-santa-vm-restore'):
            f=fixture();f['intent']['store_group']=group
            with self.assertRaises(Exception):selection.plan(f['intent'])
        f=fixture();f['intent']['verifier']=f['intent']['source']
        with self.assertRaises(Exception):selection.plan(f['intent'])

    def test_cached_context_missing_or_changed_observation_fails_closed(self):
        for mutation in ('tenant','cloud','context-drift','missing','extra','drift','etag'):
            f=fixture()
            if mutation=='tenant':f['context_before']['tenantId']=OWNER
            elif mutation=='cloud':f['context_before']['environmentName']='AzureUSGovernment'
            elif mutation=='context-drift':f['context_after']['name']='changed'
            elif mutation=='missing':f['before'].pop(next(iter(f['before'])))
            elif mutation=='extra':f['before']['https://untrusted/']={}
            else:f['after'][next(iter(f['after']))][mutation]='changed'
            with self.subTest(mutation=mutation),self.assertRaises(Exception):selection.validate(**f)

    def test_network_identity_endpoint_and_provisioning_changes_reject(self):
        for mutation in ('id','instance','nicowner','endpoint','provisioning','stale-source','allow-all'):
            f=fixture()
            if mutation=='stale-source':
                url=next(u for u in f['before'] if '/subnets/host?' in u)
                del f['before'][url]
            elif mutation=='allow-all':
                url=next(u for u in f['before'] if '/storageAccounts/' in u and '/containers/' not in u)
                f['before'][url]['properties']['networkAcls']['defaultAction']='Allow'
            else:
                fragment={'id':'/networkSecurityGroups/','instance':'/virtualMachines/','nicowner':'/networkInterfaces/',
                    'endpoint':'/subnets/host?','provisioning':'/virtualNetworks/vnet-santa-lab?'}[mutation]
                row=next(v for k,v in f['before'].items() if fragment in k)
                if mutation=='id':row['id']='/unrelated'
                elif mutation=='instance':row['properties']['vmId']=OWNER
                elif mutation=='nicowner':row['properties']['virtualMachine']['id']='/unrelated'
                elif mutation=='endpoint':row['properties']['serviceEndpoints']=[]
                else:row['properties']['provisioningState']='Updating'
            f['after']=copy.deepcopy(f['before'])
            with self.subTest(mutation=mutation),self.assertRaises(Exception):selection.validate(**f)

    def test_bridge_rejects_duplicate_json_redacts_diagnostics_and_bounds_input(self):
        script=str(Path(selection.__file__))
        for raw in (b'{"intent":{},"intent":{}}', b'{"raw":"secret-sas-sig"}', b'x'*(selection.BOUND+1)):
            p=subprocess.run([sys.executable,'-I',script],input=raw,capture_output=True,timeout=10)
            self.assertEqual(p.returncode,1)
            self.assertNotIn(b'secret',p.stdout+p.stderr)
            self.assertEqual(json.loads(p.stdout)['status'],'failed-or-unknown')

if __name__=='__main__':unittest.main()
