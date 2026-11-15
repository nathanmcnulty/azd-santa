"""Original Unlicense. Nonsecret bridge for the cached, GET-only ARM producer.

Standalone fixture validation is not authenticated ARM observation. Only the
PowerShell producer collects these facts; no fact file is an authority token.
"""
import hashlib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from blob_retention import (Blob, Store, SelectedTarget, GUID, arm_selection,
                            encoded, need, resource_id, tags_by_key, unique)

BOUND = 8 * 1024 * 1024


def plan(intent):
    need(type(intent) is dict and set(intent) == {'tenant', 'subscription', 'region',
        'store_group', 'store_name', 'owner', 'source', 'verifier'})
    for key in ('tenant', 'subscription', 'owner'):
        need(type(intent[key]) is str and re.fullmatch(GUID, intent[key]))
    need(re.fullmatch(r'[a-z0-9]{2,32}', intent['region'])
         and re.fullmatch(r'[A-Za-z0-9_()-][A-Za-z0-9_.()-]{0,88}[A-Za-z0-9_()-]|[A-Za-z0-9_()-]', intent['store_group'])
         and re.fullmatch(r'[a-z0-9]{3,24}', intent['store_name']))
    sub = '/subscriptions/' + intent['subscription']
    group = sub + '/resourceGroups/' + intent['store_group']
    account = group + '/providers/Microsoft.Storage/storageAccounts/' + intent['store_name']
    targets = []
    requests = {group: '2025-04-01', account: '2025-06-01',
        account + '/blobServices/default/containers/native-captures': '2025-06-01'}
    for selection in (intent['source'], intent['verifier']):
        if selection is None:
            need(len(targets) == 1)
            continue
        need(type(selection) is dict and set(selection) == {'environment', 'instance'}
             and re.fullmatch(r'[a-z0-9-]{2,32}', selection['environment'])
             and re.fullmatch(GUID, selection['instance']))
        vm_group = sub + '/resourceGroups/rg-azd-santa-vm-' + selection['environment']
        need(resource_id(vm_group) != resource_id(group))
        vm = vm_group + '/providers/Microsoft.Compute/virtualMachines/vm-santa-lab'
        vnet = vm_group + '/providers/Microsoft.Network/virtualNetworks/vnet-santa-lab'
        subnet = vnet + '/subnets/host'
        targets.append(SelectedTarget(vm, selection['instance'], subnet, intent['region']))
        requests.update({vm_group: '2025-04-01', vm: '2024-11-01', vnet: '2024-05-01',
            subnet: '2024-05-01', vm_group + '/providers/Microsoft.Network/networkInterfaces/nic-santa-lab': '2024-05-01',
            vm_group + '/providers/Microsoft.Network/networkSecurityGroups/nsg-santa-lab': '2024-05-01'})
    need(len(targets) in (1, 2) and len({resource_id(t.vm_id) for t in targets}) == len(targets))
    store = Store(Blob(account, '0' * 32), intent['region'], tuple(t.subnet_id for t in targets), intent['owner'])
    urls = ['https://management.azure.com' + path + '?api-version=' + version for path, version in requests.items()]
    return store, targets, urls


def validate(intent, context_before, context_after, before, after):
    store, targets, urls = plan(intent)
    for context in (context_before, context_after):
        need(type(context) is dict and context['id'].casefold() == intent['subscription']
             and context['tenantId'].casefold() == intent['tenant']
             and context['state'] == 'Enabled' and context['environmentName'] == 'AzureCloud')
    need(encoded(context_before) == encoded(context_after)
         and type(before) is dict and type(after) is dict
         and set(before) == set(urls) and set(after) == set(urls)
         and encoded(before) == encoded(after))
    facts = {}
    for url in urls:
        value = before[url]
        need(type(value) is dict and len(encoded(value)) <= 262144)
        path = url.split('https://management.azure.com', 1)[1].split('?', 1)[0]
        need(resource_id(value['id']) == resource_id(path))
        facts[resource_id(path)] = value
    group_id = store.blob.account_id.split('/providers/')[0]
    group = facts[resource_id(group_id)]
    tags = tags_by_key(group['tags'])
    need(group['location'] == store.region and group['properties']['provisioningState'] == 'Succeeded'
         and not group.get('managedBy') and tags.get('azd-santa-backup-owner') == store.ownership_id
         and tags.get('azd-santa-backup-store') == 'independent-v1'
         and tags.get('purpose') == 'encrypted-native-backup'
         and 'azd-env-name' not in tags and 'azd-service-name' not in tags)
    account = facts[resource_id(store.blob.account_id)]
    need(not account.get('managedBy') and account['properties']['provisioningState'] == 'Succeeded')
    for target in targets:
        vm_group = target.vm_id.split('/providers/')[0]
        environment = vm_group.rsplit('rg-azd-santa-vm-', 1)[1]
        for path in (vm_group, target.vm_id, target.subnet_id.rsplit('/subnets/', 1)[0],
                     vm_group + '/providers/Microsoft.Network/networkInterfaces/nic-santa-lab',
                     vm_group + '/providers/Microsoft.Network/networkSecurityGroups/nsg-santa-lab'):
            row = facts[resource_id(path)]
            tags = tags_by_key(row['tags'])
            need(tags.get('azd-solution') == 'azd-santa' and tags.get('purpose') == 'synthetic-vm-lab'
                 and tags.get('azd-env-name') == environment and row['location'] == store.region
                 and row['properties']['provisioningState'] == 'Succeeded')
        subnet = facts[resource_id(target.subnet_id)]
        need(subnet['properties']['provisioningState'] == 'Succeeded')
        nic = facts[resource_id(vm_group + '/providers/Microsoft.Network/networkInterfaces/nic-santa-lab')]
        need(resource_id(nic['properties']['virtualMachine']['id']) == resource_id(target.vm_id)
             and 'networkSecurityGroup' not in nic['properties'])
        def get(method, url, body):
            need(method == 'GET' and body is None and url in before)
            return before[url]
        arm_selection(get, store, target)
    return dict(scope='cached-arm-backup-store-selection-v1', status='selected',
        tenant_id=intent['tenant'], subscription_id=intent['subscription'],
        account_id=store.blob.account_id, ownership_id=store.ownership_id,
        region=store.region, targets=[dict(vm_id=t.vm_id, instance_id=t.instance_id, subnet_id=t.subnet_id) for t in targets],
        observation_sha256=hashlib.sha256(encoded(before)).hexdigest(),
        cloud_write=False, capability_minted=False, retention_proven=False, restore_accepted=False,
        requires_fresh_read_before_use=True)


def main():
    try:
        raw = sys.stdin.buffer.read(BOUND + 1)
        need(len(raw) <= BOUND)
        request = json.loads(raw, object_pairs_hook=unique)
        if set(request) == {'intent'}:
            _, _, urls = plan(request['intent'])
            result = dict(scope='backup-store-selection-plan-v1', urls=urls, cloud_write=False)
        else:
            need(set(request) == {'intent', 'context_before', 'context_after', 'before', 'after'})
            result = validate(**request)
        print(encoded(result).decode())
    except Exception:
        # No raw CLI facts/errors can escape through bridge diagnostics.
        print('{"scope":"backup-store-selection-failure-v1","status":"failed-or-unknown","cloud_write":false,"retention_proven":false}')
        sys.exit(1)


if __name__ == '__main__':
    main()
