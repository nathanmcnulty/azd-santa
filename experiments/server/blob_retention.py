"""Original Unlicense. Explicit native-ciphertext Blob transfer primitives.

No installer hook, login, grant, subnet mutation, cleanup or restore is provided.
The operator supplies independently retained capture facts and verified ARM
selection. The VM receives a short-lived opaque capability, never an ARM token.
"""
import base64
from contextlib import ExitStack
from dataclasses import dataclass, field
import datetime as dt
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import ssl
import stat
import struct
import sys
import time
import urllib.parse
import urllib.request

MAXIMUM = 2 * 1024**3
CHUNK = 1024 * 1024
MAGIC = b'AZDSANTABACKUP1\n'
GUID = r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}'
HEX = r'[a-f0-9]{64}'
VM = r'/subscriptions/' + GUID + r'/resourceGroups/[A-Za-z0-9_.()-]{1,90}/providers/Microsoft.Compute/virtualMachines/[A-Za-z0-9_-]{1,64}'
SUBNET = r'/subscriptions/' + GUID + r'/resourceGroups/[A-Za-z0-9_.()-]{1,90}/providers/Microsoft.Network/virtualNetworks/[A-Za-z0-9_.()-]{1,64}/subnets/[A-Za-z0-9_.()-]{1,80}'
ACCOUNT = r'/subscriptions/' + GUID + r'/resourceGroups/[A-Za-z0-9_.()-]{1,90}/providers/Microsoft.Storage/storageAccounts/([a-z0-9]{3,24})'
API_VERSION = '2023-11-03'


class RetentionRejected(ValueError):
    pass


def need(value):
    if not value:
        raise RetentionRejected('Ciphertext retention rejected; preserve original and attempt evidence')


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def unique(pairs):
    value = {}
    for key, item in pairs:
        need(key not in value); value[key] = item
    return value


def resource_id(value):
    need(type(value) is str)
    return value.casefold()


def tags_by_key(value):
    need(type(value) is dict)
    result = {}
    for key, item in value.items():
        need(type(key) is str and key.casefold() not in result)
        result[key.casefold()] = item
    return result


@dataclass(frozen=True)
class Blob:
    account_id: str
    operation: str
    container: str = 'native-captures'

    def __post_init__(self):
        need(type(self.account_id) is str and re.fullmatch(ACCOUNT, self.account_id))
        need(re.fullmatch(r'[a-f0-9]{32}', self.operation) and self.container == 'native-captures')

    @property
    def account(self): return self.account_id.rsplit('/', 1)[1]

    @property
    def uri(self): return f'https://{self.account}.blob.core.windows.net/{self.container}/{self.operation}/backup.sealed'

    @property
    def canonical(self): return f'/blob/{self.account}/{self.container}/{self.operation}/backup.sealed'


@dataclass(frozen=True)
class SelectedTarget:
    vm_id: str
    instance_id: str
    subnet_id: str
    region: str

    def __post_init__(self):
        need(re.fullmatch(VM, self.vm_id) and re.fullmatch(GUID, self.instance_id)
             and re.fullmatch(SUBNET, self.subnet_id) and re.fullmatch(r'[a-z0-9]{2,32}', self.region))


@dataclass(frozen=True)
class Store:
    """Facts are meaningful only when collected through verified ARM selection."""
    blob: Blob
    region: str
    owned_subnets: tuple
    ownership_id: str

    def __post_init__(self):
        need(re.fullmatch(GUID, self.ownership_id) and re.fullmatch(r'[a-z0-9]{2,32}', self.region))
        need(type(self.owned_subnets) is tuple and 1 <= len(self.owned_subnets) <= 2
             and len({resource_id(s) for s in self.owned_subnets}) == len(self.owned_subnets)
             and all(re.fullmatch(SUBNET, s) for s in self.owned_subnets))


def validate_store(store, account, container, subnets):
    """Fail closed on unrelated resources or unsupported network provenance.

    This validates supplied ARM facts, not their authenticity or caller rights.
    Only owned same-region service-endpoint targets are supported in this layer.
    """
    need(type(store) is Store and resource_id(account['id']) == resource_id(store.blob.account_id))
    tags = tags_by_key(account['tags']); p = account['properties']; acl = p['networkAcls']
    need(tags.get('azd-santa-backup-owner') == store.ownership_id
         and tags.get('azd-santa-backup-store') == 'independent-v1'
         and 'azd-env-name' not in tags and 'azd-service-name' not in tags)
    need(account['location'] == store.region and account['kind'] == 'StorageV2'
         and account['sku']['name'] == 'Standard_LRS'
         and p['allowBlobPublicAccess'] is False and p['allowSharedKeyAccess'] is True
         and p['supportsHttpsTrafficOnly'] is True and p['minimumTlsVersion'] == 'TLS1_2'
         and p['publicNetworkAccess'] == 'Enabled' and p['accessTier'] == 'Hot'
         and p.get('isHnsEnabled', False) is False and not p.get('sasPolicy')
         and p.get('privateEndpointConnections', []) == [])
    need(acl['defaultAction'] == 'Deny' and acl['bypass'] == 'None' and acl.get('ipRules', []) == []
         and acl.get('resourceAccessRules', []) == [])
    rules = acl['virtualNetworkRules']
    need(len(rules) == len(store.owned_subnets)
         and {resource_id(r['id']) for r in rules} == {resource_id(s) for s in store.owned_subnets}
         and all(r['action'] == 'Allow' and r.get('state') == 'Succeeded' for r in rules))
    need(resource_id(container['id']) == resource_id(store.blob.account_id + '/blobServices/default/containers/' + store.blob.container)
         and container['properties']['publicAccess'] == 'None')
    need(len(subnets) == len(store.owned_subnets)
         and {resource_id(s) for s in subnets} == {resource_id(s) for s in store.owned_subnets})
    for subnet_id, facts in subnets.items():
        # A future ARM selector must prove the VM->NIC->subnet link and ownership.
        need(resource_id(facts['id']) == resource_id(subnet_id) and facts['owned_by_solution'] is True
             and facts['region'] == store.region and facts['properties']['defaultOutboundAccess'] is False
             and any(e['service'] == 'Microsoft.Storage' and e.get('provisioningState') == 'Succeeded'
                     for e in facts['properties']['serviceEndpoints']))
    return dict(scope='backup-store-facts-check-v1', configuration_matches=True,
                arm_selection_authenticity_proven=False, authority_granted=False)


def completed(complete):
    keys = {'scope', 'ciphertext_sha256', 'ciphertext_bytes', 'recipient_sha256', 'entries',
            'restore_admission', 'current_authority', 'maintenance_sha256', 'generation_sha256'}
    need(type(complete) is dict and set(complete) == keys
         and complete['scope'] == 'azd-santa-cold-backup-ciphertext-v1'
         and type(complete['ciphertext_bytes']) is int and len(MAGIC)+32 < complete['ciphertext_bytes'] <= MAXIMUM
         and type(complete['entries']) is int and 0 < complete['entries'] <= 1000000
         and complete['restore_admission'] == 'not_implemented' and complete['current_authority'] == 'not_established')
    for name in ('ciphertext_sha256', 'recipient_sha256', 'maintenance_sha256', 'generation_sha256'):
        need(type(complete[name]) is str and re.fullmatch(HEX, complete[name]))
    return complete


def checked_record(record):
    need(type(record) is dict and set(record)=={'scope','blob_uri','operation_id','complete','source_vm_id',
        'source_instance_id','image_id','source_bundle_sha256','exact_image_retained','portable_key_recovery_proven','restore_accepted'}
         and record['scope']=='native-ciphertext-retention-selection-v1'
         and re.fullmatch(VM,record['source_vm_id']) and re.fullmatch(GUID,record['source_instance_id'])
         and re.fullmatch(r'sha256:'+HEX,record['image_id']) and re.fullmatch(HEX,record['source_bundle_sha256'])
         and re.fullmatch(r'[a-f0-9]{32}',record['operation_id'])
         and re.fullmatch(r'https://[a-z0-9]{3,24}\.blob\.core\.windows\.net/native-captures/'+record['operation_id']+r'/backup\.sealed',record['blob_uri'])
         and record['exact_image_retained'] is False and record['portable_key_recovery_proven'] is False
         and record['restore_accepted'] is False)
    completed(record['complete'])


def capture_record(blob, complete, source_target, *, maintenance_request, image_id, source_bundle_sha256):
    need(type(blob) is Blob and type(source_target) is SelectedTarget); completed(complete)
    need(type(maintenance_request) is bytes and 0 < len(maintenance_request) <= CHUNK
         and hashlib.sha256(maintenance_request).hexdigest() == complete['maintenance_sha256'])
    request=json.loads(maintenance_request,object_pairs_hook=unique)
    need(set(request)=={'scope','operation_id','manifest_sha256','generation_sha256','target','boot_id',
        'recipient_der_base64','recipient_sha256','destination','maximum_bytes','maximum_files','seconds',
        'queue_inventory','backup_program_sha256','storage_sha256','worker_instance'}
         and request['scope']=='azd-santa-backup-maintenance-v1' and request['operation_id']==blob.operation
         and type(request['target']) is dict and set(request['target']) == {'VmId','VmInstanceId'}
         and resource_id(request['target']['VmId']) == resource_id(source_target.vm_id)
         and request['target']['VmInstanceId'] == source_target.instance_id
         and request['generation_sha256']==complete['generation_sha256']
         and request['recipient_sha256']==complete['recipient_sha256'])
    need(re.fullmatch(r'sha256:' + HEX, image_id) and re.fullmatch(HEX, source_bundle_sha256))
    return dict(scope='native-ciphertext-retention-selection-v1', blob_uri=blob.uri, operation_id=blob.operation,
                complete=dict(complete), source_vm_id=source_target.vm_id, source_instance_id=source_target.instance_id,
                image_id=image_id, source_bundle_sha256=source_bundle_sha256,
                exact_image_retained=False, portable_key_recovery_proven=False, restore_accepted=False)


def selection(record, blob, store, target, permission):
    checked_record(record)
    need(type(blob) is Blob and type(store) is Store
         and resource_id(store.blob.account_id) == resource_id(blob.account_id)
         and store.blob.operation == blob.operation and store.blob.container == blob.container
         and type(target) is SelectedTarget
         and resource_id(target.subnet_id) in {resource_id(s) for s in store.owned_subnets} and target.region == store.region
         and permission in ('c', 'r') and record['scope'] == 'native-ciphertext-retention-selection-v1'
         and record['blob_uri'] == blob.uri and record['operation_id'] == blob.operation)
    need((resource_id(target.vm_id) == resource_id(record['source_vm_id']) and target.instance_id == record['source_instance_id'])
         if permission == 'c' else resource_id(target.vm_id) != resource_id(record['source_vm_id']))


def arm_selection(arm_call, store, target):
    """Read exact ARM ownership/configuration before minting any capability."""
    def get(resource, version):
        return arm_call('GET', 'https://management.azure.com'+resource+'?api-version='+version, None)
    account=get(store.blob.account_id,'2025-06-01')
    container=get(store.blob.account_id+'/blobServices/default/containers/'+store.blob.container,'2025-06-01')
    subnets={}
    for subnet_id in store.owned_subnets:
        vnet_id=subnet_id.rsplit('/subnets/',1)[0]; vnet=get(vnet_id,'2024-05-01')
        subnet=get(subnet_id,'2024-05-01'); tags=tags_by_key(vnet['tags']); environment=tags.get('azd-env-name','')
        need(re.fullmatch(r'[a-z0-9-]{2,32}',environment)
             and tags.get('azd-solution')=='azd-santa' and tags.get('purpose')=='synthetic-vm-lab'
             and resource_id(vnet_id).endswith(resource_id('/resourceGroups/rg-azd-santa-vm-'+environment+'/providers/Microsoft.Network/virtualNetworks/vnet-santa-lab')))
        subnets[subnet_id]=dict(subnet,region=vnet['location'],owned_by_solution=True)
    validate_store(store,account,container,subnets)
    vm=get(target.vm_id,'2024-11-01'); tags=tags_by_key(vm['tags']); environment=tags.get('azd-env-name','')
    need(resource_id(vm['id'])==resource_id(target.vm_id) and vm['properties']['vmId'].lower()==target.instance_id
         and vm['location']==target.region and tags.get('azd-solution')=='azd-santa'
         and tags.get('purpose')=='synthetic-vm-lab' and re.fullmatch(r'[a-z0-9-]{2,32}',environment))
    group=target.vm_id.split('/providers/')[0]
    need(resource_id(group).endswith(resource_id('/resourceGroups/rg-azd-santa-vm-'+environment))
         and resource_id(target.vm_id)==resource_id(group+'/providers/Microsoft.Compute/virtualMachines/vm-santa-lab'))
    nics=vm['properties']['networkProfile']['networkInterfaces']; need(len(nics)==1)
    nic_id=group+'/providers/Microsoft.Network/networkInterfaces/nic-santa-lab'; need(resource_id(nics[0]['id'])==resource_id(nic_id))
    nic=get(nic_id,'2024-05-01'); ips=nic['properties']['ipConfigurations']; need(len(ips)==1)
    selected_subnet=next(v for k,v in subnets.items() if resource_id(k)==resource_id(target.subnet_id))
    need(resource_id(ips[0]['properties']['subnet']['id'])==resource_id(target.subnet_id)
         and resource_id(selected_subnet['properties']['networkSecurityGroup']['id'])==resource_id(group+'/providers/Microsoft.Network/networkSecurityGroups/nsg-santa-lab'))
    nsg=get(group+'/providers/Microsoft.Network/networkSecurityGroups/nsg-santa-lab','2024-05-01')
    rules=[r['properties'] for r in nsg['properties']['securityRules'] if r['properties']['priority']==100]
    need(len(rules)==1 and all(rules[0][key]==value for key,value in dict(direction='Inbound',access='Deny',protocol='*',
        sourcePortRange='*',destinationPortRange='*',sourceAddressPrefix='*',destinationAddressPrefix='*').items()))


@dataclass(frozen=True, repr=False)
class Capability:
    blob: Blob
    target: SelectedTarget
    permission: str
    ciphertext_sha256: str
    expires: dt.datetime
    _token: str = field(repr=False)

    def __repr__(self): return '<private exact-blob capability>'

    def path(self):
        return urllib.parse.urlsplit(self.blob.uri).path + '?' + self._token + '&api-version=' + API_VERSION


def mint_capability(arm_call, record, blob, store, target, permission, *, apply=False, now=None):
    """The callback uses existing cached ARM authority; never login or grant.

    Callback receives only nonsecret request fields. Its raw response is private.
    No key retrieval, public-IP fallback, account/policy changes or token logging.
    """
    try:
        selection(record, blob, store, target, permission)
        now = now or dt.datetime.now(dt.timezone.utc); need(now.tzinfo is not None)
        start, expiry = now-dt.timedelta(minutes=15), now+dt.timedelta(minutes=15)
        stamp = lambda value: value.astimezone(dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        body = dict(canonicalizedResource=blob.canonical, signedResource='b', signedPermission=permission,
                    signedProtocol='https', signedStart=stamp(start), signedExpiry=stamp(expiry))
        url = 'https://management.azure.com' + blob.account_id + '/listServiceSas?api-version=2025-06-01'
        if not apply:
            return dict(scope='blob-capability-plan-v1', performs_mutation=False, method='POST', url=url, body=body)
        arm_selection(arm_call,store,target)
        response = arm_call('POST', url, body)
        need(type(response) is dict and set(response) == {'serviceSasToken'})
        token = response['serviceSasToken']; need(type(token) is str and 0 < len(token) <= 4096 and token.isascii())
        pairs = urllib.parse.parse_qsl(token, keep_blank_values=True, strict_parsing=True)
        values = unique(pairs)
        need(set(values) == {'sv', 'sr', 'sp', 'spr', 'st', 'se', 'sig'}
             and values['sr'] == 'b' and values['sp'] == permission and values['spr'] == 'https'
             and values['st'] == body['signedStart'] and values['se'] == body['signedExpiry']
             and dt.date.fromisoformat(values['sv']) >= dt.date(2015, 4, 5))
        signature = base64.b64decode(values['sig'], validate=True)
        need(len(signature) == 32 and base64.b64encode(signature).decode() == values['sig'])
        return Capability(blob, target, permission, record['complete']['ciphertext_sha256'],
                          dt.datetime.fromisoformat(body['signedExpiry'].replace('Z', '+00:00')), token)
    except Exception:
        raise RetentionRejected('Blob capability rejected; no policy or permission fallback') from None


def host_identity(target):
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs): return None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    request = urllib.request.Request('http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01', headers={'Metadata':'true'})
    with opener.open(request, timeout=3) as response: raw = response.read(65537)
    need(len(raw) <= 65536); value = json.loads(raw, object_pairs_hook=unique)
    need(resource_id(value['resourceId']) == resource_id(target.vm_id) and value['vmId'].lower() == target.instance_id
         and value['location'] == target.region)


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def parent(path, stack):
    need(sys.platform == 'linux')
    raw=str(path); path = Path(path); need(path.is_absolute() and raw == path.as_posix() and '..' not in path.parts)
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW); stack.callback(os.close, fd)
    for part in path.parts[1:-1]:
        fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd); stack.callback(os.close, fd)
        info = os.fstat(fd); need(info.st_uid in (0, os.geteuid()) and not info.st_mode & 0o022)
    info = os.fstat(fd); need(info.st_uid == os.geteuid() and not info.st_mode & 0o077)
    return fd, path.name


class Journal:
    def __init__(self, path, initial, stack):
        fd, name = parent(path, stack); os.mkdir(name, 0o700, dir_fd=fd); os.fsync(fd)
        self.fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd); stack.callback(os.close, self.fd)
        self.write('intent.json', initial)

    def write(self, name, value):
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.fd)
        with os.fdopen(fd, 'wb') as output: output.write(encoded(value)); output.flush(); os.fsync(output.fileno())
        os.fsync(self.fd)


def valid_capability(capability, record, permission):
    checked_record(record)
    need(type(capability) is Capability and capability.permission == permission
         and capability.ciphertext_sha256 == record['complete']['ciphertext_sha256']
         and capability.blob.uri == record['blob_uri']
         and dt.datetime.now(dt.timezone.utc) < capability.expires)


def header(stream, record):
    stream.seek(0); prefix = stream.read(len(MAGIC)+4)
    need(prefix.startswith(MAGIC) and len(prefix) == len(MAGIC)+4)
    length = struct.unpack('>I', prefix[-4:])[0]; need(1 <= length <= 2048)
    raw = stream.read(length); value = json.loads(raw, object_pairs_hook=unique)
    need(encoded(value) == raw and set(value) == {'algorithm','recipient_sha256','nonce','wrapped_key'}
         and value['algorithm'] == 'RSA-OAEP-256+A256GCM'
         and value['recipient_sha256'] == record['complete']['recipient_sha256'])
    for name, size in (('nonce',12), ('wrapped_key',384)):
        decoded = base64.b64decode(value[name], validate=True)
        need(len(decoded) == size and base64.b64encode(decoded).decode() == value[name])


def fingerprint(stream, record, deadline):
    header(stream, record); stream.seek(0)
    sha = hashlib.sha256(); md5 = hashlib.md5(usedforsecurity=False); total = 0
    while True:
        need(time.monotonic() < deadline); raw = stream.read(CHUNK)
        if not raw: break
        total += len(raw); need(total <= record['complete']['ciphertext_bytes']); sha.update(raw); md5.update(raw)
    need(total == record['complete']['ciphertext_bytes'] and sha.hexdigest() == record['complete']['ciphertext_sha256'])
    stream.seek(0); return base64.b64encode(md5.digest()).decode()


class CountingReader:
    def __init__(self, stream, expected, deadline):
        self.stream=stream; self.expected=expected; self.deadline=deadline; self.total=0; self.sha=hashlib.sha256()

    def read(self, size):
        need(type(size) is int and 0 < size <= CHUNK and time.monotonic() < self.deadline)
        raw=self.stream.read(size); self.total+=len(raw); need(self.total<=self.expected); self.sha.update(raw); return raw


class BlobHttp:
    """Direct TLS only; no proxy, redirect, retry or URL-bearing exception output."""
    def connection(self, capability, seconds):
        return http.client.HTTPSConnection(capability.blob.account+'.blob.core.windows.net',
                                           timeout=seconds, context=ssl.create_default_context())

    def put(self, capability, reader, length, md5, seconds):
        connection=self.connection(capability,seconds)
        try:
            connection.request('PUT',capability.path(),body=reader,headers={'Content-Length':str(length),
                'Content-MD5':md5,'Content-Type':'application/octet-stream','x-ms-blob-type':'BlockBlob',
                'If-None-Match':'*','x-ms-version':API_VERSION})
            response=connection.getresponse(); need(len(response.read(4097))<=4096)
            return response.status, response.getheader('ETag')
        finally: connection.close()

    def get(self, capability, seconds):
        connection=self.connection(capability,seconds)
        try:
            connection.request('GET',capability.path(),headers={'x-ms-version':API_VERSION})
            return connection, connection.getresponse()
        except BaseException: connection.close(); raise


def put_once(stream, record, capability, journal, unchanged, md5, deadline, transport):
    """Private post-reservation boundary; every ambiguous outcome needs GET proof."""
    reader=CountingReader(stream,record['complete']['ciphertext_bytes'],deadline); status=None
    try:
        valid_capability(capability,record,'c')
        status,etag=transport.put(capability,reader,record['complete']['ciphertext_bytes'],md5,max(.01,deadline-time.monotonic()))
        unchanged()
        need(status==201 and re.fullmatch(r'"[A-Za-z0-9._-]{1,128}"',etag or '')
             and reader.total==record['complete']['ciphertext_bytes']
             and reader.sha.hexdigest()==record['complete']['ciphertext_sha256'] and time.monotonic()<deadline)
        result=dict(scope='native-ciphertext-upload-v1',state='uploaded',blob_uri=record['blob_uri'],
            ciphertext_sha256=record['complete']['ciphertext_sha256'],ciphertext_bytes=reader.total,
            etag=etag,http_status=201,independent_bytes_verified=False,automatic_replay=False,restore_accepted=False)
    except Exception:
        result=dict(scope='native-ciphertext-upload-v1',state='unknown',blob_uri=record['blob_uri'],
            http_status=status if type(status) is int and 100<=status<=599 else None,
            automatic_replay=False,independent_bytes_verified=False,restore_accepted=False)
    except BaseException:
        journal.write('outcome.json',dict(state='unknown',automatic_replay=False)); raise
    journal.write('outcome.json',result); return result


def download_bytes(response, output, record, deadline):
    need(response.status==200 and response.getheader('Content-Length')==str(record['complete']['ciphertext_bytes'])
         and re.fullmatch(r'"[A-Za-z0-9._-]{1,128}"',response.getheader('ETag') or ''))
    total=0; sha=hashlib.sha256()
    while True:
        need(time.monotonic()<deadline); raw=response.read(CHUNK)
        if not raw: break
        total+=len(raw); need(total<=record['complete']['ciphertext_bytes']); sha.update(raw); output.write(raw)
    need(total==record['complete']['ciphertext_bytes'] and sha.hexdigest()==record['complete']['ciphertext_sha256'])
    return total,sha.hexdigest()


def upload_file(path, record, capability, attempt_directory, *, apply=False, seconds=900, transport=None):
    """A real PUT requires Apply and a source-VM-bound capability.

    Caller authenticates ARM selection/receipt provenance and excludes concurrent
    same-UID/root writers. Disk syscalls require an outer process deadline.
    """
    try:
        checked_record(record)
        need(type(seconds) is int and 1 <= seconds <= 1800)
        if not apply: return dict(scope='native-ciphertext-upload-plan-v1', performs_mutation=False,
                                 blob_uri=record['blob_uri'], ciphertext_bytes=record['complete']['ciphertext_bytes'])
        valid_capability(capability,record,'c'); need(resource_id(capability.target.vm_id)==resource_id(record['source_vm_id'])
            and capability.target.instance_id==record['source_instance_id']); host_identity(capability.target)
        deadline=time.monotonic()+seconds
        with ExitStack() as stack:
            fd,name=parent(path,stack); need(name=='backup.sealed')
            file_fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
            stream=stack.enter_context(os.fdopen(file_fd,'rb')); before=os.fstat(file_fd)
            need(stat.S_ISREG(before.st_mode) and before.st_uid==os.geteuid() and not before.st_mode&0o077
                 and before.st_nlink==1 and before.st_size==record['complete']['ciphertext_bytes'])
            unchanged=lambda: need(identity(before)==identity(os.fstat(file_fd))==identity(os.stat(name,dir_fd=fd,follow_symlinks=False)))
            md5=fingerprint(stream,record,deadline); unchanged()
            journal=Journal(attempt_directory,dict(record,attempt='one-create-only-put'),stack)
            return put_once(stream,record,capability,journal,unchanged,md5,deadline,transport or BlobHttp())
    except Exception:
        raise RetentionRejected('Ciphertext upload requires inspection; never overwrite or replay') from None


def verify_download(destination, record, capability, attempt_directory, *, apply=False, seconds=900, transport=None):
    """Download on a separately selected owned target; verify exact bytes only."""
    try:
        checked_record(record)
        need(type(seconds) is int and 1 <= seconds <= 1800)
        if not apply: return dict(scope='native-ciphertext-verification-plan-v1',performs_mutation=False,blob_uri=record['blob_uri'])
        valid_capability(capability,record,'r'); need(resource_id(capability.target.vm_id)!=resource_id(record['source_vm_id'])); host_identity(capability.target)
        deadline=time.monotonic()+seconds
        with ExitStack() as stack:
            journal=Journal(attempt_directory,dict(record,attempt='independent-exact-blob-download',
                verifier_vm_id=capability.target.vm_id,verifier_instance_id=capability.target.instance_id),stack)
            fd,name=parent(destination,stack); need(name=='backup.sealed')
            output_fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd)
            output=stack.enter_context(os.fdopen(output_fd,'wb')); before=os.fstat(output_fd)
            need(stat.S_ISREG(before.st_mode) and before.st_uid==os.geteuid() and before.st_nlink==1 and not before.st_mode&0o077)
            connection,response=(transport or BlobHttp()).get(capability,max(.01,deadline-time.monotonic()))
            stack.callback(connection.close)
            total,digest=download_bytes(response,output,record,deadline)
            output.flush(); os.fsync(output_fd); after=os.fstat(output_fd)
            need((before.st_dev,before.st_ino)==(after.st_dev,after.st_ino)
                 and after.st_size==total and after.st_nlink==1 and after.st_uid==os.geteuid() and not after.st_mode&0o077
                 and identity(after)==identity(os.stat(name,dir_fd=fd,follow_symlinks=False)) and time.monotonic()<deadline)
            output.close(); os.fsync(fd); connection.close()
            result=dict(scope='independent-native-ciphertext-verification-v1',blob_uri=record['blob_uri'],
                ciphertext_sha256=digest,ciphertext_bytes=total,etag=response.getheader('ETag'),
                verifier_vm_id=capability.target.vm_id,independent_bytes_verified=True,
                sealed_authenticated=False,exact_image_retained=False,restore_accepted=False,current_authority_established=False)
            journal.write('verified.json',result); return result
    except Exception:
        raise RetentionRejected('Independent ciphertext verification failed; retain original and partial output') from None
