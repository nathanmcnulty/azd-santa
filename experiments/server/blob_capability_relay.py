"""Original Unlicense. Confidential one-capture source-VM Blob relay.

Recipient encryption is NOT sender/ARM authentication. Current selected operator
and fresh ownership/mint provenance are external prerequisites. No Azure adapter,
backup key, ARM token, service changes, grants, cleanup or automatic replay.
"""
import argparse
import base64
from contextlib import ExitStack
from dataclasses import asdict
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import time
import types
import uuid
import urllib.parse

sys.path.insert(0,str(Path(__file__).resolve().parent))
import blob_retention as blob

ROOT=Path('/var/lib/azd-santa-qualification')
ALGORITHM='RSA-OAEP-256+A256GCM'  # Existing sealed_setup OAEP/SHA256 + AESGCM pattern.
RETENTION_SHA='f5aa619725104fa3a4bbe174a7ea4ceb236d9eab68675b8730d90984cb3e1818'
CONTROLLER_SHA='f0a8961f64e48471eed71757805ae4e29ee080aef30c6ab9ec040eafaf443099'
MAX_PACKET=16384
OFFER_FIELDS={'scope','version','algorithm','offer_id','created','expires','boot_id','environment','target',
    'operation','record_sha256','account_id','blob_uri','ciphertext_sha256','ciphertext_bytes','public_key_base64','kid_sha256',
    'program_sha256','retention_sha256'}
PACKET_FIELDS={'scope','version','algorithm','offer_sha256','kid_sha256','wrapped_key_base64','nonce_base64','ciphertext_base64'}

class RelayRejected(ValueError):pass

def need(value):
    if not value:raise RelayRejected('Blob relay rejected or unknown; preserve evidence and never replay')

def sha(raw):return hashlib.sha256(raw).hexdigest()
def encoded(value):return blob.encoded(value)
def parsed(raw):return json.loads(raw,object_pairs_hook=blob.unique)
def encode(raw):return base64.b64encode(raw).decode('ascii')
def decode(value,size=None,maximum=8192):
    need(type(value)is str and len(value)<=maximum*2)
    raw=base64.b64decode(value,validate=True)
    need(encode(raw)==value and len(raw)<=maximum and (size is None or len(raw)==size));return raw

def safe(action):
    def call(*args,**kwargs):
        try:return action(*args,**kwargs)
        except Exception:raise RelayRejected('Blob relay rejected or unknown; preserve evidence and never replay') from None
    return call

def operation(value):need(type(value)is str and re.fullmatch(r'[a-f0-9]{32}',value));return value

def guest():
    need(sys.platform=='linux' and os.geteuid()==0)
    script=Path(__file__).absolute();need(script.is_relative_to(ROOT) and re.fullmatch(r'/[A-Za-z0-9/_.-]+',str(script)))
    read_file(script,262144);need(sha(read_file(Path(blob.__file__),262144))==RETENTION_SHA)

def command(args,timeout=30):
    value=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
    need(value.returncode==0 and len(value.stdout.encode())<=32768);return value.stdout

def fresh(target):
    blob.host_identity(target)
    raw=Path('/proc/sys/kernel/random/boot_id').read_bytes();need(len(raw)<=64)
    boot=raw.decode().strip();need(re.fullmatch(blob.GUID,boot));return boot

class State:
    """Fixed operation paths, descriptor-relative owner-private exclusive writes."""
    def __init__(self,selected,*,create=False):
        self.operation=operation(selected);self.path=ROOT/'blob-relay-v1'/selected;self.stack=ExitStack()
        try:
            parent,name=blob.parent(ROOT/'blob-relay-v1',self.stack)
            if create:
                try:os.mkdir(name,0o700,dir_fd=parent);os.fsync(parent)
                except FileExistsError:pass
            root=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent);self.stack.callback(os.close,root)
            self.directory(os.fstat(root))
            if create:os.mkdir(selected,0o700,dir_fd=root);os.fsync(root)
            self.fd=os.open(selected,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=root);self.stack.callback(os.close,self.fd)
            self.directory(os.fstat(self.fd))
        except BaseException:self.stack.close();raise
    @staticmethod
    def directory(info):need(stat.S_ISDIR(info.st_mode) and info.st_uid==os.geteuid() and stat.S_IMODE(info.st_mode)==0o700)
    @staticmethod
    def file(info):need(stat.S_ISREG(info.st_mode) and info.st_uid==os.geteuid() and info.st_nlink==1 and stat.S_IMODE(info.st_mode)==0o600)
    @staticmethod
    def name(value):need(re.fullmatch(r'[a-z0-9.-]{1,100}',value) and value not in ('.','..'));return value
    def exists(self,name):
        try:os.stat(self.name(name),dir_fd=self.fd,follow_symlinks=False);return True
        except FileNotFoundError:return False
    def read(self,name,maximum=MAX_PACKET):
        fd=os.open(self.name(name),os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=self.fd)
        with os.fdopen(fd,'rb') as stream:
            before=os.fstat(fd);self.file(before);need(before.st_size<=maximum)
            raw=stream.read(maximum+1);need(len(raw)<=maximum and blob.identity(before)==blob.identity(os.fstat(fd)))
            need(blob.identity(before)==blob.identity(os.stat(name,dir_fd=self.fd,follow_symlinks=False)))
            return raw
    def write(self,name,raw):
        need(type(raw)is bytes and len(raw)<=MAX_PACKET)
        fd=os.open(self.name(name),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=self.fd)
        with os.fdopen(fd,'wb') as output:self.file(os.fstat(fd));output.write(raw);output.flush();os.fsync(fd)
        os.fsync(self.fd)
    def close(self):self.stack.close()
    def __enter__(self):return self
    def __exit__(self,*args):self.close()

def read_file(path,maximum=2*1024**2,*,private=False):
    path=Path(path);need(path.is_absolute() and path==path.resolve(strict=True))
    for parent in path.parents:
        info=parent.stat();need(info.st_uid==0 and not info.st_mode&0o022)
    with path.open('rb') as stream:
        before=os.fstat(stream.fileno());need(stat.S_ISREG(before.st_mode) and before.st_uid==0 and before.st_nlink==1
            and not before.st_mode&(0o077 if private else 0o022) and before.st_size<=maximum)
        raw=stream.read(maximum+1);need(len(raw)<=maximum and blob.identity(before)==blob.identity(os.fstat(stream.fileno()))
            and blob.identity(before)==blob.identity(path.stat()));return raw


def selection(environment,target,record):
    need(type(environment)is str and re.fullmatch(r'[a-z0-9-]{2,32}',environment)
        and type(target)is blob.SelectedTarget)
    blob.checked_record(record)
    need(record['source_vm_id']==target.vm_id and record['source_instance_id']==target.instance_id
        and record['source_vm_id'].split('/resourceGroups/')[1].split('/')[0]=='rg-azd-santa-vm-'+environment)
    return operation(record['operation_id'])


def capture(environment,target,record):
    """Narrow fixed-path selector; never accepts a caller-supplied host path."""
    selected=selection(environment,target,record)
    manifest=ROOT/('private-runtime-'+environment)/'runtime-service/manifest.json';raw=read_file(manifest,private=True);digest=sha(raw)
    unit=read_file(Path('/etc/systemd/system/azd-santa-runtime.service')).decode()
    pattern=r'^ExecStart=/usr/bin/python3 -I ('+re.escape(str(ROOT))+r'/(?:installers|helper-upgrades/bundles)/([a-f0-9]{64})/runtime_service.py) run --manifest '+re.escape(str(manifest))+r' --sha256 '+digest+r'$'
    found=re.findall(pattern,unit,re.M);need(len(found)==1 and found[0][1]==record['source_bundle_sha256'])
    script=Path(found[0][0]);folder=script.parent;package_raw=read_file(folder/'bundle.json');need(sha(package_raw)==record['source_bundle_sha256'])
    package=parsed(package_raw);need(set(package)=={'scope','files'} and package['scope']=='private-azd-source-v1' and len(package['files'])==25)
    for name,meta in package['files'].items():
        need(re.fullmatch(r'[A-Za-z0-9_.-]+',name) and set(meta)=={'sha256','base64'})
        body=read_file(folder/name,262144);need(sha(body)==meta['sha256'] and decode(meta['base64'],maximum=262144)==body)
    def load(name):
        module=types.ModuleType('blob_relay_'+name);module.__file__=str(folder/(name+'.py'))
        exec(compile(read_file(Path(module.__file__),262144),module.__file__,'exec'),module.__dict__);return module
    need(sha(read_file(script))==CONTROLLER_SHA)
    runtime=load('runtime_service');runtime.load_manifest(manifest,digest)
    need(unit==runtime.unit_text(script,manifest,digest))
    backup=load('cold_backup');request,request_sha,_=backup._request(types.SimpleNamespace(manifest_path=manifest,digest=digest))
    need(request['operation_id']==selected and request_sha==record['complete']['maintenance_sha256']
        and request['target']=={'VmId':target.vm_id,'VmInstanceId':target.instance_id})
    destination=Path(request['destination'])
    need(destination.parent==ROOT and re.fullmatch(r'ciphertext-[a-z0-9-]{2,64}',destination.name))
    complete_raw=read_file(destination/'complete.json',private=True);need(parsed(complete_raw)==record['complete'])
    maintenance=manifest.parent/('backup-'+selected)/'maintenance-complete.json'
    maintenance_raw=read_file(maintenance,private=True)
    need(parsed(maintenance_raw)==dict(request_sha256=request_sha,generation_sha256=request['generation_sha256'],ciphertext_receipt_sha256=sha(complete_raw)))
    generation_raw=read_file(manifest.parent/'container-generation.json',private=True)
    need(sha(generation_raw)==record['complete']['generation_sha256'] and parsed(generation_raw)['image_id']==record['image_id'])
    path=destination/'backup.sealed';deadline=time.monotonic()+120
    with ExitStack() as stack:
        fd,name=blob.parent(path,stack);file_fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
        stream=stack.enter_context(os.fdopen(file_fd,'rb'));before=os.fstat(file_fd);State.file(before)
        need(before.st_size==record['complete']['ciphertext_bytes']);blob.fingerprint(stream,record,deadline)
        need(blob.identity(before)==blob.identity(os.fstat(file_fd))==blob.identity(os.stat(name,dir_fd=fd,follow_symlinks=False)))
    return dict(path=str(path),file_identity=list(blob.identity(before)),manifest_sha256=digest,request_sha256=request_sha,
        generation_sha256=sha(generation_raw),completion_sha256=sha(complete_raw),maintenance_sha256=sha(maintenance_raw))


def check_offer(value):
    need(type(value)is dict and set(value)==OFFER_FIELDS and value['scope']=='blob-relay-offer-v1' and value['version']==1
        and type(value['version'])is int and value['algorithm']==ALGORITHM and type(value['created'])is int and type(value['expires'])is int
        and 0<value['expires']-value['created']<=1800 and type(value['ciphertext_bytes'])is int
        and 0<value['ciphertext_bytes']<=blob.MAXIMUM and re.fullmatch(blob.GUID,value['boot_id']))
    operation(value['offer_id']);operation(value['operation'])
    for name in ('record_sha256','ciphertext_sha256','kid_sha256','program_sha256','retention_sha256'):need(re.fullmatch(blob.HEX,value[name]))
    target=blob.SelectedTarget(**value['target']);selected=blob.Blob(value['account_id'],value['operation'])
    need(selected.uri==value['blob_uri'] and selected.account_id.split('/')[2]==target.vm_id.split('/')[2]
        and selected.account_id.split('/providers/')[0].casefold()!=target.vm_id.split('/providers/')[0].casefold()
        and len(encoded(value))<=4096)
    public=decode(value['public_key_base64'],maximum=1024);need(sha(public)==value['kid_sha256']);return target,public


def current(offer,record,proof,*,require_fresh=True):
    target,_=check_offer(offer);now=int(time.time())
    need((not require_fresh or offer['created']<=now<offer['expires']) and fresh(target)==offer['boot_id']
        and offer['program_sha256']==sha(Path(__file__).read_bytes()) and offer['retention_sha256']==RETENTION_SHA
        and offer['record_sha256']==sha(encoded(record)))
    need(capture(offer['environment'],target,record)==proof);return target


@safe
def create_offer(environment,target,record,selected_blob,*,apply=False,lifetime=1800):
    selected=selection(environment,target,record);need(type(selected_blob)is blob.Blob and selected_blob.uri==record['blob_uri']
        and selected_blob.operation==selected);need(type(lifetime)is int and 1<=lifetime<=1800)
    if not apply:return dict(scope='blob-relay-offer-plan-v1',performs_mutation=False,operation=selected,maximum_lifetime=1800)
    guest();boot=fresh(target);proof=capture(environment,target,record);now=int(time.time())
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    with State(selected,create=True) as state:
        state.write('offer-intent.json',encoded(dict(scope='one-ephemeral-offer-v1',record_sha256=sha(encoded(record)),boot_id=boot)))
        key=rsa.generate_private_key(public_exponent=65537,key_size=3072)
        public=key.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
        private=key.private_bytes(serialization.Encoding.DER,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
        offer=dict(scope='blob-relay-offer-v1',version=1,algorithm=ALGORITHM,offer_id=uuid.uuid4().hex,created=now,expires=now+lifetime,
            boot_id=boot,environment=environment,target=asdict(target),operation=selected,record_sha256=sha(encoded(record)),account_id=selected_blob.account_id,blob_uri=record['blob_uri'],
            ciphertext_sha256=record['complete']['ciphertext_sha256'],ciphertext_bytes=record['complete']['ciphertext_bytes'],
            public_key_base64=encode(public),kid_sha256=sha(public),program_sha256=sha(Path(__file__).read_bytes()),retention_sha256=RETENTION_SHA)
        check_offer(offer);need(fresh(target)==boot and now<=int(time.time())<offer['expires'])
        state.write('private-key.der',private);state.write('record.json',encoded(record));state.write('capture.json',encoded(proof))
        state.write('offer.json',encoded(offer));return offer


def token_fields(token,offer,now):
    need(type(token)is str and token.isascii() and 0<len(token)<=4096)
    values=blob.unique(urllib.parse.parse_qsl(token,keep_blank_values=True,strict_parsing=True))
    need(set(values)=={'sv','sr','sp','spr','st','se','sig'} and values['sr']=='b' and values['sp']=='c' and values['spr']=='https')
    need(re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}',values['sv']) and dt.date.fromisoformat(values['sv'])>=dt.date(2015,4,5))
    def stamp(value):
        need(re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z',value))
        return int(dt.datetime.fromisoformat(value.replace('Z','+00:00')).timestamp())
    start,expiry=stamp(values['st']),stamp(values['se'])
    need(start<=now<expiry<=offer['expires'] and expiry-now<=900);decode(values['sig'],32)
    return expiry


def aad(offer):return b'azd-santa/blob-capability/v1\0'+encoded(offer)

def check_packet(packet,offer):
    need(type(packet)is dict and set(packet)==PACKET_FIELDS and len(encoded(packet))<=MAX_PACKET
        and packet['scope']=='sealed-blob-relay-v1' and type(packet['version'])is int and packet['version']==1 and packet['algorithm']==ALGORITHM
        and packet['offer_sha256']==sha(encoded(offer)) and packet['kid_sha256']==offer['kid_sha256'])
    return decode(packet['wrapped_key_base64'],384),decode(packet['nonce_base64'],12),decode(packet['ciphertext_base64'])


@safe
def seal_offer(offer,capability,record):
    target,public=check_offer(offer);selection(offer['environment'],target,record)
    need(type(capability)is blob.Capability and capability.permission=='c' and asdict(capability.target)==offer['target']
        and capability.blob.account_id==offer['account_id'] and capability.blob.uri==offer['blob_uri']==record['blob_uri'] and offer['record_sha256']==sha(encoded(record))
        and capability.ciphertext_sha256==offer['ciphertext_sha256']==record['complete']['ciphertext_sha256']
        and offer['ciphertext_bytes']==record['complete']['ciphertext_bytes'])
    now=int(time.time());need(offer['created']<=now<offer['expires'] and isinstance(capability.expires,dt.datetime)
        and capability.expires.utcoffset()==dt.timedelta(0))
    expiry=token_fields(capability._token,offer,now);need(int(capability.expires.timestamp())==expiry)
    from cryptography.hazmat.primitives import hashes,serialization
    from cryptography.hazmat.primitives.asymmetric import padding,rsa
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key=serialization.load_der_public_key(public)
    need(isinstance(key,rsa.RSAPublicKey) and key.key_size==3072 and key.public_numbers().e==65537
        and key.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)==public)
    secret=AESGCM.generate_key(bit_length=256);nonce=secrets.token_bytes(12)
    body=encoded(dict(scope='blob-relay-capability-v1',offer_sha256=sha(encoded(offer)),token=capability._token,expires=expiry))
    ciphertext=AESGCM(secret).encrypt(nonce,body,aad(offer))
    wrapped=key.encrypt(secret,padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
    packet=dict(scope='sealed-blob-relay-v1',version=1,algorithm=ALGORITHM,offer_sha256=sha(encoded(offer)),kid_sha256=offer['kid_sha256'],
        wrapped_key_base64=encode(wrapped),nonce_base64=encode(nonce),ciphertext_base64=encode(ciphertext))
    check_packet(packet,offer);return packet


def private_recipient(state,offer):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    private=state.read('private-key.der',8192);key=serialization.load_der_private_key(private,password=None)
    need(isinstance(key,rsa.RSAPrivateKey) and key.key_size==3072 and key.public_key().public_numbers().e==65537
        and encode(key.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo))==offer['public_key_base64']
        and key.private_bytes(serialization.Encoding.DER,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())==private)
    return key


def decrypt(state,packet,offer,record):
    wrapped,nonce,ciphertext=check_packet(packet,offer)
    from cryptography.hazmat.primitives import hashes,serialization
    from cryptography.hazmat.primitives.asymmetric import padding,rsa
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key=private_recipient(state,offer)
    secret=key.decrypt(wrapped,padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),algorithm=hashes.SHA256(),label=None));need(len(secret)==32)
    value=parsed(AESGCM(secret).decrypt(nonce,ciphertext,aad(offer)))
    need(set(value)=={'scope','offer_sha256','token','expires'} and value['scope']=='blob-relay-capability-v1'
        and value['offer_sha256']==sha(encoded(offer)) and type(value['expires'])is int)
    expiry=token_fields(value['token'],offer,int(time.time()));need(expiry==value['expires'])
    target,_=check_offer(offer)
    selected=blob.Blob(offer['account_id'],record['operation_id'])
    need(selected.uri==record['blob_uri'])
    return blob.Capability(selected,target,'c',offer['ciphertext_sha256'],dt.datetime.fromtimestamp(expiry,dt.timezone.utc),value['token'])

def context(state,expected_offer=None):
    raw=state.read('offer.json');offer=parsed(raw);need(raw==encoded(offer) and offer['operation']==state.operation)
    check_offer(offer)
    if expected_offer is not None:need(sha(raw)==expected_offer)
    record=parsed(state.read('record.json'));target=blob.SelectedTarget(**offer['target']);selection(offer['environment'],target,record)
    need(offer['record_sha256']==sha(encoded(record)) and offer['blob_uri']==record['blob_uri']
        and offer['ciphertext_sha256']==record['complete']['ciphertext_sha256']
        and offer['ciphertext_bytes']==record['complete']['ciphertext_bytes'])
    return offer,record,parsed(state.read('capture.json'))


def unit_state(name):
    fields=('LoadState','ActiveState','SubState','Result','MainPID','InvocationID','ExecMainStatus','Job','ControlGroup')
    values={}
    for line in command(['systemctl','show',name,'--property='+','.join(fields)]).splitlines():
        key,separator,value=line.partition('=');need(separator and key in fields and key not in values);values[key]=value
    need(set(values)==set(fields) and values['LoadState'] in ('loaded','not-found'));return values


def load_intent(state,digest=None):
    raw=state.read('submit-intent.json');value=parsed(raw)
    need(raw==encoded(value) and set(value)=={'scope','operation','unit','offer_sha256','envelope_sha256','seconds','program_sha256'}
        and value['scope']=='one-source-blob-relay-v1' and value['operation']==state.operation
        and type(value['seconds'])is int and 1<=value['seconds']<=900
        and value['program_sha256']==sha(Path(__file__).read_bytes()))
    if digest is not None:need(sha(raw)==digest)
    offer,_,_=context(state,value['offer_sha256']);need(value['unit']=='azd-santa-blob-relay-'+offer['offer_id']+'.service')
    return value,sha(raw)


def launch(intent,digest):
    script=Path(__file__).absolute();need(script.is_relative_to(ROOT) and re.fullmatch(r'/[A-Za-z0-9/_.-]+',str(script)))
    need(sha(read_file(script,262144))==intent['program_sha256'])
    command(['systemd-run','--no-block','--unit='+intent['unit'].removesuffix('.service'),'--property=Type=oneshot',
        '--property=Restart=no','--property=Slice=system.slice','--property=KillMode=control-group','--property=Delegate=no','--property=NoNewPrivileges=yes','--property=PrivateTmp=yes','--property=ProtectHome=yes',
        '--property=UMask=0077','--property=TimeoutStartSec='+str(intent['seconds']+300),
        '--property=RuntimeMaxSec='+str(intent['seconds']+300),
        '--property=ExecStopPost=/usr/bin/python3 -I '+str(script)+' --record-terminal '+intent['operation']+' --sha256 '+digest,
        '/usr/bin/python3','-I',str(script),'--execute',intent['operation'],'--sha256',digest])


@safe
def get_offer(selected,*,read_guest=False):
    operation(selected)
    if not read_guest:return dict(scope='blob-relay-read-offer-plan-v1',performs_mutation=False,operation=selected)
    guest()
    with State(selected) as state:
        offer,record,proof=context(state);current(offer,record,proof);private_recipient(state,offer)
        need(not state.exists('submit-intent.json'));return offer


@safe
def submit(selected,expected_offer_sha256,packet,*,apply=False,seconds=900):
    operation(selected);need(re.fullmatch(blob.HEX,expected_offer_sha256) and type(seconds)is int and 1<=seconds<=900)
    need(type(packet)is dict and set(packet)==PACKET_FIELDS and len(encoded(packet))<=MAX_PACKET)
    if not apply:return dict(scope='blob-relay-submit-plan-v1',performs_mutation=False,operation=selected,automatic_replay=False)
    guest()
    with State(selected) as state:
        offer,record,proof=context(state,expected_offer_sha256);packet_raw=encoded(packet)
        if state.exists('submit-intent.json'):
            old,_=load_intent(state);need(old['envelope_sha256']==sha(packet_raw));return _observe(state)
        current(offer,record,proof);decrypt(state,packet,offer,record)
        name='envelope-'+sha(packet_raw)+'.json'
        if state.exists(name):need(state.read(name)==packet_raw)
        else:state.write(name,packet_raw)
        intent=dict(scope='one-source-blob-relay-v1',operation=selected,unit='azd-santa-blob-relay-'+offer['offer_id']+'.service',
            offer_sha256=sha(encoded(offer)),envelope_sha256=sha(packet_raw),seconds=seconds,program_sha256=offer['program_sha256'])
        raw=encoded(intent);state.write('submit-intent.json',raw)  # Atomic once-only reservation before one launch.
        launch(intent,sha(raw));return _observe(state)


def body(intent,digest,state,outcome=None):
    return dict(scope='blob-relay-body-v1',state=state,intent_sha256=digest,offer_sha256=intent['offer_sha256'],
        envelope_sha256=intent['envelope_sha256'],upload_outcome_sha256=sha(encoded(outcome)) if outcome is not None else None,
        automatic_replay=False,permission='c',independent_bytes_verified=False,restore_accepted=False,current_authority=False)


@safe
def execute(selected,digest,*,apply=False,transport=None):
    operation(selected);need(re.fullmatch(blob.HEX,digest))
    if not apply:return dict(scope='blob-relay-execute-plan-v1',performs_mutation=False,operation=selected)
    guest()
    with State(selected) as state:
        intent,actual=load_intent(state,digest);invocation=os.environ.get('INVOCATION_ID','')
        need(re.fullmatch(r'[a-f0-9]{32}',invocation))
        manager=unit_state(intent['unit']);need(manager['LoadState']=='loaded' and manager['InvocationID']==invocation
            and manager['MainPID']==str(os.getpid()) and manager['ActiveState'] in ('activating','active'))
        need(not any(state.exists(name) for name in ('execution-intent.json','body.json','terminal.json')))
        state.write('execution-intent.json',encoded(dict(scope='one-upload-execution-v1',intent_sha256=actual,invocation=invocation)))
        try:
            offer,record,proof=context(state,intent['offer_sha256']);current(offer,record,proof)
            raw=state.read('envelope-'+intent['envelope_sha256']+'.json');need(sha(raw)==intent['envelope_sha256'])
            capability=decrypt(state,parsed(raw),offer,record)
            remaining=min(intent['seconds'],int(capability.expires.timestamp())-int(time.time()),offer['expires']-int(time.time()))
            need(remaining>=1)
            result=blob.upload_file(proof['path'],record,capability,state.path/'put',apply=True,seconds=remaining,transport=transport)
            need(result['scope']=='native-ciphertext-upload-v1' and result['state']=='uploaded' and result['http_status']==201)
            current(offer,record,proof)
            state.write('body.json',encoded(body(intent,actual,'uploaded',result)));return body(intent,actual,'uploaded',result)
        except BaseException:
            if not state.exists('body.json'):state.write('body.json',encoded(body(intent,actual,'unknown')))
            raise


def verified_body(state,intent,digest):
    raw=state.read('body.json');value=parsed(raw)
    need(type(value)is dict and value['state'] in ('uploaded','unknown'))
    if value['state']=='unknown':need(value==body(intent,digest,'unknown'))
    else:
        observed=parsed(read_file(state.path/'put/outcome.json',private=True))
        offer,record,_=context(state,intent['offer_sha256'])
        need(set(observed)=={'scope','state','blob_uri','ciphertext_sha256','ciphertext_bytes','etag','http_status',
            'independent_bytes_verified','automatic_replay','restore_accepted'}
            and observed['scope']=='native-ciphertext-upload-v1' and observed['state']=='uploaded' and observed['http_status']==201
            and observed['blob_uri']==record['blob_uri'] and observed['ciphertext_sha256']==offer['ciphertext_sha256']
            and observed['ciphertext_bytes']==offer['ciphertext_bytes'] and re.fullmatch(r'"[A-Za-z0-9._-]{1,128}"',observed['etag'])
            and observed['independent_bytes_verified'] is False and observed['automatic_replay'] is False
            and observed['restore_accepted'] is False and value==body(intent,digest,'uploaded',observed))
    return raw,value


@safe
def record_terminal(selected,digest):
    guest();operation(selected);need(re.fullmatch(blob.HEX,digest))
    with State(selected) as state:
        intent,actual=load_intent(state,digest);invocation=os.environ.get('INVOCATION_ID','')
        result=os.environ.get('SERVICE_RESULT');code=os.environ.get('EXIT_CODE');status=os.environ.get('EXIT_STATUS','')
        need(re.fullmatch(r'[a-f0-9]{32}',invocation) and result in ('success','exit-code','signal','core-dump','watchdog','timeout','resources','protocol','start-limit-hit','oom-kill')
            and code in ('exited','killed','dumped') and (re.fullmatch(r'[0-9]{1,3}',status) or status in ('HUP','INT','QUIT','KILL','ABRT','SEGV','ALRM','TERM','PIPE','BUS','ILL','FPE')))
        execution=parsed(state.read('execution-intent.json'));need(execution==dict(scope='one-upload-execution-v1',intent_sha256=actual,invocation=invocation))
        raw,value=verified_body(state,intent,actual) if state.exists('body.json') else (None,None)
        if result=='success':need(code=='exited' and status=='0' and value is not None and value['state']=='uploaded')
        state.write('terminal.json',encoded(dict(scope='blob-relay-systemd-terminal-v1',intent_sha256=actual,invocation=invocation,
            service_result=result,exit_code=code,exit_status=status,body_sha256=sha(raw) if raw is not None else None)))


def absent_cgroup(unit):
    # A missing path alone is not proof: attest the real unified kernel tree.
    need(re.fullmatch(r'azd-santa-blob-relay-[a-f0-9]{32}\.service',unit))
    root=Path('/sys/fs/cgroup');slice=root/'system.slice'
    need(command(['/usr/bin/stat','--file-system','--format=%T',str(root)]).strip()=='cgroup2fs')
    controllers=[read_file(path,4096).decode('ascii').split() for path in (root/'cgroup.controllers',slice/'cgroup.controllers')]
    need(all('pids' in values and len(values)==len(set(values)) for values in controllers)
        and set(controllers[1])<=set(controllers[0]) and read_file(slice/'cgroup.type',4096).strip()==b'domain')
    events=[line.split() for line in read_file(slice/'cgroup.events',4096).decode('ascii').splitlines()]
    need(len(events)==2 and {tuple(v) for v in events}<={('populated','0'),('populated','1'),('frozen','0'),('frozen','1')}
        and {v[0] for v in events}=={'populated','frozen'})
    try:(slice/unit).lstat()
    except FileNotFoundError:return True
    return False  # Present, populated, empty or symlinked is never GC absence.


def _observe(state):
    offer,record,proof=context(state);current(offer,record,proof,require_fresh=False)
    result=dict(scope='blob-relay-observation-v1',operation=state.operation,offer_sha256=sha(encoded(offer)),state='offered',
        automatic_replay=False,independent_bytes_verified=False,restore_accepted=False,current_authority=False)
    if not state.exists('submit-intent.json'):return result
    intent,digest=load_intent(state);manager=unit_state(intent['unit']);phase='unknown'
    quiet=all(manager[key]==value for key,value in dict(ActiveState='inactive',SubState='dead',Result='success',
        MainPID='0',ExecMainStatus='0',Job='',ControlGroup='').items())
    terminal=parsed(state.read('terminal.json')) if state.exists('terminal.json') else None
    if terminal is not None:
        need(set(terminal)=={'scope','intent_sha256','invocation','service_result','exit_code','exit_status','body_sha256'}
            and terminal['scope']=='blob-relay-systemd-terminal-v1' and terminal['intent_sha256']==digest
            and re.fullmatch(r'[a-f0-9]{32}',terminal['invocation']))
        invocation=manager['InvocationID']==('' if manager['LoadState']=='not-found' else terminal['invocation'])
        if quiet and invocation and terminal['service_result']=='success' and terminal['exit_code']=='exited' and terminal['exit_status']=='0':
            raw,value=verified_body(state,intent,digest);need(value['state']=='uploaded' and sha(raw)==terminal['body_sha256'])
            need(parsed(state.read('execution-intent.json'))==dict(scope='one-upload-execution-v1',intent_sha256=digest,invocation=terminal['invocation']))
            if absent_cgroup(intent['unit']):phase='uploaded-unverified'
    elif manager['LoadState']=='loaded' and manager['Result']=='success' and manager['ActiveState'] in ('active','activating','deactivating'):phase='in-progress'
    result.update(state=phase,unit=intent['unit'],intent_sha256=digest);return result


@safe
def observe(selected,*,read_guest=False):
    operation(selected)
    if not read_guest:return dict(scope='blob-relay-observe-plan-v1',performs_mutation=False,operation=selected)
    guest()
    with State(selected) as state:return _observe(state)


if __name__=='__main__':
    try:
        need(sys.flags.isolated and sys.platform=='linux' and os.geteuid()==0)
        class NoRawParser(argparse.ArgumentParser):
            def error(self,message):raise RelayRejected('Invalid private relay job arguments')
        parser=NoRawParser();group=parser.add_mutually_exclusive_group(required=True)
        group.add_argument('--execute');group.add_argument('--record-terminal');parser.add_argument('--sha256',required=True)
        args=parser.parse_args()
        if args.execute:execute(args.execute,args.sha256,apply=True)
        else:record_terminal(args.record_terminal,args.sha256)
    except BaseException:
        # No envelope, decrypted capability, URL-bearing exception or raw source facts.
        sys.stderr.write('Blob relay job requires same-handle observation; never replay.\n');sys.exit(1)
