"""Original Unlicense. One proved pre-snapshot failure retirement and source fix.

Not backup resume, restore, recurring maintenance or an authorization source.
Current external ARM selection is required; original failed evidence is retained.
"""
import argparse
import base64
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import sys
import types
import uuid

ROOT=Path('/var/lib/azd-santa-qualification')
RECOVERIES=ROOT/'presnapshot-recoveries'
ACTIVE=RECOVERIES/'active.json'
CGROUP=Path('/sys/fs/cgroup')
LIBRARY_SHA='65cccdc4c0824fb1ba6b351dbce7f4ef7ad31f3737a47c91b5e972e219bf4057'
OLD='790ec1696dc8533ccf85c01947a882b2f6188f3fe5d5a2017f456e8a0b711433'
NEW='c61618d81dc53c1d9bbfad31526757be47bd88760ff12b7683cbdb4e51c86e78'
CONTROLLER='f0a8961f64e48471eed71757805ae4e29ee080aef30c6ab9ec040eafaf443099'
OLD_BUNDLE='2d3c56abbff2f1d05cd89b1a0f31bc660d9f1c4a36cf3286f05a8f0cc1329a08'
OLD_MANIFEST='965fb757114cc5a7c7f6c44f2517267253fe9e1c8e8eee47976adecff691124f'
OLD_GENERATION='755138017297c8ab14f70d4014f7cedf17c4589bc0cc68351118823da84a543d'
OLD_UNIT='dcc863166a7d11393e34a742693b19d86052599b7f75eefe1b5895cf89f2512d'
REQUEST='a6386505ed6f97fbb92ed78823a819627fe866835f7b9b3a3b8e94421fd38a16'
BACKUP_OPERATION='368c81c41b584311b3e3cafe73264dd5'
BOOT='21f522fe-937b-41fa-ae22-e09a3ddbc84f'
CALLER='azd-santa-native-backup-cold3-20261114.service'
CALLER_INVOCATION='343b579ab63b477ba711784d3e2de546'
RUNTIME_INVOCATION='98a67049adc245ca823fb74435322a4a'
CALLER_PROFILE='9eb522c0d949165d1711d40cf28b20bc14de586907198d505f95fbfb2797e5e9'
CALLER_FRAGMENT='b04ce18340a6e2574010a199209fa334bbc045b7158780df165ae28a8cffa7ca'
CALLER_CONTEXT='9f9eb0a8b27446246647fad0f7606b930b2d927ac9fceb6935b3be002596a960'
RECORDER='a70a7a792be48b0dcff452f89d05703318abe713fb7d338d31910de856068d68'
FAILED_FILES={'maintenance-failed.json':'3ed854c95967fa85c45df4792276c9a64a3ab07613e1cdb92536f06b9422e0d5',
    'maintenance-intent.json':'c0575ac8e165ce844ab776e2197b4c21b50ea26a7d7ae4912429252dc5c8041e'}
PROFILE_FIELDS=('MainPID','Result','ExecMainCode','ExecMainStatus','ExecStart','ExecStopPost',
    'LoadState','ActiveState','SubState','FragmentPath','DropInPaths','Job','InvocationID')


def need(ok):
    if not ok:raise ValueError('Exact pre-snapshot recovery requires inspection; never replay')


def sha(raw):return hashlib.sha256(raw).hexdigest()
def encoded(value):return json.dumps(value,sort_keys=True).encode()


def bootstrap_read(path):
    path=Path(path);need(path.is_absolute() and path==path.resolve(strict=True))
    for item in (path,*path.parents):
        info=item.stat();need(info.st_uid==0 and not info.st_mode&0o022)
    need(path.is_file() and path.stat().st_size<=2*1024**2)
    with path.open('rb') as stream:raw=stream.read(2*1024**2+1)
    need(len(raw)<=2*1024**2);return raw


def library():
    active=json.loads(bootstrap_read(ROOT/'helper-upgrades/active.json'))
    path=ROOT/'helper-upgrades/programs'/LIBRARY_SHA/'helper_upgrade.py'
    need(active['program_path']==str(path) and active['program_sha256']==LIBRARY_SHA)
    raw=bootstrap_read(path);need(sha(raw)==LIBRARY_SHA)
    module=types.ModuleType('frozen_upgrade_v1');module.__file__=str(path)
    exec(compile(raw,str(path),'exec'),module.__dict__);return module


def unit(h,name,fields):
    lines=h.command(['systemctl','show',name,'--property='+','.join(fields)]).splitlines()
    result={}
    for line in lines:
        key,sep,value=line.partition('=');need(sep and key in fields and key not in result);result[key]=value
    need(set(result)==set(fields));return result


def historical_upgrade(h,target):
    raw=h.read(ROOT/'helper-upgrades/active.json');value=json.loads(raw)
    need(value['scope']=='azd-santa-one-helper-upgrade-v1' and value['target']==target
        and value['program_sha256']==LIBRARY_SHA and value['new_bundle_sha256']==OLD_BUNDLE
        and value['new_manifest_sha256']==OLD_MANIFEST and value['new_generation_sha256']==OLD_GENERATION
        and value['new_unit_sha256']==OLD_UNIT)
    operation=h.checked(Path(value['operation']),directory=True)
    need(h.read(operation/'intent.json')==raw)
    complete=h.read(operation/'complete.json');need(json.loads(complete)==h.completion(value,h.sha(raw)))
    proof=json.loads(h.read(operation/'terminal-success.json'))
    need(proof==dict(scope='azd-santa-helper-upgrade-terminal-v1',intent_sha256=h.sha(raw),
        completion_sha256=h.sha(complete),invocation=proof['invocation']) and re.fullmatch(r'[a-f0-9]{32}',proof['invocation']))
    name='azd-santa-helper-upgrade-'+operation.name.removeprefix('operation-')+'.service'
    fields=('LoadState','ActiveState','SubState','Result','ExecMainStatus','MainPID','InvocationID','Job')
    state=unit(h,name,fields);need(state['LoadState'] in ('loaded','not-found'))
    if state['LoadState']=='loaded':
        need(state['ActiveState']=='inactive' and state['SubState']=='dead' and state['Result']=='success'
            and state['ExecMainStatus']=='0' and state['MainPID']=='0' and state['Job']=='' and state['InvocationID']==proof['invocation'])
    h.history_unchanged(value)
    folder=ROOT/'helper-upgrades/bundles'/OLD_BUNDLE;package_raw=h.read(folder/'bundle.json');need(h.sha(package_raw)==OLD_BUNDLE)
    package=json.loads(package_raw);need(package['scope']=='private-azd-source-v1' and len(package['files'])==25)
    for name,meta in package['files'].items():
        need(re.fullmatch(r'[A-Za-z0-9_.-]+',name) and set(meta)=={'sha256','base64'})
        body=h.read(folder/name,262144);need(h.sha(body)==meta['sha256'] and base64.b64decode(meta['base64'],validate=True)==body)
    need(h.sha(h.read(folder/'cold_backup.py'))==OLD and h.sha(h.read(folder/'runtime_service.py'))==CONTROLLER)
    return value,folder,package


def failed_unit(h,name,invocation,restart):
    fields=PROFILE_FIELDS+('ControlGroup','Slice','KillMode','Delegate','Restart','Type')
    state=unit(h,name,fields)
    need(state['LoadState']=='loaded' and state['ActiveState']=='failed' and state['SubState']=='failed'
        and state['Result']=='exit-code' and state['ExecMainStatus']=='1' and state['ExecMainCode']=='1'
        and state['MainPID']=='0' and state['Job']=='' and state['InvocationID']==invocation
        and state['Slice']=='system.slice' and state['KillMode']=='control-group' and state['Delegate']=='no'
        and state['Restart']==restart)
    # Not a missing-field heuristic: a terminal known unit plus the expected
    # kernel cgroup must positively prove no descendant processes remain.
    h.checked(CGROUP,directory=True);h.checked(CGROUP/'system.slice',directory=True)
    need(h.command(['/usr/bin/stat','--file-system','--format=%T',str(CGROUP)]).strip()=='cgroup2fs')
    # Kernel cgroup v2 exposes events on NONROOT cgroups, not the root.
    # Positively attest this exact host hierarchy; absence alone proves nothing.
    controllers='cpuset cpu io memory hugetlb pids rdma misc dmem'.split()
    need(h.read(CGROUP/'cgroup.controllers',4096).decode().split()==controllers
        and h.read(CGROUP/'system.slice/cgroup.controllers',4096).decode().split()==controllers
        and h.read(CGROUP/'system.slice/cgroup.type',4096).strip()==b'domain')
    slice_events=dict(line.split() for line in h.read(CGROUP/'system.slice/cgroup.events',4096).decode().splitlines())
    need('populated' in slice_events and slice_events['populated'] in ('0','1'))
    group=CGROUP/'system.slice'/name
    need(state['ControlGroup'] in ('','/system.slice/'+name) and not group.is_symlink())
    if group.exists():
        need(state['ControlGroup']=='/system.slice/'+name)
        events=dict(line.split() for line in h.read(group/'cgroup.events',4096).decode().splitlines())
        need('populated' in events and events['populated']=='0')
    else:need(state['ControlGroup']=='')
    return state


def eligibility(h,target,*,enabled='enabled'):
    old,folder,package=historical_upgrade(h,target)
    controller=h.load(folder,'runtime_service');backup=h.load(folder,'cold_backup')
    manifest=ROOT/('private-runtime-'+target['EnvironmentName'])/'runtime-service/manifest.json';control=manifest.parent
    need(h.sha(h.read(manifest))==OLD_MANIFEST and h.sha(h.read(control/'container-generation.json'))==OLD_GENERATION
        and h.sha(h.read(controller.UNIT))==OLD_UNIT and h.unit_enabled()==enabled)
    h.effective_unit(controller.UNIT)
    runtime=controller.Runtime(manifest,OLD_MANIFEST);ids=runtime.inspect(running=False);generation=runtime.container_generation(ids)
    need(ids==old['container_ids'] and generation['generation']==old['generation'] and generation['image_id']==old['image_id'])
    request,request_sha,_=backup._request(runtime)
    need(request_sha==REQUEST and request['operation_id']==BACKUP_OPERATION and request['boot_id']==BOOT
        and backup.host_identity(request['target'])['boot_id']==BOOT
        and request['target']=={'VmId':target['VmId'],'VmInstanceId':target['VmInstanceId']}
        and request['manifest_sha256']==OLD_MANIFEST and request['generation_sha256']==OLD_GENERATION
        and request['backup_program_sha256']==OLD)
    caller=failed_unit(h,CALLER,CALLER_INVOCATION,'no')
    need(sha(encoded({k:caller[k] for k in PROFILE_FIELDS}))==CALLER_PROFILE
        and caller['FragmentPath']=='/run/systemd/transient/'+CALLER and caller['DropInPaths']==''
        and sha(h.read(Path(caller['FragmentPath'])))==CALLER_FRAGMENT)
    runtime_state=failed_unit(h,'azd-santa-runtime.service',RUNTIME_INVOCATION,'on-failure')
    context_path=ROOT/'native-backup-cold3-20261114/context.json';recorder=ROOT/'native-backup-cold3-20261114/record-terminal.py'
    need(sha(h.read(context_path))==CALLER_CONTEXT and sha(h.read(recorder))==RECORDER)
    terminal=context_path.parent/'terminal-success.json';need(not terminal.exists() and not terminal.is_symlink())
    context=json.loads(h.read(context_path));need(set(context)=={'destination','generation_sha256','manifest','manifest_sha256',
        'maximum_bytes','recipient_sha256','scope','seconds','unit','vm_id','vm_instance_id'}
        and context['scope']=='privatehook3-native-backup-job-v1' and context['unit']==CALLER
        and context['manifest']==str(manifest) and context['manifest_sha256']==OLD_MANIFEST
        and context['generation_sha256']==OLD_GENERATION and context['destination']==request['destination']
        and context['recipient_sha256']==request['recipient_sha256'] and context['maximum_bytes']==request['maximum_bytes']
        and context['seconds']==request['seconds'] and context['vm_id']==target['VmId'] and context['vm_instance_id']==target['VmInstanceId'])
    operation=control/('backup-'+BACKUP_OPERATION)
    need({p.name for p in operation.iterdir()}==set(FAILED_FILES))
    for name,digest in FAILED_FILES.items():need(sha(h.read(operation/name))==digest)
    need(json.loads(h.read(operation/'maintenance-intent.json'))=={'generation_sha256':OLD_GENERATION,'request_sha256':REQUEST}
        and json.loads(h.read(operation/'maintenance-failed.json'))=={'request_sha256':REQUEST,'error_type':'ValueError','automatic_replay':False})
    # The current same-boot requester view must still match its original full
    # legacy fingerprint. No legacy fingerprint is silently converted to v2.
    need(backup.storage_fingerprint(runtime)==request['storage_sha256'])
    volumes=backup.volume_paths(runtime);repository=volumes['elasticsearch_snapshots']
    need(not any(repository.iterdir()))
    destination=Path(request['destination']);need(destination==ROOT/'ciphertext-cold3-20261114'
        and not destination.exists() and not destination.is_symlink())
    all_ids=h.command(controller.DOCKER+['ps','--all','--quiet','--no-trunc']).split();need(set(all_ids)==set(ids.values()) and len(all_ids)==7)
    rows=json.loads(h.command(controller.DOCKER+['inspect',*ids.values()]))
    expected_exit={name:(1 if name=='workers' else 143 if name=='elastic' else 0) for name in ids}
    need(len(rows)==7 and {r['Id'] for r in rows}==set(ids.values()))
    for row in rows:
        state=row['State'];name=next(n for n,cid in ids.items() if cid==row['Id'])
        need(state['Status']=='exited' and state['Running'] is False and state['Paused'] is False and state['Restarting'] is False
            and state['OOMKilled'] is False and state['Error']=='' and type(state['Pid']) is int and state['Pid']==0
            and type(state['ExitCode']) is int and state['ExitCode']==expected_exit[name])
    need(request['worker_instance']['container_id']==ids['workers'] and request['worker_instance']['started_at']==
        next(row['State']['StartedAt'] for row in rows if row['Id']==ids['workers']))
    evidence={str(p):sha(h.read(p)) for p in (context_path,recorder,Path(caller['FragmentPath']),
        operation/'maintenance-intent.json',operation/'maintenance-failed.json')}
    return dict(target=target,manifest=str(manifest),container_ids=ids,generation=generation['generation'],
        old_upgrade=old,old_bundle=str(folder),request=request,runtime_state=runtime_state,caller_state=caller,
        evidence_sha256=evidence,stopped_states={r['Id']:r['State'] for r in rows},
        local_mount_snapshot=backup.mount_snapshot(volumes)),runtime


def candidate(h,target,bundle,archive,count):
    _,old,package=historical_upgrade(h,target)
    need(re.fullmatch(r'[a-f0-9]{64}',bundle) and re.fullmatch(r'[a-f0-9]{64}',archive) and type(count)is int and 1<=count<=64)
    upload=RECOVERIES/'uploads'/bundle/archive
    compressed=base64.b64decode(b''.join(h.read(upload/str(i),24576) for i in range(count)),validate=True)
    need(len(compressed)<=1024**2 and sha(compressed)==archive)
    with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as stream:raw=stream.read(2*1024**2+1)
    need(len(raw)<=2*1024**2 and sha(raw)==bundle)
    value=json.loads(raw);need(set(value)=={'scope','files'} and value['scope']==package['scope'] and set(value['files'])==set(package['files']))
    bodies={}
    for name,meta in value['files'].items():
        need(set(meta)=={'sha256','base64'});body=base64.b64decode(meta['base64'],validate=True)
        need(len(body)<=262144 and sha(body)==meta['sha256'] and (sha(body)==NEW if name=='cold_backup.py' else body==h.read(old/name,262144)))
        bodies[name]=body
    folder=ROOT/'helper-upgrades/bundles'/bundle;h.secure_directories(folder)
    for name,body in {'bundle.json':raw,**bodies}.items():
        if (folder/name).exists():need(h.read(folder/name)==body)
        else:h.exclusive(folder/name,body,0o644)
    return folder


def derive(old_manifest,old_generation):
    need(old_manifest['controller_sha256']==CONTROLLER and old_manifest['helpers_sha256']['cold_backup.py']==OLD
        and sha(encoded(old_manifest))==OLD_MANIFEST and sha(encoded(old_generation))==OLD_GENERATION
        and old_generation['manifest_sha256']==OLD_MANIFEST)
    manifest=json.loads(encoded(old_manifest));manifest['helpers_sha256']['cold_backup.py']=NEW
    generation=json.loads(encoded(old_generation));generation['manifest_sha256']=sha(encoded(manifest))
    return encoded(manifest),encoded(generation)


def prepare(h,target,folder):
    proof,runtime=eligibility(h,target);manifest=Path(proof['manifest']);control=manifest.parent
    new_manifest,new_generation=derive(json.loads(h.read(manifest)),json.loads(h.read(control/'container-generation.json')))
    controller=h.load(folder,'runtime_service')
    new_unit=controller.unit_text(folder/'runtime_service.py',manifest,sha(new_manifest)).encode()
    operation=RECOVERIES/('operation-'+uuid.uuid4().hex);operation.mkdir(mode=0o700)
    snapshots={'old-manifest.json':h.read(manifest),'new-manifest.json':new_manifest,
        'old-generation.json':h.read(control/'container-generation.json'),'new-generation.json':new_generation,
        'old-unit':h.read(controller.UNIT),'new-unit':new_unit,'request-preserved.json':h.read(control/'backup-request.json'),
        'eligibility.json':encoded(proof)}
    for name,raw in snapshots.items():h.exclusive(operation/name,raw)
    for index,path in enumerate(sorted(proof['evidence_sha256'])):h.exclusive(operation/('evidence-'+str(index)),h.read(Path(path)))
    intent=dict(scope='exact-presnapshot-retirement-v1',target=target,operation=str(operation),candidate=str(folder),
        bundle_sha256=folder.name,program_sha256=sha(h.read(Path(__file__))),proof_sha256=sha(encoded(proof)),
        snapshot_sha256={name:sha(raw) for name,raw in snapshots.items()},request_sha256=REQUEST,
        new_manifest_sha256=sha(new_manifest),new_generation_sha256=sha(new_generation),new_unit_sha256=sha(new_unit))
    raw=encoded(intent);h.exclusive(operation/'intent.json',raw);h.exclusive(ACTIVE,raw);return intent


def verify_candidate(h,intent):
    folder=Path(intent['candidate']);need(folder==ROOT/'helper-upgrades/bundles'/intent['bundle_sha256'])
    raw=h.read(folder/'bundle.json');need(sha(raw)==intent['bundle_sha256'])
    value=json.loads(raw);old=ROOT/'helper-upgrades/bundles'/OLD_BUNDLE;package=json.loads(h.read(old/'bundle.json'))
    need(sha(h.read(old/'bundle.json'))==OLD_BUNDLE and value['scope']==package['scope'] and set(value['files'])==set(package['files']))
    for name,meta in value['files'].items():
        need(re.fullmatch(r'[A-Za-z0-9_.-]+',name) and set(meta)=={'sha256','base64'})
        body=h.read(folder/name,262144)
        need(sha(body)==meta['sha256'] and base64.b64decode(meta['base64'],validate=True)==body
            and (sha(body)==NEW if name=='cold_backup.py' else body==h.read(old/name,262144)))


def snapshots(h,intent):
    operation=Path(intent['operation'])
    for name,digest in intent['snapshot_sha256'].items():need(sha(h.read(operation/name))==digest)
    need(sha(h.read(operation/'request-preserved.json'))==REQUEST)
    need(derive(json.loads(h.read(operation/'old-manifest.json')),json.loads(h.read(operation/'old-generation.json')))==
        (h.read(operation/'new-manifest.json'),h.read(operation/'new-generation.json')))
    controller=h.load(Path(intent['candidate']),'runtime_service')
    proof=json.loads(h.read(operation/'eligibility.json'));need(sha(encoded(proof))==intent['proof_sha256'])
    need(h.read(operation/'new-unit')==controller.unit_text(Path(intent['candidate'])/'runtime_service.py',
        Path(proof['manifest']),intent['new_manifest_sha256']).encode())
    return proof


def evidence_unchanged(h,proof):
    for path,digest in proof['evidence_sha256'].items():need(sha(h.read(Path(path)))==digest)
    h.history_unchanged(proof['old_upgrade'])


def no_request(control):
    path=control/'backup-request.json';need(not path.exists() and not path.is_symlink())


def retirement(h,operation,control):
    source=control/'backup-request.json';destination=operation/'retired-request.json'
    need(sha(h.read(source))==REQUEST and sha(h.read(operation/'request-preserved.json'))==REQUEST
        and not destination.exists() and not destination.is_symlink() and source.stat().st_dev==operation.stat().st_dev)
    h.exclusive(operation/'retirement-intent.json',encoded(dict(scope='one-explicit-failed-request-retirement-v1',
        request_sha256=REQUEST,source=str(source),destination=str(destination))))
    # Unique private journal destination plus the exclusive maintenance window
    # prevents replacement; no overwrite/copy-delete or cross-device fallback.
    os.rename(source,destination);h.sync(control);h.sync(operation)
    need(sha(h.read(destination))==REQUEST);no_request(control)
    h.exclusive(operation/'retirement-receipt.json',encoded(dict(scope='failed-request-retired-not-completed-v1',
        request_sha256=REQUEST,backup_completed=False,backup_replayed=False)))


def completion(intent,digest):
    return dict(scope='exact-presnapshot-recovery-complete-v1',intent_sha256=digest,failed_request_sha256=REQUEST,
        failed_backup_operation=BACKUP_OPERATION,request_retired=True,old_backup_completed=False,new_backup_requested=False,
        new_helper_sha256=NEW,new_bundle_sha256=intent['bundle_sha256'],new_manifest_sha256=intent['new_manifest_sha256'],
        new_generation_sha256=intent['new_generation_sha256'],new_unit_sha256=intent['new_unit_sha256'],
        container_count=7,images_changed=False,credentials_reset=False,clean_worker_proof=False,backup_qualified=False)


def execute(intent_path,digest):
    import fcntl
    h=library();raw=h.read(intent_path);need(sha(raw)==digest and h.read(ACTIVE)==raw)
    intent=json.loads(raw);operation=h.checked(Path(intent['operation']),directory=True)
    need(Path(intent_path)==operation/'intent.json' and sha(h.read(Path(__file__)))==intent['program_sha256'])
    need(not any((operation/name).exists() for name in ('disable-intent.json','retirement-intent.json','start-intent.json','failed.json','complete.json')))
    try:
        verify_candidate(h,intent);proof=snapshots(h,intent)
        current,runtime=eligibility(h,intent['target']);need(current==proof)
        h.exclusive(operation/'disable-intent.json',encoded({'scope':'persistent-boot-hold-v1'}))
        h.command(['systemctl','disable','azd-santa-runtime.service']);need(h.unit_enabled()=='disabled')
        control=Path(proof['manifest']).parent
        with h.checked(control/'supervisor.lock').open('r+b') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            current,runtime=eligibility(h,intent['target'],enabled='disabled');need(current==proof)
            verify_candidate(h,intent);snapshots(h,intent);evidence_unchanged(h,proof)
            retirement(h,operation,control)
            for name,path,old in (('manifest',Path(proof['manifest']),OLD_MANIFEST),
                ('generation',control/'container-generation.json',OLD_GENERATION),('unit',h.load(Path(intent['candidate']),'runtime_service').UNIT,OLD_UNIT)):
                h.exclusive(operation/('promote-'+name+'.json'),encoded({'old_sha256':old}))
                h.replace_bound(path,old,h.read(operation/('new-'+name+('.json' if name!='unit' else ''))))
            h.command(['systemctl','daemon-reload']);controller=h.load(Path(intent['candidate']),'runtime_service')
            controller.load_manifest(proof['manifest'],intent['new_manifest_sha256']);h.effective_unit(controller.UNIT)
            updated=controller.Runtime(proof['manifest'],intent['new_manifest_sha256'])
            need(updated.inspect(running=False)==proof['container_ids'] and
                updated.container_generation(proof['container_ids'])['generation']==proof['generation'])
            old_backup=h.load(Path(proof['old_bundle']),'cold_backup')
            need(old_backup.mount_snapshot(old_backup.volume_paths(runtime))==proof['local_mount_snapshot'])
            evidence_unchanged(h,proof);no_request(control)
            h.exclusive(operation/'reset-runtime-failed-intent.json',encoded({'preserved_failure_sha256':intent['proof_sha256']}))
            h.command(['systemctl','reset-failed','azd-santa-runtime.service']);h.inactive();need(h.unit_enabled()=='disabled')
            h.exclusive(operation/'enable-intent.json',encoded({'restore_original_enabled_state':True}))
            h.command(['systemctl','enable','azd-santa-runtime.service']);need(h.unit_enabled()=='enabled')
            h.exclusive(operation/'start-intent.json',encoded({'one_normal_start':True,'backup_resume':False}))
        h.command(['systemctl','start','azd-santa-runtime.service'],timeout=450)
        current_binding(h,intent,proof)
        h.exclusive(operation/'complete.json',encoded(completion(intent,digest)))
    except BaseException as error:
        h.exclusive(operation/'failed.json',encoded({'error_type':type(error).__name__,'automatic_replay':False}));raise


def current_binding(h,intent,proof):
    historical_upgrade(h,intent['target']);verify_candidate(h,intent);evidence_unchanged(h,proof)
    caller=failed_unit(h,CALLER,CALLER_INVOCATION,'no')
    need(sha(encoded({k:caller[k] for k in PROFILE_FIELDS}))==CALLER_PROFILE)
    controller=h.load(Path(intent['candidate']),'runtime_service')
    controller.load_manifest(proof['manifest'],intent['new_manifest_sha256']);h.effective_unit(controller.UNIT)
    control=Path(proof['manifest']).parent;no_request(control)
    need(sha(h.read(control/'container-generation.json'))==intent['new_generation_sha256']
        and sha(h.read(controller.UNIT))==intent['new_unit_sha256'] and h.unit_enabled()=='enabled'
        and sha(h.read(Path(intent['operation'])/'retired-request.json'))==REQUEST)
    backup=h.load(Path(proof['old_bundle']),'cold_backup')
    need(backup.host_identity({'VmId':intent['target']['VmId'],'VmInstanceId':intent['target']['VmInstanceId']})['boot_id']==BOOT)
    state=h.unit_state();need(state['ActiveState']=='active' and state['SubState']=='running' and state['Job']==''
        and re.fullmatch(r'[1-9][0-9]*',state['MainPID']))
    need(h.read(Path('/proc')/state['MainPID']/'cmdline',8192).rstrip(b'\0').split(b'\0')[1:]==
        [str(v).encode() for v in ('-I',Path(intent['candidate'])/'runtime_service.py','run','--manifest',proof['manifest'],'--sha256',intent['new_manifest_sha256'])])
    rows=json.loads(h.command(controller.DOCKER+['inspect',*proof['container_ids'].values()]))
    need(len(rows)==7 and {r['Id'] for r in rows}==set(proof['container_ids'].values())
        and all(r['State']['Running'] is True and r['State']['Paused'] is False and r['State']['Restarting'] is False for r in rows))


def record_terminal(intent_path,digest):
    h=library();raw=h.read(intent_path);need(sha(raw)==digest and h.read(ACTIVE)==raw)
    intent=json.loads(raw);operation=Path(intent['operation'])
    need(Path(intent_path)==operation/'intent.json' and sha(h.read(Path(__file__)))==intent['program_sha256']
        and os.environ.get('SERVICE_RESULT')=='success' and os.environ.get('EXIT_CODE')=='exited'
        and os.environ.get('EXIT_STATUS')=='0' and re.fullmatch(r'[a-f0-9]{32}',os.environ.get('INVOCATION_ID','')))
    body=h.read(operation/'complete.json');need(json.loads(body)==completion(intent,digest))
    h.exclusive(operation/'terminal-success.json',encoded(dict(scope='exact-presnapshot-recovery-terminal-v1',
        intent_sha256=digest,completion_sha256=sha(body),invocation=os.environ['INVOCATION_ID'])))


def observe(h,target,bundle):
    if not ACTIVE.exists():return dict(scope='exact-presnapshot-recovery-observation-v1',state='not-requested',new_bundle_sha256=bundle)
    raw=h.read(ACTIVE);intent=json.loads(raw);need(intent['target']==target and intent['bundle_sha256']==bundle)
    operation=h.checked(Path(intent['operation']),directory=True);need(h.read(operation/'intent.json')==raw)
    name='azd-santa-presnapshot-recovery-'+operation.name.removeprefix('operation-')+'.service'
    state=unit(h,name,('LoadState','ActiveState','SubState','Result','ExecMainStatus','MainPID','InvocationID','Job'))
    need(state['LoadState'] in ('loaded','not-found'));phase='unknown'
    if (operation/'failed.json').exists() or (state['LoadState']=='loaded' and (state['Result']!='success' or state['ActiveState']=='failed')):phase='failed'
    elif (operation/'terminal-success.json').exists():
        proof=json.loads(h.read(operation/'terminal-success.json'));body=h.read(operation/'complete.json')
        need(json.loads(body)==completion(intent,sha(raw)) and proof==dict(scope='exact-presnapshot-recovery-terminal-v1',
            intent_sha256=sha(raw),completion_sha256=sha(body),invocation=proof['invocation']) and re.fullmatch(r'[a-f0-9]{32}',proof['invocation']))
        if state['LoadState']=='loaded':need(state['Result']=='success' and state['ExecMainStatus']=='0' and state['InvocationID']==proof['invocation'])
        if state['LoadState']=='not-found' or (state['ActiveState']=='inactive' and state['SubState']=='dead' and state['MainPID']=='0' and state['Job']==''):
            current_binding(h,intent,json.loads(h.read(operation/'eligibility.json')));phase='completed'
        else:phase='in-progress'
    elif state['LoadState']=='loaded' and state['ActiveState'] in ('active','activating','deactivating'):phase='in-progress'
    return dict(scope='exact-presnapshot-recovery-observation-v1',state=phase,new_bundle_sha256=bundle,unit=name,
        intent_sha256=sha(raw),completion=completion(intent,sha(raw)) if phase=='completed' else None)


def run(value):
    h=library();need(sys.platform=='linux' and os.geteuid()==0 and type(value)is dict
        and set(value)<={'mode','target','bundle_sha256','archive_sha256','count','index','data'})
    mode=value['mode'];target=value['target'];bundle=value['bundle_sha256']
    need(mode in ('observe','chunk','request') and re.fullmatch(r'[a-f0-9]{64}',bundle))
    if ACTIVE.exists():return observe(h,target,bundle)
    historical_upgrade(h,target)
    if mode=='observe':return observe(h,target,bundle)
    h.secure_directories(RECOVERIES)
    if mode=='chunk':
        archive=value['archive_sha256'];index=value['index'];count=value['count'];data=value['data']
        need(re.fullmatch(r'[a-f0-9]{64}',archive) and type(index)is int and type(count)is int and 0<=index<count<=64
            and type(data)is str and 0<len(data)<=24576 and re.fullmatch(r'[A-Za-z0-9+/=]+',data))
        folder=h.secure_directories(RECOVERIES/'uploads'/bundle/archive);path=folder/str(index)
        if path.exists():need(h.read(path)==data.encode())
        else:h.exclusive(path,data.encode())
        return dict(scope='exact-presnapshot-recovery-chunk-v1',index=index,new_bundle_sha256=bundle)
    folder=candidate(h,target,bundle,value['archive_sha256'],value['count']);intent=prepare(h,target,folder)
    operation=Path(intent['operation']);digest=sha(h.read(operation/'intent.json'));program=Path(__file__)
    h.command(['systemd-run','--no-block','--unit=azd-santa-presnapshot-recovery-'+operation.name.removeprefix('operation-'),
        '--property=Type=oneshot','--property=Restart=no','--property=TimeoutStartSec=900','--property=RuntimeMaxSec=900',
        '--property=PrivateTmp=no','--property=ProtectHome=no','--property=NoNewPrivileges=yes','--property=UMask=0077',
        '--property=ExecStopPost=/usr/bin/python3 -I '+str(program)+' --record-terminal '+str(operation/'intent.json')+' --sha256 '+digest,
        '/usr/bin/python3','-I',str(program),'--execute',str(operation/'intent.json'),'--sha256',digest])
    return observe(h,target,bundle)


if __name__=='__main__':
    try:
        need(sys.platform=='linux' and os.geteuid()==0 and sys.flags.isolated)
        parser=argparse.ArgumentParser();group=parser.add_mutually_exclusive_group()
        group.add_argument('--execute');group.add_argument('--record-terminal');parser.add_argument('--sha256');args=parser.parse_args()
        if args.execute:execute(args.execute,args.sha256)
        elif args.record_terminal:record_terminal(args.record_terminal,args.sha256)
        else:print('SANTA_HELPER_UPGRADE_JSON:'+json.dumps(run(json.loads(base64.b64decode(os.environ['AZD_HELPER_UPGRADE_COMMAND'],validate=True))),separators=(',',':')))
    except BaseException:raise SystemExit('Pre-snapshot recovery outcome requires inspection; do not replay.') from None
