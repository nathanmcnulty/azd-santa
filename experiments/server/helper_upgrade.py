"""Original Unlicense. One explicit host-only nsfs helper upgrade, never install.

The caller must select the current ARM VM externally. This utility uses IMDS,
retained installer history and original runtime bindings; none grants authority.
Only the reviewed cold_backup.py transition is supported. No rollback/replay.
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
import subprocess
import sys
import types
import uuid

ROOT = Path('/var/lib/azd-santa-qualification')
UPGRADES = ROOT / 'helper-upgrades'
ACTIVE = UPGRADES / 'active.json'
OLD = '7c6f0b25bc090b5c4efa03c47565e5a28e64a3eef2823e667885e951262a539a'
NEW = '790ec1696dc8533ccf85c01947a882b2f6188f3fe5d5a2017f456e8a0b711433'
CONTROLLER = 'f0a8961f64e48471eed71757805ae4e29ee080aef30c6ab9ec040eafaf443099'
HEX = r'[a-f0-9]{64}'


def need(ok):
    if not ok: raise ValueError('Helper upgrade requires inspection; never replay stop/start')


def sha(raw): return hashlib.sha256(raw).hexdigest()
def encoded(value): return json.dumps(value, sort_keys=True).encode()


def checked(path, *, directory=False):
    path = Path(path); need(path.is_absolute() and path == path.resolve(strict=True))
    for parent in (path.parent, *path.parent.parents):
        info = parent.stat(); need(info.st_uid == 0 and not info.st_mode & 0o022)
    info = path.stat()
    need(info.st_uid == 0 and not info.st_mode & 0o022 and (path.is_dir() if directory else path.is_file()))
    return path


def read(path, maximum=2*1024**2):
    path = checked(path); need(path.stat().st_size <= maximum)
    with path.open('rb') as stream: raw = stream.read(maximum + 1)
    need(len(raw) <= maximum); return raw


def sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)


def secure_directories(path):
    current=checked(ROOT,directory=True)
    for part in path.relative_to(ROOT).parts:
        current=current/part
        current.mkdir(mode=0o700,exist_ok=True)
        checked(current,directory=True)
    return current


def exclusive(path, raw, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as output: output.write(raw); output.flush(); os.fsync(output.fileno())
    sync(path.parent)


def load(folder, name):
    path = checked(folder / (name + '.py')); module = types.ModuleType('upgrade_' + name); module.__file__ = str(path)
    exec(compile(read(path), str(path), 'exec'), module.__dict__); return module


def command(args, timeout=30):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    need(result.returncode == 0); return result.stdout


def unit_state():
    return dict(line.split('=', 1) for line in command(['systemctl', 'show', 'azd-santa-runtime.service',
        '--property=LoadState,ActiveState,SubState,MainPID,Result,Job']).splitlines() if '=' in line)


def unit_enabled():
    return command(['systemctl','show','azd-santa-runtime.service','--property=UnitFileState','--value']).strip()


def effective_unit(path):
    values=dict(line.split('=',1) for line in command(['systemctl','show','azd-santa-runtime.service',
        '--property=FragmentPath,DropInPaths,Type,Restart,NoNewPrivileges,PrivateTmp,ProtectHome']).splitlines() if '=' in line)
    need(values==dict(FragmentPath=str(path),DropInPaths='',Type='notify',Restart='on-failure',
        NoNewPrivileges='yes',PrivateTmp='yes',ProtectHome='yes'))


def history(target):
    raw = read(ROOT / 'private-azd-install.json'); context = json.loads(raw)
    need(set(context) == {'scope', 'bundle_sha256', 'target'} and context['scope'] == 'private-azd-install-v1'
         and context['target'] == target and re.fullmatch(HEX, context['bundle_sha256']))
    folder = checked(ROOT / 'installers' / context['bundle_sha256'], directory=True)
    need(read(folder / 'context.json') == raw)
    bundle_raw = read(folder / 'bundle.json'); need(sha(bundle_raw) == context['bundle_sha256'])
    package = json.loads(bundle_raw)
    need(set(package) == {'scope', 'files'} and package['scope'] == 'private-azd-source-v1')
    for name, metadata in package['files'].items():
        need(re.fullmatch(r'[A-Za-z0-9_.-]+', name) and set(metadata) == {'sha256', 'base64'})
        body = read(folder / name, 262144)
        need(sha(body) == metadata['sha256'] and base64.b64decode(metadata['base64'], validate=True) == body)
    need(sha(read(folder / 'runtime_service.py')) == CONTROLLER and sha(read(folder / 'cold_backup.py')) == OLD)
    relay = load(folder, 'private_install_transport'); need(set(package['files']) == relay.FILES)
    need(relay.status(context['bundle_sha256'])['state'] == 'completed')
    installer = load(folder, 'private_install'); installer.validate_target(target)
    backup = load(folder, 'cold_backup'); identity = backup.host_identity({'VmId': target['VmId'], 'VmInstanceId': target['VmInstanceId']})
    # Original installer evidence remains unchanged and historical. This verifies
    # its complete terminal proof without claiming it installs the new helper.
    proof = json.loads(read(folder / 'terminal-success.json')); complete_raw = read(folder / 'complete.json')
    need(proof['scope'] == 'private-azd-install-terminal-success' and proof['context_sha256'] == sha(raw)
         and proof['bundle_sha256'] == context['bundle_sha256'] and proof['completion_sha256'] == sha(complete_raw)
         and proof['service_result'] == 'success' and proof['exit_code'] == 'exited' and proof['exit_status'] == '0')
    complete = json.loads(complete_raw); need(complete['bundle_sha256'] == context['bundle_sha256']
        and all(complete['outputs'][k] == value for k, value in target.items()))
    return folder, package, identity


def no_backup(control):
    path = control / 'backup-request.json'; need(not path.exists() and not path.is_symlink())


def baseline(target):
    folder, package, identity = history(target)
    controller = load(folder, 'runtime_service')
    manifest_path = ROOT / ('private-runtime-' + target['EnvironmentName']) / 'runtime-service/manifest.json'
    manifest_raw = read(manifest_path); digest = sha(manifest_raw); runtime = controller.Runtime(manifest_path, digest)
    no_backup(manifest_path.parent)
    selected = runtime.inspect(running=True); generation = runtime.container_generation(selected)
    state = unit_state()
    need(state['LoadState'] == 'loaded' and state['ActiveState'] == 'active' and state['SubState'] == 'running'
         and re.fullmatch(r'[1-9][0-9]*', state['MainPID']) and not state['Job'])
    unit = read(controller.UNIT); need(unit == controller.unit_text(folder / 'runtime_service.py', manifest_path, digest).encode())
    effective_unit(controller.UNIT)
    argv = read(Path('/proc') / state['MainPID'] / 'cmdline', 8192).rstrip(b'\0').split(b'\0')
    need(argv[1:] == [str(v).encode() for v in ('-I', folder / 'runtime_service.py', 'run', '--manifest', manifest_path, '--sha256', digest)])
    need(runtime.binding['helpers_sha256']['cold_backup.py'] == OLD)
    need(unit_enabled() == 'enabled')
    historical = {str(folder/name):meta['sha256'] for name,meta in package['files'].items()}
    historical.update({str(path):sha(read(path)) for path in (ROOT/'private-azd-install.json',
        folder/'context.json',folder/'bundle.json',folder/'complete.json',folder/'terminal-success.json')})
    return dict(target=target, boot_id=identity['boot_id'], old_bundle_sha256=folder.name,
        manifest_path=str(manifest_path), old_manifest_sha256=digest,
        old_generation_sha256=sha(read(manifest_path.parent / 'container-generation.json')),
        old_unit_sha256=sha(unit), container_ids=selected, generation=generation['generation'],
        image_id=generation['image_id'], project=generation['project'], old_main_pid=state['MainPID'],
        old_unit_enabled='enabled',historical_sha256=historical)


def stage_bundle(target, bundle_sha, archive_sha, count):
    old, package, _ = history(target)
    need(re.fullmatch(HEX, bundle_sha) and re.fullmatch(HEX, archive_sha) and type(count) is int and 1 <= count <= 64)
    upload = UPGRADES / 'uploads' / bundle_sha / archive_sha
    joined = b''.join(read(upload / str(i), 24576) for i in range(count))
    compressed = base64.b64decode(joined, validate=True); need(len(compressed) <= 1024**2 and sha(compressed) == archive_sha)
    with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as stream: raw = stream.read(2*1024**2+1)
    need(len(raw) <= 2*1024**2 and sha(raw) == bundle_sha)
    candidate = json.loads(raw); need(set(candidate) == {'scope', 'files'} and candidate['scope'] == package['scope']
        and set(candidate['files']) == set(package['files']))
    bodies = {}
    for name, metadata in candidate['files'].items():
        need(set(metadata) == {'sha256', 'base64'})
        body = base64.b64decode(metadata['base64'], validate=True); need(len(body) <= 262144 and sha(body) == metadata['sha256'])
        need(sha(body) == NEW if name == 'cold_backup.py' else body == read(old / name, 262144))
        bodies[name] = body
    folder = UPGRADES / 'bundles' / bundle_sha
    folder.parent.mkdir(mode=0o700, exist_ok=True); checked(folder.parent, directory=True)
    if folder.exists():
        need(read(folder / 'bundle.json') == raw)
        for name, body in bodies.items(): need(read(folder / name) == body)
    else:
        folder.mkdir(mode=0o700); exclusive(folder / 'bundle.json', raw)
        for name, body in bodies.items(): exclusive(folder / name, body, 0o644)
    return folder


def derive_transition(old_manifest, old_generation, new_helper_hash):
    """Pure, exact transition. No change to images, policies, generation or IDs."""
    need(new_helper_hash == NEW and old_manifest['controller_sha256'] == CONTROLLER
         and old_manifest['helpers_sha256']['cold_backup.py'] == OLD
         and old_generation['manifest_sha256'] == sha(encoded(old_manifest)))
    manifest = json.loads(encoded(old_manifest)); manifest['helpers_sha256']['cold_backup.py'] = NEW
    generation = json.loads(encoded(old_generation)); generation['manifest_sha256'] = sha(encoded(manifest))
    return encoded(manifest), encoded(generation)


def candidate_matches(intent):
    folder = checked(Path(intent['candidate']), directory=True)
    need(folder == UPGRADES / 'bundles' / intent['new_bundle_sha256'])
    raw = read(folder / 'bundle.json'); need(sha(raw) == intent['new_bundle_sha256'])
    candidate = json.loads(raw)
    old = ROOT / 'installers' / intent['old_bundle_sha256']
    package = json.loads(read(old / 'bundle.json'))
    need(sha(read(old / 'bundle.json')) == intent['old_bundle_sha256'] and set(candidate['files']) == set(package['files']))
    need(sha(read(old/'cold_backup.py')) == OLD)
    for name, metadata in candidate['files'].items():
        need(re.fullmatch(r'[A-Za-z0-9_.-]+', name) and set(metadata) == {'sha256','base64'})
        body = read(folder / name, 262144)
        need(sha(body) == metadata['sha256'] and base64.b64decode(metadata['base64'], validate=True) == body)
        need(sha(body) == NEW if name == 'cold_backup.py' else body == read(old / name, 262144))
    return folder


def snapshots_match(intent):
    operation = Path(intent['operation'])
    for name, field in (('old-manifest.json','old_manifest_sha256'), ('new-manifest.json','new_manifest_sha256'),
        ('old-generation.json','old_generation_sha256'), ('new-generation.json','new_generation_sha256'),
        ('old-unit','old_unit_sha256'), ('new-unit','new_unit_sha256')):
        need(sha(read(operation / name)) == intent[field])
    derived = derive_transition(json.loads(read(operation / 'old-manifest.json')),
        json.loads(read(operation / 'old-generation.json')), NEW)
    need(derived == (read(operation / 'new-manifest.json'), read(operation / 'new-generation.json')))
    new = load(Path(intent['candidate']), 'runtime_service')
    need(read(operation / 'new-unit') == new.unit_text(Path(intent['candidate']) / 'runtime_service.py',
        Path(intent['manifest_path']), intent['new_manifest_sha256']).encode())


def reserve(target, candidate, program):
    snapshot = baseline(target); manifest_path = Path(snapshot['manifest_path']); control = manifest_path.parent
    old_manifest = read(manifest_path); old_generation = read(control / 'container-generation.json')
    new_manifest, new_generation = derive_transition(json.loads(old_manifest), json.loads(old_generation), NEW)
    need(encoded(json.loads(old_manifest)) == old_manifest and encoded(json.loads(old_generation)) == old_generation)
    controller = load(candidate, 'runtime_service')
    new_unit = controller.unit_text(candidate / 'runtime_service.py', manifest_path, sha(new_manifest)).encode()
    operation = UPGRADES / ('operation-' + uuid.uuid4().hex); operation.mkdir(mode=0o700)
    for name, raw in {'old-manifest.json':old_manifest, 'new-manifest.json':new_manifest,
        'old-generation.json':old_generation, 'new-generation.json':new_generation,
        'old-unit':read(controller.UNIT), 'new-unit':new_unit}.items(): exclusive(operation / name, raw)
    intent = dict(scope='azd-santa-one-helper-upgrade-v1', **snapshot, candidate=str(candidate),
        new_bundle_sha256=candidate.name, new_manifest_sha256=sha(new_manifest),
        new_generation_sha256=sha(new_generation), new_unit_sha256=sha(new_unit),
        program_path=str(program), program_sha256=sha(read(program)), operation=str(operation))
    raw = encoded(intent); exclusive(operation / 'intent.json', raw)
    # This once-per-host reservation is never replaced or removed automatically.
    exclusive(ACTIVE, raw)
    return intent


def replace_bound(path, old_hash, raw):
    """One explicit compare/replace under flock; old bytes retained in operation."""
    need(sha(read(path)) == old_hash)
    temporary = path.parent / (path.name + '.helper-upgrade-' + uuid.uuid4().hex)
    exclusive(temporary, raw, path.stat().st_mode & 0o777)
    need(sha(read(path)) == old_hash); os.replace(temporary, path); sync(path.parent)


def inactive():
    state = unit_state()
    need(state == {'LoadState':'loaded', 'ActiveState':'inactive', 'SubState':'dead', 'MainPID':'0', 'Result':'success', 'Job':''})


def history_unchanged(intent):
    need(all(sha(read(Path(path)))==digest for path,digest in intent['historical_sha256'].items()))


def completion(intent, expected):
    return {'scope':'azd-santa-helper-upgrade-complete-v1','intent_sha256':expected,
        'old_helper_sha256':OLD,'new_helper_sha256':NEW,'new_bundle_sha256':intent['new_bundle_sha256'],
        'new_manifest_sha256':intent['new_manifest_sha256'],'new_generation_sha256':intent['new_generation_sha256'],
        'new_unit_sha256':intent['new_unit_sha256'],'container_count':7,
        'images_changed':False,'installer_history_changed':False,'backup_qualified':False}


def execute(intent_path, expected):
    import fcntl
    raw = read(intent_path); need(sha(raw) == expected and read(ACTIVE) == raw)
    intent = json.loads(raw); operation = checked(Path(intent['operation']), directory=True)
    need(Path(intent_path) == operation / 'intent.json' and sha(read(Path(__file__))) == intent['program_sha256'])
    need(not any((operation / name).exists() for name in ('disable-intent.json','stop-intent.json', 'start-intent.json', 'complete.json', 'failed.json')))
    try:
        need(baseline(intent['target']) == {k:intent[k] for k in baseline_fields()})
        candidate_matches(intent); snapshots_match(intent)
        # Persistent boot hold during a non-atomic file tuple transition. A
        # normal stop cancels Restart=; disabled prevents boot-time admission.
        exclusive(operation/'disable-intent.json',encoded({'scope':'one-disable-existing-enabled-unit-v1'}))
        command(['systemctl','disable','azd-santa-runtime.service']); need(unit_enabled()=='disabled')
        exclusive(operation / 'stop-intent.json', encoded({'scope':'one-normal-stop-v1'}))
        command(['systemctl', 'stop', 'azd-santa-runtime.service'], timeout=240)
        inactive(); control = Path(intent['manifest_path']).parent
        no_backup(control)
        with checked(control / 'supervisor.lock').open('r+b') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            old = ROOT / 'installers' / intent['old_bundle_sha256']; controller = load(old, 'runtime_service')
            runtime = controller.Runtime(intent['manifest_path'], intent['old_manifest_sha256'])
            need(runtime.inspect(running=False) == intent['container_ids'])
            need(runtime.container_generation(intent['container_ids'])['generation'] == intent['generation'])
            rows = json.loads(runtime.call('upgrade-stopped', controller.DOCKER + ['inspect', *intent['container_ids'].values()]).stdout)
            need(len(rows) == 7 and {r['Id'] for r in rows} == set(intent['container_ids'].values())
                and all(r['State']['Running'] is False and r['State']['Paused'] is False and r['State']['Restarting'] is False
                    and type(r['State']['Pid']) is int and r['State']['Pid'] == 0 for r in rows))
            no_backup(control)
            candidate_matches(intent); snapshots_match(intent)
            for name, path, old_hash in (('manifest', Path(intent['manifest_path']), intent['old_manifest_sha256']),
                ('generation', control / 'container-generation.json', intent['old_generation_sha256']),
                ('unit', controller.UNIT, intent['old_unit_sha256'])):
                exclusive(operation / ('promote-' + name + '.json'), encoded({'old_sha256':old_hash}))
                replace_bound(path, old_hash, read(operation / ('new-' + name + ('.json' if name != 'unit' else ''))))
            command(['systemctl', 'daemon-reload']); inactive(); no_backup(control); effective_unit(controller.UNIT)
            new = load(Path(intent['candidate']), 'runtime_service')
            runtime = new.Runtime(intent['manifest_path'], intent['new_manifest_sha256'])
            need(runtime.inspect(running=False) == intent['container_ids']
                 and runtime.container_generation(intent['container_ids'])['generation'] == intent['generation'])
            need(sha(read(new.UNIT)) == intent['new_unit_sha256'])
            history_unchanged(intent)
            exclusive(operation/'enable-intent.json',encoded({'scope':'restore-original-enabled-state-v1'}))
            command(['systemctl','enable','azd-santa-runtime.service']); need(unit_enabled()=='enabled')
            # At this point a boot or the explicit start below can admit only
            # the fully checked new tuple; no incomplete tuple is enabled.
            exclusive(operation / 'start-intent.json', encoded({'scope':'one-normal-start-v1'}))
        command(['systemctl', 'start', 'azd-santa-runtime.service'], timeout=450)
        state = unit_state(); need(state['ActiveState'] == 'active' and state['SubState'] == 'running' and not state['Job'])
        need(runtime.inspect(running=True) == intent['container_ids']
             and runtime.container_generation(intent['container_ids'])['generation'] == intent['generation'])
        no_backup(control)
        history_unchanged(intent)
        need(read(Path('/proc') / state['MainPID'] / 'cmdline',8192).rstrip(b'\0').split(b'\0')[1:] ==
            [str(v).encode() for v in ('-I',Path(intent['candidate'])/'runtime_service.py','run','--manifest',intent['manifest_path'],'--sha256',intent['new_manifest_sha256'])])
        exclusive(operation / 'complete.json', encoded(completion(intent,expected)))
    except BaseException as error:
        exclusive(operation / 'failed.json', encoded({'error_type':type(error).__name__, 'automatic_replay':False}))
        raise


def baseline_fields():
    return ('target','boot_id','old_bundle_sha256','manifest_path','old_manifest_sha256','old_generation_sha256',
            'old_unit_sha256','container_ids','generation','image_id','project','old_main_pid','old_unit_enabled','historical_sha256')


def record_terminal(intent_path, expected):
    raw = read(intent_path); need(sha(raw) == expected and read(ACTIVE) == raw)
    intent = json.loads(raw); operation = Path(intent['operation'])
    need(sha(read(Path(__file__))) == intent['program_sha256'])
    need(Path(intent_path) == operation/'intent.json' and os.environ.get('SERVICE_RESULT') == 'success'
         and os.environ.get('EXIT_CODE') == 'exited' and os.environ.get('EXIT_STATUS') == '0'
         and re.fullmatch(r'[a-f0-9]{32}',os.environ.get('INVOCATION_ID','')))
    complete = read(operation/'complete.json'); need(json.loads(complete) == completion(intent,expected))
    exclusive(operation/'terminal-success.json',encoded(dict(scope='azd-santa-helper-upgrade-terminal-v1',
        intent_sha256=expected,completion_sha256=sha(complete),invocation=os.environ['INVOCATION_ID'])))


def current_binding(intent):
    history_unchanged(intent)
    candidate_matches(intent)
    new = load(Path(intent['candidate']),'runtime_service')
    new.load_manifest(intent['manifest_path'],intent['new_manifest_sha256'])
    effective_unit(new.UNIT)
    need(sha(read(Path(intent['manifest_path']).parent/'container-generation.json')) == intent['new_generation_sha256']
         and sha(read(new.UNIT)) == intent['new_unit_sha256'] and unit_enabled()=='enabled')
    state = unit_state()
    need(state['ActiveState']=='active' and state['SubState']=='running' and not state['Job']
         and re.fullmatch(r'[1-9][0-9]*',state['MainPID']))
    need(read(Path('/proc')/state['MainPID']/'cmdline',8192).rstrip(b'\0').split(b'\0')[1:] ==
        [str(v).encode() for v in ('-I',Path(intent['candidate'])/'runtime_service.py','run','--manifest',intent['manifest_path'],'--sha256',intent['new_manifest_sha256'])])
    rows=json.loads(command(new.DOCKER+['inspect',*intent['container_ids'].values()]))
    need(len(rows)==7 and {r['Id'] for r in rows}==set(intent['container_ids'].values())
         and all(r['State']['Running'] is True and r['State']['Paused'] is False and r['State']['Restarting'] is False for r in rows))
    no_backup(Path(intent['manifest_path']).parent)


def observe(target, bundle_sha):
    if not ACTIVE.exists(): return {'scope':'azd-santa-helper-upgrade-observation-v1','state':'not-requested','new_bundle_sha256':bundle_sha}
    raw = read(ACTIVE); intent = json.loads(raw)
    need(intent['target'] == target and intent['new_bundle_sha256'] == bundle_sha)
    operation = checked(Path(intent['operation']), directory=True); need(read(operation / 'intent.json') == raw)
    unit='azd-santa-helper-upgrade-'+operation.name.removeprefix('operation-')+'.service'
    values=dict(line.split('=',1) for line in command(['systemctl','show',unit,
        '--property=LoadState,ActiveState,SubState,Result,ExecMainStatus,InvocationID']).splitlines() if '=' in line)
    need(values.get('LoadState') in ('loaded','not-found'))
    state = 'unknown'
    if (operation / 'failed.json').exists() or (values['LoadState']=='loaded'
            and (values.get('ActiveState')=='failed' or values.get('Result')!='success')): state = 'failed'
    elif (operation / 'terminal-success.json').exists():
        proof=json.loads(read(operation/'terminal-success.json')); complete=read(operation/'complete.json')
        need(json.loads(complete)==completion(intent,sha(raw)))
        need(proof==dict(scope='azd-santa-helper-upgrade-terminal-v1',intent_sha256=sha(raw),
            completion_sha256=sha(complete),invocation=proof['invocation']) and re.fullmatch(r'[a-f0-9]{32}',proof['invocation']))
        if values['LoadState']=='loaded': need(values.get('Result')=='success' and values.get('ExecMainStatus')=='0'
            and values.get('InvocationID')==proof['invocation'])
        if values['LoadState']=='not-found' or (values.get('ActiveState')=='inactive' and values.get('SubState')=='dead'):
            current_binding(intent); state='completed'
        else: state='in-progress'
    elif values['LoadState']=='loaded' and values.get('ActiveState') in ('activating','active','deactivating'): state='in-progress'
    return dict(scope='azd-santa-helper-upgrade-observation-v1', state=state, new_bundle_sha256=bundle_sha, unit=unit,
        intent_sha256=sha(raw), stop_submitted=(operation / 'stop-intent.json').exists(),
        start_submitted=(operation / 'start-intent.json').exists(),completion=completion(intent,sha(raw)) if state=='completed' else None)


def run(value):
    need(sys.platform == 'linux' and os.geteuid() == 0 and type(value) is dict
         and set(value) <= {'mode','target','bundle_sha256','archive_sha256','count','index','data'})
    mode = value['mode']; need(mode in ('chunk','request','observe')); target = value['target']; bundle = value['bundle_sha256']
    need(type(bundle) is str and re.fullmatch(HEX, bundle))
    if ACTIVE.exists(): return observe(target, bundle)  # Never reserve, stop, start or submit twice.
    history(target)
    if mode == 'observe': return observe(target, bundle)
    UPGRADES.mkdir(mode=0o700, exist_ok=True); checked(UPGRADES, directory=True)
    if mode == 'chunk':
        archive = value['archive_sha256']; index = value['index']; count = value['count']; data = value['data']
        need(re.fullmatch(HEX, archive) and type(index) is int and type(count) is int and 0 <= index < count <= 64
             and type(data) is str and 0 < len(data) <= 24576 and re.fullmatch(r'[A-Za-z0-9+/=]+', data))
        folder = UPGRADES / 'uploads' / bundle / archive
        secure_directories(folder)
        path = folder / str(index)
        if path.exists(): need(read(path) == data.encode())
        else: exclusive(path, data.encode())
        return dict(scope='azd-santa-helper-upgrade-chunk-v1', index=index, new_bundle_sha256=bundle)
    candidate = stage_bundle(target, bundle, value['archive_sha256'], value['count'])
    program = checked(Path(__file__)); intent = reserve(target, candidate, program)
    operation = Path(intent['operation']); intent_sha = sha(read(operation / 'intent.json'))
    # Durable intent exists before this one unknown-outcome submission boundary.
    command(['systemd-run','--no-block','--unit=azd-santa-helper-upgrade-' + operation.name.removeprefix('operation-'),
        '--property=Type=oneshot','--property=Restart=no','--property=TimeoutStartSec=900','--property=RuntimeMaxSec=900',
        '--property=ExecStopPost=/usr/bin/python3 -I '+str(program)+' --record-terminal '+str(operation/'intent.json')+' --sha256 '+intent_sha,
        '--property=UMask=0077','/usr/bin/python3','-I',str(program),'--execute',str(operation / 'intent.json'),'--sha256',intent_sha])
    return observe(target, bundle)


if __name__ == '__main__':
    try:
        need(sys.platform == 'linux' and os.geteuid() == 0 and sys.flags.isolated)
        parser = argparse.ArgumentParser(); parser.add_argument('--execute'); parser.add_argument('--record-terminal'); parser.add_argument('--sha256'); args = parser.parse_args()
        if args.execute: execute(args.execute, args.sha256)
        elif args.record_terminal: record_terminal(args.record_terminal,args.sha256)
        else:
            value = json.loads(base64.b64decode(os.environ['AZD_HELPER_UPGRADE_COMMAND'], validate=True))
            print('SANTA_HELPER_UPGRADE_JSON:' + json.dumps(run(value), separators=(',', ':')))
    except BaseException: raise SystemExit('Helper upgrade outcome requires inspection; do not replay stop/start.') from None
