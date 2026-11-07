"""Original Unlicense bounded source relay and same-job observation only."""
import base64
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path('/var/lib/azd-santa-qualification')
ACTIVE = ROOT / 'private-azd-install.json'
FILES = {'private_install.py', 'private_install_transport.py', 'bootstrap-host.sh', 'prepare_source.py',
    'prepare_core_build.py', 'prepare_operator_mfa.py', 'operator_mfa.py', 'prepare_operator_recovery.py',
    'operator_recovery.py', 'sealed_setup.py', 'prepare_request_limits.py', 'santa_request_limits.py',
    'prepare_database_roles.py', 'database_roles.py', 'prepare_zentral_eval.py', 'stage_runtime.py',
    'runtime_service.py', 'test_live_zentral.py', 'zentral-source.lock.json', 'dependency-images.lock.json'}


def need(value):
    if not value: raise ValueError('Private installer transport boundary failed')


def exclusive(path, raw, mode=0o600):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(descriptor, 'wb') as output:
        output.write(raw); output.flush(); os.fsync(output.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)


def secure(path):
    need(path == path.resolve(strict=True))
    for item in (path, *path.parents):
        info = item.stat(); need(info.st_uid == 0 and not info.st_mode & 0o022)


def command(args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=30)
    need(result.returncode == 0)
    return result.stdout


def status(bundle_sha):
    need(ACTIVE.exists())
    secure(ACTIVE); active = json.loads(ACTIVE.read_bytes())
    need(active['bundle_sha256'] == bundle_sha)
    unit = 'azd-santa-install-' + bundle_sha[:16] + '.service'
    values = dict(line.split('=', 1) for line in command(['systemctl', 'show', unit,
        '--property=LoadState,ActiveState,SubState,Result,ExecMainStatus,InvocationID']).splitlines() if '=' in line)
    need(values.get('LoadState') == 'loaded')  # Unknown submit never launches again.
    directory = ROOT / 'installers' / bundle_sha
    complete = directory / 'complete.json'
    result = dict(scope='private-azd-install-observation', bundle_sha256=bundle_sha, unit=unit,
                  state=values['ActiveState'], substate=values['SubState'], result=values.get('Result'),
                  invocation=values.get('InvocationID'), completion=None)
    if complete.exists():
        secure(complete)
        need(values['SubState'] == 'exited' and values['ExecMainStatus'] == '0' and values['Result'] == 'success')
        command(['systemctl', 'is-active', 'azd-santa-runtime.service'])
        result['completion'] = json.loads(complete.read_bytes())
    return result


def run(value):
    need(os.geteuid() == 0 and set(value) <= {'mode', 'bundle_sha256', 'archive_sha256', 'index', 'count', 'data', 'target'})
    os.umask(0o077)
    digest = value['bundle_sha256']; need(re.fullmatch('[a-f0-9]{64}', digest))
    ROOT.mkdir(mode=0o700, exist_ok=True); secure(ROOT)
    mode = value['mode']; need(mode in ('chunk', 'submit', 'observe'))
    if ACTIVE.exists():
        secure(ACTIVE); old = json.loads(ACTIVE.read_bytes())
        need(old['bundle_sha256'] == digest)
        if mode == 'submit':
            need(old['target'] == value['target']); return status(digest)
        if mode == 'observe': return status(digest)
    else:
        need(not Path('/etc/systemd/system/azd-santa-runtime.service').exists())
        if mode == 'observe':
            return dict(scope='private-azd-install-observation', bundle_sha256=digest, state='not-installed', substate='absent', completion=None)
    uploads = ROOT / 'install-uploads'; uploads.mkdir(mode=0o700, exist_ok=True); secure(uploads)
    source_folder = uploads / digest; source_folder.mkdir(mode=0o700, exist_ok=True); secure(source_folder)
    archive = value['archive_sha256']; need(re.fullmatch('[a-f0-9]{64}', archive))
    folder = source_folder / archive; folder.mkdir(mode=0o700, exist_ok=True); secure(folder)
    if mode == 'chunk':
        index, count, data = value['index'], value['count'], value['data']
        need(type(index) is int and type(count) is int and 0 <= index < count <= 64
             and type(data) is str and 0 < len(data) <= 24576 and re.fullmatch('[A-Za-z0-9+/=]+', data))
        path = folder / ('chunk-' + str(index))
        if path.exists(): secure(path); need(path.read_text() == data)
        else: exclusive(path, data.encode('ascii'))
        return dict(scope='private-azd-install-chunk', bundle_sha256=digest, index=index, count=count)
    count = value['count']; need(type(count) is int and 1 <= count <= 64)
    joined = ''.join((folder / ('chunk-' + str(i))).read_text() for i in range(count))
    compressed = base64.b64decode(joined, validate=True)
    need(len(compressed) <= 1024 * 1024 and hashlib.sha256(compressed).hexdigest() == archive)
    import io
    with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as stream: raw = stream.read(2 * 1024 * 1024 + 1)
    need(len(raw) <= 2 * 1024 * 1024 and hashlib.sha256(raw).hexdigest() == digest)
    package = json.loads(raw); need(set(package) == {'scope', 'files'} and package['scope'] == 'private-azd-source-v1' and set(package['files']) == FILES)
    base = ROOT / 'installers'; base.mkdir(mode=0o700, exist_ok=True); secure(base)
    selected = base / digest
    if not selected.exists():
        selected.mkdir(mode=0o700)
        exclusive(selected / 'bundle.json', raw)
    secure(selected)
    need((selected / 'bundle.json').read_bytes() == raw)
    for name, metadata in package['files'].items():
        need(set(metadata) == {'sha256', 'base64'})
        body = base64.b64decode(metadata['base64'], validate=True)
        need(len(body) <= 256 * 1024 and hashlib.sha256(body).hexdigest() == metadata['sha256'])
        if (selected / name).exists(): secure(selected / name); need((selected / name).read_bytes() == body)
        else: exclusive(selected / name, body, 0o644)
    # Fresh-host admission: no existing runtime/data is repurposed or stopped.
    if Path('/var/lib/docker/volumes').exists():
        need(not command(['docker', '--host', 'unix:///var/run/docker.sock', 'ps', '--all', '--quiet']).strip())
        need(not command(['docker', '--host', 'unix:///var/run/docker.sock', 'volume', 'ls', '--quiet']).strip())
    context = dict(scope='private-azd-install-v1', bundle_sha256=digest, target=value['target'])
    context_raw = json.dumps(context, sort_keys=True).encode()
    exclusive(selected / 'context.json', context_raw)
    # Cross-process exclusive durable reservation precedes systemd submission.
    exclusive(ACTIVE, context_raw)
    unit = 'azd-santa-install-' + digest[:16]
    command(['systemd-run', '--no-block', '--unit=' + unit, '--property=Type=oneshot', '--property=RemainAfterExit=yes',
             '--property=Restart=no', '--property=RuntimeMaxSec=6300', '--property=TimeoutStartSec=6300',
             '--property=UMask=0077', '/usr/bin/python3', '-I', str(selected / 'private_install.py'),
             '--context', str(selected / 'context.json'), '--sha256', hashlib.sha256(context_raw).hexdigest()])
    return status(digest)


if __name__ == '__main__':
    try:
        value = json.loads(base64.b64decode(os.environ['AZD_PRIVATE_INSTALL_COMMAND'], validate=True))
        print('SANTA_PRIVATE_INSTALL_JSON:' + json.dumps(run(value), separators=(',', ':')))
    except BaseException:
        raise SystemExit('Private install state requires inspection; same job and data retained. Do not replay initialization.') from None
