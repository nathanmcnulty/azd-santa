"""Original Unlicense. Check staged certificate service readiness without starting it."""
import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import urllib.request


HELD_UNIT = 'azd-santa-pilot-https-held.service'
FIREWALL_UNIT = 'azd-santa-https-firewall-443.service'
LINUX_CADDY_SHA256 = 'a563843e11cbce39c557bd429ebb787d56f49d51d9bbb3292cd9b36b37a60cdf'


def require(value, message):
    if not value:
        raise ValueError(message)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def source_bytes(path):
    return Path(path).read_bytes().replace(b'\r\n', b'\n')


def render_request(facts):
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import https_edge as edge
    from prepare_held_https import BINARY_DIR, CONFIG, STATE, UNIT_DIR

    binary = BINARY_DIR / 'caddy'
    script = BINARY_DIR / 'https_edge.py'
    config = edge.held_configuration(facts, STATE, phase='production')
    raw = {
        str(CONFIG): json.dumps(config, sort_keys=True).encode(),
        str(CONFIG.with_name('endpoint.json')): json.dumps(facts, sort_keys=True).encode(),
        str(UNIT_DIR / HELD_UNIT): edge.unit_text(binary, CONFIG, STATE, port=443, runtime_max_seconds=300).encode(),
        str(UNIT_DIR / FIREWALL_UNIT): edge.firewall_unit_text(script, port=443).encode(),
        '/etc/tmpfiles.d/azd-santa-https-lock.conf': edge.lock_tmpfiles_text().encode(),
    }
    for name in ('https_edge.py', 'prepare_https_proxy.py'):
        raw[str(BINARY_DIR / name)] = source_bytes(Path(__file__).with_name(name))
    files = {path: sha256(content) for path, content in raw.items()}
    files[str(binary)] = LINUX_CADDY_SHA256
    return dict(facts=facts, files=files, state=str(STATE), binary=str(binary))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def metadata():
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    request = urllib.request.Request('http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01',
                                     headers={'Metadata': 'true'})
    with opener.open(request, timeout=3) as response:
        raw = response.read(65537)
    require(len(raw) <= 65536, 'Guest metadata exceeded the response bound.')
    return json.loads(raw)


def check_file(path, digest, mode):
    info = path.lstat()
    require(path == path.resolve(strict=True) and stat.S_ISREG(info.st_mode) and info.st_uid == 0
            and stat.S_IMODE(info.st_mode) == mode and 0 < info.st_size <= 80 * 1024**2,
            'A staged HTTPS file is not protected.')
    for parent in path.parents:
        info = parent.lstat()
        require(info.st_uid == 0 and stat.S_ISDIR(info.st_mode) and not info.st_mode & 0o022,
                'A staged HTTPS parent is not protected.')
    if path.suffix == '.py':
        observed = sha256(source_bytes(path))
    else:
        with path.open('rb') as data:
            observed = hashlib.file_digest(data, 'sha256').hexdigest()
    require(observed == digest, 'A staged HTTPS file differs from the deployment source.')


def command(*arguments):
    result = subprocess.run(arguments, check=True, capture_output=True, text=True, timeout=10)
    require(len(result.stdout) <= 8192, 'Guest command exceeded the response bound.')
    return result.stdout.strip()


def unit_properties(unit):
    fields = 'LoadState,ActiveState,UnitFileState,FragmentPath,DropInPaths,NeedDaemonReload,RuntimeMaxUSec,User'
    raw = command('/usr/bin/systemctl', 'show', unit, '--all', '--property=' + fields)
    properties = dict(line.split('=', 1) for line in raw.splitlines())
    require(properties['LoadState'] == 'loaded' and properties['FragmentPath'] == '/etc/systemd/system/' + unit
            and properties['DropInPaths'] == '' and properties['NeedDaemonReload'] == 'no',
            'The loaded HTTPS unit has an unexpected source, override, or pending reload.')
    return properties


def observe(request):
    import pwd

    facts = request['facts']
    identity = metadata()
    require(identity['vmId'].lower() == facts['VmInstanceId'] and identity['resourceId'].lower() == facts['VmId'].lower()
            and identity['subscriptionId'].lower() == facts['SubscriptionId'], 'Guest identity does not match the selected endpoint.')
    for path, digest in request['files'].items():
        check_file(Path(path), digest, 0o755 if path == request['binary'] else 0o644)

    state = Path(request['state'])
    account = pwd.getpwnam('azd-santa-https')
    require(account.pw_uid != 0 and account.pw_gid != 0, 'The HTTPS service account must be unprivileged.')
    for folder in (state, state / 'acme', state / 'logs'):
        info = folder.lstat()
        require(folder == folder.resolve(strict=True) and stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700
                and info.st_uid == account.pw_uid and info.st_gid == account.pw_gid, 'HTTPS state is not private to the service account.')
    held = unit_properties(HELD_UNIT)
    require(held['ActiveState'] == 'inactive' and held['UnitFileState'] == 'disabled' and held['RuntimeMaxUSec'] == '5min'
            and held['User'] == account.pw_name, 'The held unit is not stopped, disabled, and time-bounded.')
    firewall = unit_properties(FIREWALL_UNIT)
    require(firewall['ActiveState'] in ('inactive', 'active') and firewall['UnitFileState'] == 'static',
            'The firewall unit has an unexpected state.')
    require(not os.path.lexists('/etc/systemd/system/azd-santa-pilot-https-application.service'), 'An application HTTPS unit is present.')
    require(not command('/usr/bin/ss', '-Hlt', 'sport = :443'), 'The selected guest already has a TCP443 listener.')
    return dict(scope='santa-held-https-readiness-v1', vm_instance_id=facts['VmInstanceId'], fqdn=facts['Fqdn'],
                binary_sha256=request['files'][request['binary']], held_unit='disabled', tcp443='unbound',
                acme_empty=not any((state / 'acme').iterdir()))


if __name__ == '__main__':
    if len(sys.argv) == 2 and sys.argv[1] == 'render':
        facts = json.load(sys.stdin)
        data = json.dumps(render_request(facts), sort_keys=True).encode()
        token = base64.b64encode(data).decode('ascii')
        source = source_bytes(__file__).decode('utf-8')
        print(f"set -eu\n/usr/bin/python3 -I -B - '{token}' <<'SANTA_HELD_READY'\n{source}\nSANTA_HELD_READY")
    elif len(sys.argv) == 2:
        try:
            request = json.loads(base64.b64decode(sys.argv[1], validate=True))
            print('SANTA_HELD_READY:' + json.dumps(observe(request), separators=(',', ':')))
        except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
            raise SystemExit(str(error)) from None
    else:
        raise SystemExit('Expected readiness render or guest request.')
