"""Original Unlicense. Package the TLS-only pilot service without installing it."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import tarfile
import urllib.request

import https_edge as edge


SOURCE = Path(__file__).resolve().parent
BINARY_DIR = PurePosixPath('/opt/azd-santa-https/pilot')
CONFIG = PurePosixPath('/etc/azd-santa-https/pilot/held.json')
STATE = PurePosixPath('/var/lib/azd-santa-https/pilot')
UNIT_DIR = PurePosixPath('/etc/systemd/system')
ARCHIVE_LIMIT = 32 * 1024**2


def release_files(archive, lock):
    if len(archive) > ARCHIVE_LIMIT or hashlib.sha256(archive).hexdigest() != lock['archiveSha256']:
        raise ValueError('Caddy release archive does not match the pinned Linux AMD64 release.')

    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as release:
        members = release.getmembers()
        limits = {'caddy': 80 * 1024**2, 'LICENSE': 64 * 1024, 'README.md': 64 * 1024}
        if len(members) != len(limits) or {entry.name for entry in members} != set(limits):
            raise ValueError('Unexpected files in the pinned Caddy release.')
        files = {}
        for entry in members:
            if not entry.isfile() or not 0 < entry.size <= limits[entry.name]:
                raise ValueError('Invalid file in the pinned Caddy release.')
            with release.extractfile(entry) as stream:
                files[entry.name] = stream.read()
    return files


def package_files(facts, archive, lock_bytes):
    config = edge.held_configuration(facts, STATE, phase='production')
    release = release_files(archive, json.loads(lock_bytes)['linuxAmd64'])
    return {
        BINARY_DIR / 'caddy': (release['caddy'], 0o755),
        BINARY_DIR / 'LICENSE': (release['LICENSE'], 0o644),
        BINARY_DIR / 'README.md': (release['README.md'], 0o644),
        BINARY_DIR / 'https_edge.py': ((SOURCE / 'https_edge.py').read_bytes(), 0o644),
        BINARY_DIR / 'prepare_https_proxy.py': ((SOURCE / 'prepare_https_proxy.py').read_bytes(), 0o644),
        BINARY_DIR / 'caddy.lock.json': (lock_bytes, 0o644),
        CONFIG: (json.dumps(config, sort_keys=True).encode(), 0o644),
        CONFIG.with_name('endpoint.json'): (json.dumps(facts, sort_keys=True).encode(), 0o644),
        UNIT_DIR / 'azd-santa-pilot-https-held.service': (edge.unit_text(
            BINARY_DIR / 'caddy', CONFIG, STATE, port=443, runtime_max_seconds=300).encode(), 0o644),
        UNIT_DIR / 'azd-santa-https-firewall-443.service': (
            edge.firewall_unit_text(BINARY_DIR / 'https_edge.py', port=443).encode(), 0o644),
        PurePosixPath('/etc/tmpfiles.d/azd-santa-https-lock.conf'): (edge.lock_tmpfiles_text().encode(), 0o644),
    }


def prepare(facts, release_path, package_path):
    with Path(release_path).open('rb') as stream:
        archive = stream.read(ARCHIVE_LIMIT + 1)
    files = package_files(facts, archive, edge.candidate.LOCK.read_bytes())
    # Package only root-owned regular files. The guest installer must separately
    # create the service user and its private ACME state on the selected VM.
    with tarfile.open(package_path, 'x:', format=tarfile.USTAR_FORMAT) as package:
        for path, (data, mode) in files.items():
            entry = tarfile.TarInfo(path.as_posix().lstrip('/'))
            entry.size = len(data)
            entry.mode = mode
            package.addfile(entry, io.BytesIO(data))


def secure_guest_parent(path):
    for directory in (path, *path.parents):
        info = directory.lstat()
        if info.st_uid != 0 or not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022:
            raise ValueError('HTTPS package parent is not a protected root directory.')


def stage_on_guest(facts, run):
    """Fresh verified guest only. Install files, with no systemd activation."""
    import pwd

    lock_bytes = edge.candidate.LOCK.read_bytes()
    lock = json.loads(lock_bytes)['linuxAmd64']
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(lock['archiveUrl'], timeout=30) as response:
        archive = response.read(ARCHIVE_LIMIT + 1)
    files = package_files(facts, archive, lock_bytes)
    del archive

    folders = [Path(folder) for folder in (BINARY_DIR, CONFIG.parent, STATE)]
    for folder in folders:
        secure_guest_parent(folder.parent.parent)
        if os.path.lexists(folder.parent):
            raise FileExistsError(folder.parent)
    for path in files:
        if os.path.lexists(path):
            raise FileExistsError(path)
        if path.parent not in (BINARY_DIR, CONFIG.parent):
            secure_guest_parent(Path(path.parent))
    if run('https-port-before', ['/usr/bin/ss', '-Hlt', 'sport = :443']).strip():
        raise ValueError('TCP443 already has a listener on the selected VM.')

    # --user-group reserves a fresh account and group. Do not adopt either.
    run('https-account', ['/usr/sbin/useradd', '--system', '--user-group', '--no-create-home',
                          '--shell', '/usr/sbin/nologin', 'azd-santa-https'])
    user = pwd.getpwnam('azd-santa-https')
    for folder in folders:
        folder.parent.mkdir(mode=0o755)
        folder.parent.chmod(0o755)
        folder.mkdir(mode=0o700 if folder == STATE else 0o755)
        if folder != STATE:
            folder.chmod(0o755)
    for name in ('acme', 'logs'):
        directory = Path(STATE) / name
        directory.mkdir(mode=0o700)
        os.chown(directory, user.pw_uid, user.pw_gid)
    os.chown(STATE, user.pw_uid, user.pw_gid)

    for path, (content, mode) in files.items():
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        with os.fdopen(os.open(path, flags, mode), 'wb') as output:
            os.fchmod(output.fileno(), mode)
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
    if run('https-port-after', ['/usr/bin/ss', '-Hlt', 'sport = :443']).strip():
        raise ValueError('TCP443 gained a listener during HTTPS staging.')
    return dict(scope='santa-held-https-staged', endpoint=facts,
                release_sha256=lock['archiveSha256'], listener='unbound')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--facts', type=Path, required=True, help='Selected ARM endpoint facts JSON')
    parser.add_argument('--release', type=Path, required=True, help='Pinned Caddy Linux AMD64 release archive')
    parser.add_argument('--output', type=Path, required=True, help='New package tar path')
    args = parser.parse_args()
    try:
        prepare(json.loads(args.facts.read_bytes()), args.release, args.output)
    except (OSError, ValueError, tarfile.TarError) as error:
        parser.exit(1, f'HTTPS package preparation failed: {error}\n')
