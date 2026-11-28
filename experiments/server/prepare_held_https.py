"""Original Unlicense. Package the TLS-only pilot service without installing it."""
import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import tarfile

import https_edge as edge


SOURCE = Path(__file__).resolve().parent
BINARY_DIR = PurePosixPath('/opt/azd-santa-https/pilot')
CONFIG = PurePosixPath('/etc/azd-santa-https/pilot/held.json')
STATE = PurePosixPath('/var/lib/azd-santa-https/pilot')
UNIT_DIR = PurePosixPath('/etc/systemd/system')
ARCHIVE_LIMIT = 32 * 1024**2


def release_files(archive_path):
    lock = json.loads(edge.candidate.LOCK.read_bytes())['linuxAmd64']
    with Path(archive_path).open('rb') as stream:
        archive = stream.read(ARCHIVE_LIMIT + 1)
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


def prepare(facts, release_path, package_path):
    config = edge.held_configuration(facts, STATE, phase='production')
    release = release_files(release_path)
    files = {
        BINARY_DIR / 'caddy': (release['caddy'], 0o755),
        BINARY_DIR / 'LICENSE': (release['LICENSE'], 0o644),
        BINARY_DIR / 'README.md': (release['README.md'], 0o644),
        BINARY_DIR / 'https_edge.py': ((SOURCE / 'https_edge.py').read_bytes(), 0o644),
        BINARY_DIR / 'prepare_https_proxy.py': ((SOURCE / 'prepare_https_proxy.py').read_bytes(), 0o644),
        BINARY_DIR / 'caddy.lock.json': (edge.candidate.LOCK.read_bytes(), 0o644),
        CONFIG: (json.dumps(config, sort_keys=True).encode(), 0o644),
        CONFIG.with_name('endpoint.json'): (json.dumps(facts, sort_keys=True).encode(), 0o644),
        UNIT_DIR / 'azd-santa-pilot-https-held.service': (edge.unit_text(
            BINARY_DIR / 'caddy', CONFIG, STATE, port=443, runtime_max_seconds=300).encode(), 0o644),
        UNIT_DIR / 'azd-santa-https-firewall-443.service': (
            edge.firewall_unit_text(BINARY_DIR / 'https_edge.py', port=443).encode(), 0o644),
        PurePosixPath('/etc/tmpfiles.d/azd-santa-https-lock.conf'): (edge.lock_tmpfiles_text().encode(), 0o644),
    }
    # Package only root-owned regular files. The guest installer must separately
    # create the service user and its private ACME state on the selected VM.
    with tarfile.open(package_path, 'x:', format=tarfile.USTAR_FORMAT) as package:
        for path, (data, mode) in files.items():
            entry = tarfile.TarInfo(path.as_posix().lstrip('/'))
            entry.size = len(data)
            entry.mode = mode
            package.addfile(entry, io.BytesIO(data))


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
