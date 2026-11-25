"""Acquire the exact Zentral source archive for private nonproduction evaluation.

This never starts a server, publishes an image or touches a device. Dependency
build reproducibility and production licensing are separate qualification gates.
"""
import argparse
import hashlib
import json
import tarfile
import urllib.request
from pathlib import Path

COMMIT = '88e67b3ce49033aab028029937a6e14f7c489073'
ARCHIVE_SHA256 = 'e8379103ccbda8e900e6215cd87125c61817473d4a483eacb1c63f463f927c9f'
URL = 'https://codeload.github.com/zentralopensource/zentral/tar.gz/' + COMMIT


def verify_archive(path):
    with Path(path).open('rb') as source:
        digest = hashlib.file_digest(source, 'sha256').hexdigest()
    if digest != ARCHIVE_SHA256:
        raise ValueError('source archive digest mismatch')


def prepare(destination):
    destination = Path(destination).resolve()
    destination.mkdir(mode=0o700)  # never overwrite or silently resume partial state
    archive = destination / 'source.tar.gz'
    with urllib.request.urlopen(URL, timeout=120) as response, archive.open('xb') as output:
        count = 0
        while chunk := response.read(1024 * 1024):
            count += len(chunk)
            if count > 50 * 1024 * 1024:
                raise ValueError('source archive exceeds qualification bound')
            output.write(chunk)
    verify_archive(archive)
    with tarfile.open(archive, 'r:gz') as bundle:
        members = bundle.getmembers()
        if len(members) > 100000 or sum(item.size for item in members) > 512 * 1024 * 1024:
            raise ValueError('expanded source exceeds qualification bound')
        prefix = 'zentral-' + COMMIT
        if any(Path(item.name).parts[0] != prefix for item in members):
            raise ValueError('unexpected source tree root')
        bundle.extractall(destination, filter='data')
    source = destination / prefix
    # The data filter ignores directory modes. Umask 077 would otherwise make
    # copied source directories inaccessible to the image's non-root user.
    # Keep the acquisition parent private; normalize only verified source dirs.
    source.chmod(0o755)
    for directory in source.rglob('*'):
        if directory.is_dir() and not directory.is_symlink():
            directory.chmod(0o755)
    receipt = dict(commit=COMMIT, archive_sha256=ARCHIVE_SHA256,
                   source=str(source), purpose='private-synthetic-evaluation-only')
    with (destination / 'acquisition.json').open('x') as output:
        json.dump(receipt, output, indent=2)
    return receipt


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('destination')
    arguments = parser.parse_args()
    print(json.dumps(prepare(arguments.destination)))
