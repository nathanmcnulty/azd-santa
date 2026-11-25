"""Original Unlicense. Retain and verify the reviewed Santa recovery source set."""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time

SERVER = 'experiments/server/'
PATHS = tuple(sorted(('LICENSE', 'THIRD_PARTY_NOTICES.md', 'third_party/santa-2026.8/LICENSE.txt',
    'docs/restore-census.md', 'docs/offhost-ciphertext-retention.md', *(
        SERVER + name for name in (
            'cold_backup.py', 'native_snapshot.py', 'restore_cipher.py', 'restore_quarantine.py',
            'restore_census.py', 'secret_rewrap.py', 'retention_image_inventory.py', 'retained_image_archive.py',
            'retained_image_export.py', 'retained_image_readback.py', 'retained_image_parts.py', 'dependency-images.lock.json',
            'zentral-source.lock.json', 'secret-rewrap-source.lock.json', 'restore_tooling_bundle.py')))))
SCOPE = 'azd-santa-restore-tooling-bundle-v1'
MAX_FILE = 256 * 1024
MAX_BUNDLE = 2 * 1024**2
COMMIT = r'[0-9a-f]{40}'


class ToolingRejected(ValueError):
    pass


def need(condition):
    if not condition:
        raise ToolingRejected('Santa restore tooling bundle rejected')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encoded(data):
    return json.dumps(data, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def unique(pairs):
    result = dict(pairs)
    need(len(result) == len(pairs))
    return result


def build(repo, commit):
    """Read exact blobs from a caller-selected, reviewed Git commit, without filters."""
    try:
        need(type(commit) is str and re.fullmatch(COMMIT, commit))
        deadline = time.monotonic() + 30
        env = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
        env['GIT_NO_LAZY_FETCH'] = '1'

        def git(*args):
            remaining = deadline - time.monotonic()
            need(remaining > 0)
            return subprocess.run(['git', '--no-replace-objects', '-C', str(repo), *args], env=env,
                                  stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                  timeout=remaining, check=True).stdout

        need(git('cat-file', '-t', commit).strip() == b'commit')
        records = {}
        for entry in git('ls-tree', '-r', '-l', '-z', commit, '--', *PATHS).split(b'\0')[:-1]:
            fields, path = entry.split(b'\t', 1)
            mode, kind, object_id, size = fields.decode('ascii').split()
            name = path.decode('ascii')
            need(name in PATHS and name not in records and mode in ('100644', '100755') and kind == 'blob'
                 and re.fullmatch(COMMIT, object_id) and 0 < int(size) <= MAX_FILE)
            records[name] = (object_id, int(size))
        need(set(records) == set(PATHS) and sum(size for _, size in records.values()) <= MAX_BUNDLE // 2)

        files = {}
        for name, (object_id, size) in records.items():
            body = git('cat-file', 'blob', object_id)
            header = f'blob {size}\0'.encode('ascii')
            need(len(body) == size and hashlib.sha1(header + body).hexdigest() == object_id)
            files[name] = {'sha256': sha(body), 'base64': base64.b64encode(body).decode('ascii')}
        raw = encoded({'scope': SCOPE, 'commit': commit, 'files': files})
        need(len(raw) <= MAX_BUNDLE)
        return raw
    except (TypeError, ValueError, OSError, RecursionError, subprocess.SubprocessError):
        raise ToolingRejected('Santa restore tooling bundle rejected') from None


def verify(raw, *, commit, bundle_sha256):
    """Return the inert file bytes only after all trusted pins and entries match."""
    try:
        need(type(raw) is bytes and 0 < len(raw) <= MAX_BUNDLE and sha(raw) == bundle_sha256
             and type(commit) is str and re.fullmatch(COMMIT, commit))
        bundle = json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: need(False))
        need(type(bundle) is dict and set(bundle) == {'scope', 'commit', 'files'}
             and bundle['scope'] == SCOPE and bundle['commit'] == commit and encoded(bundle) == raw)
        files = bundle['files']
        need(type(files) is dict and set(files) == set(PATHS))
        decoded = {}
        for path, data in files.items():
            need(type(data) is dict and set(data) == {'base64', 'sha256'} and type(data['base64']) is str)
            body = base64.b64decode(data['base64'], validate=True)
            need(0 < len(body) <= MAX_FILE and sha(body) == data['sha256']
                 and base64.b64encode(body).decode('ascii') == data['base64'])
            decoded[path] = body
        need(sum(map(len, decoded.values())) <= MAX_BUNDLE // 2)
        return decoded
    except (ValueError, KeyError, TypeError, RecursionError):
        raise ToolingRejected('Santa restore tooling bundle rejected') from None


def stage(raw, destination, *, commit, bundle_sha256):
    """Write inert source into a new operator-owned destination, never run it."""
    files = verify(raw, commit=commit, bundle_sha256=bundle_sha256)
    root = Path(destination)
    root.mkdir(mode=0o700)
    for name, body in files.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as output:
            output.write(body)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    create = sub.add_parser('build')
    create.add_argument('repo')
    create.add_argument('commit')
    create.add_argument('bundle', type=Path)
    for name in ('verify', 'stage'):
        command = sub.add_parser(name)
        command.add_argument('bundle', type=Path)
        command.add_argument('commit')
        command.add_argument('bundle_sha256')
        if name == 'stage':
            command.add_argument('destination', type=Path)
    args = parser.parse_args()
    try:
        if args.action == 'build':
            raw = build(args.repo, args.commit)
            with args.bundle.open('xb') as output:
                output.write(raw)
        else:
            with args.bundle.open('rb') as source:
                raw = source.read(MAX_BUNDLE + 1)
            pins = {'commit': args.commit, 'bundle_sha256': args.bundle_sha256}
            if args.action == 'stage':
                stage(raw, args.destination, **pins)
            else:
                verify(raw, **pins)
        print(encoded({'scope': SCOPE, 'commit': args.commit, 'bundle_sha256': sha(raw),
                       'files': len(PATHS), 'bytes': len(raw)}).decode('ascii'))
    except (OSError, ToolingRejected):
        parser.exit(1, 'Santa restore tooling operation failed; preserve any existing output\n')


if __name__ == '__main__':
    main()
