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
            'cold_backup.py', 'native_snapshot.py', 'restore_cipher.py', 'restore_quarantine.py', 'restore_recipient_key.py',
            'restore_census.py', 'secret_rewrap.py', 'retention_image_inventory.py',
            'retained_image_inventory_command.py', 'retained_image_compatibility.py', 'retained_image_archive.py',
            'retained_image_export.py', 'retained_image_export_job.py', 'retained_image_export_command.py',
            'retained_image_readback.py', 'retained_image_load.py',
            'retained_image_parts.py',
            'retained_image_blob.py', 'blob_retention.py', 'native_retention_verifier.py',
            'native_retention_verify_command.py', 'native_retention_upload_command.py',
            'native_retention_upload_guest.py', 'native_capture_record_command.py', 'blob_capability_relay.py',
            'retained_image_sas.py', 'retained_image_handoff.py',
            'retained_image_delivery.py', 'retained_image_run_command.py', 'retained_image_runner.py',
            'retained_image_operator.py',
            'private_arm_adapter.py', 'backup_store_selection.py', 'dependency-images.lock.json',
            'zentral-source.lock.json', 'secret-rewrap-source.lock.json', 'restore_tooling_bundle.py')))))
SCOPE = 'azd-santa-restore-tooling-bundle-v1'
AUTHORITY_SCOPE = 'azd-santa-restore-tooling-bundle-v2'
AUTHORITY_PATHS = tuple(sorted((*PATHS, 'docs/restore-quarantine-design.md',
                               SERVER + 'Export-SantaRecoveryRecipient.ps1',
                               SERVER + 'restore_authority_plan.py',
                               SERVER + 'restore_authority_transaction.py')))
REWRAP_SCOPE = 'azd-santa-restore-tooling-bundle-v3'
REWRAP_PATHS = tuple(sorted((*AUTHORITY_PATHS, 'docs/offline-secret-rewrap.md',
                            SERVER + 'restore_secret_transaction.py')))
JOURNAL_SCOPE = 'azd-santa-restore-tooling-bundle-v4'
JOURNAL_PATHS = tuple(sorted((*REWRAP_PATHS, SERVER + 'restore_quarantine_journal.py')))
REVIEW_SCOPE = 'azd-santa-restore-tooling-bundle-v5'
REVIEW_PATHS = tuple(sorted((*JOURNAL_PATHS, SERVER + 'restore_census_review.py')))
ARM_SCOPE = 'azd-santa-restore-tooling-bundle-v6'
ARM_PATHS = tuple(sorted((*REVIEW_PATHS, SERVER + 'restore_arm_authorization.py')))
GUEST_SCOPE = 'azd-santa-restore-tooling-bundle-v7'
GUEST_PATHS = tuple(sorted((*ARM_PATHS, SERVER + 'restore_guest_readback.py')))
JOB_SCOPE = 'azd-santa-restore-tooling-bundle-v8'
JOB_PATHS = tuple(sorted((*GUEST_PATHS, SERVER + 'restore_guest_job.py')))
INPUT_SCOPE = 'azd-santa-restore-tooling-bundle-v9'
INPUT_PATHS = tuple(sorted((*JOB_PATHS, SERVER + 'restore_sealed_inputs.py')))
BLOB_SCOPE = 'azd-santa-restore-tooling-bundle-v10'
BLOB_PATHS = tuple(sorted((*INPUT_PATHS, SERVER + 'restore_input_blob.py')))
SAS_SCOPE = 'azd-santa-restore-tooling-bundle-v11'
SAS_PATHS = tuple(sorted((*BLOB_PATHS, SERVER + 'restore_input_sas.py')))
HANDOFF_SCOPE = 'azd-santa-restore-tooling-bundle-v12'
HANDOFF_PATHS = tuple(sorted((*SAS_PATHS, SERVER + 'restore_input_handoff.py')))
CARRIER_SCOPE = 'azd-santa-restore-tooling-bundle-v13'
CARRIER_PATHS = tuple(sorted((*HANDOFF_PATHS, SERVER + 'restore_carrier_command.py')))
PACKET_STAGING_SCOPE = 'azd-santa-restore-tooling-bundle-v14'
PACKET_OPERATOR_SCOPE = 'azd-santa-restore-tooling-bundle-v15'
PACKET_OPERATOR_PATHS = tuple(sorted((*CARRIER_PATHS, SERVER + 'restore_packet_operator.py')))
RECEIVED_PACKET_SCOPE = 'azd-santa-restore-tooling-bundle-v16'
APPROVAL_SCOPE = 'azd-santa-restore-tooling-bundle-v17'
APPROVAL_PATHS = tuple(sorted((*PACKET_OPERATOR_PATHS, SERVER + 'restore_operator_approval.py')))
BOOT_RECIPIENT_SCOPE = 'azd-santa-restore-tooling-bundle-v18'
DATABASE_COMMAND_SCOPE = 'azd-santa-restore-tooling-bundle-v19'
DATABASE_COMMAND_PATHS = tuple(sorted((*APPROVAL_PATHS, SERVER + 'restore_database_command.py')))
PACKET_STAGING_SCOPES = (PACKET_STAGING_SCOPE, PACKET_OPERATOR_SCOPE, RECEIVED_PACKET_SCOPE, APPROVAL_SCOPE,
                         BOOT_RECIPIENT_SCOPE, DATABASE_COMMAND_SCOPE)
INVENTORIES = {SCOPE: PATHS, AUTHORITY_SCOPE: AUTHORITY_PATHS, REWRAP_SCOPE: REWRAP_PATHS,
               JOURNAL_SCOPE: JOURNAL_PATHS, REVIEW_SCOPE: REVIEW_PATHS, ARM_SCOPE: ARM_PATHS,
               GUEST_SCOPE: GUEST_PATHS, JOB_SCOPE: JOB_PATHS, INPUT_SCOPE: INPUT_PATHS,
               BLOB_SCOPE: BLOB_PATHS, SAS_SCOPE: SAS_PATHS, HANDOFF_SCOPE: HANDOFF_PATHS, CARRIER_SCOPE: CARRIER_PATHS,
               PACKET_STAGING_SCOPE: CARRIER_PATHS, PACKET_OPERATOR_SCOPE: PACKET_OPERATOR_PATHS,
               RECEIVED_PACKET_SCOPE: PACKET_OPERATOR_PATHS, APPROVAL_SCOPE: APPROVAL_PATHS,
               BOOT_RECIPIENT_SCOPE: APPROVAL_PATHS, DATABASE_COMMAND_SCOPE: DATABASE_COMMAND_PATHS}
VERSIONS = {1: SCOPE, 2: AUTHORITY_SCOPE, 3: REWRAP_SCOPE, 4: JOURNAL_SCOPE, 5: REVIEW_SCOPE, 6: ARM_SCOPE,
            7: GUEST_SCOPE, 8: JOB_SCOPE, 9: INPUT_SCOPE, 10: BLOB_SCOPE, 11: SAS_SCOPE, 12: HANDOFF_SCOPE,
            13: CARRIER_SCOPE, 14: PACKET_STAGING_SCOPE, 15: PACKET_OPERATOR_SCOPE, 16: RECEIVED_PACKET_SCOPE,
            17: APPROVAL_SCOPE, 18: BOOT_RECIPIENT_SCOPE, 19: DATABASE_COMMAND_SCOPE}
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


def build(repo, commit, *, version=1):
    """Read exact blobs from a caller-selected, reviewed Git commit, without filters."""
    try:
        need(type(commit) is str and re.fullmatch(COMMIT, commit))
        need(type(version) is int and version in VERSIONS)
        scope = VERSIONS[version]
        paths = INVENTORIES[scope]
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
        for entry in git('ls-tree', '-r', '-l', '-z', commit, '--', *paths).split(b'\0')[:-1]:
            fields, path = entry.split(b'\t', 1)
            mode, kind, object_id, size = fields.decode('ascii').split()
            name = path.decode('ascii')
            need(name in paths and name not in records and mode in ('100644', '100755') and kind == 'blob'
                 and re.fullmatch(COMMIT, object_id) and 0 < int(size) <= MAX_FILE)
            records[name] = (object_id, int(size))
        need(set(records) == set(paths) and sum(size for _, size in records.values()) <= MAX_BUNDLE // 2)

        files = {}
        for name, (object_id, size) in records.items():
            body = git('cat-file', 'blob', object_id)
            header = f'blob {size}\0'.encode('ascii')
            need(len(body) == size and hashlib.sha1(header + body).hexdigest() == object_id)
            files[name] = {'sha256': sha(body), 'base64': base64.b64encode(body).decode('ascii')}
        raw = encoded({'scope': scope, 'commit': commit, 'files': files})
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
             and type(bundle['scope']) is str and bundle['scope'] in INVENTORIES
             and bundle['commit'] == commit and encoded(bundle) == raw)
        files = bundle['files']
        need(type(files) is dict and set(files) == set(INVENTORIES[bundle['scope']]))
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
    create.add_argument('--version', type=int, choices=VERSIONS, default=1)
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
            raw = build(args.repo, args.commit, version=args.version)
            scope = VERSIONS[args.version]
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
            scope = json.loads(raw)['scope']
        print(encoded({'scope': scope, 'commit': args.commit, 'bundle_sha256': sha(raw),
                       'files': len(INVENTORIES[scope]), 'bytes': len(raw)}).decode('ascii'))
    except (OSError, ToolingRejected):
        parser.exit(1, 'Santa restore tooling operation failed; preserve any existing output\n')


if __name__ == '__main__':
    main()
