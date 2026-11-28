"""Authenticate a local Santa backup with an independently pinned portable recovery key."""

import argparse
import os
import re
import sys

import restore_cipher
import restore_recipient_key
from restore_quarantine import encoded


def digest(value):
    if re.fullmatch(r'[a-f0-9]{64}', value) is None:
        raise argparse.ArgumentTypeError('expected a lowercase SHA-256 digest')
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--backup', required=True, help='absolute path to the retained ciphertext')
    parser.add_argument('--backup-sha256', required=True, type=digest)
    parser.add_argument('--portable-key', required=True, help='absolute path to the encrypted recovery key')
    parser.add_argument('--portable-key-sha256', required=True, type=digest)
    args = parser.parse_args(argv)
    if sys.platform != 'linux' or os.geteuid() != 0:
        parser.exit(1, 'Run Santa backup verification as root on the private Linux recovery host.\n')
    try:
        key = restore_recipient_key.load(args.portable_key, args.portable_key_sha256)
        report = restore_cipher.verify_file(args.backup, args.backup_sha256, key)
    except Exception:
        parser.exit(1, 'Santa backup authentication failed. Check the retained archive, digests, and recovery key.\n')
    print(encoded(report).decode('ascii'))


if __name__ == '__main__':
    main()
