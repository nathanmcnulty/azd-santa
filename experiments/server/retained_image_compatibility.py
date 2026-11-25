"""Original Unlicense. Recover only compatibility metadata from an authenticated backup on Linux."""

import argparse
from contextlib import ExitStack
import hashlib
import io
import os
import sys
import time
import uuid

import restore_cipher as cipher
import restore_quarantine as quarantine
from restore_recipient_key import load, private_input

SCOPE = 'azd-santa-authenticated-capture-compatibility-v1'
PREFIX_LIMIT = cipher.CHUNK + 8192


def first_compatibility(prefix, recipient_sha256, deadline):
    source = io.BytesIO(prefix)
    records = quarantine.members(source, maximum=len(prefix), maximum_member=cipher.CHUNK,
                                 maximum_entries=1, deadline=deadline)
    member, chunks = next(records)
    quarantine.need(member['path'] == 'backup/compatibility.json' and not member['directory'])
    raw = b''.join(chunks)
    padding = (-member['size']) % 512
    quarantine.need(source.read(padding) == bytes(padding) and time.monotonic() < deadline)
    capture = quarantine.compatibility(quarantine.document(raw, canonical=True))
    quarantine.need(capture['selection']['recipient_sha256'] == recipient_sha256)
    return raw, capture['selection']['target']['VmInstanceId']


def collect(source, ciphertext_sha256, key, destination, *, maximum=1024**3, seconds=600):
    """Verify the full ciphertext and publish only its first, canonical metadata member."""
    quarantine.need(sys.platform == 'linux' and type(seconds) is int and 1 <= seconds <= 7200
                    and type(maximum) is int and cipher.CHUNK <= maximum <= 32*1024**3)
    deadline = time.monotonic() + seconds
    with ExitStack() as stack:
        output, name = quarantine.private_parent(destination, stack)
        try:
            os.stat(name, dir_fd=output, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise FileExistsError('Compatibility output already exists')
        stream, size, unchanged = private_input(source, stack, maximum)
        auth, prefix = cipher.authenticate_prefix(stream, size, ciphertext_sha256, key,
            prefix_limit=PREFIX_LIMIT, maximum=maximum, seconds=max(1, int(deadline - time.monotonic())))
        unchanged()
        raw, source_instance = first_compatibility(prefix, auth['recipient_sha256'], deadline)
        unchanged()
        pending = '.compatibility-' + uuid.uuid4().hex
        staging = quarantine.Directory(output)
        try:
            staging.file(pending, iter((raw,)))
            os.link(pending, name, src_dir_fd=output, dst_dir_fd=output, follow_symlinks=False)
        finally:
            try:
                os.unlink(pending, dir_fd=output)
            except FileNotFoundError:
                pass
        os.fsync(output)
    return {'scope': SCOPE, 'source_vm_instance_id': source_instance, 'ciphertext_sha256': ciphertext_sha256,
            'compatibility_sha256': hashlib.sha256(raw).hexdigest(), 'compatibility': str(destination),
            'restore_accepted': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('ciphertext', 'ciphertext-sha256', 'recipient-key', 'output'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--encrypted-key-sha256')
    parser.add_argument('--maximum', type=int, default=1024**3)
    parser.add_argument('--seconds', type=int, default=600)
    args = parser.parse_args()
    try:
        quarantine.need(sys.platform == 'linux')
        key = load(args.recipient_key, args.encrypted_key_sha256)
        receipt = collect(args.ciphertext, args.ciphertext_sha256, key, args.output,
                          maximum=args.maximum, seconds=args.seconds)
        print(quarantine.encoded(receipt).decode('ascii'))
    except Exception:
        parser.exit(1, 'Santa capture compatibility verification failed. Preserve the original capture.\n')


if __name__ == '__main__':
    main()
