"""Original Unlicense. Pack and unlock a portable encrypted Santa recovery key on Linux."""

import argparse
from contextlib import ExitStack
import getpass
import hashlib
import os
import re
import stat
import subprocess
import sys
import warnings

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import restore_cipher as cipher
import restore_quarantine as quarantine

KEY_LIMIT = 8192


def private_input(path, stack, maximum):
    parent, name = quarantine.private_parent(path, stack)
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    stream = stack.enter_context(os.fdopen(fd, 'rb'))
    before = os.fstat(fd)
    quarantine.need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
                    and before.st_nlink == 1 and not before.st_mode & 0o077 and 0 < before.st_size <= maximum)

    def unchanged():
        quarantine.need(cipher.identity(before) == cipher.identity(os.fstat(fd))
                        == cipher.identity(os.stat(name, dir_fd=parent, follow_symlinks=False)))

    return stream, before.st_size, unchanged


def fingerprint(key):
    quarantine.need(isinstance(key, rsa.RSAPrivateKey) and key.key_size == 3072
                    and key.public_key().public_numbers().e == 65537)
    public = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(public).hexdigest()


def passphrase(prompt):
    # Refuse a fallback that could echo the passphrase or read redirected input.
    with warnings.catch_warnings():
        warnings.simplefilter('error', getpass.GetPassWarning)
        value = getpass.getpass(prompt).encode('utf-8')
    quarantine.need(0 < len(value) <= 512 and not any(character in value for character in (b'\n', b'\r', b'\0')))
    return value


def load(path, encrypted_sha256=None):
    """Unlock a hash-pinned encrypted file in memory, or read the existing private DER input."""
    with ExitStack() as stack:
        source, size, unchanged = private_input(path, stack, KEY_LIMIT)
        data = source.read(KEY_LIMIT + 1)
        quarantine.need(len(data) == size)
        unchanged()
    password = None
    if encrypted_sha256 is not None:
        quarantine.need(hashlib.sha256(data).hexdigest() == encrypted_sha256)
        password = passphrase('Recovery key passphrase: ')
    key = serialization.load_der_private_key(data, password=password)
    fingerprint(key)
    return key


def pack(source_path, destination, recipient_sha256, password):
    """Use OpenSSL PBES2 encryption; publish only after decrypting and checking the result in memory."""
    quarantine.need(sys.platform == 'linux' and re.fullmatch(r'[a-f0-9]{64}', recipient_sha256)
                    and type(password) is bytes and 16 <= len(password) <= 512
                    and not any(character in password for character in (b'\n', b'\r', b'\0')))
    with ExitStack() as stack:
        source, size, unchanged = private_input(source_path, stack, KEY_LIMIT)
        data = source.read(KEY_LIMIT + 1)
        quarantine.need(len(data) == size
                        and fingerprint(serialization.load_der_private_key(data, password=None)) == recipient_sha256)
        parent, name = quarantine.private_parent(destination, stack)
        source.seek(0)
        fd = source.fileno()
        process = subprocess.run(['/usr/bin/openssl', 'pkcs8', '-topk8', '-inform', 'DER',
            '-outform', 'DER', '-in', f'/proc/self/fd/{fd}', '-passout', 'stdin',
            '-v2', 'aes-256-cbc', '-v2prf', 'hmacWithSHA256', '-iter', '600000'],
            input=password + b'\n', pass_fds=(fd,), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=20, env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'})
        unchanged()
        encrypted = process.stdout
        quarantine.need(process.returncode == 0 and 0 < len(encrypted) <= KEY_LIMIT
                        and fingerprint(serialization.load_der_private_key(encrypted, password=password)) == recipient_sha256)
        quarantine.Directory(parent).file(name, iter((encrypted,)))
    return {'scope': 'azd-santa-portable-recipient-key-v1', 'recipient_sha256': recipient_sha256,
            'encrypted_key_sha256': hashlib.sha256(encrypted).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--recipient-key', required=True)
    parser.add_argument('--recipient-sha256', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    try:
        quarantine.need(sys.platform == 'linux')
        password = passphrase('New recovery key passphrase: ')
        quarantine.need(password == passphrase('Repeat recovery key passphrase: '))
        report = pack(args.recipient_key, args.output, args.recipient_sha256, password)
        print(quarantine.encoded(report).decode('ascii'))
    except Exception:
        parser.exit(1, 'Santa recovery key export failed. Preserve the original key and any existing output.\n')


if __name__ == '__main__':
    main()
