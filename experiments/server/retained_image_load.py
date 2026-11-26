"""Original Unlicense. Verify and import one retained image on an isolated Linux recovery host."""

import argparse
from contextlib import ExitStack
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

import blob_retention as blob
from retained_image_archive import ARCHIVE_MAXIMUM
from retained_image_readback import need, open_verified_image, remaining_seconds
from restore_recipient_key import load, private_input

SCOPE = 'azd-santa-retained-image-load-v1'


class RecoveryDocker:
    def __init__(self, socket):
        path = Path(socket)
        need(path.is_absolute() and path == path.resolve(strict=True)
             and re.fullmatch(r'/[A-Za-z0-9_./-]+', path.as_posix()))
        info = path.lstat()
        need(stat.S_ISSOCK(info.st_mode))
        self.path = path
        self.identity = (info.st_dev, info.st_ino)

    def assert_current(self):
        info = self.path.lstat()
        need(stat.S_ISSOCK(info.st_mode) and (info.st_dev, info.st_ino) == self.identity)

    def run(self, arguments, deadline, *, archive=None):
        self.assert_current()
        command = ['/usr/bin/docker', '--host', 'unix://' + self.path.as_posix(), *arguments]
        result = subprocess.run(command, stdin=archive if archive is not None else subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL if archive is not None else subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=remaining_seconds(deadline),
                                env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'})
        need(result.returncode == 0 and time.monotonic() < deadline)
        return result.stdout

    def require_idle(self, deadline):
        need(self.run(['container', 'ls', '--all', '--last', '1', '--quiet'], deadline) == b'')

    def confirm_image(self, image_id, platform, deadline):
        observed = self.run(['image', 'inspect', '--format', '{{.Id}} {{.Os}}/{{.Architecture}}', image_id],
                            deadline)
        need(observed == f'{image_id} {platform}\n'.encode('ascii'))


def verify_or_load(source, completion, key, staging, *, completion_sha256, inventory_sha256,
                   image_name, image_id, maximum=ARCHIVE_MAXIMUM, seconds=600,
                   socket=None, attempt=None):
    need((socket is None) == (attempt is None) and type(seconds) is int and 1 <= seconds <= 1800)
    deadline = time.monotonic() + seconds
    with open_verified_image(source, completion, key, staging, completion_sha256=completion_sha256,
                             inventory_sha256=inventory_sha256, image_name=image_name, image_id=image_id,
                             maximum=maximum, seconds=seconds) as (archive, verified):
        result = {**verified, 'scope': SCOPE, 'state': 'verified', 'restore_accepted': False}
        if socket is None:
            return result
        docker = RecoveryDocker(socket)
        intent = {**result, 'state': 'load-uncertain', 'socket': docker.path.as_posix(),
                  'socket_device': docker.identity[0], 'socket_inode': docker.identity[1]}
        with ExitStack() as stack:
            journal = blob.Journal(attempt, intent, stack)
            docker.require_idle(deadline)
            docker.run(['image', 'load', '--quiet', '--platform', verified['platform']],
                       deadline, archive=archive)
            docker.confirm_image(image_id, verified['platform'], deadline)
            docker.require_idle(deadline)
            result.update(state='loaded', image_loaded=True, container_started=False)
            journal.write('outcome.json', result)
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('verify', 'load'))
    for name in ('ciphertext', 'completion', 'completion-sha256', 'recipient-key',
                 'inventory-sha256', 'image', 'image-id'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--staging', type=Path, required=True)
    parser.add_argument('--docker-socket', type=Path)
    parser.add_argument('--attempt', type=Path)
    parser.add_argument('--encrypted-key-sha256')
    parser.add_argument('--maximum', type=int, default=ARCHIVE_MAXIMUM)
    parser.add_argument('--seconds', type=int, default=600)
    args = parser.parse_args()
    try:
        need(sys.platform == 'linux')
        need((args.action == 'load' and args.docker_socket is not None and args.attempt is not None)
             or (args.action == 'verify' and args.docker_socket is None and args.attempt is None))
        key = load(args.recipient_key, args.encrypted_key_sha256)
        with ExitStack() as stack:
            stream, length, unchanged = private_input(args.completion, stack, 4096)
            completion = stream.read(4097)
            need(len(completion) == length)
            unchanged()
        result = verify_or_load(args.ciphertext, completion, key, args.staging,
                                completion_sha256=args.completion_sha256, inventory_sha256=args.inventory_sha256,
                                image_name=args.image, image_id=args.image_id, maximum=args.maximum,
                                seconds=args.seconds, socket=args.docker_socket, attempt=args.attempt)
        print(blob.encoded(result).decode('ascii'))
    except Exception:
        parser.exit(1, 'Santa retained image operation failed or is unknown. Preserve the attempt.\n')


if __name__ == '__main__':
    main()
