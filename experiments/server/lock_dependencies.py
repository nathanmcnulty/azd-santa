"""Resolve and record actual local image digests for private evaluation only.

Tags are acquisition inputs, never emitted runtime references. This is not a
production version/security/license approval; all four components need review.
"""
import argparse
import json
import re
import subprocess
from pathlib import Path

IMAGES = {
    'postgres': 'docker.io/library/postgres:18',
    'redis': 'docker.io/library/redis:7.2',
    'rabbitmq': 'docker.io/library/rabbitmq:3',
    'elasticsearch': 'docker.elastic.co/elasticsearch/elasticsearch:9.2.1',
}


def acquire(destination):
    destination = Path(destination)
    if destination.exists() or destination.is_symlink():
        raise FileExistsError('Dependency lock already exists; inspect it before acquiring again')
    lock = {}
    for name, image in IMAGES.items():
        subprocess.run(['docker', 'pull', image], check=True, timeout=300)
        metadata = json.loads(subprocess.check_output(['docker', 'image', 'inspect', image], text=True))[0]
        digests = metadata.get('RepoDigests', [])
        if len(digests) != 1 or not re.fullmatch(r'[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}', digests[0]):
            raise ValueError('Expected one actual registry digest for ' + name)
        lock[name] = digests[0]
    with destination.open('x') as output:
        json.dump(lock, output, indent=2)
    print('SANTA_DEPENDENCY_DIGEST_LOCK_READY')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('destination')
    acquire(parser.parse_args().destination)
