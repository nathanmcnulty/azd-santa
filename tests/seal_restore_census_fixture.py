"""Seal and quarantine a disposable PostgreSQL cluster inside the synthetic Santa fixture."""

import hashlib
from pathlib import Path, PurePosixPath
import sys
import tarfile
import time

from test_restore_quarantine import Quarantine, producer, quarantine

MAXIMUM = 192 * 1024**2
MAXIMUM_FILES = 10000


def fixture_members(archive):
    paths = set()
    total = 0
    for member in archive:
        path = PurePosixPath(member.name)
        if (not path.parts or path.parts[0] != 'fixture' or '..' in path.parts or path in paths
                or not (member.isdir() or member.isreg())):
            raise ValueError('Unexpected source fixture member')
        paths.add(path)
        total += member.size
        if len(paths) > MAXIMUM_FILES or total > MAXIMUM:
            raise ValueError('Source fixture exceeded its limits')
        yield member


def run(root):
    source = root / 'source'
    source.mkdir(mode=0o700)
    with tarfile.open(fileobj=sys.stdin.buffer, mode='r|') as archive:
        archive.extractall(source, members=fixture_members(archive), filter='data')
    cluster = source / 'fixture'
    assert (cluster / 'PG_VERSION').read_bytes() == b'18\n'

    Quarantine.setUpClass()
    fixture = Quarantine()
    controls = root / 'fixture-controls'
    controls.mkdir(mode=0o700)
    roots, compatibility = fixture.fixture(controls, maximum_bytes=MAXIMUM, maximum_files=MAXIMUM_FILES)
    roots['volumes/postgres_data'] = cluster
    capture = root / 'sealed'
    capture.mkdir(mode=0o700)
    control_digest = hashlib.sha256((cluster / 'global/pg_control').read_bytes()).digest()

    def check_source():
        assert not (cluster / 'postmaster.pid').exists()
        assert hashlib.sha256((cluster / 'global/pg_control').read_bytes()).digest() == control_digest

    sealed = producer.write_capture(capture, fixture.public, roots, compatibility, MAXIMUM, MAXIMUM_FILES,
                                    time.monotonic() + 60, check_source)
    complete = quarantine.document((capture / 'complete.json').read_bytes(), canonical=True)
    with sealed.open('rb') as stream:
        assert hashlib.file_digest(stream, 'sha256').hexdigest() == complete['ciphertext_sha256']
    destination = root / 'quarantine'
    receipt = quarantine.extract(sealed, complete['ciphertext_sha256'], fixture.key, destination,
                                 maximum=MAXIMUM, maximum_member=MAXIMUM, maximum_entries=MAXIMUM_FILES,
                                 seconds=60)
    assert receipt['entries'] == complete['entries'] + 2
    assert not receipt['restore_accepted'] and not receipt['current_authority_established']
    quarantined = destination / 'contents' / 'volumes' / 'postgres_data'
    assert hashlib.sha256((quarantined / 'global/pg_control').read_bytes()).digest() == control_digest
    print('Santa sealed and authenticated the cold PostgreSQL fixture into quarantine')


if __name__ == '__main__':
    run(Path(sys.argv[1]))
