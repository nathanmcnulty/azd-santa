"""Read existing synthetic state and indexed count; never initialize or send sync."""
import argparse
import hashlib
import json
from pathlib import Path

from test_live_zentral import assert_committed, load_fixture, snapshot, validate_compose
from upgrade_core_runtime import write_private
from verify_indexing import verify


def check_previous(previous, *, boot, digest, state, count):
    if (previous.get('scope') != 'private-synthetic-reboot-persistence' or
            previous.get('boot_id') == boot or previous.get('compose_sha256') != digest or
            previous.get('state') != state or previous.get('indexed_events') != count):
        raise ValueError('Reboot/state/index persistence receipt does not match')


def record(compose, fixture, expected, output, previous=None):
    compose, digest = validate_compose(compose)
    fixture_path = Path(fixture)
    fixture = load_fixture(fixture_path, digest)
    state = snapshot(compose, fixture)
    assert_committed(state, fixture)
    verify(compose, fixture_path, expected)
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    receipt = dict(scope='private-synthetic-reboot-persistence', compose_sha256=digest,
                   boot_id=boot, state=state, indexed_events=expected,
                   limitation='Manual lab resume; not automatic recovery or native Mac proof')
    if previous:
        raw = Path(previous).read_bytes()
        check_previous(json.loads(raw), boot=boot, digest=digest, state=state, count=expected)
        receipt['previous_receipt_sha256'] = hashlib.sha256(raw).hexdigest()
    write_private(Path(output), receipt)
    print('SANTA_PERSISTENCE_READBACK_OK ' + str(output))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', required=True)
    parser.add_argument('--fixture', required=True)
    parser.add_argument('--expected', type=int, required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--previous')
    args = parser.parse_args()
    record(args.compose, args.fixture, args.expected, args.output, args.previous)
