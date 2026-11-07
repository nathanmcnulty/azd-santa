"""Synthetic disk-reopen receipt for the isolated Azure VM lab, never enrollment."""
import argparse
import json
from pathlib import Path

from durable import State
from model import Snapshot

EXPECTED = Snapshot.fixture(1, [dict(
    identifier='a' * 64, policy='BLOCKLIST', rule_type='BINARY')])


def probe(path, initialize=False):
    path = Path(path)
    if initialize:
        # Reserve exclusively: never reset or overwrite a previous receipt.
        with path.open('xb'):
            pass
    state = State(path, create=initialize)
    try:
        if initialize:
            state.publish_fixture(EXPECTED)
            state.report_fixture('device-a', 1)
            state.revoke_fixture('device-b')
        snapshot = state.snapshot()
        if (snapshot != EXPECTED or state.device('device-a') != (False, 1)
                or state.device('device-b') != (True, 0)):
            raise ValueError('unexpected synthetic disk state')
        return dict(scope='synthetic-only', revision=1, reported=1, revoked=True)
    finally:
        state.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('path')
    parser.add_argument('--initialize', action='store_true')
    args = parser.parse_args()
    print(json.dumps(probe(args.path, args.initialize), sort_keys=True))
