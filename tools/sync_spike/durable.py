"""Local synthetic durability experiment, NOT a production database adapter.

No enrollment, credentials, authorization, Azure storage or restore trust anchor.
An approval label and a client report are fixture data, not security evidence.
"""
import hashlib
import json
import re
import sqlite3
from contextlib import contextmanager
from pathlib import Path

from model import Model, Snapshot, canonical


class State:
    def __init__(self, path, *, create=False):
        path = Path(path).resolve()
        # Reopening never silently creates an empty replacement after data loss.
        mode = 'rwc' if create else 'rw'
        self.db = sqlite3.connect(path.as_uri() + '?mode=' + mode, uri=True,
                                  isolation_level=None, timeout=1)
        try:
            self.db.execute('PRAGMA synchronous=FULL')
            self.db.execute('PRAGMA journal_mode=DELETE')
            with self.transaction():
                version = self.db.execute('PRAGMA user_version').fetchone()[0]
                tables = self.db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
                if version == 0 and create and not tables:
                    self.db.execute('CREATE TABLE snapshots (revision INTEGER PRIMARY KEY, payload BLOB NOT NULL, digest TEXT NOT NULL)')
                    self.db.execute('CREATE TABLE devices (device TEXT PRIMARY KEY, revoked INTEGER NOT NULL DEFAULT 0, reported INTEGER NOT NULL DEFAULT 0)')
                    self.db.execute('PRAGMA user_version=1')
                elif version != 1:
                    raise ValueError('unsupported synthetic state schema')
        except BaseException:
            self.db.close()
            raise

    @contextmanager
    def transaction(self):
        self.db.execute('BEGIN IMMEDIATE')
        try:
            yield
            self.db.execute('COMMIT')
        except BaseException:
            if self.db.in_transaction:
                self.db.execute('ROLLBACK')
            raise

    def close(self):
        self.db.close()

    @staticmethod
    def device_id(device):
        if not isinstance(device, str) or not re.fullmatch(r'device-[ab]', device):
            raise ValueError('synthetic device required')
        return device

    def publish_fixture(self, snapshot):
        # Validate even directly constructed dataclass instances; do not trust
        # callers to have used Snapshot.fixture. Labels are not real approval.
        if not isinstance(snapshot, Snapshot):
            raise ValueError('synthetic snapshot required')
        rules = [json.loads(rule) for rule in snapshot.rules]
        Snapshot.fixture(snapshot.revision, rules, snapshot.approval)
        if (not rules or not isinstance(snapshot.approval, str)
                or len(snapshot.approval) > 128):
            raise ValueError('nonempty bounded fixture required')
        payload = canonical(dict(revision=snapshot.revision, rules=rules, approval=snapshot.approval))
        if len(payload) > 65536:
            raise ValueError('fixture too large')
        digest = hashlib.sha256(payload).hexdigest()
        with self.transaction():
            maximum = self.db.execute('SELECT COALESCE(MAX(revision),0) FROM snapshots').fetchone()[0]
            if snapshot.revision <= maximum:
                raise ValueError('revision must increase')
            if self.db.execute('SELECT COUNT(*) FROM snapshots').fetchone()[0] >= 100:
                raise ValueError('fixture history full')
            self.db.execute('INSERT INTO snapshots VALUES (?,?,?)', (snapshot.revision, payload, digest))

    def snapshot(self):
        row = self.db.execute('SELECT revision,payload,digest FROM snapshots ORDER BY revision DESC LIMIT 1').fetchone()
        if row is None or hashlib.sha256(row[1]).hexdigest() != row[2]:
            raise ValueError('missing or damaged fixture snapshot')
        try:
            value = json.loads(row[1])
            if value['revision'] != row[0] or not value['rules'] or canonical(value) != row[1]:
                raise ValueError()
            return Snapshot.fixture(value['revision'], value['rules'], value['approval'])
        except (KeyError, TypeError, ValueError):
            raise ValueError('invalid fixture snapshot') from None

    def device(self, device):
        row = self.db.execute('SELECT revoked,reported FROM devices WHERE device=?', (self.device_id(device),)).fetchone()
        return (bool(row[0]), row[1]) if row else (False, 0)

    def revoke_fixture(self, device):
        with self.transaction():
            self.db.execute('INSERT INTO devices(device,revoked) VALUES (?,1) ON CONFLICT(device) DO UPDATE SET revoked=1', (self.device_id(device),))

    def report_fixture(self, device, revision):
        if type(revision) is not int or revision < 1:
            raise ValueError('invalid reported revision')
        with self.transaction():
            revoked, previous = self.device(device)
            if revoked or revision < previous:
                raise ValueError('revoked or regressing report')
            if not self.db.execute('SELECT 1 FROM snapshots WHERE revision=?', (revision,)).fetchone():
                raise ValueError('unknown reported revision')
            self.db.execute('INSERT INTO devices(device,reported) VALUES (?,?) ON CONFLICT(device) DO UPDATE SET reported=excluded.reported', (device, revision))


class DurableModel(Model):
    """Reuse only the loopback model; sessions/keys/tokens die on restart.

    This intentionally does not persist telemetry or implement distributed sync.
    A persisted postflight report never proves endpoint receipt or enforcement.
    """
    def __init__(self, state):
        self.state = state
        super().__init__(state.snapshot())

    def revoke_fixture_device(self, device):
        self.state.revoke_fixture(device)  # commit before changing ephemeral state
        super().revoke_fixture_device(device)

    def rotate_fixture_device(self, device):
        raise NotImplementedError('durable credential rotation is not implemented')

    def handle(self, stage, device, body):
        try:
            revoked, reported = self.state.device(device)
            if revoked:
                return 403, {}
            self.acknowledged[device] = reported
            if stage == 'preflight':
                self.snapshot = self.state.snapshot()
            # Do not let the superclass acknowledge before persistence commits.
            previous = dict(self.acknowledged)
            status, response = super().handle(stage, device, body)
            if stage == 'postflight' and status == 200:
                try:
                    self.state.report_fixture(device, self.acknowledged[device])
                except (sqlite3.Error, ValueError):
                    self.acknowledged = previous
                    self.sessions.pop(device, None)
                    return 503, {}
            return status, response
        except (sqlite3.Error, ValueError):
            self.sessions.pop(device, None)
            return 503, {}
