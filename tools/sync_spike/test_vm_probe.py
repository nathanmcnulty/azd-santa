"""Offline fail-closed coverage for the VM receipt helper."""
import tempfile
import unittest
from pathlib import Path
import sqlite3

from vm_probe import probe
from durable import State
from model import canonical
import hashlib
import json


class Probe(unittest.TestCase):
    def test_reopen(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.db'
            self.assertEqual(probe(path, True), probe(path))
            original = path.read_bytes()
            with self.assertRaises(FileExistsError):
                probe(path, True)
            self.assertEqual(original, path.read_bytes())

    def test_missing_or_corrupt_not_reinitialized(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.db'
            with self.assertRaises(sqlite3.Error):
                probe(path)
            self.assertFalse(path.exists())
            path.write_bytes(b'not a SQLite database')
            with self.assertRaises(sqlite3.Error):
                probe(path)
            self.assertEqual(path.read_bytes(), b'not a SQLite database')

    def test_changed_valid_snapshot_is_not_a_persistence_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.db'
            probe(path, True)
            state = State(path)
            try:
                value = json.loads(state.db.execute('SELECT payload FROM snapshots').fetchone()[0])
                value['rules'][0]['identifier'] = 'b' * 64
                payload = canonical(value)
                state.db.execute('UPDATE snapshots SET payload=?,digest=?',
                                 (payload, hashlib.sha256(payload).hexdigest()))
            finally:
                state.close()
            with self.assertRaises(ValueError):
                probe(path)


if __name__ == '__main__':
    unittest.main()
