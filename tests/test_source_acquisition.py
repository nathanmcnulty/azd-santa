"""Offline archive/provenance guards; never contacts upstream or Azure."""
import hashlib
import importlib.util
import io
import json
import os
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('prepare_source', ROOT / 'experiments/server/prepare_source.py')
source = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(source)


class Acquisition(unittest.TestCase):
    def test_lock_matches_code(self):
        lock = json.loads((ROOT / 'experiments/server/zentral-source.lock.json').read_text())
        self.assertEqual(lock['commit'], source.COMMIT)
        self.assertEqual(lock['archiveSha256'], source.ARCHIVE_SHA256)
        self.assertEqual(lock['archiveUrl'], source.URL)

    def test_existing_destination_never_downloaded_or_overwritten(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(source.urllib.request, 'urlopen') as download:
            marker = Path(directory) / 'keep'
            marker.write_text('existing')
            with self.assertRaises(FileExistsError):
                source.prepare(directory)
            download.assert_not_called()
            self.assertEqual(marker.read_text(), 'existing')

    def test_wrong_hash_has_no_extraction_receipt(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(source.urllib.request, 'urlopen', return_value=io.BytesIO(b'wrong bytes')):
            destination = Path(directory) / 'new'
            with self.assertRaisesRegex(ValueError, 'digest mismatch'):
                source.prepare(destination)
            self.assertFalse((destination / 'acquisition.json').exists())

    def test_pinned_bytes_extract_and_record_without_running_code(self):
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode='w:gz') as bundle:
            item = tarfile.TarInfo('zentral-' + source.COMMIT + '/LICENSE')
            item.size = 7
            bundle.addfile(item, io.BytesIO(b'fixture'))
        data = archive.getvalue()
        with tempfile.TemporaryDirectory() as directory, patch.object(source, 'ARCHIVE_SHA256', hashlib.sha256(data).hexdigest()), patch.object(source.urllib.request, 'urlopen', return_value=io.BytesIO(data)):
            destination = Path(directory) / 'new'
            receipt = source.prepare(destination)
            self.assertEqual(receipt['commit'], source.COMMIT)
            self.assertEqual((Path(receipt['source']) / 'LICENSE').read_bytes(), b'fixture')
            self.assertTrue((destination / 'acquisition.json').exists())

    @unittest.skipIf(os.name == 'nt', 'POSIX non-root container source access')
    def test_restrictive_umask_keeps_private_parent_and_readable_source(self):
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode='w:gz') as bundle:
            parent = tarfile.TarInfo('zentral-' + source.COMMIT + '/server')
            parent.type, parent.mode = tarfile.DIRTYPE, 0o755
            bundle.addfile(parent)
            item = tarfile.TarInfo(parent.name + '/settings.py')
            item.mode, item.size = 0o644, 7
            bundle.addfile(item, io.BytesIO(b'fixture'))
        data = archive.getvalue()
        with tempfile.TemporaryDirectory() as directory, patch.object(source, 'ARCHIVE_SHA256', hashlib.sha256(data).hexdigest()), patch.object(source.urllib.request, 'urlopen', return_value=io.BytesIO(data)):
            destination = Path(directory) / 'new'
            previous = os.umask(0o077)
            try:
                receipt = source.prepare(destination)
            finally:
                os.umask(previous)
            self.assertEqual(destination.stat().st_mode & 0o777, 0o700)
            self.assertEqual((Path(receipt['source']) / 'server').stat().st_mode & 0o777, 0o755)
            self.assertEqual((Path(receipt['source']) / 'server/settings.py').stat().st_mode & 0o777, 0o644)


if __name__ == '__main__':
    unittest.main()
