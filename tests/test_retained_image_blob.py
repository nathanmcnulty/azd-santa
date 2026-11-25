"""Execute actual HTTP request formatting against a synthetic Blob connection."""
import base64
import datetime as dt
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlencode, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'experiments/server'))
import blob_retention as blob
import retained_image_blob as transfer
import retained_image_parts as parts


SUB = '/subscriptions/00000000-0000-4000-8000-000000000001/resourceGroups/'
OPERATION = '1' * 32


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def target(label):
    group = SUB + 'rg-' + label
    return blob.SelectedTarget(group + '/providers/Microsoft.Compute/virtualMachines/vm',
        f'00000000-0000-4000-8000-0000000000{ord(label[0]) % 100:02d}',
        group + '/providers/Microsoft.Network/virtualNetworks/vnet/subnets/vm', 'westus2')


class Response(io.BytesIO):
    def __init__(self, status, data=b''):
        super().__init__(data)
        self.status, self.size = status, len(data)

    def getheader(self, key):
        return {'Content-Length': str(self.size), 'ETag': '"fixture"'}[key]


@unittest.skipUnless(sys.platform == 'linux', 'Linux selected-host and journal contract')
class TransferTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(dir=Path.home())
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)
        self.source = target('source')
        self.reader = target('reader')
        store = blob.Store(blob.Blob(SUB + 'rg-store/providers/Microsoft.Storage/storageAccounts/santafixture',
                                     OPERATION), 'westus2', (self.source.subnet_id, self.reader.subnet_id),
                          '00000000-0000-4000-8000-000000000070')
        data = b'x' * 1024 + b'y' * 1024 + b'z' * 500
        self.source_file = self.root / 'source.sealed'
        self.source_file.write_bytes(data)
        self.source_file.chmod(0o600)
        self.read_dir = self.root / 'read'
        self.read_dir.mkdir(mode=0o700)
        completion = parts.encoded({'scope': 'azd-santa-retained-image-export-v1', 'image_id': 'sha256:'+'a'*64,
            'intent_sha256': 'b'*64, 'archive_sha256': 'c'*64, 'archive_bytes': 2048,
            'ciphertext_sha256': sha(data), 'ciphertext_bytes': len(data)})
        part_size = patch.object(parts, 'PART_BYTES', 1024)
        part_size.start()
        self.addCleanup(part_size.stop)
        manifest = parts.plan(io.BytesIO(data), completion, completion_sha256=sha(completion), operation=OPERATION)
        self.transfer = transfer.Transfer(manifest, completion, store, self.source, manifest_sha256=sha(manifest),
                                           completion_sha256=sha(completion), operation=OPERATION)
        self.names = [part['object'] for part in json.loads(manifest)['parts']]
        self.calls, self.objects = [], {}
        self.failure = False
        transport = patch.object(blob.BlobHttp, 'connection', return_value=self)
        transport.start()
        self.addCleanup(transport.stop)
        host = patch.object(blob, 'host_identity')
        self.host = host.start()
        self.addCleanup(host.stop)

    def tokens(self, permission):
        now = dt.datetime.now(dt.timezone.utc)
        stamp = lambda value: value.strftime('%Y-%m-%dT%H:%M:%SZ')
        return {name: urlencode(dict(sv='2023-11-03', sr='b', sp=permission, spr='https',
            st=stamp(now-dt.timedelta(minutes=1)), se=stamp(now+dt.timedelta(minutes=4)),
            sig=base64.b64encode(bytes([index])*32).decode('ascii'))) for index, name in enumerate(self.names)}

    def request(self, method, path, body=None, headers=None):
        parsed = urlsplit(path)
        key = parsed.path.removeprefix('/native-captures/')
        self.assertIn(key, self.names)
        query = parse_qs(parsed.query)
        self.assertEqual(query['sp'], ['c' if method == 'PUT' else 'r'])
        self.assertEqual(query['api-version'], ['2023-11-03'])
        self.calls.append((method, key))
        if method == 'PUT':
            self.assertTrue((self.root / OPERATION / 'intent.json').exists())
            self.assertEqual(headers['If-None-Match'], '*')
            value = b''.join(iter(lambda: body.read(8192), b''))
            self.assertEqual(len(value), int(headers['Content-Length']))
            md5 = hashlib.md5(value, usedforsecurity=False).digest()
            self.assertEqual(headers['Content-MD5'], base64.b64encode(md5).decode('ascii'))
            self.objects[key] = value
            if self.failure:
                raise TimeoutError('ambiguous fixture response')
            self.response = Response(201)
        else:
            self.response = Response(200, self.objects[key])

    def getresponse(self):
        return self.response

    def close(self):
        pass

    def test_create_only_upload_and_independent_readback(self):
        self.assertFalse(self.transfer.upload(None, None)['performs_mutation'])
        self.host.assert_not_called()
        upload = self.transfer.upload(self.source_file, self.root, self.tokens('c'), apply=True)
        self.assertEqual(upload['state'], 'uploaded')
        self.assertEqual(upload['confirmed_parts'], 3)
        report = self.transfer.download(self.read_dir, self.reader, self.tokens('r'), apply=True)
        self.assertEqual(report['verified_parts'], 3)
        self.assertEqual((self.read_dir/OPERATION/'image.sealed').read_bytes(), self.source_file.read_bytes())
        self.assertEqual(self.calls, [('PUT', name) for name in self.names] + [('GET', name) for name in self.names])

    def test_ambiguous_put_stops_and_same_operation_cannot_replay(self):
        self.failure = True
        report = self.transfer.upload(self.source_file, self.root, self.tokens('c'), apply=True)
        self.assertEqual(report['state'], 'unknown')
        self.assertEqual(report['confirmed_parts'], 0)
        self.assertEqual(self.calls, [('PUT', self.names[0])])
        with self.assertRaises(blob.RetentionRejected):
            self.transfer.upload(self.source_file, self.root, self.tokens('c'), apply=True)
        self.assertEqual(self.calls, [('PUT', self.names[0])])
        self.assertNotIn('sig', (self.root/OPERATION/'intent.json').read_text())

    def test_wrong_permission_same_host_and_modified_source_make_no_requests(self):
        with self.assertRaises(blob.RetentionRejected):
            self.transfer.upload(self.source_file, self.root, self.tokens('r'), apply=True)
        with self.assertRaises(blob.RetentionRejected):
            same_token = next(iter(self.tokens('c').values()))
            self.transfer.upload(self.source_file, self.root, dict.fromkeys(self.names, same_token), apply=True)
        with self.assertRaises(blob.RetentionRejected):
            self.transfer.download(self.read_dir, self.source, self.tokens('r'), apply=True)
        self.source_file.write_bytes(b'z'*self.source_file.stat().st_size)
        with self.assertRaises(blob.RetentionRejected):
            self.transfer.upload(self.source_file, self.root, self.tokens('c'), apply=True)
        self.assertEqual(self.calls, [])
