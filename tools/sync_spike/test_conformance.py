"""Synthetic local HTTP tests; does not execute Santa or prove interoperability."""
import gzip
import http.client
import json
import socket
from pathlib import Path
import threading
import unittest
import zlib

from model import MAX_BYTES, Model, Snapshot, canonical, loopback_server

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = json.loads((ROOT / 'tests/fixtures/sync/clean-sync.json').read_text())
RULES = [r for page in FIXTURE['rulePages'] for r in page['rules']]


class Conformance(unittest.TestCase):
    def setUp(self):
        self.model = Model(Snapshot.fixture(1, RULES))
        self.tokens = {d: t for t, d in self.model.tokens.items()}
        self.server = loopback_server(self.model)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': .01}, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop)

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)

    def request(self, stage, body=None, device='device-a', token=None, encoding='', raw=None,
                content_type='application/json', method='POST', path=None):
        value = {'machine_id': device} if body is None else body
        payload = canonical(value) if raw is None else raw
        if encoding == 'deflate':
            payload = zlib.compress(payload)
        elif encoding == 'gzip':
            payload = gzip.compress(payload, mtime=0)
        headers = {'Content-Type': content_type, 'Authorization': 'Bearer ' + (self.tokens[device] if token is None else token)}
        if encoding:
            headers['Content-Encoding'] = encoding
        connection = http.client.HTTPConnection(*self.server.server_address, timeout=3)
        try:
            connection.request(method, path or '/' + stage + '/' + device, payload, headers)
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    def preflight(self, **kw):
        result = self.request('preflight', **kw)
        self.assertEqual(result[0], 200)
        return result[1]

    def pages(self, device='device-a'):
        rules, cursor = [], ''
        for _ in range(100):
            status, response = self.request('ruledownload', {'machine_id': device, 'cursor': cursor}, device=device)
            self.assertEqual(status, 200)
            rules += response['rules']
            cursor = response['cursor']
            if not cursor:
                return rules
        self.fail('unbounded cursor')

    def postflight(self, device='device-a', count=2):
        return self.request('postflight', {'machine_id': device, 'rules_received': count,
                                          'rules_processed': count, 'syncType': 'CLEAN'}, device=device)

    def event(self, **extra):
        return {'file_sha256': 'a' * 64, 'execution_time': 1720000000.5, 'decision': 'BLOCK_BINARY', **extra}

    def test_full_flow_deflate_paged_and_postflight(self):
        response = self.preflight(encoding='deflate')
        self.assertEqual(response, {'clientMode': 'MONITOR', 'syncType': 'CLEAN', 'batchSize': 50})
        body = {'machine_id': 'device-a', 'events': [self.event()]}
        self.assertEqual(self.request('eventupload', body, encoding='deflate')[0], 200)
        self.assertEqual(self.pages(), RULES)
        self.assertEqual(self.postflight()[0], 200)
        self.assertEqual(self.model.acknowledged, {'device-a': 1})

    def test_optional_events_can_be_skipped(self):
        self.preflight()
        self.pages()
        self.assertEqual(self.postflight()[0], 200)
        self.assertEqual(self.model.event_digests['device-a'], set())

    def test_gzip_none_and_deflate(self):
        for encoding in ('gzip', '', 'deflate'):
            self.preflight(encoding=encoding)

    def test_duplicate_upload_across_batches_and_retry(self):
        self.preflight()
        for events in ([self.event()] * 2, [self.event()], [self.event(execution_time=1720000001)]):
            self.assertEqual(self.request('eventupload', {'machine_id': 'device-a', 'events': events})[0], 200)
        self.assertEqual(len(self.model.event_digests['device-a']), 2)
        self.assertEqual(self.model.snapshot.rules, Snapshot.fixture(1, RULES).rules)
        self.assertFalse(self.model.acknowledged)

    def test_invalid_event_batch_is_atomic_and_bounded(self):
        self.preflight()
        for events in ([], [self.event()] * 51, [self.event(), {}], 'invalid'):
            self.assertEqual(self.request('eventupload', {'machine_id': 'device-a', 'events': events})[0], 400)
        self.assertFalse(self.model.event_digests['device-a'])
        for start in range(0, 250, 50):
            events = [self.event(execution_time=i) for i in range(start, start + 50)]
            self.assertEqual(self.request('eventupload', {'machine_id': 'device-a', 'events': events})[0], 200)
        self.assertEqual(self.request('eventupload', {'machine_id': 'device-a', 'events': [self.event(execution_time=i) for i in range(250, 300)]})[0], 429)
        self.assertEqual(len(self.model.event_digests['device-a']), 250)

    def test_cursor_replay_stable_snapshot_during_new_revision(self):
        self.preflight()
        first = self.request('ruledownload')
        self.model.snapshot = Snapshot.fixture(2, list(reversed(RULES)))
        self.assertEqual(first, self.request('ruledownload'))
        cursor = first[1]['cursor']
        body = {'machine_id': 'device-a', 'cursor': cursor}
        self.assertEqual(self.request('ruledownload', body), self.request('ruledownload', body))
        self.assertEqual(self.postflight()[0], 200)
        self.assertEqual(self.model.acknowledged['device-a'], 1)
        self.preflight()
        self.assertEqual(self.pages(), list(reversed(RULES)))

    def test_interrupted_download_cannot_ack_and_restarts_after_expiry(self):
        self.preflight()
        first = self.request('ruledownload')[1]
        self.assertEqual(self.postflight()[0], 409)
        self.assertFalse(self.model.acknowledged)
        self.model.now = lambda: 10**15
        self.assertEqual(self.request('ruledownload', {'machine_id': 'device-a', 'cursor': first['cursor']})[0], 409)
        self.preflight()
        self.assertEqual(self.request('ruledownload', {'machine_id': 'device-a', 'cursor': first['cursor']})[0], 400)
        self.pages()
        self.assertEqual(self.postflight()[0], 200)

    def test_cursor_tampering_and_cross_device_rejected(self):
        self.preflight()
        cursor = self.request('ruledownload')[1]['cursor']
        for bad in (cursor[:-3] + 'xxx', 'x' * 513, [], 123):
            self.assertEqual(self.request('ruledownload', {'machine_id': 'device-a', 'cursor': bad})[0], 400)
        self.preflight(device='device-b')
        self.assertEqual(self.request('ruledownload', {'machine_id': 'device-b', 'cursor': cursor}, device='device-b')[0], 400)

    def test_no_preflight_no_download_or_postflight(self):
        self.assertEqual(self.request('ruledownload')[0], 409)
        self.assertEqual(self.postflight()[0], 409)

    def test_postflight_duplicate_and_misreported_counts(self):
        self.preflight()
        self.pages()
        self.assertEqual(self.postflight(count=0)[0], 409)
        self.assertEqual(self.postflight()[0], 200)
        self.assertEqual(self.postflight()[0], 200)
        self.assertEqual(self.model.acknowledged['device-a'], 1)

    def test_stale_same_count_postflight_is_only_untrusted_report(self):
        self.preflight()
        self.pages()
        self.assertEqual(self.postflight()[0], 200)
        self.model.snapshot = Snapshot.fixture(2, list(reversed(RULES)))
        self.preflight()
        self.pages()
        # Public v1 has no session/revision in this report. Identical old counts
        # cannot prove the client processed the newer revision, even with 200.
        self.assertEqual(self.postflight()[0], 200)
        self.assertEqual(self.model.acknowledged['device-a'], 2)

    def test_empty_clean_snapshot_fails_closed(self):
        self.model.snapshot = Snapshot.fixture(2, [])
        self.assertEqual(self.request('preflight', {'machine_id': 'device-a', 'request_clean_sync': True})[0], 503)
        self.assertFalse(self.model.sessions)
        self.assertFalse(self.model.acknowledged)

    def test_rollback_revision_fails_closed(self):
        self.model.snapshot = Snapshot.fixture(2, RULES)
        self.preflight()
        self.pages()
        self.postflight()
        self.model.snapshot = Snapshot.fixture(1, RULES)
        self.assertEqual(self.request('preflight')[0], 409)

    def test_authentication_and_identity_binding(self):
        for token in ('', 'invalid', self.tokens['device-b']):
            self.assertEqual(self.request('preflight', token=token)[0], 401)
        self.assertEqual(self.request('preflight', {'machine_id': 'device-b'})[0], 403)
        self.assertFalse(self.model.sessions)

    def test_revocation_and_rotation_synthetic_only(self):
        self.preflight()
        old = self.tokens['device-a']
        cursor = self.request('ruledownload')[1]['cursor']
        replacement = self.model.rotate_fixture_device('device-a')
        self.assertEqual(self.request('ruledownload', token=old)[0], 401)
        self.assertEqual(self.request('ruledownload', token=replacement)[0], 409)
        self.assertEqual(self.request('preflight', token=replacement)[0], 200)
        self.assertEqual(self.request('ruledownload', {'machine_id': 'device-a', 'cursor': cursor}, token=replacement)[0], 400)
        self.assertEqual(self.request('ruledownload', token=replacement)[0], 200)
        self.assertEqual(self.request('ruledownload', device='device-b', token=replacement)[0], 401)
        self.model.revoke_fixture_device('device-a')
        self.assertEqual(self.request('ruledownload', token=replacement)[0], 401)
        self.assertNotIn('device-a', self.model.sessions)

    def test_numeric_hash_and_short_body_fail_closed(self):
        self.preflight()
        self.assertEqual(self.request('eventupload', {'machine_id': 'device-a', 'events': [self.event(file_sha256=int('1' * 64))]})[0], 400)
        payload = canonical({'machine_id': 'device-a'})
        with socket.create_connection(self.server.server_address, timeout=3) as connection:
            request = ('POST /preflight/device-a HTTP/1.1\r\nHost: localhost\r\n'
                       'Content-Type: application/json\r\nAuthorization: Bearer ' + self.tokens['device-a'] +
                       '\r\nContent-Length: ' + str(len(payload) + 10) + '\r\n\r\n').encode() + payload
            connection.sendall(request)
            connection.shutdown(socket.SHUT_WR)
            self.assertIn(b' 400 ', connection.recv(4096).split(b'\r\n')[0])

    def test_malformed_json_duplicate_keys_utf8_and_depth(self):
        for raw in (b'{', b'[]', b'{"machine_id":"device-a","machine_id":"device-a"}', b'{"n":NaN}', b'\xff', b'[' * 1100):
            self.assertEqual(self.request('preflight', raw=raw)[0], 400)

    def test_oversize_compression_bomb_and_corrupt_stream(self):
        for encoding in ('', 'deflate', 'gzip'):
            self.assertEqual(self.request('preflight', raw=b' ' * (MAX_BYTES + 1), encoding=encoding)[0], 413)
        connection = http.client.HTTPConnection(*self.server.server_address, timeout=3)
        try:
            connection.request('POST', '/preflight/device-a', b'broken', {
                'Authorization': 'Bearer ' + self.tokens['device-a'], 'Content-Type': 'application/json', 'Content-Encoding': 'deflate'})
            self.assertEqual(connection.getresponse().status, 400)
        finally:
            connection.close()

    def test_wrong_content_type_encoding_method_route(self):
        self.assertEqual(self.request('preflight', content_type='application/x-protobuf')[0], 415)
        self.assertEqual(self.request('preflight', encoding='br')[0], 415)
        self.assertEqual(self.request('preflight', method='GET')[0], 405)
        self.assertEqual(self.request('preflight', path='/preflight/device-a?secret=canary')[0], 404)

    def test_logs_are_bounded_request_ids_and_outcomes_only(self):
        self.preflight(raw=b'{"machine_id":"device-a","hostname":"PAYLOAD-CANARY"}')
        audit = repr(self.model.audit)
        self.assertNotIn('PAYLOAD-CANARY', audit)
        self.assertNotIn(self.tokens['device-a'], audit)
        self.assertNotIn('device-a', audit)
        self.assertTrue(all(len(row) == 2 and len(row[0]) == 16 for row in self.model.audit))


if __name__ == '__main__':
    unittest.main(verbosity=2)
