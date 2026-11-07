"""Offline decoder and image-package boundaries; no server acceptance claim."""
import gzip
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'experiments/server'))
import santa_request_limits as limits
import prepare_request_limits as package
import test_request_limits_live as gate
import zlib


class Decoder(unittest.TestCase):
    def rejects(self, raw, encoding=None, status=400, **kwargs):
        with self.assertRaises(limits.RequestRejected) as caught:
            limits.decode_bytes(raw, encoding, **kwargs)
        self.assertEqual(caught.exception.status, status)

    def test_real_protocol_encodings_and_empty_batches(self):
        raw = b'{"events":[],"file_access_events":[]}'
        for encoding, data in ((None, raw), ('identity', raw), ('deflate', zlib.compress(raw)),
                               ('zlib', zlib.compress(raw)), ('gzip', gzip.compress(raw)),
                               (' GZIP ', gzip.compress(raw))):
            with self.subTest(encoding=encoding):
                self.assertEqual(limits.decode_bytes(data, encoding), json.loads(raw))

    def test_strict_unsupported_encodings(self):
        for encoding in ('br', 'gzip, deflate', 'none', 'compress', 3):
            self.rejects(b'{}', encoding, 415)
        raw_deflate = zlib.compress(b'{}')[2:-4]
        self.rejects(raw_deflate, 'deflate')

    def test_compressed_streams_must_be_complete_single_and_valid(self):
        for encoding, encode in (('deflate', zlib.compress), ('gzip', gzip.compress)):
            blob = encode(b'{}')
            for bad in (b'', blob[:-1], blob + b'junk', blob + encode(b'{}'), b'broken'):
                with self.subTest(encoding=encoding, bad=bad):
                    self.rejects(bad, encoding)

    def test_raw_and_expanded_size_boundaries(self):
        small = limits.Limits(compressed=40, expanded=20)
        at_limit = b'{"x":"' + b'x' * 12 + b'"}'
        self.assertEqual(len(at_limit), 20)
        self.assertEqual(limits.decode_bytes(at_limit, limits=small)['x'], 'x' * 12)
        self.rejects(b' ' * 41, status=413, limits=small)
        self.rejects(b'{"x":"' + b'x' * 13 + b'"}', status=413, limits=small)
        for encoding, encode in (('deflate', zlib.compress), ('gzip', gzip.compress)):
            self.assertEqual(limits.decode_bytes(encode(at_limit), encoding, limits=small)['x'], 'x' * 12)
            self.rejects(encode(b'{"x":"' + b'x' * 100000 + b'"}'), encoding, 413,
                         limits=limits.Limits(compressed=1000, expanded=20))

    def test_bounded_stream_read_with_or_without_content_length(self):
        class Request(io.BytesIO):
            META = {}
            def read(self, size):
                self.last_read = size
                return super().read(size)
        for declared in (None, '', '2'):
            request = Request(b'{}' + b' ' * 100)
            request.META = {} if declared is None else {'CONTENT_LENGTH': declared}
            with self.assertRaises(limits.RequestRejected) as caught:
                limits.decode_request(request, limits=limits.Limits(compressed=10))
            self.assertEqual(caught.exception.status, 413)
            self.assertEqual(request.last_read, 11)
            self.assertEqual(request.tell(), 11)
        for declared, status in (('11', 413), ('-1', 400), ('1.5', 400), ('a', 400), ('9' * 200, 413)):
            request = Request(b'{}')
            request.META = {'CONTENT_LENGTH': declared}
            with self.assertRaises(limits.RequestRejected) as caught:
                limits.decode_request(request, limits=limits.Limits(compressed=10))
            self.assertEqual(caught.exception.status, status)
            self.assertEqual(request.tell(), 0)

    def test_depth_is_bounded_before_parser_and_ignores_escaped_string_contents(self):
        small = limits.Limits(depth=3)
        self.assertEqual(limits.decode_bytes(b'{"a":[{}]}', limits=small), {'a': [{}]})
        self.rejects(b'{"a":[[{}]]}', limits=small)
        self.assertEqual(limits.decode_bytes(json.dumps({'x': '"\\{{[[}'}).encode(), limits=small)['x'], '"\\{{[[}')
        self.rejects(b'{"a":' + b'[' * 2000 + b'0' + b']' * 2000 + b'}')

    def test_json_is_strict_and_requires_mapping(self):
        for raw in (b'', b'[]', b'null', b'3', b'{"a":1,"a":2}', b'{"a":NaN}',
                    b'{"a":Infinity}', b'{"a":1e999}', b'{} junk', b'{"a":"\xff"}', b'{"a":}'):
            with self.subTest(raw=raw):
                self.rejects(raw)

    def test_event_budget_counts_all_protocol_collections_together(self):
        data = {name: [{}] for name in limits.EVENT_COLLECTIONS}
        small = limits.Limits(events=len(data))
        self.assertEqual(limits.decode_bytes(json.dumps(data).encode(), limits=small), data)
        data['events'].append({})
        self.rejects(json.dumps(data).encode(), status=413, limits=small)
        for value in ({}, None, [None], [3]):
            self.rejects(json.dumps({'events': value}).encode())
        self.assertEqual(limits.decode_bytes(json.dumps({'events': [{}] * 100}).encode())['events'], [{}] * 100)
        self.rejects(json.dumps({'events': [{}] * 101}).encode(), status=413)

    def test_configuration_rejects_unsafe_or_invalid_values(self):
        self.assertEqual(limits.configured_limits({}), limits.Limits())
        self.assertEqual(limits.configured_limits({'AZD_SANTA_MAX_EVENTS': '50'}).events, 50)
        for field, maximum in (('COMPRESSED', 4 * 1024 * 1024), ('EXPANDED', 16 * 1024 * 1024),
                               ('DEPTH', 64), ('EVENTS', 1000)):
            for raw in ('0', '-1', 'true', '1.2', str(maximum + 1), '١'):
                with self.subTest(field=field, raw=raw), self.assertRaises(ValueError):
                    limits.configured_limits({'AZD_SANTA_MAX_' + field: raw})


class Package(unittest.TestCase):
    def test_unreviewed_input_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Unreviewed guarded Santa input'):
            package.transform(b'changed source')

    def test_generated_layer_preserves_helper_checks_source_and_wires_rejections(self):
        # Small original source shape exercises the generated transform without
        # vendoring the full upstream tree or requiring Django in offline CI.
        raw = ('from django.views.generic import View\nclass Sample:\n    def _get_enrollment_secret_secret(self): pass\n' + package.OLD +
               '    def post(self, request):\n        self.request_data = self._get_json_data(request)\n').encode()
        text = raw.decode()
        for old, new in package.PATCHES:
            text = text.replace(old, new, 1)
        result = (package.NOTICE + text).encode()
        admission = result.decode()
        for old, new in package.ADMISSION_PATCHES: admission = admission.replace(old, new, 1)
        admission = admission.encode()
        digest = lambda data: hashlib.sha256(data).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / package.SOURCE
            source.parent.mkdir(parents=True)
            source.write_bytes(raw)
            (root / 'server').mkdir()
            helper = root / 'limits.py'
            helper.write_bytes(b'ORIGINAL = True\n')
            with patch.object(package, 'UPSTREAM_SHA256', digest(raw)), patch.object(package, 'INPUT_SHA256', digest(raw)), patch.object(package, 'OUTPUT_SHA256', digest(result)), patch.object(package, 'ADMISSION_OUTPUT_SHA256', digest(admission)):
                self.assertEqual(package.transform(raw), result)
                program, helper_hash = package.docker_program(root, helper)
                self.assertEqual(helper_hash, digest(helper.read_bytes()))
                program = program.replace('Path("/zentral")', 'Path(' + repr(root.as_posix()) + ')')
                program = program.replace('"/zentral/server/azd_santa_request_limits.py"', repr((root / 'server/azd_santa_request_limits.py').as_posix()))
                program = program.replace('\"/zentral/server/azd_santa_admission.py\"', repr((root / 'server/azd_santa_admission.py').as_posix()))
                exec(compile(program, 'bounded-image-layer', 'exec'), {})
                self.assertEqual(source.read_bytes(), admission)
                self.assertEqual((root / 'server/azd_santa_request_limits.py').read_bytes(), helper.read_bytes())
                self.assertEqual((root / 'server/azd_santa_admission.py').read_bytes(),
                    package.Path(package.__file__).with_name('santa_admission.py').read_bytes().replace(b'\r\n', b'\n'))
                self.assertIn(b'except RequestRejected as exc:', result)
                source.write_bytes(b'changed')
                with self.assertRaisesRegex(RuntimeError, 'Santa limits input mismatch'):
                    exec(compile(program, 'bounded-image-layer', 'exec'), {})
                self.assertEqual(source.read_bytes(), b'changed')


class LiveGateGuards(unittest.TestCase):
    def test_stale_runtime_hash_rejects_before_any_http(self):
        root = Path(__file__).resolve().parents[1]
        compose = root / 'not-a-real-compose.json'
        helper_hash = hashlib.sha256((root / 'experiments/server/santa_request_limits.py').read_bytes().replace(b'\r\n', b'\n')).hexdigest()
        with patch.object(gate.live, 'validate_compose', return_value=(compose, 'a' * 64)), \
             patch.object(gate.live, 'load_fixture', return_value={}), \
             patch.object(gate.live, 'snapshot', return_value={}), \
             patch.object(gate.live, 'assert_committed'), \
             patch.object(gate.live, 'orm', return_value={'helper_sha256': helper_hash, 'view_sha256': 'stale'}), \
             patch.object(gate, 'post_raw') as post:
            with self.assertRaisesRegex(ValueError, 'Runtime request boundary differs'):
                gate.run(compose, root / 'not-a-real-fixture.json')
            post.assert_not_called()

    def test_gate_targets_all_hostile_categories_without_constructing_unbounded_probes(self):
        bounds = dict(compressed=1048576, expanded=4194304, depth=32, events=100)
        cases = list(gate.cases(bounds))
        self.assertEqual(len(cases), 21)
        self.assertEqual({status for _, _, _, status in cases}, {400, 413, 415})
        self.assertLessEqual(max(len(body) for _, body, _, _ in cases), bounds['compressed'] + 1)


if __name__ == '__main__':
    unittest.main()
