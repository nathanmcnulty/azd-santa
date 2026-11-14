"""Synthetic crypto/preservation tests against Apache-2.0 pinned source excerpts.

No Django, SQL, cloud, service activation or restored-authority acceptance.
"""
import base64
import copy
import hashlib
import io
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zlib

from cryptography.fernet import Fernet, MultiFernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'experiments/server'))
import secret_rewrap as rewrap

FIXTURE = json.loads((ROOT / 'tests/fixtures/server/secret-rewrap-upstream.json').read_bytes())
LOCK = json.loads((ROOT / 'experiments/server/secret-rewrap-source.lock.json').read_bytes())


def upstream(kind, salt='', passwords=()):
    ns = dict(base64=base64, Fernet=Fernet, MultiFernet=MultiFernet, hashes=hashes,
        PBKDF2HMAC=PBKDF2HMAC, settings=SimpleNamespace(SECRET_KEY=salt),
        ConfigDict=type('ConfigDict', (), {}), ImproperlyConfigured=ValueError)
    exec(FIXTURE['snippets']['base']['code'], ns)
    exec(FIXTURE['snippets'][kind]['code'], ns)
    return ns['SecretEngine']({'secret_engine_name': 'noop' if kind == 'noop' else kind,
                               'passwords': passwords})


def token(engine, data):
    return engine.name + '$' + engine.encrypt(data)


def store(backend='HTTP', pk='11111111-1111-4111-8111-111111111111', kwargs=None):
    return dict(id=pk, name='historical-store', description='keep $ literal',
        created_at='2024-01-01T00:00:00Z', updated_at='2025-01-01T00:00:00Z',
        provisioning_uid=None, slug='historical', admin_console=False,
        event_filters={'keep': ['all', 12]}, backend=backend, backend_kwargs=kwargs or {})


class Rewrap(unittest.TestCase):
    def setUp(self):
        self.old = upstream('fernet', 'old-signing-salt', ('old-password', 'older-password'))
        self.new = upstream('fernet', 'different-signing-salt', ('new-password',))
        self.noop = upstream('noop')
        self.kw = dict(apps=rewrap.APPS,
            old_material={'fernet': rewrap.Material('fernet', ('old-password', 'older-password'), 'old-signing-salt'),
                          'noop': rewrap.Material('noop')},
            new_material={'new': rewrap.Material('fernet', ('new-password',), 'different-signing-salt'),
                          'noop': rewrap.Material('noop')}, targets={'fernet': 'new', 'noop': 'noop'})

    def run_projection(self, stores, states=None, contexts=None, actions=None, **overrides):
        arguments = {**self.kw, **overrides}
        return rewrap.rewrap_projection(stores=stores, actions=actions or [], state_versions=states or [],
            expected_contexts=contexts or [], **arguments)

    def ctx(self, row, field):
        return dict(model='stores.store', pk=row['id'], field=field)

    def test_nested_http_headers_exact_upstream_walk_and_complete_preservation(self):
        row = store(kwargs={'headers': [{'name': 'X-First', 'value': token(self.old, b'first-secret')},
            {'name': 'X-Second', 'value': token(self.noop, b'second-secret')},
            {'name': 'X-Null', 'value': None}], 'password': token(self.old, b'password'),
            'endpoint_url': 'https://offline.invalid/literal$dollar', 'verify_tls': True})
        original = copy.deepcopy(row)
        contexts = [self.ctx(row, 'headers.0.value'), self.ctx(row, 'headers.1.value'), self.ctx(row, 'password')]
        # Compare selection/order/context to the actual pinned recursive Backend.
        ns = {}; exec(FIXTURE['snippets']['backend']['code'], ns)
        backend = ns['Backend'](SimpleNamespace(pk=row['id'], name=row['name'],
            created_at='', updated_at='', _meta=SimpleNamespace(app_label='stores', model_name='store')), load=False)
        backend.encrypted_kwargs_paths = LOCK['stores']['HTTP']['encrypted_kwargs_paths']
        captured = []
        backend._iter_kwargs(lambda value, **ctx: captured.append(ctx), row['backend_kwargs'])
        self.assertEqual(captured, contexts)
        output = self.run_projection([row], contexts=contexts)
        self.assertEqual(row, original)
        new_row = output.stores[0]
        new_kwargs = new_row['backend_kwargs']
        self.assertEqual(self.new.decrypt(new_kwargs['headers'][0]['value'].split('$')[1]), b'first-secret')
        self.assertEqual(new_kwargs['headers'][1], original['backend_kwargs']['headers'][1])
        expected = copy.deepcopy(original)
        expected['backend_kwargs']['headers'][0]['value'] = new_kwargs['headers'][0]['value']
        expected['backend_kwargs']['password'] = new_kwargs['password']
        self.assertEqual(new_row, expected)
        self.assertEqual(output.receipt['rewrapped'], 2)
        self.assertEqual(output.receipt['noop_preserved'], 1)

    def test_each_declared_core_backend_secret_path(self):
        for backend, declaration in LOCK['stores'].items():
            kwargs = {}; expected = []
            for path in declaration['encrypted_kwargs_paths']:
                if '*' in path:
                    kwargs['headers'] = [{'name': 'X-Test', 'value': token(self.old, b'hello')}]
                    expected.append('headers.0.value')
                elif len(path) == 2:
                    kwargs[path[0]] = {path[1]: token(self.old, b'hello')}
                    expected.append('.'.join(path))
                else:
                    kwargs[path[0]] = token(self.old, b'hello'); expected.append(path[0])
            row = store(backend, kwargs=kwargs)
            result = self.run_projection([row], contexts=[self.ctx(row, p) for p in expected])
            self.assertEqual(result.receipt['rewrapped'], len(expected))
            self.assertEqual(set(result.stores[0]), set(row))

    def test_probe_actions_are_required_encrypted_surfaces_and_preserved(self):
        for backend, declaration in LOCK['actions'].items():
            row = {k: v for k, v in store().items() if k in rewrap.ACTION_FIELDS}
            row['backend'] = backend; contexts = []
            for path in declaration['encrypted_kwargs_paths']:
                if '*' in path:
                    row['backend_kwargs']['headers'] = [{'name': 'X-Action', 'value': token(self.old, b'action-secret')}]
                    actual = 'headers.0.value'
                else:
                    row['backend_kwargs'][path[0]] = token(self.old, b'action-secret'); actual = path[0]
                contexts.append(dict(model='probes.action', pk=row['id'], field=actual))
            original = copy.deepcopy(row)
            result = self.run_projection([], actions=[row], contexts=contexts)
            self.assertEqual(row, original)
            self.assertEqual(result.receipt['actions'], 1)
            self.assertEqual(result.receipt['rewrapped'], len(contexts))
            for key in rewrap.ACTION_FIELDS - {'backend_kwargs'}:
                self.assertEqual(result.actions[0][key], row[key])

    def test_terraform_history_uses_pinned_get_data_and_preserves_data_bytes(self):
        rows = []; contexts = []; expected = {}
        for pk in (1, 2, 100):
            encryption_key = Fernet.generate_key()
            data = ('historical state ' + str(pk)).encode() * 100
            rows.append(dict(id=pk, state_id=7, encryption_key=token(self.old, encryption_key),
                data=Fernet(encryption_key).encrypt(zlib.compress(data, level=9)), created_by_id=None,
                created_by_username='inactive historical admin', created_at='2020-01-01T00:00:00Z'))
            contexts.append(dict(model='terraform.stateversion', pk=pk, field='encryption_key'))
            expected[pk] = data
        original = copy.deepcopy(rows)
        result = self.run_projection([], rows, contexts)
        for old_row, new_row in zip(rows, result.state_versions):
            self.assertEqual(old_row['data'], new_row['data'])
            ns = dict(Fernet=Fernet, zlib=zlib, ensure_bytes=lambda v: v,
                decrypt=lambda value, **ctx: self.new.decrypt(value.split('$')[1], **ctx))
            exec(FIXTURE['snippets']['terraform']['code'], ns)
            instance = ns['StateVersion'](); instance.pk = new_row['id']
            instance.encryption_key = new_row['encryption_key']; instance.data = new_row['data']
            self.assertEqual(instance.get_data(), expected[instance.pk])
            comparison = copy.deepcopy(new_row); comparison['encryption_key'] = old_row['encryption_key']
            self.assertEqual(comparison, old_row)
        self.assertEqual(rows, original)

    def test_noop_preserves_exact_token_and_rotated_password_fallback(self):
        fallback = upstream('fernet', 'old-signing-salt', ('older-password',))
        row = store(kwargs={'password': token(fallback, b'older secret')})
        result = self.run_projection([row], contexts=[self.ctx(row, 'password')])
        self.assertEqual(self.new.decrypt(result.stores[0]['backend_kwargs']['password'].split('$')[1]), b'older secret')
        row['backend_kwargs']['password'] = token(self.noop, b'')
        result = self.run_projection([row], contexts=[self.ctx(row, 'password')])
        self.assertEqual(result.stores, [row])

    def test_noop_terraform_retains_key_and_history_bytes(self):
        key = Fernet.generate_key()
        row = dict(id=3, state_id=2, encryption_key=token(self.noop, key),
            data=Fernet(key).encrypt(zlib.compress(b'preserve old version')),
            created_by_id=10, created_by_username='old', created_at='old')
        result = self.run_projection([], [row], [dict(model='terraform.stateversion', pk=3, field='encryption_key')])
        self.assertEqual(result.state_versions, [row])
        self.assertEqual(result.receipt['noop_preserved'], 1)

    def test_identical_fernet_material_preserves_values_without_authority_claim(self):
        row = store(kwargs={'password': token(self.old, b'preserve without rotating material')})
        result = self.run_projection([row], contexts=[self.ctx(row, 'password')],
            new_material=self.kw['old_material'], targets={'fernet': 'fernet', 'noop': 'noop'})
        payload = result.stores[0]['backend_kwargs']['password'].split('$')[1]
        self.assertEqual(self.old.decrypt(payload), b'preserve without rotating material')
        self.assertFalse(result.receipt['restore_accepted'])
        self.assertFalse(result.receipt['current_authority_established'])

    def test_unknown_apps_fields_backends_duplicates_or_incomplete_rows_reject(self):
        row = store()
        bad_rows = [{**row, 'new_secret': 'unhandled'}, {k: v for k, v in row.items() if k != 'description'},
                    {**row, 'backend': 'SPLUNK'}, {**row, 'backend_kwargs': {'unknown': 'secret'}},
                    {**row, 'backend_kwargs': {'password': {'nested': 'not a token'}}}]
        for bad in bad_rows:
            with self.assertRaises(rewrap.RewrapRejected): self.run_projection([bad])
        with self.assertRaises(rewrap.RewrapRejected): self.run_projection([row, row])
        with self.assertRaises(rewrap.RewrapRejected): self.run_projection([row], apps=rewrap.APPS + ('zentral.contrib.mdm',))
        with patch.object(rewrap, 'MAX_ROWS', 0):
            with self.assertRaises(rewrap.RewrapRejected): self.run_projection([row])
        with patch.object(rewrap, 'MAX_BYTES', 1):
            with self.assertRaises(rewrap.RewrapRejected): self.run_projection([row])

    def test_wrong_context_inventory_missing_or_duplicate_context_rejects(self):
        row = store(kwargs={'password': token(self.old, b'secret')})
        good = self.ctx(row, 'password')
        for contexts in ([], [good, good], [{**good, 'field': 'headers.1.value'}],
                         [{**good, 'pk': 'different'}], [{**good, 'model': 'other.store'}]):
            with self.assertRaises(rewrap.RewrapRejected): self.run_projection([row], contexts=contexts)

    def test_wrong_salt_key_malformed_unknown_engine_or_kms_reject_without_mutation(self):
        tokens = ['unknown$payload', 'fernet$bad', 'bad', 'noop$%%%', 'noop$YQ==$',
                  token(upstream('fernet', 'wrong-salt', ('old-password',)), b'secret'),
                  token(upstream('fernet', 'old-signing-salt', ('wrong-password',)), b'secret')]
        for value in tokens:
            row = store(kwargs={'password': value}); original = copy.deepcopy(row)
            with self.assertRaises(rewrap.RewrapRejected) as caught:
                self.run_projection([row], contexts=[self.ctx(row, 'password')])
            self.assertEqual(row, original); self.assertNotIn(value, str(caught.exception))
        with self.assertRaises(rewrap.RewrapRejected):
            self.run_projection([], old_material={'kms': rewrap.Material('aws_kms')}, targets={'kms': 'new'})
        with self.assertRaises(rewrap.RewrapRejected):
            self.run_projection([], targets={'fernet': 'noop', 'noop': 'noop'})

    def test_late_failure_and_interrupt_leave_entire_inputs_unchanged(self):
        good = store(kwargs={'password': token(self.old, b'first')})
        bad = store(pk='22222222-2222-4222-8222-222222222222', kwargs={'password': 'fernet$invalid'})
        rows = [good, bad]; original = copy.deepcopy(rows)
        with self.assertRaises(rewrap.RewrapRejected):
            self.run_projection(rows, contexts=[self.ctx(r, 'password') for r in rows])
        self.assertEqual(rows, original)
        with patch.object(rewrap.Engine, 'encrypt', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt): self.run_projection([good], contexts=[self.ctx(good, 'password')])
        self.assertEqual(rows, original)

    def test_bad_terraform_data_and_decompression_bound_reject_preserving_history(self):
        key = Fernet.generate_key()
        row = dict(id=1, state_id=2, encryption_key=token(self.old, key), data=b'bad-data',
            created_by_id=None, created_by_username='keep', created_at='keep')
        ctx = [dict(model='terraform.stateversion', pk=1, field='encryption_key')]
        for data in (b'bad-data', Fernet(key).encrypt(b'not zlib'),
                     Fernet(key).encrypt(zlib.compress(b'a' * 10000))):
            row['data'] = data; original = copy.deepcopy(row)
            with patch.object(rewrap, 'MAX_STATE', 1000):
                with self.assertRaises(rewrap.RewrapRejected): self.run_projection([], [row], ctx)
            self.assertEqual(row, original)

    def test_receipt_repr_and_output_do_not_disclose_material_or_values(self):
        row = store(kwargs={'password': token(self.noop, b'synthetic-private-secret')})
        stdout = io.StringIO(); stderr = io.StringIO()
        from contextlib import redirect_stdout, redirect_stderr
        with redirect_stdout(stdout), redirect_stderr(stderr):
            result = self.run_projection([row], contexts=[self.ctx(row, 'password')])
        self.assertEqual(stdout.getvalue() + stderr.getvalue(), '')
        public = repr(result) + json.dumps(result.receipt) + repr(self.kw['old_material'])
        for sensitive in ('synthetic-private-secret', row['backend_kwargs']['password'], 'old-password', 'old-signing-salt'):
            self.assertNotIn(sensitive, public)
        self.assertFalse(result.receipt['restore_accepted'])
        self.assertFalse(result.receipt['current_authority_established'])

    def test_exact_source_fixture_provenance_and_profile_pin(self):
        self.assertEqual(LOCK['commit'], rewrap.COMMIT)
        self.assertEqual(FIXTURE['commit'], rewrap.COMMIT)
        for item in FIXTURE['snippets'].values():
            self.assertEqual(LOCK['files'][item['path']], item['sha256'])
        for name, item in FIXTURE['snippets'].items():
            self.assertEqual(hashlib.sha256(item['code'].encode()).hexdigest(), LOCK['test_excerpt_sha256'][name])
            source = item['source_code'].encode()
            wrapper = item['wrapper_prefix'].encode()
            self.assertEqual(item['code'].encode(), wrapper + source)
            self.assertEqual(len(source), item['source_byte_length'])
            self.assertEqual(hashlib.sha256(source).hexdigest(), item['source_sha256'])
            self.assertEqual(item['source_sha256'], LOCK['test_source_excerpt_sha256'][name])
            self.assertEqual(hashlib.sha256(wrapper).hexdigest(), item['wrapper_sha256'])
            self.assertEqual(item['wrapper_prefix'], 'class StateVersion:\n' if name == 'terraform' else '')
            self.assertGreaterEqual(item['source_byte_offset'], 0)
        self.assertEqual(LOCK['files']['zentral/core/secret_engines/backends/fernet.py'],
                         '0429f8298bbb382260f76c8448e061988d5633cb727dad36484e396794712cf4')


if __name__ == '__main__':
    unittest.main()
