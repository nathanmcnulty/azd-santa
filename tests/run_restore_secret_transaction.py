"""Verify a populated database rewrap and rollback on the sealed PostgreSQL fixture."""
from datetime import datetime
from pathlib import Path
import sys
import zlib

from cryptography.fernet import Fernet

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'experiments/server'))
import restore_authority_transaction as recovery
import restore_census as census
import restore_secret_transaction as transaction
import run_restore_authority_transaction as fixture
import secret_rewrap as secret

DATABASE = 'azd_recovery_' + 'b' * 24
KEY = b'synthetic rewrap census key.....'
STORE = '11111111-1111-4111-8111-111111111111'
ACTION = '22222222-2222-4222-8222-222222222222'
OLD = {'old': secret.Material('fernet', ('synthetic previous password',), 'synthetic previous signing salt'),
       'noop': secret.Material('noop')}
NEW = {'new': secret.Material('fernet', ('synthetic new password',), 'synthetic new signing salt'),
       'noop': secret.Material('noop')}
TARGETS = {'old': 'new', 'noop': 'noop'}
CONTEXTS = [
    {'model': 'stores.store', 'pk': STORE, 'field': 'headers.0.value'},
    {'model': 'stores.store', 'pk': STORE, 'field': 'password'},
    {'model': 'probes.action', 'pk': ACTION, 'field': 'url'},
    {'model': 'terraform.stateversion', 'pk': 1, 'field': 'encryption_key'},
]
MODELS = {
    'stores': '''
from django.db import models

class Store(models.Model):
    id = models.UUIDField(primary_key=True)
    name = models.TextField()
    description = models.TextField()
    created_at = models.DateTimeField()
    updated_at = models.DateTimeField()
    provisioning_uid = models.TextField()
    slug = models.TextField()
    admin_console = models.BooleanField()
    event_filters = models.JSONField()
    backend = models.TextField()
    backend_kwargs = models.JSONField()
''',
    'probes': '''
from django.db import models

class Action(models.Model):
    id = models.UUIDField(primary_key=True)
    name = models.TextField()
    description = models.TextField()
    created_at = models.DateTimeField()
    updated_at = models.DateTimeField()
    backend = models.TextField()
    backend_kwargs = models.JSONField()
''',
    'terraform': '''
from django.db import models

class StateVersion(models.Model):
    state_id = models.BigIntegerField()
    encryption_key = models.TextField()
    data = models.BinaryField()
    created_by_id = models.BigIntegerField()
    created_by_username = models.TextField()
    created_at = models.DateTimeField()
''',
}


def reject(call):
    try:
        call()
    except transaction.TransactionRejected as error:
        return error
    raise AssertionError('Expected rewrap to reject the attempt')


def run(root):
    fixture.DATABASE = DATABASE
    fixture.MODELS.update(MODELS)
    fixture.configure(root)
    from django.apps import apps
    from django.core.management import call_command
    from django.db import connections

    writer, observer, peer = (connections[name] for name in ('default', 'observer', 'peer'))
    try:
        call_command('makemigrations', 'accounts', 'realms', 'inventory', *MODELS, verbosity=0, interactive=False)
        call_command('migrate', verbosity=0, interactive=False)
        previous = secret.Engine('old', OLD['old'])
        replacement = secret.Engine('new', NEW['new'])

        def token(value, context):
            return 'old$' + previous.encrypt(value, context)

        model = apps.get_model('stores', 'Store')
        recorded = datetime(2026, 1, 1)
        model.objects.create(id=STORE, name='retained store', description='description',
            created_at=recorded, updated_at=recorded, provisioning_uid='retained', slug='retained',
            admin_console=False, event_filters={'retain': True}, backend='HTTP', backend_kwargs={
                'headers': [{'name': 'legacy', 'value': 'noop$c3ludGhldGlj'}],
                'password': token(b'store-password-fixture', CONTEXTS[1]), 'request_timeout': 1})
        apps.get_model('probes', 'Action').objects.create(id=ACTION, name='retained action',
            description='description', created_at=recorded, updated_at=recorded,
            backend='SLACK_INCOMING_WEBHOOK', backend_kwargs={'url': token(b'webhook-fixture', CONTEXTS[2])})
        history_key = Fernet.generate_key()
        history = Fernet(history_key).encrypt(zlib.compress(b'{"retained":"Terraform history"}'))
        apps.get_model('terraform', 'StateVersion').objects.create(id=1, state_id=7,
            encryption_key=token(history_key, CONTEXTS[3]), data=history,
            created_by_id=4, created_by_username='retained creator', created_at=recorded)
        numeric = '123456789.123456789012345678901234567890'
        with writer.cursor() as cursor:
            cursor.execute("""UPDATE stores_store SET backend_kwargs=jsonb_set(
                backend_kwargs, '{request_timeout}', to_jsonb(%s::numeric), false) WHERE id=%s""", (numeric, STORE))
            # A write on the last table should roll back the previous two writes.
            cursor.execute("""ALTER TABLE terraform_stateversion ADD CONSTRAINT preserved_old_key
                               CHECK (left(encryption_key, 4) = 'old$')""")

        observer.ensure_connection()

        def observe():
            return census.collect(observer, apps, fingerprint_key=KEY)

        def reviewed():
            initial = observe()
            assert initial.receipt['complete_supported_data']
            return dict(expected=initial, dispositions={item: 'preserve_inert'
                        for item in census.coverage_items(initial, fingerprint_key=KEY)})

        def invoke(baseline, **kwargs):
            options = dict(target=recovery.read_target(observer), expected_contexts=CONTEXTS,
                           old_material=OLD, new_material=NEW, targets=TARGETS, fingerprint_key=KEY)
            return transaction.run(writer, observer, apps, **{**options, **baseline, **kwargs})

        def unchanged(baseline):
            assert census.compare(observe(), fingerprint_key=KEY, **baseline)['exact_match']

        baseline = reviewed()
        preview = invoke(baseline)
        assert preview['inspected'] == 4 and preview['rewrapped'] == 3 and preview['noop_preserved'] == 1
        assert not preview['performs_mutation'] and not preview['rewrap_committed']
        assert invoke(baseline)['plan_digest'] == preview['plan_digest']
        failed = reject(lambda: invoke(baseline, apply=True, plan_digest=preview['plan_digest']))
        assert isinstance(failed.__context__, writer.Database.errors.CheckViolation)
        assert failed.__context__.diag.constraint_name == 'preserved_old_key'
        unchanged(baseline)

        with writer.cursor() as cursor:
            cursor.execute('ALTER TABLE terraform_stateversion DROP CONSTRAINT preserved_old_key')
        baseline = reviewed()
        preview = invoke(baseline)
        reject(lambda: invoke(baseline, apply=True, plan_digest='0' * 64))
        changed_key = {**NEW, 'new': secret.Material('fernet', ('another target password',), 'different salt')}
        reject(lambda: invoke(baseline, apply=True, plan_digest=preview['plan_digest'], new_material=changed_key))
        peer.ensure_connection()
        try:
            reject(lambda: invoke(baseline))
        finally:
            peer.close()
        unchanged(baseline)

        result = invoke(baseline, apply=True, plan_digest=preview['plan_digest'])
        assert result['rewrap_committed'] and result['performs_mutation']
        assert not result['restore_accepted'] and not result['current_authority_established']
        with observer.cursor() as cursor:
            cursor.execute("SELECT backend_kwargs #>> '{request_timeout}' FROM stores_store WHERE id=%s", (STORE,))
            assert cursor.fetchone() == (numeric,)
            cursor.execute('SELECT name, backend_kwargs::text FROM stores_store WHERE id=%s', (STORE,))
            name, raw = cursor.fetchone()
            kwargs = census.parse(raw)
            assert name == 'retained store' and kwargs['headers'] == [{'name':'legacy','value':'noop$c3ludGhldGlj'}]
            cursor.execute('SELECT backend_kwargs->>%s FROM probes_action WHERE id=%s', ('url', ACTION))
            action, = cursor.fetchone()
            cursor.execute('SELECT data, encryption_key FROM terraform_stateversion WHERE id=1')
            persisted_history, state_key = cursor.fetchone()
        assert bytes(persisted_history) == history
        for value, index, decoded in ((kwargs['password'], 1, b'store-password-fixture'),
                                      (action, 2, b'webhook-fixture'), (state_key, 3, history_key)):
            engine, payload = value.split('$', 1)
            assert engine == 'new' and replacement.decrypt(payload, CONTEXTS[index]) == decoded
        reject(lambda: invoke(baseline, apply=True, plan_digest=preview['plan_digest']))
        print('Verified transactional rewrap, late rollback, unchanged Terraform bytes and exact JSONB numbers')
    finally:
        connections.close_all()


if __name__ == '__main__':
    run(Path(sys.argv[1]))
