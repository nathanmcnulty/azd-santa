"""Verify a populated database rewrap and rollback on the sealed PostgreSQL fixture."""
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import sys
import zlib

from cryptography.fernet import Fernet

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'experiments/server'))
import restore_authority_transaction as recovery
import restore_census as census
import restore_census_review as review
import restore_quarantine_journal as journal
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


def reject(call, error_type=transaction.TransactionRejected):
    try:
        call()
    except error_type as error:
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
        user = apps.get_model('accounts', 'User').objects.create_user(
            username='archived-operator', password='synthetic archived password', is_superuser=True)
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
        target = recovery.read_target(observer)
        cutoff = datetime.now(timezone.utc)
        directory = root / 'journal'
        directory.mkdir(mode=0o700)
        bound = dict(target=target, archive_sha256='a' * 64, generation='b' * 64, fingerprint_key=KEY)
        secret_options = dict(expected_contexts=CONTEXTS, old_material=OLD, new_material=NEW, targets=TARGETS)

        def observe():
            return census.collect(observer, apps, fingerprint_key=KEY)

        def reviewed():
            initial = observe()
            assert initial.receipt['complete_supported_data']
            return dict(expected=initial, dispositions={item: 'preserve_inert'
                        for item in census.coverage_items(initial, fingerprint_key=KEY)})

        def invoke(baseline, **kwargs):
            options = dict(target=target, fingerprint_key=KEY, **secret_options)
            return transaction.run(writer, observer, apps, **{**options, **baseline, **kwargs})

        def published(stage, baseline, context=bound):
            raw = review.publish(**baseline, **context, stage=stage)
            return dict(review=raw, review_sha256=hashlib.sha256(raw).hexdigest())

        def guided(stage, baseline, *, folder=directory, context=bound, **kwargs):
            options = secret_options if stage == 'rewrap' else dict(cutoff=cutoff)
            inputs = published(stage, baseline, context)
            return review.run(writer, observer, apps, **context, directory=folder, stage=stage,
                              **{**inputs, 'options': options, **kwargs})

        def deny(call):
            return reject(call, (journal.JournalRejected, review.ReviewRejected))

        def authorized(stage, baseline, preview, context, record):
            assert record == dict(scope=review.SCOPE, binding=journal.binding_for(
                context['target'], context['archive_sha256'], context['generation'], KEY), stage=stage,
                plan_digest=preview['plan_digest'], review_sha256=published(stage, baseline, context)['review_sha256'])
            return True

        def unchanged(baseline):
            assert census.compare(observe(), fingerprint_key=KEY, **baseline)['exact_match']

        baseline = reviewed()
        preview = invoke(baseline)
        assert preview['inspected'] == 4 and preview['rewrapped'] == 3 and preview['noop_preserved'] == 1
        assert not preview['performs_mutation'] and not preview['rewrap_committed']
        assert invoke(baseline)['plan_digest'] == preview['plan_digest']
        failed = reject(lambda: invoke(baseline, apply=True, plan_digest=preview['plan_digest']))
        constraint_failure = failed.__context__.__cause__
        assert isinstance(constraint_failure, writer.Database.errors.CheckViolation)
        assert constraint_failure.diag.constraint_name == 'preserved_old_key'
        unchanged(baseline)
        failed_directory = root / 'journal-failed'
        failed_directory.mkdir(mode=0o700)
        failed_bound = {**bound, 'generation': 'f' * 64}
        interrupted = guided('rewrap', baseline, folder=failed_directory, context=failed_bound)
        deny(lambda: guided('rewrap', baseline, folder=failed_directory, context=failed_bound,
                            plan_digest=interrupted['plan_digest'], authorize=lambda record: authorized(
                                'rewrap', baseline, interrupted, failed_bound, record)))
        assert journal.inspect(failed_directory, **failed_bound)['stages'] == {
            'rewrap': 'inspect', 'quarantine': 'pending'}
        deny(lambda: guided('rewrap', baseline, folder=failed_directory, context=failed_bound))
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

        deny(lambda: guided('quarantine', baseline))
        deny(lambda: guided('rewrap', baseline, options={**secret_options, 'apply': True,
                                                          'plan_digest': preview['plan_digest']}))
        reviewed_plan = guided('rewrap', baseline)
        assert reviewed_plan['stages'] == {'rewrap': 'pending', 'quarantine': 'pending'}
        artifact = published('rewrap', baseline)
        deny(lambda: guided('rewrap', baseline, review=artifact['review'] + b' '))
        deny(lambda: guided('quarantine', baseline, **artifact))
        deny(lambda: guided('rewrap', baseline, context={**bound, 'generation': '0' * 64}, **artifact))
        deny(lambda: guided('rewrap', baseline, plan_digest=reviewed_plan['plan_digest']))
        deny(lambda: guided('rewrap', baseline, plan_digest=reviewed_plan['plan_digest'], authorize=lambda _: False))
        calls = []
        deny(lambda: guided('rewrap', baseline, context={**bound, 'archive_sha256': 'c' * 64},
                            plan_digest=reviewed_plan['plan_digest'], authorize=calls.append))
        assert not calls
        with writer.cursor() as cursor:
            cursor.execute("UPDATE stores_store SET description='temporarily changed'")
        deny(lambda: guided('rewrap', baseline, **artifact))
        with writer.cursor() as cursor:
            cursor.execute("UPDATE stores_store SET description='description'")
        unchanged(baseline)
        assert not list(directory.iterdir())
        applied = guided('rewrap', baseline, plan_digest=reviewed_plan['plan_digest'],
                         authorize=lambda record: authorized('rewrap', baseline, reviewed_plan, bound, record))
        assert applied['stages'] == {'rewrap': 'committed', 'quarantine': 'pending'}
        result = applied['result']
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
        deny(lambda: guided('rewrap', baseline, plan_digest=reviewed_plan['plan_digest'], authorize=calls.append))
        deny(lambda: guided('quarantine', baseline))
        deny(lambda: journal.inspect(directory, **{**bound, 'generation': '0' * 64}))
        subsequent = reviewed()
        quarantine = guided('quarantine', subsequent)
        completed = guided('quarantine', subsequent, plan_digest=quarantine['plan_digest'],
                           authorize=lambda record: authorized('quarantine', subsequent, quarantine, bound, record))
        assert completed['result']['authority_updates_committed'] and completed['result']['performs_mutation']
        user.refresh_from_db()
        assert not user.is_active and not user.check_password('synthetic archived password')
        inspected = journal.inspect(directory, **bound)
        assert inspected['stages'] == {'rewrap': 'committed', 'quarantine': 'committed'}
        assert not inspected['activation_allowed'] and not inspected['current_authority_established']
        deny(lambda: guided('quarantine', subsequent, plan_digest=quarantine['plan_digest'], authorize=calls.append))
        assert not calls
        with journal.locked(directory):
            deny(lambda: journal.inspect(directory, **bound))
        (directory / 'quarantine-committed.json').write_text('{}')
        deny(lambda: journal.inspect(directory, **bound))
        unchanged_failure = journal.inspect(failed_directory, **failed_bound)
        assert unchanged_failure['stages']['rewrap'] == 'inspect'
        print('Verified guided rewrap and authority handoff, durable intent, replay denial and closed activation')
        print('Verified private review handoff, stale census rejection and authorization before database intent')
        print('Verified transactional rewrap, late rollback, unchanged Terraform bytes and exact JSONB numbers')
    finally:
        connections.close_all()


if __name__ == '__main__':
    run(Path(sys.argv[1]))
