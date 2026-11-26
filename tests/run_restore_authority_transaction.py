"""Exercise the authority transaction on the disposable restored PostgreSQL node."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys

import django
from django.conf import settings

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'experiments/server'))
import restore_authority_transaction as transaction
import restore_census as census

DATABASE = 'azd_recovery_' + 'a' * 24
KEY = b'synthetic restore census key....'

MODELS = {
    'accounts': '''
import uuid
from django.contrib.auth.models import AbstractUser
from django.db import models

class User(AbstractUser):
    pass

class Policy(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    is_active = models.BooleanField(default=True)
    source = models.TextField()

class APIToken(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    expiry = models.DateTimeField(null=True)
    hashed_key = models.CharField(max_length=64)

class OIDCAPITokenIssuer(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    cel_condition = models.TextField()
''',
    'realms': '''
import uuid
from django.db import models

class Realm(models.Model):
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4)
    enabled_for_login = models.BooleanField(default=True)
    user_portal = models.BooleanField(default=True)
    scim_enabled = models.BooleanField(default=True)

class RealmAuthenticationSession(models.Model):
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4)
    expires_at = models.DateTimeField(null=True)
''',
    'inventory': '''
from django.db import models

class EnrollmentSecret(models.Model):
    revoked_at = models.DateTimeField(null=True)
    request_count = models.IntegerField()
''',
}


def configure(root):
    source = root / (DATABASE + '-apps')
    source.mkdir(mode=0o700)
    sys.path.insert(0, str(source))
    for app in census.CONFIGURED:
        directory = source / app
        directory.mkdir()
        (directory / '__init__.py').touch()
        if app in MODELS:
            (directory / 'models.py').write_text(MODELS[app], encoding='utf-8')
    database = {'ENGINE': 'django.db.backends.postgresql', 'NAME': DATABASE,
                'HOST': str(root / 'socket'), 'USER': 'postgres', 'PORT': 5432}
    settings.configure(
        SECRET_KEY='synthetic-authority-fixture-only',
        INSTALLED_APPS=['django.contrib.auth', 'django.contrib.contenttypes',
                        'django.contrib.sessions', *census.CONFIGURED],
        AUTH_USER_MODEL='accounts.User', DEFAULT_AUTO_FIELD='django.db.models.AutoField',
        DATABASES={alias: database.copy() for alias in ('default', 'observer', 'peer')},
        TIME_ZONE='UTC', USE_TZ=False)
    django.setup()


def reject(operation):
    try:
        operation()
    except transaction.TransactionRejected as error:
        return error
    raise AssertionError('Expected the authority transaction to reject this attempt')


def run(root):
    configure(root)
    from django.apps import apps
    from django.core.management import call_command
    from django.db import connections

    writer, observer = connections['default'], connections['observer']
    peer = connections['peer']
    try:
        call_command('makemigrations', 'accounts', 'realms', 'inventory', verbosity=0, interactive=False)
        call_command('migrate', verbosity=0, interactive=False)
        cutoff = datetime.now(timezone.utc)
        later = cutoff.replace(tzinfo=None) + timedelta(days=1)
        earlier = cutoff.replace(tzinfo=None) - timedelta(days=1)
        user = apps.get_model('accounts', 'User').objects.create_user(
            username='historical-fixture', password='historical-example-password', is_staff=True, is_superuser=True)
        policy = apps.get_model('accounts', 'Policy').objects.create(source='retained-policy')
        token = apps.get_model('accounts', 'APIToken').objects.create(hashed_key='retained-token-hash')
        expired = apps.get_model('accounts', 'APIToken').objects.create(hashed_key='earlier-token', expiry=earlier)
        issuer = apps.get_model('accounts', 'OIDCAPITokenIssuer').objects.create(cel_condition='true')
        session = apps.get_model('sessions', 'Session').objects.create(
            session_key='history-fixture', session_data='retained-session', expire_date=later)
        realm = apps.get_model('realms', 'Realm').objects.create()
        realm_session = apps.get_model('realms', 'RealmAuthenticationSession').objects.create()
        enroll = apps.get_model('inventory', 'EnrollmentSecret').objects.create(request_count=3)
        revoked = apps.get_model('inventory', 'EnrollmentSecret').objects.create(request_count=7, revoked_at=earlier)
        peer.close()
        observer.ensure_connection()
        target = transaction.read_target(observer)

        def observe():
            return census.collect(observer, apps, fingerprint_key=KEY)

        def reviewed():
            expected = observe()
            assert expected.receipt['complete_supported_data'], expected.manifest['unsupported']
            dispositions = {item: 'preserve_inert' for item in census.coverage_items(expected, fingerprint_key=KEY)}
            return expected, dispositions

        def invoke(expected, dispositions, **options):
            return transaction.run(writer, observer, apps, expected=expected, dispositions=dispositions,
                                   fingerprint_key=KEY, **{'cutoff': cutoff, 'target': target, **options})

        # PostgreSQL must roll back earlier updates if the last authority table
        # rejects its write. The reviewed census intentionally includes this test constraint.
        with writer.cursor() as cursor:
            cursor.execute("""ALTER TABLE inventory_enrollmentsecret
                ADD CONSTRAINT test_deny_quarantine CHECK (request_count<>3 OR revoked_at IS NULL)""")
        expected, dispositions = reviewed()
        preview = invoke(expected, dispositions)
        assert not preview['performs_mutation'] and not preview['authority_updates_committed']
        assert sum(preview['planned_rows'].values()) == 8
        failure = reject(lambda: invoke(expected, dispositions, apply=True, plan_digest=preview['plan_digest']))
        constraint_failure = failure.__context__.__cause__
        assert isinstance(constraint_failure, writer.Database.errors.CheckViolation)
        assert constraint_failure.diag.constraint_name == 'test_deny_quarantine'
        assert census.compare(observe(), expected, dispositions, fingerprint_key=KEY)['exact_match']

        with writer.cursor() as cursor:
            cursor.execute('ALTER TABLE inventory_enrollmentsecret DROP CONSTRAINT test_deny_quarantine')
        expected, dispositions = reviewed()
        preview = invoke(expected, dispositions)
        reject(lambda: invoke(expected, dispositions, target=replace(target, database_oid=target.database_oid+1)))
        reject(lambda: invoke(expected, dispositions, apply=True, plan_digest='0' * 64))
        peer.ensure_connection()
        try:
            reject(lambda: invoke(expected, dispositions))
        finally:
            peer.close()
        assert census.compare(observe(), expected, dispositions, fingerprint_key=KEY)['exact_match']
        result = invoke(expected, dispositions, apply=True, plan_digest=preview['plan_digest'])
        assert result['authority_updates_committed'] and result['performs_mutation']
        assert not result['restore_accepted'] and not result['current_authority_established']
        for row in (user, policy, token, expired, issuer, session, realm, realm_session, enroll, revoked):
            row.refresh_from_db()
        assert not user.is_active and not user.check_password('historical-example-password')
        assert user.is_superuser and user.is_staff
        assert not policy.is_active and policy.source == 'retained-policy'
        assert token.expiry == cutoff.replace(tzinfo=None) and token.hashed_key == 'retained-token-hash'
        assert expired.expiry == earlier
        assert issuer.cel_condition == 'false'
        assert session.expire_date == cutoff.replace(tzinfo=None) and session.session_data == 'retained-session'
        assert not any((realm.enabled_for_login, realm.user_portal, realm.scim_enabled))
        assert realm_session.expires_at == cutoff.replace(tzinfo=None)
        assert enroll.revoked_at == cutoff.replace(tzinfo=None) and enroll.request_count == 3
        assert revoked.revoked_at == earlier and revoked.request_count == 7
        reject(lambda: invoke(expected, dispositions, apply=True, plan_digest=preview['plan_digest']))
        print('Restored authority transaction committed all eight dispositions and rejected stale review and partial writes')
    finally:
        connections.close_all()


if __name__ == '__main__':
    run(Path(sys.argv[1]))
