"""Synthetic Django/PostgreSQL restore census integration for Linux CI."""

from pathlib import Path
import stat
import sys
from unittest.mock import patch

import django
from django.conf import settings

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'experiments/server'))
import restore_census as census

KEY = b'synthetic restore census key....'


def configure(root):
    socket_dir = root / 'socket'
    assert stat.S_ISSOCK((socket_dir / '.s.PGSQL.5432').stat().st_mode)
    apps_path = root / 'apps'
    apps_path.mkdir()
    sys.path.insert(0, str(apps_path))
    for label in census.CONFIGURED:
        package = apps_path / label
        package.mkdir()
        (package / '__init__.py').touch()
    (apps_path / 'accounts' / 'models.py').write_text('''
from django.contrib.auth.models import AbstractUser

class User(AbstractUser):
    pass

class UserProxy(User):
    class Meta:
        proxy = True
''', encoding='utf-8')
    settings.configure(
        SECRET_KEY='synthetic-census-fixture-only',
        INSTALLED_APPS=['django.contrib.contenttypes', 'django.contrib.auth', *census.CONFIGURED],
        AUTH_USER_MODEL='accounts.User',
        DEFAULT_AUTO_FIELD='django.db.models.AutoField',
        DATABASES={'default': {
            'ENGINE': 'django.db.backends.postgresql', 'NAME': 'santa_census_fixture',
            'USER': 'postgres', 'HOST': str(socket_dir), 'PORT': 5432,
            'OPTIONS': {'connect_timeout': 5},
        }},
        USE_TZ=True,
    )
    django.setup()


def reject(operation):
    try:
        operation()
    except census.CensusRejected:
        return
    raise AssertionError('Expected the restore census to reject the fixture')


def run(root):
    configure(root)
    from django.apps import apps
    from django.core.management import call_command
    from django.db import connections

    db = connections['default']
    try:
        with db.cursor() as cursor:
            cursor.execute("SELECT current_database(), inet_server_addr(), current_setting('server_version_num')")
            name, address, version = cursor.fetchone()
            assert name == 'santa_census_fixture' and address is None and int(version) // 10000 == 18
        assert django.get_version() == '5.2.18'
        assert db.Database.__version__.split()[0] == '2.9.11'
        call_command('makemigrations', 'accounts', verbosity=0, interactive=False)
        call_command('migrate', verbosity=0, interactive=False)
        user = apps.get_model('accounts', 'User').objects.create(username='synthetic-user')
        user.groups.add(apps.get_model('auth', 'Group').objects.create(name='synthetic-group'))
        with db.cursor() as cursor:
            cursor.execute('CREATE TABLE "probe%s%rows" (name text, tombstone integer)')
            cursor.execute('ALTER TABLE "probe%s%rows" DROP COLUMN tombstone')
            cursor.execute('INSERT INTO "probe%s%rows" VALUES (\'same row\'), (\'same row\')')

        def observe(**kwargs):
            return census.collect(db, apps, fingerprint_key=KEY, **kwargs)

        baseline = observe()
        assert baseline.receipt['complete_supported_data'], baseline.manifest['unsupported']
        assert not baseline.receipt['schema_complete']
        models = {row['label']: row for row in baseline.manifest['registry']['models']}
        assert models['accounts.userproxy']['proxy']
        assert models['auth.user']['swapped'] == 'accounts.User'
        assert models['accounts.user_groups']['auto_created']
        assert 'contenttypes.contenttype' in models
        migrations = baseline.manifest['migrations']
        assert ('accounts', '0001_initial') in {(r['app'], r['name']) for r in migrations['applied']}
        graph = {tuple(row['node']): row['parents'] for row in migrations['graph']}
        assert graph['auth', '0002_alter_permission_name_max_length'] == [['auth', '0001_initial']]
        relations = baseline.manifest['catalog']['columns']
        columns = [column for column in relations if column['table'] == 'probe%s%rows']
        assert any(column['dropped'] for column in columns)
        assert any(column['type_oid'] == 25 for column in columns)
        table = census.relation_key('public', 'probe%s%rows')
        assert baseline.manifest['data'][table]['rows'] == 2
        dispositions = {item: 'preserve_inert' for item in census.coverage_items(baseline, fingerprint_key=KEY)}

        def compare(observed):
            return census.compare(observed, baseline, dispositions, fingerprint_key=KEY)

        assert compare(observe())['exact_match']
        reject(lambda: observe(limits=census.Limits(rows=1)))
        raw = db.connection
        idle = db.Database.extensions.TRANSACTION_STATUS_IDLE
        assert raw.get_transaction_status() == idle
        with patch.dict(census.CATALOG, {'schemas': "SELECT 'null'::text FROM pg_sleep(2)"}):
            reject(lambda: observe(limits=census.Limits(statement_ms=50)))
        assert raw.get_transaction_status() == idle
        with raw.cursor() as cursor:
            cursor.execute('BEGIN')
            try:
                cursor.execute('INSERT INTO "probe%s%rows" VALUES (\'uncommitted\')')
                with patch.object(census, 'Reader', side_effect=AssertionError('Unexpected reader')) as reader:
                    reject(observe)
                    reader.assert_not_called()
                cursor.execute('SELECT count(*) FROM "probe%s%rows"')
                assert cursor.fetchone() == (3,)
            finally:
                cursor.execute('ROLLBACK')
        assert raw.get_transaction_status() == idle
        assert compare(observe())['exact_match']

        with db.cursor() as cursor:
            cursor.execute('INSERT INTO "probe%s%rows" VALUES (\'same row\')')
        changed = observe()
        assert changed.manifest['data'][table]['rows'] == 3
        reject(lambda: compare(changed))
        with db.cursor() as cursor:
            cursor.execute('ALTER TABLE "probe%s%rows" ENABLE ROW LEVEL SECURITY')
        blocked = observe()
        assert blocked.manifest['data'] == {} and not blocked.receipt['complete_supported_data']
        reject(lambda: compare(blocked))
        print('Django migration, schema, row and transaction census fixture passed')
    finally:
        db.close()


if __name__ == '__main__':
    run(Path(sys.argv[1]))
