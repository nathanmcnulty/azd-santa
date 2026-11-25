"""Synthetic Django/PostgreSQL restore census integration for Linux CI."""

import argparse
import json
from pathlib import Path
import stat
import sys
from unittest.mock import patch

import django
from django.conf import settings

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'experiments/server'))
import restore_census as census

KEY = b'synthetic restore census key....'


def configure(root, *, restored=False):
    socket_dir = root / 'socket'
    assert stat.S_ISSOCK((socket_dir / '.s.PGSQL.5432').stat().st_mode)
    apps_path = root / 'apps'
    sys.path.insert(0, str(apps_path))
    if not restored:
        apps_path.mkdir()
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
    database = {
        'ENGINE': 'django.db.backends.postgresql', 'NAME': 'santa_census_fixture',
        'USER': 'postgres', 'HOST': str(socket_dir), 'PORT': 5432,
        'OPTIONS': {'connect_timeout': 5},
    }
    settings.configure(
        SECRET_KEY='synthetic-census-fixture-only',
        INSTALLED_APPS=['django.contrib.contenttypes', 'django.contrib.auth', *census.CONFIGURED],
        AUTH_USER_MODEL='accounts.User',
        DEFAULT_AUTO_FIELD='django.db.models.AutoField',
        DATABASES={'default': database, 'census_runtime': {**database, 'USER': 'census_runtime'}},
        USE_TZ=True,
    )
    django.setup()


def reject(operation):
    try:
        operation()
    except census.CensusRejected as error:
        return error
    raise AssertionError('Expected the restore census to reject the fixture')


def run(root):
    configure(root)
    from django.apps import apps
    from django.core.management import call_command
    from django.db import connections

    db = connections['default']
    runtime = connections['census_runtime']
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
            cursor.execute('CREATE ROLE census_runtime LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS')
            cursor.execute('GRANT CONNECT, TEMPORARY ON DATABASE santa_census_fixture TO census_runtime')
            cursor.execute('REVOKE CREATE ON SCHEMA public FROM PUBLIC')
            cursor.execute('GRANT USAGE ON SCHEMA public TO census_runtime')
            cursor.execute('GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO census_runtime')
            cursor.execute('REVOKE INSERT, UPDATE, DELETE ON public.django_migrations FROM census_runtime')
            cursor.execute('GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO census_runtime')
            cursor.execute('ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO census_runtime')
            cursor.execute('ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO census_runtime')

        def observe(**kwargs):
            return census.collect(db, apps, fingerprint_key=KEY, **kwargs)

        baseline = observe()
        assert baseline.receipt['complete_supported_data'], baseline.manifest['unsupported']
        assert not baseline.receipt['schema_complete']
        grants = {row['object_type']: row for row in baseline.manifest['catalog']['default_privileges']}
        assert set(grants) == {'r', 'S'}, grants
        for object_type, privileges in (('r', ['DELETE', 'INSERT', 'SELECT', 'UPDATE']), ('S', ['SELECT', 'USAGE'])):
            assert grants[object_type] == {
                'owner': 'postgres', 'schema': 'public', 'object_type': object_type,
                'grants': [{'grantor': 'postgres', 'grantee': 'census_runtime',
                            'privilege': privilege, 'grantable': False} for privilege in privileges],
            }, grants
        models = {row['label']: row for row in baseline.manifest['registry']['models']}
        assert models['accounts.userproxy']['proxy']
        assert models['auth.user']['swapped'] == 'accounts.User'
        assert models['accounts.user_groups']['auto_created']
        assert 'contenttypes.contenttype' in models
        migrations = baseline.manifest['migrations']
        applied = {(r['app'], r['name']) for r in migrations['applied']}
        with db.cursor() as cursor:
            cursor.execute('SELECT app, name FROM django_migrations')
            assert applied == set(cursor.fetchall())
        assert ('accounts', '0001_initial') in applied
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
        with runtime.cursor() as cursor:
            cursor.execute("""SELECT current_user, session_user, inet_server_addr(),
              has_schema_privilege(current_user, 'public', 'CREATE'),
              has_table_privilege(current_user, 'public.django_migrations', 'INSERT,UPDATE,DELETE'),
              has_column_privilege(current_user, 'pg_catalog.pg_subscription', 'subconninfo', 'SELECT')""")
            assert cursor.fetchone() == ('census_runtime', 'census_runtime', None, False, False, False)

        def observe_runtime():
            return census.collect(runtime, apps, fingerprint_key=KEY)

        runtime_baseline = observe_runtime()
        assert runtime_baseline.receipt['complete_supported_data'], runtime_baseline.manifest['unsupported']
        assert runtime_baseline.manifest['data'] == baseline.manifest['data']
        assert runtime_baseline.manifest['migrations'] == baseline.manifest['migrations']
        runtime_dispositions = {
            item: 'preserve_inert' for item in census.coverage_items(runtime_baseline, fingerprint_key=KEY)
        }

        def compare_runtime(observed):
            return census.compare(observed, runtime_baseline, runtime_dispositions, fingerprint_key=KEY)

        assert compare_runtime(observe_runtime())['exact_match']
        with db.cursor() as cursor:
            cursor.execute("""CREATE SUBSCRIPTION census_inert_subscription
              CONNECTION 'host=/no-census-publisher dbname=fixture'
              PUBLICATION census_inert_publication WITH (connect=false, slot_name=NONE)""")
        subscription = observe_runtime()
        assert {'kind': 'subscriptions', 'count': 1} in subscription.manifest['catalog']['global_blockers']
        assert not subscription.receipt['complete_supported_data']
        assert subscription.manifest['data'] == {} and subscription.manifest['migrations'] is None
        reject(lambda: compare_runtime(subscription))
        with db.cursor() as cursor:
            cursor.execute('DROP SUBSCRIPTION census_inert_subscription')
        assert compare_runtime(observe_runtime())['exact_match']
        with db.cursor() as cursor:
            cursor.execute('ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE UPDATE ON TABLES FROM census_runtime')
        changed_grants = observe()
        assert changed_grants.manifest['data'] == baseline.manifest['data']
        assert changed_grants.receipt['complete_supported_data']
        reject(lambda: compare(changed_grants))
        with db.cursor() as cursor:
            cursor.execute('ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT UPDATE ON TABLES TO census_runtime')
            cursor.execute('ALTER DEFAULT PRIVILEGES GRANT SELECT ON TABLES TO PUBLIC')
        global_grants = observe()
        assert global_grants.receipt['complete_supported_data']
        assert any(row['schema'] is None and row['object_type'] == 'r'
                   and any(grant['grantee'] is None and grant['privilege'] == 'SELECT' for grant in row['grants'])
                   for row in global_grants.manifest['catalog']['default_privileges'])
        reject(lambda: compare(global_grants))
        with db.cursor() as cursor:
            cursor.execute('ALTER DEFAULT PRIVILEGES REVOKE SELECT ON TABLES FROM PUBLIC')
        assert compare(observe())['exact_match']
        with db.cursor() as cursor:
            cursor.execute('CREATE ACCESS METHOD census_heap TYPE TABLE HANDLER pg_catalog.heap_tableam_handler')
            cursor.execute('CREATE TABLE custom_storage (name text) USING census_heap')
        blocked = observe()
        refs = blocked.manifest['catalog']['unreviewed_references']
        assert any(ref['catalog'] == 'pg_am' and ref['schema'] is None
                   and ref['identity'] == 'census_heap' for ref in refs), refs
        assert not blocked.receipt['complete_supported_data']
        assert blocked.manifest['data'] == {} and blocked.manifest['migrations'] is None
        reject(lambda: compare(blocked))
        with db.cursor() as cursor:
            cursor.execute('DROP TABLE custom_storage')
            cursor.execute('DROP ACCESS METHOD census_heap')
        assert compare(observe())['exact_match']
        reject(lambda: observe(limits=census.Limits(rows=1)))
        raw = db.connection
        idle = db.Database.extensions.TRANSACTION_STATUS_IDLE
        assert raw.get_transaction_status() == idle
        with patch.dict(census.CATALOG, {'schemas': "SELECT 'null'::text FROM pg_sleep(2)"}):
            error = reject(lambda: observe(limits=census.Limits(statement_ms=50)))
        while error is not None and not isinstance(error, db.Database.errors.QueryCanceled):
            error = error.__context__
        assert isinstance(error, db.Database.errors.QueryCanceled)
        assert raw.get_transaction_status() == idle
        with patch.object(census.Reader, 'read', side_effect=KeyboardInterrupt):
            try:
                observe()
            except KeyboardInterrupt:
                pass
            else:
                raise AssertionError('Interrupt did not propagate')
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
        with db.cursor() as cursor:
            cursor.execute('ALTER TABLE "probe%s%rows" DISABLE ROW LEVEL SECURITY')
        final_source = observe_runtime()
        assert final_source.receipt['complete_supported_data'], final_source.manifest['unsupported']
        assert final_source.manifest['data'][table]['rows'] == 3
        # The fingerprint encoding has typed tags. Keep the fixture handoff
        # as ordinary JSON so the second process can rebuild the same Census.
        with (root / 'source-census.json').open('x', encoding='utf-8') as output:
            json.dump({'manifest': final_source.manifest, 'receipt': final_source.receipt}, output)
        print('Django migration, schema, restricted role, row and transaction census fixture passed')
    finally:
        runtime.close()
        db.close()


def verify_restored(root):
    configure(root, restored=True)
    from django.apps import apps
    from django.db import connections

    expected = census.Census(**census.parse((root / 'source-census.json').read_bytes()))
    dispositions = {item: 'preserve_inert' for item in census.coverage_items(expected, fingerprint_key=KEY)}
    runtime = connections['census_runtime']
    try:
        with runtime.cursor() as cursor:
            cursor.execute('SELECT current_user, session_user, current_database(), inet_server_addr(), pg_is_in_recovery()')
            assert cursor.fetchone() == ('census_runtime', 'census_runtime', 'santa_census_fixture', None, False)
        observed = census.collect(runtime, apps, fingerprint_key=KEY)
        result = census.compare(observed, expected, dispositions, fingerprint_key=KEY)
        assert result['exact_match'] and not result['restore_accepted'] and not result['current_authority']
        with runtime.cursor() as cursor:
            cursor.execute('INSERT INTO "probe%s%rows" VALUES (\'changed restored row\')')
        changed = census.collect(runtime, apps, fingerprint_key=KEY)
        table = census.relation_key('public', 'probe%s%rows')
        assert changed.manifest['data'][table]['rows'] == 4
        reject(lambda: census.compare(changed, expected, dispositions, fingerprint_key=KEY))
        print('Cold PostgreSQL volume restored to a fresh isolated container and matched the source census')
    finally:
        runtime.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('--verify-restored', action='store_true')
    args = parser.parse_args()
    (verify_restored if args.verify_restored else run)(args.root)
