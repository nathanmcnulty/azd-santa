"""Original Unlicense fresh-only local PostgreSQL authority separation.

No cloud authority or imports of Django/psycopg until explicitly invoked. Normal
runtime checks never migrate, provision, create a role or rotate a credential.
"""
import json
import os
from pathlib import Path
import re
import stat
from contextlib import closing

BOOTSTRAP = 'zentral_owner'
RUNTIME = 'zentral_runtime'
DATABASE = 'zentral'
ENV_KEYS = {'POSTGRES_USER', 'POSTGRES_PASSWORD', 'ZENTRAL_DJANGO_SECRET',
            'ZENTRAL_METRICS_TOKEN', 'AZD_SANTA_SECURITY_STORE_ID', 'ZENTRAL_QUEUE_URL'}
# PostgreSQL excludes our own temporary TOAST namespace from
# pg_is_other_temp_schema too; derive it from the actual current temp namespace.
PERMANENT_SCHEMAS = '''n.oid <> pg_my_temp_schema() AND NOT pg_is_other_temp_schema(n.oid)
    AND n.nspname NOT IN (SELECT 'pg_toast_temp_' || substr(t.nspname,9)
                         FROM pg_namespace t WHERE t.oid=pg_my_temp_schema())'''


def need(condition):
    if not condition:
        raise ValueError('Database authority or initialization boundary failed')


def runtime_file(value):
    path = Path(value)
    need(path.is_absolute() and path == path.resolve(strict=True))
    info = path.stat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_mode & 0o077 == 0)
    result = {}
    for line in path.read_text().splitlines():
        key, item = line.split('=', 1)
        need(key not in result)
        result[key] = item
    need(set(result) == ENV_KEYS and result['POSTGRES_USER'] == RUNTIME
         and re.fullmatch(r'[A-Za-z0-9_-]{64}', result['POSTGRES_PASSWORD']))
    return result


def check_role(cursor):
    cursor.execute('SELECT current_user, session_user, current_database()')
    need(cursor.fetchone() == (RUNTIME, RUNTIME, DATABASE))
    cursor.execute('''SELECT rolsuper, rolcreatedb, rolcreaterole, rolreplication,
                            rolbypassrls, rolinherit FROM pg_roles WHERE rolname = current_user''')
    need(cursor.fetchone() == (False,) * 6)
    cursor.execute('''SELECT EXISTS (SELECT 1 FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.member
                                    WHERE r.rolname=current_user)''')
    need(not cursor.fetchone()[0])
    cursor.execute("SELECT has_database_privilege(current_user,current_database(),'CREATE'), has_database_privilege(current_user,current_database(),'TEMPORARY'), has_schema_privilege(current_user,'public','CREATE'), has_schema_privilege(current_user,'public','USAGE')")
    need(cursor.fetchone() == (False, True, False, True))
    cursor.execute('SELECT datdba=(SELECT oid FROM pg_roles WHERE rolname=current_user) FROM pg_database WHERE datname=current_database()')
    need(not cursor.fetchone()[0])
    cursor.execute('''SELECT EXISTS (SELECT 1 FROM pg_namespace n WHERE ''' + PERMANENT_SCHEMAS + '''
                                     AND (n.nspowner=(SELECT oid FROM pg_roles WHERE rolname=current_user)
                                          OR has_schema_privilege(current_user,n.oid,'CREATE')))''')
    need(not cursor.fetchone()[0])
    cursor.execute('''SELECT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
                                     WHERE ''' + PERMANENT_SCHEMAS + '''
                                     AND c.relowner=(SELECT oid FROM pg_roles WHERE rolname=current_user))''')
    need(not cursor.fetchone()[0])
    cursor.execute("SELECT has_table_privilege(current_user,'public.django_migrations','SELECT'), has_table_privilege(current_user,'public.django_migrations','INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER,REFERENCES')")
    need(cursor.fetchone() == (True, False))
    cursor.execute('''SELECT EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
                                     WHERE ''' + PERMANENT_SCHEMAS + '''
                                     AND ((p.prosecdef AND n.nspname NOT IN ('pg_catalog','information_schema'))
                                          OR p.proowner=(SELECT oid FROM pg_roles WHERE rolname=current_user)))''')
    need(not cursor.fetchone()[0])


def check_runtime():
    from django.db import connection
    from django.db.migrations.executor import MigrationExecutor
    need(connection.settings_dict['USER'] == RUNTIME and connection.settings_dict['NAME'] == DATABASE)
    with connection.cursor() as cursor:
        check_role(cursor)
    executor = MigrationExecutor(connection)
    need(not executor.migration_plan(executor.loader.graph.leaf_nodes()))
    from zentral.core.stores.models import Store
    need(Store.objects.count() == 1 and Store.objects.filter(
        provisioning_uid='elasticsearch', backend='ELASTICSEARCH', admin_console=True).exists())


def initialize(runtime_env_path, receipt):
    """One deliberately selected fresh database; no retry or existing-role repair."""
    from django.core.management import call_command
    from django.db import connection, transaction
    from psycopg2 import connect, sql
    runtime = runtime_file(runtime_env_path)
    settings = connection.settings_dict
    need(settings['USER'] == BOOTSTRAP and settings['NAME'] == DATABASE
         and settings['HOST'] == 'db' and runtime['POSTGRES_PASSWORD'] != settings['PASSWORD'])
    path = Path(receipt)
    need(path.is_absolute() and path.parent == path.parent.resolve(strict=True))
    completion = Path(str(path) + '.complete')
    need(not completion.exists() and not completion.is_symlink())
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    # Reserve a durable unknown-outcome checkpoint before the first DB mutation.
    with os.fdopen(fd, 'w') as stream:
        json.dump({'scope': 'fresh-database-initialization', 'state': 'outcome-requires-inspection'}, stream)
        stream.flush(); os.fsync(stream.fileno())
    locked = False
    try:
        with connection.cursor() as cursor:
            cursor.execute('SELECT current_user, session_user, current_database(), pg_backend_pid()')
            row = cursor.fetchone()
            need(row[:3] == (BOOTSTRAP, BOOTSTRAP, DATABASE))
            backend = row[3]
            cursor.execute('SELECT pg_try_advisory_lock(%s,%s)', (1396788820, 1094992433))
            locked = cursor.fetchone()[0]; need(locked)
            cursor.execute('SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=%s)', (RUNTIME,))
            need(not cursor.fetchone()[0])
            cursor.execute("SELECT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema')")
            need(not cursor.fetchone()[0])
            cursor.execute('SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname=current_database()')
            need(cursor.fetchone()[0] == BOOTSTRAP)
            # Unqualified migration DDL must create in public, not pg_catalog.
            # This schema was checked fresh and is owned by the trusted owner.
            cursor.execute('SET search_path TO public, pg_catalog, pg_temp')
        call_command('migrate', interactive=False, verbosity=0)
        call_command('provision', verbosity=0)
        from zentral.core.stores.models import Store
        need(Store.objects.count() == 1 and Store.objects.filter(
            provisioning_uid='elasticsearch', backend='ELASTICSEARCH', admin_console=True).exists())
        with transaction.atomic(), connection.cursor() as cursor:
            cursor.execute('SELECT pg_backend_pid()'); need(cursor.fetchone()[0] == backend)
            cursor.execute("SELECT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relowner<>(SELECT oid FROM pg_roles WHERE rolname=current_user))")
            need(not cursor.fetchone()[0])
            cursor.execute("SELECT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.prosecdef)")
            need(not cursor.fetchone()[0])
            cursor.execute(sql.SQL('CREATE ROLE {} LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD {}').format(sql.Identifier(RUNTIME), sql.Literal(runtime['POSTGRES_PASSWORD'])))
            cursor.execute(sql.SQL('REVOKE ALL ON DATABASE {} FROM PUBLIC').format(sql.Identifier(DATABASE)))
            cursor.execute(sql.SQL('GRANT CONNECT, TEMPORARY ON DATABASE {} TO {}').format(sql.Identifier(DATABASE), sql.Identifier(RUNTIME)))
            cursor.execute('REVOKE CREATE ON SCHEMA public FROM PUBLIC')
            cursor.execute(sql.SQL('GRANT USAGE ON SCHEMA public TO {}').format(sql.Identifier(RUNTIME)))
            cursor.execute(sql.SQL('GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {}').format(sql.Identifier(RUNTIME)))
            cursor.execute(sql.SQL('REVOKE INSERT, UPDATE, DELETE ON TABLE public.django_migrations FROM {}').format(sql.Identifier(RUNTIME)))
            cursor.execute(sql.SQL('GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {}').format(sql.Identifier(RUNTIME)))
            cursor.execute(sql.SQL('ALTER DEFAULT PRIVILEGES FOR ROLE {} IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {}').format(sql.Identifier(BOOTSTRAP), sql.Identifier(RUNTIME)))
            cursor.execute(sql.SQL('ALTER DEFAULT PRIVILEGES FOR ROLE {} IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO {}').format(sql.Identifier(BOOTSTRAP), sql.Identifier(RUNTIME)))
            cursor.execute(sql.SQL('ALTER ROLE {} SET search_path TO pg_catalog, public, pg_temp').format(sql.Identifier(RUNTIME)))
        # Genuine independent password authentication and role/grant checks.
        with closing(connect(host=settings['HOST'], port=settings.get('PORT') or 5432, dbname=DATABASE,
                             user=RUNTIME, password=runtime['POSTGRES_PASSWORD'], connect_timeout=10)) as probe:
            with probe.cursor() as cursor:
                check_role(cursor)
        # Keep the initial unknown checkpoint; success is a separate exclusive file.
        success = os.open(str(path) + '.complete', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(success, 'w') as stream:
            json.dump({'scope': 'fresh-database-initialization', 'state': 'runtime-role-checked',
                       'temporary_tables': 'required by pinned inventory cleanup; permanent schema creation denied'}, stream)
            stream.flush(); os.fsync(stream.fileno())
    finally:
        if locked:
            with connection.cursor() as cursor:
                cursor.execute('SELECT pg_advisory_unlock(%s,%s)', (1396788820, 1094992433))


def command_class():
    from django.core.management.base import BaseCommand, CommandError
    class Command(BaseCommand):
        help = 'Check restricted runtime authority or explicitly initialize one fresh database.'
        def add_arguments(self, parser):
            parser.add_argument('mode', choices=('check', 'initialize'))
            parser.add_argument('--runtime-env-file')
            parser.add_argument('--receipt')
        def handle(self, *args, **options):
            try:
                if options['mode'] == 'check':
                    need(not options['runtime_env_file'] and not options['receipt'])
                    check_runtime()
                else:
                    need(options['runtime_env_file'] and options['receipt'])
                    initialize(options['runtime_env_file'], options['receipt'])
            except Exception:
                raise CommandError('Database boundary failed; inspect private state before deliberate retry. No credentials exported.') from None
            self.stdout.write('Database authority check completed; no cloud grant or endpoint proof.')
    return Command
