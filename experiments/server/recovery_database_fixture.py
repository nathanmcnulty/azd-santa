"""Original Unlicense owner-only disposable recovery fixture jobs.

Never called by normal startup. Credentials remain in each process's existing
selected environment; the receipt contains hashes/identities only.
"""
import hashlib
import json
import os
from pathlib import Path
import re

OWNER = 'zentral_owner'
RUNTIME = 'zentral_runtime'
NAME = re.compile(r'azd_recovery_[0-9a-f]{24}')


def need(value):
    if not value:
        raise ValueError('Isolated recovery database binding failed')


def read_binding(path):
    value = json.loads(Path(path).read_text())
    need(set(value) == {'scope', 'database', 'image', 'compose_sha256', 'config_sha256',
                       'runtime_env_sha256', 'owner_env_sha256', 'harness_sha256',
                       'fixture_sha256', 'policy_sha256', 'recovery_sha256'})
    need(value['scope'] == 'restricted-runtime-recovery-fixture' and NAME.fullmatch(value['database']))
    need(re.fullmatch(r'sha256:[a-f0-9]{64}', value['image']))
    need(all(re.fullmatch(r'[a-f0-9]{64}', v) for k, v in value.items() if k.endswith('_sha256')))
    need(value['fixture_sha256'] == hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    need(value['config_sha256'] == hashlib.sha256(Path('/run/azd-recovery-conf/base.json').read_bytes()).hexdigest())
    return value


def write_new(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    os.fchmod(fd, 0o644)
    with os.fdopen(fd, 'w') as stream:
        json.dump(value, stream, sort_keys=True)
        stream.flush(); os.fsync(stream.fileno())


def initialize(path):
    from contextlib import closing
    from django.core.management import call_command
    from django.db import connection
    from psycopg2 import connect, sql
    binding = read_binding(path)
    conf = connection.settings_dict
    need(conf['HOST'] == 'db' and conf['USER'] == OWNER and conf['NAME'] == binding['database'])
    # Connect to the existing maintenance DB without ever selecting its ORM.
    with closing(connect(host=conf['HOST'], port=conf.get('PORT') or 5432,
                         dbname='zentral', user=OWNER, password=conf['PASSWORD'], connect_timeout=10)) as admin:
        admin.autocommit = True
        with admin.cursor() as cursor:
            cursor.execute('SELECT current_user,session_user'); need(cursor.fetchone() == (OWNER, OWNER))
            cursor.execute('SELECT 1 FROM pg_database WHERE datname=%s', [binding['database']]); need(not cursor.fetchone())
            cursor.execute(sql.SQL('CREATE DATABASE {} OWNER {} TEMPLATE template0').format(
                sql.Identifier(binding['database']), sql.Identifier(OWNER)))
            cursor.execute(sql.SQL('REVOKE ALL ON DATABASE {} FROM PUBLIC').format(sql.Identifier(binding['database'])))
    with connection.cursor() as cursor:
        cursor.execute('SET search_path TO public,pg_catalog,pg_temp')
    call_command('migrate', interactive=False, verbosity=0)
    with connection.cursor() as cursor:
        cursor.execute(sql.SQL('REVOKE ALL ON DATABASE {} FROM PUBLIC').format(sql.Identifier(binding['database'])))
        cursor.execute(sql.SQL('GRANT CONNECT,TEMPORARY ON DATABASE {} TO {}').format(sql.Identifier(binding['database']), sql.Identifier(RUNTIME)))
        cursor.execute('REVOKE CREATE ON SCHEMA public FROM PUBLIC')
        cursor.execute(sql.SQL('GRANT USAGE ON SCHEMA public TO {}').format(sql.Identifier(RUNTIME)))
        cursor.execute(sql.SQL('GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA public TO {}').format(sql.Identifier(RUNTIME)))
        cursor.execute(sql.SQL('REVOKE INSERT,UPDATE,DELETE ON public.django_migrations FROM {}').format(sql.Identifier(RUNTIME)))
        cursor.execute(sql.SQL('GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA public TO {}').format(sql.Identifier(RUNTIME)))
        cursor.execute('SELECT oid,pg_get_userbyid(datdba) FROM pg_database WHERE datname=current_database()')
        oid, owner = cursor.fetchone(); need(owner == OWNER)
    connection.close()
    write_new(Path(path).with_name('fixture.json'), dict(binding=binding, database_oid=oid, owner=owner))


def runtime_identity(path):
    from django.db import connection, connections
    binding = read_binding(Path(path).with_name('binding.json'))
    fixture = json.loads(Path(path).read_text())
    need(set(fixture) == {'binding', 'database_oid', 'owner'} and fixture['binding'] == binding
         and type(fixture['database_oid']) is int and fixture['database_oid'] > 0 and fixture['owner'] == OWNER)
    need(set(connections) == {'default'} and connection.vendor == 'postgresql'
         and connection.settings_dict['NAME'] == binding['database'] and connection.settings_dict['USER'] == RUNTIME
         and os.environ.get('POSTGRES_USER') == RUNTIME
         and not Path('/run/azd-runtime.env').exists())
    with connection.cursor() as cursor:
        cursor.execute('SELECT current_user,session_user,current_database(),oid,pg_get_userbyid(datdba) FROM pg_database WHERE datname=current_database()')
        need(cursor.fetchone() == (RUNTIME, RUNTIME, binding['database'], fixture['database_oid'], OWNER))
        cursor.execute('SELECT rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls,rolinherit FROM pg_roles WHERE rolname=current_user')
        need(cursor.fetchone() == (False,) * 6)
        cursor.execute("SELECT has_database_privilege(current_user,current_database(),'CREATE'),has_schema_privilege(current_user,'public','CREATE'),has_table_privilege(current_user,'public.django_migrations','INSERT,UPDATE,DELETE,TRUNCATE')")
        need(cursor.fetchone() == (False, False, False))
        cursor.execute('SELECT EXISTS(SELECT 1 FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.member WHERE r.rolname=current_user)')
        need(not cursor.fetchone()[0])
        cursor.execute("SELECT EXISTS(SELECT 1 FROM pg_namespace n WHERE n.oid<>pg_my_temp_schema() AND NOT pg_is_other_temp_schema(n.oid) AND (n.nspowner=(SELECT oid FROM pg_roles WHERE rolname=current_user) OR has_schema_privilege(current_user,n.oid,'CREATE')))")
        need(not cursor.fetchone()[0])
        cursor.execute("SELECT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND (c.relowner=(SELECT oid FROM pg_roles WHERE rolname=current_user) OR (c.relkind IN ('r','p') AND has_table_privilege(current_user,c.oid,'TRUNCATE'))))")
        need(not cursor.fetchone()[0])
    return dict(database=binding['database'], database_oid=fixture['database_oid'],
                sql_user=RUNTIME, fixture_sha256=hashlib.sha256(Path(path).read_bytes()).hexdigest())


def teardown(path):
    from contextlib import closing
    from django.db import connection
    from psycopg2 import connect, sql
    binding = read_binding(Path(path).with_name('binding.json'))
    fixture = json.loads(Path(path).read_text())
    need(set(fixture) == {'binding', 'database_oid', 'owner'} and fixture['binding'] == binding and fixture['owner'] == OWNER)
    conf = connection.settings_dict
    need(conf['USER'] == OWNER and conf['HOST'] == 'db' and conf['NAME'] == binding['database'])
    connection.close()
    with closing(connect(host=conf['HOST'], port=conf.get('PORT') or 5432, dbname='zentral',
                         user=OWNER, password=conf['PASSWORD'], connect_timeout=10)) as admin:
        admin.autocommit = True
        with admin.cursor() as cursor:
            cursor.execute('SELECT current_user,session_user'); need(cursor.fetchone() == (OWNER, OWNER))
            # Lock out name/OID replacement by keeping the catalog row locked in
            # a separate transaction is impossible with DROP DATABASE. The host
            # serializes this private namespace; fail if any connected backend.
            cursor.execute('SELECT oid,pg_get_userbyid(datdba) FROM pg_database WHERE datname=%s', [binding['database']])
            need(cursor.fetchone() == (fixture['database_oid'], OWNER))
            cursor.execute('SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=%s)', [binding['database']]); need(not cursor.fetchone()[0])
            cursor.execute(sql.SQL('DROP DATABASE {}').format(sql.Identifier(binding['database'])))
    write_new(Path(path).with_name('teardown.json'), {'database': binding['database'], 'database_oid': fixture['database_oid'], 'dropped': True})
