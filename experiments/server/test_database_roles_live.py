"""Explicit real-PostgreSQL checks for an empty isolated role-split stack.

Not invoked by imports or offline CI. No cloud/Docker operations. Run only in a
source/image-bound private job before adding qualification users or devices.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import uuid


def run(expected):
    import os
    sys.path.insert(0, '/zentral/server')
    import azd_santa_database_roles as roles
    if hashlib.sha256(Path(roles.__file__).read_bytes()).hexdigest() != expected:
        raise ValueError('Database boundary module mismatch')
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'server.settings')
    import django
    django.setup()
    from django.db import connection, transaction, DatabaseError
    from psycopg2 import sql
    from accounts.models import User
    from zentral.contrib.inventory.models import EnrollmentSecret, MachineSnapshotCommit
    from zentral.contrib.inventory.utils.cleanup import cleanup_inventory, get_cleanup_max_date
    from zentral.contrib.santa.models import Configuration
    if hashlib.sha256(Path(cleanup_inventory.__code__.co_filename).read_bytes()).hexdigest() != '3e0cef0d4bc1bfbeee1c35183488ab09ff0e53e8c02a609fdeebc51c89c5904b':
        raise ValueError('Pinned original inventory cleanup source mismatch')
    roles.check_runtime()
    if (User.objects.filter(is_service_account=False).exists() or EnrollmentSecret.objects.exists()
            or MachineSnapshotCommit.objects.exists() or Configuration.objects.exists()):
        raise ValueError('Only a fresh empty isolated qualification database is supported')
    # Exercise the original TEMP table/index/analyze/drop cleanup, not a stub.
    with transaction.atomic(), connection.cursor() as cursor:
        cleanup_inventory(cursor, lambda *args, **kwargs: None, get_cleanup_max_date())
        transaction.set_rollback(True)
    denied = []
    name = 'azd_role_probe_' + uuid.uuid4().hex
    statements = {
        'permanent-table': sql.SQL('CREATE TABLE public.{} (id integer)').format(sql.Identifier(name)),
        'permanent-alter': sql.SQL('ALTER TABLE public.django_session ADD COLUMN {} integer').format(sql.Identifier(name)),
        'permanent-index': sql.SQL('CREATE INDEX {} ON public.django_session (session_key)').format(sql.Identifier(name)),
        'permanent-drop': sql.SQL('DROP TABLE public.django_session'),
        'migration-ledger-write': sql.SQL('UPDATE public.django_migrations SET applied=applied WHERE false'),
        'permanent-schema': sql.SQL('CREATE SCHEMA {}').format(sql.Identifier(name)),
        'create-role': sql.SQL('CREATE ROLE {} NOLOGIN').format(sql.Identifier(name)),
        'set-bootstrap-role': sql.SQL('SET ROLE {}').format(sql.Identifier(roles.BOOTSTRAP)),
        'promote-runtime': sql.SQL('ALTER ROLE {} CREATEDB').format(sql.Identifier(roles.RUNTIME)),
    }
    for label, statement in statements.items():
        try:
            with transaction.atomic(), connection.cursor() as cursor:
                cursor.execute(statement)
                transaction.set_rollback(True)
        except DatabaseError as error:
            if getattr(error.__cause__, 'pgcode', None) != '42501':
                raise ValueError('Wrong database denial class') from None
            denied.append(label)
        else:
            raise ValueError('Unexpected runtime DDL authority; transaction rolled back')
    # CREATE DATABASE inside a transaction would be a false denial. Test it in
    # actual autocommit and remove its unique probe DB if a broken role permits it.
    if not connection.get_autocommit():
        raise ValueError('CREATE DATABASE test requires actual autocommit')
    with connection.cursor() as cursor:
        try:
            cursor.execute(sql.SQL('CREATE DATABASE {}').format(sql.Identifier(name)))
        except DatabaseError as error:
            if getattr(error.__cause__, 'pgcode', None) != '42501':
                raise ValueError('Wrong database-create denial class') from None
            denied.append('create-database')
        else:
            cursor.execute(sql.SQL('DROP DATABASE {}').format(sql.Identifier(name)))
            raise ValueError('Unexpected runtime database-create authority')
    roles.check_runtime()
    return dict(scope='empty-isolated-postgres-role-boundary', original_temp_cleanup='passed',
                denied=denied, limitations=['Empty inventory only; nonempty retention semantics, HTTP, MFA and developer test jobs require separate acceptance'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--confirm-empty-isolated', action='store_true', required=True)
    parser.add_argument('--module-sha256', required=True)
    args = parser.parse_args()
    try:
        result = run(args.module_sha256)
        print('SANTA_DATABASE_ROLE_JSON:' + json.dumps(result, sort_keys=True))
    except Exception:
        print('Private database-role qualification failed; inspect private job evidence.', file=sys.stderr)
        raise SystemExit(1)
