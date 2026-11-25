"""Offline package/precondition tests; SQL outcomes need the real DB harness."""
import ast
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch, Mock, MagicMock

SERVER = Path(__file__).resolve().parents[1] / 'experiments/server'
sys.path.insert(0, str(SERVER))
import database_roles as roles
import prepare_database_roles as package


class DatabaseBoundary(unittest.TestCase):
    def test_unreviewed_entrypoint_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Unreviewed'):
            package.transform(b'not reviewed upstream')

    def test_entrypoint_normal_path_only_checks_runtime_and_preserves_original_input(self):
        raw = package.HEADER + b'import subprocess\nif True:\n    if True:\n        if True:\n' + package.OLD
        expected = package.HEADER + package.NOTICE + raw[len(package.HEADER):].replace(package.OLD, package.NEW)
        with patch.object(package, 'INPUT', hashlib.sha256(raw).hexdigest()), \
                patch.object(package, 'OUTPUT', hashlib.sha256(expected).hexdigest()):
            output = package.transform(raw)
        calls = Mock()
        with patch('subprocess.run', calls):
            exec(compile(output, 'synthetic-entrypoint', 'exec'), {})
        calls.assert_called_once_with(['python', 'server/manage.py', 'operator_database', 'check'], check=True)
        self.assertIn(b'wait_for_db_migration()', raw)
        self.assertNotIn(b'wait_for_db_migration()', output)
        self.assertEqual(output.splitlines()[:2], package.HEADER.splitlines())

    def test_installer_preserves_module_bytes_and_requires_exact_entrypoint_hash(self):
        raw = package.HEADER + b'import subprocess\nif True:\n    if True:\n        if True:\n' + package.OLD
        output = package.HEADER + package.NOTICE + raw[len(package.HEADER):].replace(package.OLD, package.NEW)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'docker-entrypoint.py').write_bytes(raw)
            with patch.object(package, 'INPUT', hashlib.sha256(raw).hexdigest()), \
                    patch.object(package, 'OUTPUT', hashlib.sha256(output).hexdigest()):
                program = package.docker_program(root)
            ast.parse(program)
            target = root / 'zentral'
            (target / 'server/accounts/management/commands').mkdir(parents=True)
            (target / 'docker-entrypoint.py').write_bytes(raw)
            chmod = Path.chmod
            with patch.object(Path, 'chmod', autospec=True, side_effect=chmod) as modes:
                exec(program.replace('/zentral', target.as_posix()), {})
            self.assertIn(((target / 'database-role-entrypoint.py', 0o755), {}), modes.call_args_list)
            self.assertEqual((target / 'docker-entrypoint.py').read_bytes(), output)
            self.assertEqual((target / 'server/azd_santa_database_roles.py').read_bytes(),
                             (SERVER / 'database_roles.py').read_bytes().replace(b'\r\n', b'\n'))
            if os.name != 'nt':
                self.assertEqual((target / 'docker-entrypoint.py').stat().st_mode & 0o777, 0o755)
                (target / 'server/manage.py').write_text("import sys\nassert sys.argv[1:]==['operator_database','check']\nprint('SYNTHETIC_RUNTIME_CHECK')\n")
                executed = subprocess.run([str(target / 'docker-entrypoint.py')], cwd=target,
                                          capture_output=True, text=True, timeout=10)
                self.assertEqual(executed.returncode, 0, executed.stderr)
                self.assertIn('SYNTHETIC_RUNTIME_CHECK', executed.stdout)
            with self.assertRaisesRegex(RuntimeError, 'input mismatch'):
                exec(program.replace('/zentral', target.as_posix()), {})

    def test_runtime_role_check_rejects_each_authority_drift(self):
        expected = [(roles.RUNTIME, roles.RUNTIME, roles.DATABASE), (False,) * 6, (False,),
                    (False, True, False, True), (False,), (False,), (False,), (True, False), (False,)]
        cursor = Mock(); cursor.fetchone.side_effect = expected
        roles.check_role(cursor)
        for index, changed in enumerate([
            (roles.BOOTSTRAP, roles.BOOTSTRAP, roles.DATABASE), (True, False, False, False, False, False),
            (True,), (True, True, False, True), (True,), (True,), (True,), (True, True), (True,)]):
            results = list(expected); results[index] = changed
            cursor = Mock(); cursor.fetchone.side_effect = results
            with self.subTest(index=index), self.assertRaises(ValueError):
                roles.check_role(cursor)

    def test_permanent_system_schema_create_is_not_exempted_as_temporary(self):
        safe = [(roles.RUNTIME, roles.RUNTIME, roles.DATABASE), (False,) * 6, (False,),
                (False, True, False, True), (False,), (False,), (False,), (True, False), (False,)]
        for schema in ('pg_catalog', 'information_schema'):
            cursor = Mock()
            unsafe = list(safe); unsafe[5] = (True,)
            cursor.fetchone.side_effect = unsafe
            with self.subTest(schema=schema), self.assertRaises(ValueError):
                roles.check_role(cursor)
            query = cursor.execute.call_args.args[0]
            self.assertIn('pg_my_temp_schema()', query)
            self.assertIn('pg_is_other_temp_schema(n.oid)', query)
            self.assertIn("'pg_toast_temp_' || substr(t.nspname,9)", query)
            self.assertNotIn("!~ '^pg_'", query)
            self.assertNotIn("<> 'information_schema'", query)

    def test_runtime_file_rejects_bootstrap_identity_duplicate_keys_and_unsafe_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'runtime.env'
            values = {key: 'synthetic' for key in roles.ENV_KEYS}
            values.update(POSTGRES_USER=roles.RUNTIME, POSTGRES_PASSWORD='p' * 64)
            path.write_text(''.join(k + '=' + v + '\n' for k, v in values.items()))
            safe = SimpleNamespace(st_mode=0o100600, st_uid=0)
            with patch.object(Path, 'resolve', autospec=True, side_effect=lambda p, **kwargs: p), \
                    patch.object(Path, 'stat', return_value=safe):
                self.assertEqual(roles.runtime_file(path), values)
                path.write_text(path.read_text() + 'POSTGRES_USER=zentral_owner\n')
                with self.assertRaises(ValueError): roles.runtime_file(path)
            for mode, uid in ((0o100644, 0), (0o100600, 1)):
                with patch.object(Path, 'resolve', autospec=True, side_effect=lambda p, **kwargs: p), \
                        patch.object(Path, 'stat', return_value=SimpleNamespace(st_mode=mode, st_uid=uid)):
                    with self.assertRaises(ValueError): roles.runtime_file(path)

    def test_conflicting_role_tables_or_database_owner_prevent_migrations_and_grants(self):
        # A state-machine guard test, not proof of real PostgreSQL permissions.
        for tail in ([(True,)], [(False,), (True,)], [(False,), (False,), ('foreign-owner',)]):
            with self.subTest(conflict=tail), tempfile.TemporaryDirectory() as tmp:
                receipt = Path(tmp).resolve() / 'attempt.json'
                cursor = MagicMock()
                cursor.fetchone.side_effect = [(roles.BOOTSTRAP, roles.BOOTSTRAP, roles.DATABASE, 7), (True,), *tail]
                connection = SimpleNamespace(settings_dict={'USER': roles.BOOTSTRAP, 'NAME': roles.DATABASE,
                                                              'HOST': 'db', 'PASSWORD': 'owner-password'},
                                             cursor=MagicMock(return_value=cursor))
                cursor.__enter__.return_value = cursor
                call_command, connect, sql = Mock(), Mock(), Mock()
                fake = {'django.core.management': SimpleNamespace(call_command=call_command),
                        'django.db': SimpleNamespace(connection=connection, transaction=Mock()),
                        'psycopg2': SimpleNamespace(connect=connect, sql=sql)}
                with patch.dict(sys.modules, fake), patch.object(roles, 'runtime_file', return_value={'POSTGRES_PASSWORD': 'runtime-password'}):
                    with self.assertRaises(ValueError):
                        roles.initialize('/not-read-in-this-guard-test', receipt)
                call_command.assert_not_called(); connect.assert_not_called(); sql.SQL.assert_not_called()
                self.assertTrue(receipt.exists())
                self.assertFalse(Path(str(receipt) + '.complete').exists())

    def test_real_harness_requires_explicit_confirmation_and_tests_database_create_outside_transaction(self):
        source = (SERVER / 'test_database_roles_live.py').read_text()
        ast.parse(source)
        self.assertIn("cleanup_inventory(cursor,", source)
        self.assertIn("getattr(error.__cause__, 'pgcode', None) != '42501'", source)
        self.assertIn('connection.get_autocommit()', source)
        self.assertIn("'--confirm-empty-isolated', action='store_true', required=True", source)


if __name__ == '__main__':
    unittest.main()
