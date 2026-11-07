"""Offline package/helpers; these do not prove real Django/PostgreSQL recovery."""
import ast
import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1] / 'experiments/server'


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


recovery = load('operator_recovery')
package = load('prepare_operator_recovery')


class RecoveryPackage(unittest.TestCase):
    def test_validation_requires_explicit_identity_and_reason(self):
        recovery.validate_request('recover', 'admin', 'admin@example.invalid', 'lost all factors')
        for values in (('reset', 'a', 'a@example.invalid', 'reason'),
                       ('recover', ' admin', 'admin@example.invalid', 'reason'),
                       ('recover', 'admin', 'admin@example.invalid', ''),
                       ('recover', 'admin', 'admin@example.invalid', 'bad\nreason')):
            with self.assertRaises(recovery.AccessError):
                recovery.validate_request(*values)

    def test_private_output_is_exclusive_and_does_not_print(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / 'private.json'
            descriptor = recovery.reserve_output(path)
            with os.fdopen(descriptor, 'w') as stream:
                stream.write('private')
            if os.name != 'nt':
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                recovery.reserve_output(path)
            self.assertEqual(path.read_text(), 'private')
            with self.assertRaises(recovery.AccessError):
                recovery.reserve_output(Path('relative.json'))

    def test_rejects_unreviewed_patch_inputs(self):
        for name in package.INPUTS:
            with self.assertRaises(ValueError):
                package.transform(name, b'unknown')

    def test_installer_layer_checks_exact_bytes_and_installs_readable_exclusive_modules(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'server/accounts/management/commands').mkdir(parents=True)
            (root / 'server/server').mkdir()
            urls = b'VALUE = 1\n'
            settings = b'VALUE = 2\n'
            (root / package.URLS).write_bytes(urls)
            (root / package.SETTINGS).write_bytes(settings)
            patches = {package.URLS: [('VALUE = 1', 'VALUE = 3')], package.SETTINGS: [('VALUE = 2', 'VALUE = 4')]}
            inputs = {package.URLS: hashlib.sha256(urls).hexdigest(), package.SETTINGS: hashlib.sha256(settings).hexdigest()}
            outputs = {name: hashlib.sha256((package.NOTICE + text).encode()).hexdigest()
                       for name, text in ((package.URLS, 'VALUE = 3\n'), (package.SETTINGS, 'VALUE = 4\n'))}
            with patch.object(package, 'ORIGINAL_SETTINGS', inputs[package.SETTINGS]), patch.object(package, 'INPUTS', inputs), patch.object(package, 'OUTPUTS', outputs), patch.object(package, 'PATCHES', patches):
                program = package.docker_program(root)
            program = program.replace("Path('/zentral')", 'Path(' + repr(root.as_posix()) + ')')
            exec(compile(program, 'original-package-installer', 'exec'), {})
            installed = root / 'server/azd_santa_operator_recovery.py'
            self.assertEqual(installed.read_bytes(), (ROOT / 'operator_recovery.py').read_bytes().replace(b'\r\n', b'\n'))
            self.assertTrue((root / 'server/accounts/management/commands/operator_access.py').exists())
            self.assertEqual((root / 'server/azd_santa_sealed_setup.py').read_bytes(),
                             (ROOT / 'sealed_setup.py').read_bytes().replace(b'\r\n', b'\n'))
            self.assertEqual(hashlib.sha256((root / package.URLS).read_bytes()).hexdigest(), outputs[package.URLS])
            # Subsequent runs fail at the exact patch boundary, never silently replay.
            with self.assertRaises(RuntimeError):
                exec(compile(program, 'original-package-installer', 'exec'), {})

    def test_original_module_import_does_not_resolve_django_models(self):
        tree = ast.parse((ROOT / 'operator_recovery.py').read_text())
        imports = [node for node in tree.body if isinstance(node, (ast.Import, ast.ImportFrom))]
        self.assertFalse(any(isinstance(node, ast.ImportFrom) and (node.module or '').startswith(('django', 'accounts')) for node in imports))
        text = (ROOT / 'operator_recovery.py').read_text()
        self.assertIn('select_for_update().get(', text)
        self.assertIn('is_service_account=False).exists()', text)
        self.assertIn('user.email != email', text)
        self.assertIn('post_reset_login = False', text)


if __name__ == '__main__':
    unittest.main()
