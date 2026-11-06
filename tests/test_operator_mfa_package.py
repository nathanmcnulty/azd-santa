"""Offline package integrity checks, not a claim of actual MFA authorization."""
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'experiments/server'))
import prepare_operator_mfa as package


class Integrity(unittest.TestCase):
    def test_rejects_unreviewed_core_inputs(self):
        for name in package.INPUTS:
            with self.assertRaisesRegex(ValueError, 'Unreviewed operator MFA input'):
                package.transform(name, b'not the pinned source')

    def test_generated_program_checks_both_input_and_output_and_preserves_policy_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            name = 'server/sample.py'
            path = root / name
            path.parent.mkdir()
            source = b'VALUE = 1\n'
            result = (package.NOTICE + 'VALUE = 2\n').encode()
            path.write_bytes(source)
            module = root / 'policy.py'
            module.write_bytes(b'POLICY = "original"\n')
            inputs = {name: hashlib.sha256(source).hexdigest()}
            outputs = {name: hashlib.sha256(result).hexdigest()}
            with patch.object(package, 'INPUTS', inputs), patch.object(package, 'OUTPUTS', outputs), patch.object(package, 'PATCHES', {name: [('VALUE = 1', 'VALUE = 2')]}):
                program, digest = package.docker_program(root, module)
                self.assertEqual(digest, hashlib.sha256(module.read_bytes()).hexdigest())
                program = program.replace("Path('/zentral')", 'Path(' + repr(root.as_posix()) + ')')
                program = program.replace("'/zentral/server/azd_santa_operator.py'", repr((root / 'server/azd_santa_operator.py').as_posix()))
                exec(compile(program, 'reviewed-package', 'exec'), {})
                self.assertEqual(path.read_bytes(), result)
                self.assertEqual((root / 'server/azd_santa_operator.py').read_bytes(), module.read_bytes())
                path.write_bytes(b'changed')
                with self.assertRaisesRegex(RuntimeError, 'MFA input mismatch'):
                    exec(compile(program, 'reviewed-package', 'exec'), {})
                self.assertEqual(path.read_bytes(), b'changed')


if __name__ == '__main__':
    unittest.main()
