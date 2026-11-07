"""Offline bounded relay/job guards. No package, Docker, systemd or Azure calls."""
import base64
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('install_transport', ROOT / 'experiments/server/private_install_transport.py')
relay = importlib.util.module_from_spec(spec); spec.loader.exec_module(relay)
spec = importlib.util.spec_from_file_location('private_install', ROOT / 'experiments/server/private_install.py')
installer = importlib.util.module_from_spec(spec); spec.loader.exec_module(installer)


def package():
    files = {}
    for name in relay.FILES:
        body = b'# original synthetic source\n'
        files[name] = dict(sha256=hashlib.sha256(body).hexdigest(), base64=base64.b64encode(body).decode())
    raw = json.dumps(dict(scope='private-azd-source-v1', files=files), sort_keys=True).encode()
    zipped = gzip.compress(raw)
    return hashlib.sha256(raw).hexdigest(), hashlib.sha256(zipped).hexdigest(), base64.b64encode(zipped).decode()


class Relay(unittest.TestCase):
    def harness(self, root, external):
        def secure(path):
            self.assertTrue(path.is_relative_to(root)); self.assertFalse(path.is_symlink())
        def exclusive(path, raw, mode=0o600):
            with path.open('xb') as output: output.write(raw)
        return (patch.object(relay, 'ROOT', root), patch.object(relay, 'ACTIVE', root / 'private-azd-install.json'),
            patch.object(relay.os, 'geteuid', return_value=0, create=True), patch.object(relay.os, 'umask'),
            patch.object(relay, 'secure', side_effect=secure), patch.object(relay, 'exclusive', side_effect=exclusive),
            patch.object(relay, 'command', side_effect=external))

    def test_bounded_chunks_and_hash_tamper_cannot_launch_job(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); calls = []
            guards = self.harness(root, lambda args: calls.append(args))
            from contextlib import ExitStack
            with ExitStack() as stack:
                for guard in guards: stack.enter_context(guard)
                digest, archive, data = package()
                with self.assertRaises(ValueError):
                    relay.run(dict(mode='chunk', bundle_sha256=digest, archive_sha256=archive, index=0, count=1, data='a' * 24577))
                relay.run(dict(mode='chunk', bundle_sha256=digest, archive_sha256=archive, index=0, count=1, data=data))
                # Same chunk is safe to retransmit, but not replace.
                relay.run(dict(mode='chunk', bundle_sha256=digest, archive_sha256=archive, index=0, count=1, data=data))
                with self.assertRaises(ValueError):
                    relay.run(dict(mode='chunk', bundle_sha256=digest, archive_sha256=archive, index=0, count=1, data='AAAA'))
                relay.run(dict(mode='chunk', bundle_sha256='f' * 64, archive_sha256=archive, index=0, count=1, data=data))
                with self.assertRaises(ValueError):
                    relay.run(dict(mode='submit', bundle_sha256='f' * 64, archive_sha256=archive, count=1, target={}))
                self.assertFalse((root / 'private-azd-install.json').exists())
                self.assertEqual(calls, [])

    def test_unknown_submission_reserves_once_and_never_restarts_initializer(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); calls = []
            def external(args):
                calls.append(args)
                if args[0] == 'systemd-run': raise subprocess.TimeoutExpired(args, 30)
                if args[:2] == ['systemctl', 'show']: return 'LoadState=not-found\n'
                return ''
            from contextlib import ExitStack
            with ExitStack() as stack:
                for guard in self.harness(root, external): stack.enter_context(guard)
                digest, archive, data = package()
                relay.run(dict(mode='chunk', bundle_sha256=digest, archive_sha256=archive, index=0, count=1, data=data))
                command = dict(mode='submit', bundle_sha256=digest, archive_sha256=archive, count=1, target={'EnvironmentName': 'synthetic'})
                with self.assertRaises(subprocess.TimeoutExpired): relay.run(command)
                self.assertTrue((root / 'private-azd-install.json').exists())
                with self.assertRaises(ValueError): relay.run(command)
                self.assertEqual(sum(args[0] == 'systemd-run' for args in calls), 1)
                launch = next(args for args in calls if args[0] == 'systemd-run')
                self.assertIn('--no-block', launch); self.assertIn('--property=Restart=no', launch)

    def test_existing_different_bundle_or_failed_same_job_is_never_reinitialized(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); digest = 'a' * 64; calls = []
            (root / 'private-azd-install.json').write_text(json.dumps(dict(bundle_sha256=digest, target={})))
            def external(args):
                calls.append(args)
                return 'LoadState=loaded\nActiveState=failed\nSubState=failed\nResult=exit-code\nExecMainStatus=1\nInvocationID=synthetic\n'
            from contextlib import ExitStack
            with ExitStack() as stack:
                for guard in self.harness(root, external): stack.enter_context(guard)
                result = relay.run(dict(mode='observe', bundle_sha256=digest))
                self.assertEqual(result['state'], 'failed')
                with self.assertRaises(ValueError): relay.run(dict(mode='submit', bundle_sha256='b' * 64, target={}))
                self.assertFalse(any(args[0] == 'systemd-run' for args in calls))


class Installer(unittest.TestCase):
    def test_wrong_immutable_vm_fails_before_package_or_data_operations(self):
        import io
        from unittest.mock import MagicMock
        sub = '11111111-1111-4111-8111-111111111111'
        context = dict(target={'TenantId': '22222222-2222-4222-8222-222222222222', 'SubscriptionId': sub,
            'EnvironmentName': 'synthetic', 'ResourceGroup': 'rg-azd-santa-vm-synthetic', 'VmName': 'vm-santa-lab',
            'VmId': '/subscriptions/' + sub + '/resourceGroups/rg-azd-santa-vm-synthetic/providers/Microsoft.Compute/virtualMachines/vm-santa-lab',
            'VmInstanceId': '33333333-3333-4333-8333-333333333333'})
        response = MagicMock(); response.__enter__.return_value = io.BytesIO(json.dumps(dict(subscriptionId='wrong', resourceId='/wrong', vmId='wrong')).encode())
        opener = MagicMock(); opener.open.return_value = response
        with patch.object(installer.os, 'geteuid', return_value=0, create=True), patch.object(installer.os, 'umask'), \
             patch.object(installer.platform, 'machine', return_value='x86_64'), patch.object(installer, 'verified', return_value=(context, Path('/synthetic'))), \
             patch.object(installer.urllib.request, 'build_opener', return_value=opener), patch.object(installer.subprocess, 'run') as external:
            with self.assertRaises(ValueError): installer.install('/synthetic/context', 'a' * 64)
            external.assert_not_called()

    def test_source_preserves_fresh_only_order_and_qualified_supplier(self):
        source = (ROOT / 'experiments/server/private_install.py').read_text()
        self.assertEqual(installer.COMPOSE_VERSION, '2.40.3+ds1-0ubuntu1~24.04.1')
        self.assertEqual(installer.DOCKER_VERSION, '29.1.3-0ubuntu3~24.04.2')
        self.assertEqual(installer.COMPOSE_SHA, 'd87a11e944c990dc9f2186115b1136c1cbffffc870845caff0cbdcce0780f41d')
        self.assertLess(source.index('stage.stage('), source.index("'operator_security_store', 'fresh'"))
        self.assertLess(source.index("'operator_security_store', 'fresh'"), source.index('runtime.install_unit('))
        self.assertNotIn('operator_access', source)
        self.assertNotIn("'migrate'", source) # Existing explicit fresh-stage API owns schema authority.


if __name__ == '__main__': unittest.main()
