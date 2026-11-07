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
    def completed(self, root, digest):
        directory = root / 'installers' / digest; directory.mkdir(parents=True)
        active = dict(scope='private-azd-install-v1', bundle_sha256=digest, target={'EnvironmentName': 'synthetic'})
        context = json.dumps(active).encode()
        (root / 'private-azd-install.json').write_bytes(context)
        (directory / 'context.json').write_bytes(context)
        complete = dict(scope='private-azd-install-complete', bundle_sha256=digest,
                        outputs={'EnvironmentName': 'synthetic'}, limitation='synthetic')
        raw = json.dumps(complete).encode(); (directory / 'complete.json').write_bytes(raw)
        proof = dict(scope='private-azd-install-terminal-success', context_sha256=hashlib.sha256(context).hexdigest(),
                     bundle_sha256=digest, completion_sha256=hashlib.sha256(raw).hexdigest(), invocation='c' * 32,
                     service_result='success', exit_code='exited', exit_status='0')
        (directory / 'terminal-success.json').write_text(json.dumps(proof))
        return directory

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

    def test_completed_reboot_observes_durable_terminal_proof_without_resubmission(self):
        from contextlib import ExitStack
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); digest = 'a' * 64; self.completed(root, digest); calls = []
            def external(args):
                calls.append(args)
                return 'LoadState=not-found\n' if args[:2] == ['systemctl', 'show'] else 'active\n'
            with ExitStack() as stack:
                for guard in self.harness(root, external): stack.enter_context(guard)
                value = relay.run(dict(mode='observe', bundle_sha256=digest))
                self.assertEqual(value['state'], 'completed'); self.assertIsNotNone(value['completion'])
                self.assertIn(['systemctl', 'is-active', 'azd-santa-runtime.service'], calls)
                self.assertFalse(any(args[0] == 'systemd-run' for args in calls))

    def test_missing_or_tampered_terminal_proof_never_accepts_completion_after_reboot(self):
        from contextlib import ExitStack
        for missing in (True, False):
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as folder:
                root = Path(folder); digest = 'a' * 64; directory = self.completed(root, digest)
                if missing: (directory / 'terminal-success.json').unlink()
                else: (directory / 'complete.json').write_text('{}')
                with ExitStack() as stack:
                    for guard in self.harness(root, lambda args: 'LoadState=not-found\n'): stack.enter_context(guard)
                    with self.assertRaises((ValueError, KeyError)): relay.run(dict(mode='observe', bundle_sha256=digest))

    def test_failed_loaded_unit_overrides_even_valid_terminal_proof_and_completion(self):
        from contextlib import ExitStack
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); digest = 'a' * 64; self.completed(root, digest)
            def external(args): return 'LoadState=loaded\nActiveState=failed\nResult=exit-code\nExecMainStatus=1\nInvocationID=' + 'c' * 32 + '\n'
            with ExitStack() as stack:
                for guard in self.harness(root, external): stack.enter_context(guard)
                with self.assertRaises(ValueError): relay.run(dict(mode='observe', bundle_sha256=digest))

    def test_terminal_recorder_refuses_inferred_success_without_systemd_exit(self):
        with patch.object(relay.os, 'geteuid', return_value=0, create=True), patch.dict(os.environ, {}, clear=True), patch.object(relay, 'exclusive') as write:
            with self.assertRaises(ValueError): relay.record_terminal('/missing', 'a' * 64)
            write.assert_not_called()

    def test_terminal_recorder_binds_actual_exit_to_exclusive_context_and_completion(self):
        from contextlib import ExitStack
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); manifest = b'original pinned public source manifest'
            digest = hashlib.sha256(manifest).hexdigest(); directory = self.completed(root, digest)
            (directory / 'bundle.json').write_bytes(manifest)
            proof_path = directory / 'terminal-success.json'; proof_path.unlink()
            context = directory / 'context.json'; context_sha = hashlib.sha256(context.read_bytes()).hexdigest()
            with ExitStack() as stack:
                for guard in self.harness(root, lambda args: self.fail('Recorder must not execute external commands')): stack.enter_context(guard)
                stack.enter_context(patch.dict(os.environ, dict(SERVICE_RESULT='success', EXIT_CODE='exited', EXIT_STATUS='0', INVOCATION_ID='c' * 32)))
                relay.record_terminal(str(context), context_sha)
                proof = json.loads(proof_path.read_bytes())
                self.assertEqual(proof['context_sha256'], context_sha)
                self.assertEqual(proof['completion_sha256'], hashlib.sha256((directory / 'complete.json').read_bytes()).hexdigest())
                with self.assertRaises(FileExistsError): relay.record_terminal(str(context), context_sha)


class Installer(unittest.TestCase):
    def verification_bundle(self, root, entries):
        raw = json.dumps(dict(scope='private-azd-source-v1', files=entries), sort_keys=True).encode()
        digest = hashlib.sha256(raw).hexdigest()
        folder = root / digest; folder.mkdir()
        (folder / 'bundle.json').write_bytes(raw)
        context = dict(scope='private-azd-install-v1', bundle_sha256=digest)
        context_raw = json.dumps(context).encode()
        path = folder / 'context.json'; path.write_bytes(context_raw)
        return folder, path, hashlib.sha256(context_raw).hexdigest()

    def test_worker_verifies_all_real_bundle_files_and_rejects_changed_bytes(self):
        from types import SimpleNamespace
        entries = {}
        for name in relay.FILES:
            body = (ROOT / 'experiments/server' / name).read_bytes()
            entries[name] = dict(sha256=hashlib.sha256(body).hexdigest(), base64=base64.b64encode(body).decode())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            folder, path, digest = self.verification_bundle(root, entries)
            for name, metadata in entries.items():
                (folder / name).write_bytes(base64.b64decode(metadata['base64']))
            # Host ownership/mode are Linux-only; all names, paths and bytes are real.
            with patch.object(installer, 'ROOT', root), patch.object(Path, 'lstat', return_value=SimpleNamespace(st_uid=0, st_mode=0o100600)):
                context, actual = installer.verified(path, digest)
                self.assertEqual(actual, folder)
                self.assertEqual(context['bundle_sha256'], folder.name)
                (folder / 'zentral-source.lock.json').write_bytes(b'changed')
                with self.assertRaises(ValueError): installer.verified(path, digest)

    def test_worker_rejects_paths_and_unrecognized_lock_names_before_reading_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            with patch.object(installer, 'ROOT', root):
                for name in ('../outside.py', 'nested/file.py', 'source.lock.py', 'zentral-source.lock.json.py'):
                    with self.subTest(name=name):
                        _, path, digest = self.verification_bundle(root, {name: dict(sha256='a' * 64)})
                        with self.assertRaises(ValueError): installer.verified(path, digest)

    def plugin_canary(self, allowed):
        import io
        from unittest.mock import MagicMock
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve(); canary = root / 'untrusted-compose'; canary.write_text('DO NOT EXECUTE')
            sub = '11111111-1111-4111-8111-111111111111'
            target = dict(TenantId='22222222-2222-4222-8222-222222222222', SubscriptionId=sub, EnvironmentName='synthetic',
                ResourceGroup='rg-azd-santa-vm-synthetic', VmName='vm-santa-lab',
                VmId='/subscriptions/' + sub + '/resourceGroups/rg-azd-santa-vm-synthetic/providers/Microsoft.Compute/virtualMachines/vm-santa-lab',
                VmInstanceId='33333333-3333-4333-8333-333333333333')
            metadata = dict(subscriptionId=sub, resourceId=target['VmId'], vmId=target['VmInstanceId'], tagsList=[
                dict(name=key, value=value) for key, value in {'azd-solution': 'azd-santa', 'purpose': 'synthetic-vm-lab', 'azd-env-name': 'synthetic'}.items()])
            response = MagicMock(); response.__enter__.return_value = io.BytesIO(json.dumps(metadata).encode())
            opener = MagicMock(); opener.open.return_value = response
            with patch.object(installer.os, 'geteuid', return_value=0, create=True), patch.object(installer.os, 'umask'), \
                 patch.object(installer.platform, 'machine', return_value='x86_64'), patch.object(installer, 'ROOT', root), \
                 patch.object(installer, 'verified', return_value=(dict(target=target), root)), \
                 patch.object(installer, 'OVERRIDING_PLUGINS', () if allowed else (str(canary),)), \
                 patch.object(installer, 'COMPOSE_PLUGIN', canary if allowed else root / 'absent-compose'), \
                 patch.object(installer.urllib.request, 'build_opener', return_value=opener), \
                 patch.object(installer.subprocess, 'run') as external, patch.object(installer, 'write'):
                with self.assertRaises(ValueError): installer.install('/synthetic/context', 'a' * 64)
                external.assert_not_called()

    def test_override_canary_rejected_before_bootstrap_or_plugin_metadata_execution(self):
        self.plugin_canary(False)

    def test_mismatched_allowed_plugin_rejected_before_bootstrap_or_execution(self):
        self.plugin_canary(True)

    def test_absent_allowed_plugin_preserves_fresh_path_and_exact_existing_bytes_pass(self):
        with tempfile.TemporaryDirectory() as folder:
            plugin = (Path(folder) / 'compose').resolve()
            with patch.object(installer, 'COMPOSE_PLUGIN', plugin), patch.object(installer, 'OVERRIDING_PLUGINS', ()):
                installer.reject_plugin_overrides()
                plugin.write_bytes(b'qualified synthetic bytes')
                with patch.object(installer, 'COMPOSE_SHA', hashlib.sha256(plugin.read_bytes()).hexdigest()):
                    installer.reject_plugin_overrides()

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
