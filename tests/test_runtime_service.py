"""Offline lifecycle guards; no Docker, systemd, Azure or root operations."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import py_compile
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'experiments/server'))
import runtime_service as service


class Lifecycle(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()

    def fixture(self):
        # Reuse the real generator against the existing synthetic source fixture.
        spec = importlib.util.spec_from_file_location('generator_fixture', ROOT / 'tests/test_zentral_eval.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        fixture = module.ZentralEvaluation()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.prepare()
        return (fixture.destination / 'compose.json').resolve()

    def test_manifest_pins_actual_generated_files_and_rejects_modified_secret_file(self):
        compose = self.fixture()
        # Privileged ownership is not simulated as acceptance on this host.
        with patch.object(service, 'checked_path', side_effect=lambda p, **_: Path(p)):
            manifest = service.prepare(compose, compose.parent / 'runtime-service', {n: 'a' * 64 for n in service.POLICIES})
            digest = service.sha(manifest.read_bytes())
            binding, _ = service.load_manifest(manifest, digest)
            self.assertIn(str(compose.parent / 'runtime.env'), binding['files'])
            self.assertNotIn('POSTGRES_PASSWORD', manifest.read_text())
            with (compose.parent / 'runtime.env').open('a') as stream:
                stream.write('UNAPPROVED_CHANGE=1\n')
            with self.assertRaisesRegex(ValueError, 'configuration changed'):
                service.load_manifest(manifest, digest)

    def test_refuses_unpinned_dependency_and_independent_autostart(self):
        for kind in ('restart', 'image'):
            compose = self.fixture()
            data = json.loads(compose.read_text())
            data['services']['db'][kind] = 'always' if kind == 'restart' else 'postgres:latest'
            compose.write_text(json.dumps(data))
            with patch.object(service, 'checked_path', side_effect=lambda p, **_: Path(p)):
                with self.assertRaises(ValueError):
                    service.bundle(compose)

    def test_manifest_collision_and_tampered_bytes_cannot_start_any_process(self):
        compose = self.fixture()
        with patch.object(service, 'checked_path', side_effect=lambda p, **_: Path(p)), patch.object(service.subprocess, 'run') as run:
            manifest = service.prepare(compose, compose.parent / 'runtime-service', {n: 'a' * 64 for n in service.POLICIES})
            self.assertEqual(manifest, service.prepare(compose, compose.parent / 'runtime-service', {n: 'a' * 64 for n in service.POLICIES}))
            with self.assertRaises(FileExistsError):
                service.prepare(compose, compose.parent / 'runtime-service', {n: 'b' * 64 for n in service.POLICIES})
            with self.assertRaisesRegex(ValueError, 'manifest changed'):
                service.Runtime(manifest, 'f' * 64)
            run.assert_not_called()

    def test_path_escape_is_rejected_before_file_content_is_read(self):
        private = self.root / 'private'
        private.mkdir()
        path = self.root / 'outside.json'
        path.write_text('synthetic')
        with patch.object(service, 'ROOT', private):
            with self.assertRaises(ValueError):
                service.checked_path(path)

    def test_systemd_unit_has_readiness_failure_restart_and_no_shell_or_initializer(self):
        text = service.unit_text('/var/lib/azd-santa-qualification/tools/runtime_service.py',
                                 '/var/lib/azd-santa-qualification/runtime/runtime-service/manifest.json', 'a' * 64)
        self.assertIn('Type=notify', text)
        self.assertIn('Restart=on-failure', text)
        self.assertIn('StartLimitBurst=3', text)
        self.assertNotIn('/bin/sh', text)
        self.assertNotIn('migrate', text)
        self.assertNotIn('operator_security_store fresh', text)
        for bad in ('/path with spaces/controller.py', '/path/%i/controller.py', '/path/\ncontroller.py', '/tmp/controller.py'):
            with self.assertRaises(ValueError):
                service.unit_text(bad, '/var/lib/runtime/manifest.json', 'a' * 64)

    def test_install_is_opt_in_and_never_overwrites_a_different_unit(self):
        target = self.root / 'synthetic.service'
        with patch.object(service, 'UNIT', target), patch.object(service, 'load_manifest'), \
                patch.object(service, 'trusted_sources', return_value=Path('/var/lib/azd-santa-qualification/controller.py')), \
                patch.object(service, 'unit_text', return_value='synthetic unit\n'), patch.object(service.subprocess, 'run') as run:
            service.install_unit('/not-read.json', 'a' * 64)
            self.assertEqual(target.read_text(), 'synthetic unit\n')
            self.assertEqual(run.call_count, 1)
            self.assertEqual(run.call_args.args[0], ['systemctl', 'daemon-reload'])
            target.write_text('unrelated unit\n')
            run.reset_mock()
            with self.assertRaises(ValueError):
                service.install_unit('/not-read.json', 'a' * 64, enable_now=True)
            run.assert_not_called()
            self.assertEqual(target.read_text(), 'unrelated unit\n')

    def inspection_fixture(self):
        runtime = service.Runtime.__new__(service.Runtime)
        runtime.project = 'santa-zentral-eval-' + 'a' * 12
        runtime.binding = {'compose': '/var/lib/azd-santa-qualification/runtime/compose.json'}
        runtime.command = ['docker', 'compose', '-f', runtime.binding['compose']]
        runtime.ids, runtime.images = [], {}
        runtime.stopping = False
        runtime.data = {'services': {}}
        runtime.rendered = {'services': {}}
        rows, images = [], {}
        for index, name in enumerate((*service.DEPENDENCIES, *service.APPS)):
            image_id = 'sha256:' + format(index + 1, '064x')
            ref = image_id
            cmd = ['synthetic', name]
            runtime.data['services'][name] = {'image': ref, 'command': cmd, 'volumes': ['media_data:/var/zentral'] if name in service.APPS else []}
            runtime.rendered['services'][name] = {'environment': {'SELECTED_TEST_VALUE': name}}
            image = {'Id': image_id, 'Config': {'Cmd': cmd, 'Entrypoint': ['/entry'], 'User': 'synthetic', 'Env': ['BASE=value'], 'Labels': {'org.opencontainers.image.revision': service.COMMIT}}}
            images[ref] = image
            rows.append({'Id': format(index + 1, '064x'), 'Image': image_id,
                         'State': {'Running': True},
                         'Config': {**image['Config'], 'Env': ['BASE=value', 'SELECTED_TEST_VALUE=' + name],
                                    'Labels': {'com.docker.compose.project': runtime.project, 'com.docker.compose.service': name}},
                         'Mounts': [{'Type': 'volume', 'Name': runtime.project + '_media_data', 'Destination': '/var/zentral', 'RW': True}] if name in service.APPS else [],
                         'HostConfig': {'RestartPolicy': {'Name': 'no'}, 'SecurityOpt': ['no-new-privileges:true'], 'NetworkMode': runtime.project + '_default',
                                        'PortBindings': {'8000/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '8000'}]} if name == 'web' else {}},
                         'NetworkSettings': {'Networks': {runtime.project + '_default': {}},
                                             'Ports': {'8000/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '8000'}]} if name == 'web' else {}}})

        def call(label, args, **kwargs):
            if label == 'container-selection':
                stdout = '\n'.join(row['Id'] for row in rows)
            elif label == 'container-inspection':
                stdout = json.dumps(rows)
            elif label == 'image-inspection':
                stdout = json.dumps([images[args[-1]]])
            elif label == 'listener':
                stdout = ''
            else:
                raise AssertionError(label)
            return SimpleNamespace(stdout=stdout, returncode=0)
        runtime.call = Mock(side_effect=call)
        return runtime, rows

    def test_inspection_rejects_wrong_image_secrets_mount_network_command_and_extra_container(self):
        changes = (
            lambda r: r[-1].update(Image='sha256:' + 'f' * 64),
            lambda r: r[-1]['Config']['Env'].append('UNEXPECTED_SECRET=canary'),
            lambda r: r[-1]['Mounts'][0].update(Name='unselected-media'),
            lambda r: r[-1]['HostConfig'].update(NetworkMode='host'),
            lambda r: r[-1]['Config'].update(Cmd=['alternate-command']),
            lambda r: r.append(copy.deepcopy(r[-1])),
            lambda r: r[-1]['HostConfig'].update(Privileged=True),
            lambda r: r[-1]['State'].update(Running=False),
            lambda r: r[-1]['HostConfig'].update(PublishAllPorts=True),
            lambda r: r[-3]['HostConfig']['PortBindings']['8000/tcp'][0].update(HostIp='0.0.0.0'),
            lambda r: r[-3]['NetworkSettings']['Ports']['8000/tcp'][0].update(HostIp='::'),
            lambda r: r[0]['NetworkSettings'].update(Ports={'5432/tcp': [{'HostIp': '0.0.0.0', 'HostPort': '5432'}]}),
        )
        for change in changes:
            with self.subTest(change=changes.index(change)):
                runtime, rows = self.inspection_fixture()
                change(rows)
                with self.assertRaises(ValueError):
                    runtime.inspect(running=True)
                self.assertEqual(runtime.ids, [])

    def test_health_inspection_requires_original_ids_and_does_not_record_success_logs(self):
        runtime, rows = self.inspection_fixture()
        runtime.inspect(running=True)
        runtime.call.reset_mock()
        runtime.inspect(running=True, record=False)
        self.assertTrue(all(call.kwargs.get('record') is False for call in runtime.call.call_args_list))
        rows[-1]['Id'] = 'f' * 64
        with self.assertRaisesRegex(ValueError, 'identity changed'):
            runtime.inspect(running=True, record=False)

    def test_image_default_user_accepts_docker_null_to_empty_normalization_only(self):
        runtime, rows = self.inspection_fixture()
        for row in rows:
            row['Config']['User'] = ''
        # Docker image inspection reports null for an unspecified user while
        # container inspection reports an empty string for the same default.
        def call(label, args, **kwargs):
            if label == 'container-selection':
                value = '\n'.join(row['Id'] for row in rows)
            elif label == 'container-inspection':
                value = json.dumps(rows)
            elif label == 'image-inspection':
                row = next(row for row in rows if row['Image'] == args[-1])
                image = {'Id': row['Image'], 'Config': {**row['Config'], 'User': None, 'Env': ['BASE=value'],
                         'Labels': {'org.opencontainers.image.revision': service.COMMIT}}}
                value = json.dumps([image])
            else:
                raise AssertionError(label)
            return SimpleNamespace(stdout=value, returncode=0)
        runtime.call = Mock(side_effect=call)
        runtime.inspect(running=True)
        rows[0]['Config']['User'] = 'unexpected-user'
        with self.assertRaisesRegex(ValueError, 'privilege boundary'):
            runtime.inspect(running=True)

    def test_security_admission_failure_prevents_worker_and_listener_start(self):
        runtime, _ = self.inspection_fixture()
        runtime.data['volumes'] = {'redis_data': {}}
        runtime.binding['policy_hashes'] = {n: 'a' * 64 for n in service.POLICIES}
        runtime.inspect = Mock(return_value={name: format(i + 1, '064x') for i, name in enumerate(runtime.data['services'])})
        runtime.python = Mock()
        runtime.backing_data = Mock()
        calls = []
        def call(label, args, **kwargs):
            calls.append((label, args))
            if label == 'security-store':
                raise RuntimeError('Unadmitted store')
            return SimpleNamespace(returncode=0, stdout=json.dumps([{'Labels': {'com.docker.compose.project': runtime.project}}]))
        runtime.call = call
        runtime.start_ids = lambda label, names: calls.append((label, ['start', *names]))
        def oneoff(label, args):
            calls.append((label, args))
            if label == 'security-store':
                raise RuntimeError('Unadmitted store')
        runtime.oneoff = oneoff
        with patch.object(service.Path, 'read_text', return_value='1048576'):
            with self.assertRaisesRegex(RuntimeError, 'Unadmitted store'):
                runtime.start()
        labels = [label for label, _ in calls]
        self.assertLess(labels.index('close-admission'), labels.index('security-store'))
        self.assertNotIn('workers', labels)
        self.assertNotIn('listener', labels)
        text = repr(calls)
        self.assertNotIn(' fresh', text)
        self.assertNotIn('migrate', text)
        self.assertNotIn('provision', text)

    def test_repeated_healthy_calls_do_not_persist_unbounded_secret_bearing_output(self):
        runtime = service.Runtime.__new__(service.Runtime)
        runtime.environment, runtime.evidence = {}, self.root
        runtime.stopping = False
        result = SimpleNamespace(returncode=0, stdout='PRIVATE-CANARY', stderr='')
        with patch.object(service.subprocess, 'run', return_value=result), patch.object(service, 'private_write') as write:
            for _ in range(20):
                runtime.call('health', ['no-execution'], record=False)
            write.assert_not_called()
        self.assertFalse(list(self.root.iterdir()))

    def test_cancelled_start_or_wait_never_performs_another_step(self):
        runtime, _ = self.inspection_fixture()
        runtime.stopping = True
        with self.assertRaises(service.Cancelled):
            runtime.start()
        runtime.call.assert_not_called()
        predicate = Mock(return_value=True)
        with self.assertRaises(service.Cancelled):
            runtime.wait('ready', predicate)
        predicate.assert_not_called()

    def test_cancellation_during_successful_call_is_observed_before_next_stage(self):
        runtime = service.Runtime.__new__(service.Runtime)
        runtime.stopping, runtime.environment, runtime.evidence = False, {}, self.root
        def finish(*_, **kwargs):
            runtime.stopping = True
            return SimpleNamespace(returncode=0, stdout='', stderr='')
        with patch.object(service.subprocess, 'run', side_effect=finish) as run:
            with self.assertRaises(service.Cancelled):
                runtime.call('security-store', ['synthetic'])
            run.assert_called_once()

    def test_cancel_before_notify_stops_original_targets_without_reporting_ready(self):
        runtime = service.Runtime.__new__(service.Runtime)
        runtime.manifest_path, runtime.evidence = self.root / 'manifest.json', self.root
        runtime.stopping, runtime.phase = False, 'prepared'
        runtime.start = lambda: setattr(runtime, 'stopping', True)
        runtime.stop = Mock()
        fake_fcntl = SimpleNamespace(flock=Mock(), LOCK_EX=1, LOCK_NB=2)
        with patch.dict(sys.modules, {'fcntl': fake_fcntl}), patch.object(service.signal, 'signal'), \
                patch.object(service.socket, 'socket') as notify:
            runtime.supervise()
        runtime.stop.assert_called_once()
        notify.assert_not_called()
        self.assertTrue(json.loads((self.root / 'cancelled.json').read_text())['cancelled'])

    def test_start_uses_only_inspected_ids_and_never_creates_a_missing_service(self):
        runtime, _ = self.inspection_fixture()
        runtime.manifest_path, runtime.digest = self.root / 'manifest.json', 'a' * 64
        selected = runtime.inspect(running=False)
        original = selected['web']
        with patch.object(service, 'load_manifest'):
            runtime.start_ids('listener', ('web',))
            self.assertEqual(runtime.call.call_args.args[1], service.DOCKER + ['start', original])
            runtime.inspect = Mock(side_effect=ValueError('Original ID disappeared'))
            runtime.call.reset_mock()
            with self.assertRaises(ValueError):
                runtime.start_ids('listener', ('web',))
            runtime.call.assert_not_called()

    def test_helper_cleanup_failure_does_not_skip_original_container_stop(self):
        runtime = service.Runtime.__new__(service.Runtime)
        runtime.ids = ['a' * 64]
        runtime.stop_helpers = Mock(side_effect=RuntimeError('Helper cleanup failed'))
        runtime.call = Mock(return_value=SimpleNamespace(stdout='a' * 64))
        with self.assertRaises(RuntimeError):
            runtime.stop()
        self.assertEqual(runtime.call.call_args.args[1], service.DOCKER + ['stop', '--time', '30', 'a' * 64])
        self.assertTrue(runtime.call.call_args.kwargs['allow_stopping'])

    def test_untrusted_executable_tree_is_rejected_before_systemd_or_artifact_writes(self):
        private = self.root / 'private'
        private.mkdir()
        script = self.root / 'untrusted.py'
        script.write_text('# synthetic')
        with patch.object(service, 'ROOT', private), patch.object(service, '__file__', str(script)), \
                patch.object(service.subprocess, 'run') as run:
            with self.assertRaises(ValueError):
                service.install_unit(private / 'manifest.json', 'a' * 64, enable_now=True)
            run.assert_not_called()
        self.assertEqual(list(private.iterdir()), [])

    def test_helper_import_is_guarded_and_unsafe_sibling_code_never_executes(self):
        with patch.object(service, 'trusted_sources', side_effect=ValueError('Untrusted helper')), \
                patch.object(service.types, 'ModuleType') as spec:
            with self.assertRaises(ValueError):
                service.compose_helper()
            spec.assert_not_called()
        controller = self.root / 'runtime_service.py'
        controller.write_bytes(Path(service.__file__).read_bytes())
        canary = self.root / 'canary.txt'
        (self.root / 'test_live_zentral.py').write_text(f"from pathlib import Path\nPath({str(canary)!r}).write_text('unexpected execution')\n")
        for flags in ([], ['-I']):
            result = subprocess.run([sys.executable, *flags, str(controller), 'unit',
                                     '--manifest', str(self.root / 'manifest.json'), '--sha256', 'a' * 64],
                                    capture_output=True, text=True, timeout=15)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(canary.exists())

    def test_helper_executes_checked_source_instead_of_matching_timestamp_bytecode(self):
        controller = self.root / 'runtime_service.py'
        helper = self.root / 'prepare_zentral_eval.py'
        unsafe = "CACHE_EXECUTED = True\n"
        safe = "CACHE_EXECUTED = None\n"
        self.assertEqual(len(unsafe), len(safe))
        helper.write_bytes(unsafe.encode())
        timestamp = helper.stat().st_mtime_ns
        py_compile.compile(str(helper), doraise=True,
                           invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP)
        helper.write_bytes(safe.encode())
        os.utime(helper, ns=(timestamp, timestamp))
        (self.root / 'test_live_zentral.py').write_text(
            f'from prepare_zentral_eval import CACHE_EXECUTED\nCOMMIT = {service.COMMIT!r}\n')
        names = ('prepare_zentral_eval', 'test_live_zentral')
        previous = {name: sys.modules.get(name) for name in names}
        try:
            with patch.object(service, 'trusted_sources', return_value=controller), \
                    patch.object(service, '_HELPER', None):
                self.assertIsNone(service.compose_helper().CACHE_EXECUTED)
        finally:
            for name, module in previous.items():
                if module is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = module

    def test_empty_or_wrong_version_postgres_is_rejected_without_starting_it(self):
        root = self.root / 'postgres'
        root.mkdir()
        environment = {'PG_MAJOR': '18', 'PGDATA': '/var/lib/postgresql/18/docker'}
        with self.assertRaises((OSError, ValueError)):
            service.check_postgres_data(root, environment, {})
        data = root / '18/docker'
        for name in ('global', 'base', 'pg_wal'):
            (data / name).mkdir(parents=True, exist_ok=True)
        for name in ('global/pg_control', 'postgresql.conf', 'pg_hba.conf'):
            (data / name).write_bytes(b'synthetic')
        (data / 'PG_VERSION').write_text('18\n')
        service.check_postgres_data(root, environment, {})
        (data / 'PG_VERSION').write_text('17\n')
        with self.assertRaisesRegex(ValueError, 'version mismatch'):
            service.check_postgres_data(root, environment, {})

    def test_redis_requires_existing_manifest_and_each_referenced_data_file(self):
        root = self.root / 'redis'
        root.mkdir()
        with self.assertRaises((OSError, ValueError)):
            service.check_redis_data(root)
        data = root / 'appendonlydir'
        data.mkdir()
        (data / 'appendonly.aof.manifest').write_text('file appendonly.aof.1.base.rdb seq 1 type b\nfile appendonly.aof.1.incr.aof seq 1 type i\n')
        (data / 'appendonly.aof.1.base.rdb').write_bytes(b'synthetic')
        (data / 'appendonly.aof.1.incr.aof').write_bytes(b'')
        service.check_redis_data(root)
        (data / 'appendonly.aof.1.incr.aof').unlink()
        with self.assertRaises((OSError, ValueError)):
            service.check_redis_data(root)


if __name__ == '__main__':
    unittest.main()
