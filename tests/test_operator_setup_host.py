"""Offline original host-program guards; not VM/Django/Azure acceptance."""
import base64
import copy
from concurrent.futures import ThreadPoolExecutor
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('setup_host', ROOT / 'experiments/server/operator_setup_host.py')
host = importlib.util.module_from_spec(spec); spec.loader.exec_module(host)


def request():
    sub = '11111111-1111-4111-8111-111111111111'
    key = base64.b64encode(b'public-key-validation-is-delegated-to-installed-sealer').decode()
    b = dict(TenantId='22222222-2222-4222-8222-222222222222', SubscriptionId=sub,
        EnvironmentName='synthetic', ResourceGroup='rg-azd-santa-vm-synthetic', VmName='vm-santa-lab',
        VmId=f'/subscriptions/{sub}/resourceGroups/rg-azd-santa-vm-synthetic/providers/Microsoft.Compute/virtualMachines/vm-santa-lab',
        VmInstanceId='33333333-3333-4333-8333-333333333333', ImageId='sha256:' + 'a' * 64,
        ComposePath='/var/lib/azd-santa-qualification/synthetic/compose.json', ComposeSha256='b' * 64,
        SourceCommit='c' * 40, RecoverySha256='d' * 64, SealedSha256='e' * 64,
        Origin='https://santa.example.invalid', RemoteProgramSha256='f' * 64)
    context = dict(scope='azd-santa-setup-request-v1', nonce='a' * 64,
        binding={k: b[k] for k in host.BINDINGS}, mode='recover', target_sha256=host.target('synthetic-é', 'synthetic@example.invalid'),
        recipient_sha256=host.sha(base64.b64decode(key)))
    return dict(context=context, context_sha256=host.sha(host.encoded(context)), recipient_public_key=key,
                username='synthetic-é', email='synthetic@example.invalid', reason='Synthetic qualification')


def environment(value):
    return {'AZD_SANTA_SETUP_REQUEST_B64': base64.b64encode(host.encoded(value)).decode(), 'AZD_SANTA_SETUP_OPERATION': 'create'}


def envelope(value):
    return host.encoded(dict(scope='azd-santa-sealed-setup', version=1, algorithm='RSA-OAEP-256+A256GCM',
        mode=value['context']['mode'], kid_sha256=value['context']['recipient_sha256'], context_sha256=value['context_sha256'],
        target_sha256=value['context']['target_sha256'], wrapped_key_base64=base64.b64encode(bytes(384)).decode(),
        nonce_base64=base64.b64encode(bytes(12)).decode(), ciphertext_base64=base64.b64encode(bytes(17)).decode()))


class RequestGuards(unittest.TestCase):
    def test_private_path_rejects_wrong_owner_link_and_permissions_with_metadata_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); selected = root / 'a/compose.json'
            bad = None
            def metadata(path):
                if path == selected:
                    return bad or SimpleNamespace(st_uid=0, st_mode=stat.S_IFREG | 0o600)
                return SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o700)
            with patch.object(host, 'ROOT', root), patch.object(Path, 'lstat', autospec=True, side_effect=metadata):
                self.assertEqual(host.private_path(selected), selected)
                for uid, mode in ((1, stat.S_IFREG | 0o600), (0, stat.S_IFLNK | 0o600), (0, stat.S_IFREG | 0o666)):
                    bad = SimpleNamespace(st_uid=uid, st_mode=mode)
                    with self.assertRaises(ValueError): host.private_path(selected)
                with self.assertRaises(ValueError): host.private_path(root.parent / 'outside.json')

    def test_context_digest_unicode_target_and_mutations_before_external_calls(self):
        value = request()
        with patch.dict(os.environ, environment(value)), patch.object(host, 'docker') as docker:
            self.assertEqual(host.request_from_environment()[0], value)
            docker.assert_not_called()
        for key, change in (('username', 'changed'), ('email', 'changed@example.invalid'), ('reason', 'bad\nreason')):
            modified = copy.deepcopy(value); modified[key] = change
            with patch.dict(os.environ, environment(modified)), self.assertRaises(ValueError):
                host.request_from_environment()

    def test_rejects_duplicate_fields_and_modified_context_or_recipient(self):
        value = request()
        for change in (
            lambda v: v['context']['binding'].update(VmInstanceId='wrong'),
            lambda v: v.update(recipient_public_key=base64.b64encode(b'wrong').decode()),
            lambda v: v['context'].update(mode='anything'),
        ):
            modified = copy.deepcopy(value); change(modified)
            with patch.dict(os.environ, environment(modified)), self.assertRaises(ValueError):
                host.request_from_environment()
        with self.assertRaises(ValueError):
            host.loads('{"username":"one","username":"two"}')

    def test_fixed_metadata_no_proxy_no_redirect_timeout_and_immutable_instance(self):
        value = request(); b = value['context']['binding']
        metadata = dict(subscriptionId=b['SubscriptionId'], vmId=b['VmInstanceId'], resourceId=b['VmId'].upper(),
                        name=b['VmName'], resourceGroupName=b['ResourceGroup'])
        response = unittest.mock.MagicMock()
        response.__enter__.return_value.read.return_value = host.encoded(metadata)
        opener = unittest.mock.Mock(); opener.open.return_value = response
        with patch.object(host.urllib.request, 'build_opener', return_value=opener) as build:
            host.attest_metadata(b)
            handlers = build.call_args.args
            self.assertEqual(handlers[0].proxies, {})
            self.assertIsInstance(handlers[1], host.NoRedirect)
            self.assertIsNone(handlers[1].redirect_request())
            args, kwargs = opener.open.call_args
            self.assertEqual(args[0].full_url, 'http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01')
            self.assertEqual(kwargs, {'timeout': 2})
            metadata['vmId'] = '44444444-4444-4444-8444-444444444444'
            response.__enter__.return_value.read.return_value = host.encoded(metadata)
            with self.assertRaises(ValueError):
                host.attest_metadata(b)

    def test_envelope_rejects_plaintext_schema_wrong_context_and_encoding(self):
        value = request(); sealed = envelope(value)
        self.assertEqual(host.envelope(sealed, value), sealed)
        for raw in (b'{"setup_url":"never-export"}', sealed.replace(b'"version":1', b'"version":true'),
                    sealed.replace(value['context_sha256'].encode(), b'f' * 64), b' ' * 2601):
            with self.assertRaises(ValueError):
                host.envelope(raw, value)


class RuntimeGuards(unittest.TestCase):
    def fixture(self, directory):
        value = request(); b = value['context']['binding']
        compose = Path(directory) / 'compose.json'; b['ComposePath'] = str(compose)
        project = 'santa-zentral-eval-' + 'a' * 12
        environments = {name: {key: 'synthetic' for key in keys} for name, keys in host.ENV_KEYS.items()}
        environments['db.env'].update(POSTGRES_USER='zentral_owner', POSTGRES_PASSWORD='synthetic-owner')
        environments['runtime.env'].update(POSTGRES_USER='zentral_runtime', POSTGRES_PASSWORD='synthetic-runtime')
        services = {}
        names = ('web', 'workers', 'celery', 'db', 'redis', 'rabbitmq', 'elastic')
        volumes = dict(db=['postgres_data:/var/lib/postgresql'], redis=['redis_data:/data'],
            rabbitmq=['rabbitmq_data:/var/lib/rabbitmq'], elastic=['elasticsearch_data:/usr/share/elasticsearch/data'])
        ids, infos, images = {}, {}, {}
        for index, name in enumerate(names):
            app = name in ('web', 'workers', 'celery')
            image = b['ImageId'] if app else name + '@sha256:' + str(index) * 64
            image_id = b['ImageId'] if app else 'sha256:' + str(index) * 64
            declaration = {'image': image, 'volumes': ['./conf:/zentral-eval-conf:ro', 'media_data:/var/zentral'] if app else volumes[name]}
            envfile = 'db.env' if name == 'db' else 'rabbitmq.env' if name == 'rabbitmq' else 'runtime.env'
            if name not in ('redis', 'elastic'):
                declaration['env_file'] = ['./' + envfile]
            if name == 'web': declaration['ports'] = ['127.0.0.1:8000:8000']
            if name == 'redis': declaration['command'] = host.REDIS
            services[name] = declaration
            ids[name] = str(index + 1) * 64
            mounts = []
            for item in declaration['volumes']:
                source, destination, *mode = item.split(':')
                mounts.append(dict(Destination=destination, Type='bind' if source == './conf' else 'volume',
                    Source=str(Path(directory) / 'conf') if source == './conf' else 'unused',
                    Name=project + '_' + source, RW=not mode))
            env = ['PATH=/synthetic'] + ([] if name in ('redis', 'elastic') else [key + '=' + item for key, item in environments[envfile].items()])
            infos[ids[name]] = dict(Config={'Image': image, 'Env': env, 'Labels': {'com.docker.compose.project': project,
                'com.docker.compose.service': name, 'org.opencontainers.image.revision': b['SourceCommit']}},
                State={'Running': True}, Image=image_id, Mounts=mounts,
                HostConfig={'Privileged': False, 'PortBindings': {'8000/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '8000'}]} if name == 'web' else {}},
                NetworkSettings={'Networks': {project + '_default': {'NetworkID': 'f' * 64}},
                    'Ports': {'8000/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '8000'}]} if name == 'web' else {'5432/tcp': None}})
            images[image] = dict(Id=image_id, Config={'Labels': {'io.azd-santa.variant': 'core-experiment'}, 'ExposedPorts': {'5432/tcp': {}}})
        data = dict(name=project, services=services, volumes={name: {} for name in host.VOLUMES})
        compose.write_bytes(host.encoded(data)); (Path(directory) / 'conf').mkdir(); (Path(directory) / 'conf/base.json').write_text('{}')
        for filename, items in environments.items():
            (Path(directory) / filename).write_text(''.join(key + '=' + item + '\n' for key, item in items.items()))
        b['ComposeSha256'] = host.sha(compose.read_bytes())
        def docker(args, **kwargs):
            if args[0] == 'compose': return ids[args[-1]].encode()
            if args[0] == 'inspect': return host.encoded([infos[args[1]]])
            if args[:2] == ['image', 'inspect']: return host.encoded([images[args[2]]])
            if args[0] == 'exec':
                compile(args[-1], 'actual-django-attestation-probe', 'exec')
                self.assertIn("b['RecoverySha256']", args[-1]); self.assertIn("b['SealedSha256']", args[-1])
                self.assertIn('policy.check_security_store()', args[-1])
                return b'SANTA_SETUP_HOST_ATTESTED\n'
            self.fail('Unexpected Docker operation')
        return value, data, infos, docker, ids

    def test_actual_container_image_network_mount_and_private_compose_guard_shapes(self):
        with tempfile.TemporaryDirectory() as directory:
            value, data, infos, docker, ids = self.fixture(directory)
            with patch.object(host, 'private_path', side_effect=lambda path, **kwargs: Path(path)), patch.object(host, 'docker', side_effect=docker):
                self.assertEqual(host.attest_runtime(value), ids)
                for name, key, changed in (('web', 'Image', 'sha256:' + 'b' * 64), ('redis', 'State', {'Running': False}),
                    ('db', 'HostConfig', {'Privileged': True}), ('celery', 'NetworkSettings', {'Networks': {'wrong': {}}})):
                    previous = infos[ids[name]][key]; infos[ids[name]][key] = changed
                    try:
                        with self.assertRaises((ValueError, KeyError)): host.attest_runtime(value)
                    finally: infos[ids[name]][key] = previous
                infos[ids['db']]['Config']['Env'].append('ZENTRAL_DJANGO_SECRET=old-shared-secret')
                with self.assertRaises(ValueError): host.attest_runtime(value)
                infos[ids['db']]['Config']['Env'].pop()
                data['services']['db']['volumes'].append('media_data:/var/zentral')
                compose = Path(value['context']['binding']['ComposePath']); compose.write_bytes(host.encoded(data))
                value['context']['binding']['ComposeSha256'] = host.sha(compose.read_bytes())
                with self.assertRaises(ValueError): host.attest_runtime(value)

    def test_actual_published_ports_reject_wildcard_ipv6_extra_and_dependency_publication(self):
        def info(bindings, observed=None, publish_all=False):
            return {'HostConfig': {'PortBindings': bindings, 'PublishAllPorts': publish_all},
                    'NetworkSettings': {'Ports': bindings if observed is None else observed}}
        correct = {'8000/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '8000'}]}
        host.actual_ports(info(correct, dict(correct, **{'9000/tcp': None})), 'web', {'9000/tcp'})
        host.actual_ports(info({}, {'5432/tcp': None}), 'db', {'5432/tcp'})
        with self.assertRaises(ValueError): host.actual_ports(info(correct, dict(correct, **{'9000/tcp': None})), 'web')
        for binding in (
            {'8000/tcp': [{'HostIp': '0.0.0.0', 'HostPort': '8000'}]},
            {'8000/tcp': [{'HostIp': '::', 'HostPort': '8000'}]},
            {'8000/tcp': correct['8000/tcp'] + [{'HostIp': '::1', 'HostPort': '8000'}]},
            dict(correct, **{'9000/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '9000'}]}),
            {'8000/tcp': []}, {},
        ):
            with self.subTest(binding=binding):
                with self.assertRaises(ValueError): host.actual_ports(info(binding, correct), 'web')
                with self.assertRaises(ValueError): host.actual_ports(info(correct, binding), 'web')
        for service in ('db', 'redis', 'rabbitmq', 'elastic', 'workers', 'celery'):
            with self.subTest(service=service), self.assertRaises(ValueError):
                host.actual_ports(info(correct), service)
        with self.assertRaises(ValueError): host.actual_ports(info(correct, publish_all=True), 'web')


class MutationCheckpoint(unittest.TestCase):
    def test_unknown_commit_cannot_retry_and_readback_never_runs_command(self):
        value = request(); raw = host.encoded(value); sealed = envelope(value)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def write(path, data):
                with Path(path).open('xb') as output: output.write(data)
            with patch.object(host, 'ROOT', root), patch.object(host, 'private_path', side_effect=lambda path, **kwargs: Path(path)), \
                 patch.object(host, 'write_new', side_effect=write), patch.object(host, 'sync_directory'), \
                 patch.object(host.os, 'geteuid', return_value=0, create=True), patch.object(host, 'attest_metadata'), \
                 patch.object(host, 'attest_runtime', return_value={'web': 'a' * 64}), patch.object(host.os, 'umask'), \
                 patch.object(host.subprocess, 'run', side_effect=subprocess.TimeoutExpired('selected-docker-exec', 180)) as action, \
                 patch.dict(os.environ, environment(value)), patch('sys.stdout', new_callable=io.StringIO) as output:
                with self.assertRaises(subprocess.TimeoutExpired): host.run()
                self.assertEqual(action.call_count, 1)
                with self.assertRaises(FileExistsError): host.run()
                self.assertEqual(action.call_count, 1)
                self.assertEqual(output.getvalue(), '')
                folder = root / 'operator-setup' / value['context_sha256']
                self.assertEqual((folder / 'request.json').read_bytes(), raw)
                self.assertTrue((folder / 'attempt.json').exists())
                with patch.dict(os.environ, {'AZD_SANTA_SETUP_OPERATION': 'readback'}), patch.object(host, 'read_artifact', return_value=sealed):
                    host.run()
                self.assertEqual(action.call_count, 1)
                self.assertEqual(output.getvalue(), host.MARKER + sealed.decode() + '\n')
                changed = copy.deepcopy(value); changed['reason'] = 'Different reason'
                with patch.dict(os.environ, dict(environment(changed), AZD_SANTA_SETUP_OPERATION='readback')):
                    with self.assertRaises(ValueError): host.run()
                self.assertEqual(action.call_count, 1)

    def test_concurrent_same_context_reservations_allow_only_one_mutation_attempt(self):
        value = request()
        with tempfile.TemporaryDirectory() as directory:
            def write(path, data):
                with Path(path).open('xb') as output: output.write(data)
            with patch.object(host, 'ROOT', Path(directory)), patch.object(host, 'private_path', side_effect=lambda p, **kw: Path(p)), \
                 patch.object(host, 'write_new', side_effect=write), patch.object(host, 'sync_directory'), \
                 patch.object(host.os, 'geteuid', return_value=0, create=True), patch.object(host, 'attest_metadata'), \
                 patch.object(host, 'attest_runtime', return_value={'web': 'a' * 64}), patch.object(host.os, 'umask'), \
                 patch.object(host.subprocess, 'run', side_effect=subprocess.TimeoutExpired('selected-docker-exec', 180)) as action, \
                 patch.dict(os.environ, environment(value)):
                def attempt(_):
                    try: host.run()
                    except (FileExistsError, subprocess.TimeoutExpired) as error: return type(error).__name__
                with ThreadPoolExecutor(max_workers=2) as pool:
                    self.assertEqual(sorted(pool.map(attempt, (0, 1))), ['FileExistsError', 'TimeoutExpired'])
                self.assertEqual(action.call_count, 1)

    def test_bad_attestation_does_not_reserve_or_mutate(self):
        value = request()
        with tempfile.TemporaryDirectory() as directory, patch.object(host, 'ROOT', Path(directory)), \
             patch.object(host.os, 'geteuid', return_value=0, create=True), patch.object(host.os, 'umask'), \
             patch.object(host, 'attest_metadata', side_effect=ValueError('wrong instance')), \
             patch.object(host.subprocess, 'run') as action, patch.dict(os.environ, environment(value)):
            with self.assertRaises(ValueError): host.run()
            action.assert_not_called()
            self.assertEqual(list(Path(directory).iterdir()), [])


if __name__ == '__main__':
    unittest.main()
