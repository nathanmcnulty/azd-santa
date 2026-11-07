"""Offline generator tests; no Docker, tenant, downloads or upstream execution."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

MODULE_PATH = Path(__file__).resolve().parents[1] / 'experiments/server/prepare_zentral_eval.py'
SPEC = importlib.util.spec_from_file_location('prepare_zentral_eval', MODULE_PATH)
generator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(generator)


class ZentralEvaluation(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.source = self.root / 'upstream'
        (self.source / 'conf/start/zentral').mkdir(parents=True)
        config = {
            'api': {'tls_privkey': '{{ file:/not-available }}'},
            'extra_links': [{'url': 'https://example.invalid'}],
            'django': {'DEBUG': True, 'SECRET_KEY': 'insecure', 'CACHES': {
                'default': {'BACKEND': 'django_redis.cache.RedisCache',
                            'LOCATION': 'redis://redis:6379/1'}}},
            'apps': {'zentral.contrib.santa': {}, 'zentral.core.stores': {
                'provisioning': {'stores': {'elasticsearch': {
                    'backend': 'ELASTICSEARCH', 'admin_console': True,
                    'elasticsearch_kwargs': {'hosts': ['http://elastic:9200']}}}}}},
        }
        files = {'Dockerfile': b'FROM test-only\n', 'LICENSE': b'test-only license\n',
                 'conf/start/zentral/base.json': json.dumps(config).encode()}
        for name, data in files.items():
            (self.source / name).write_bytes(data)
        self.hashes = {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}
        self.lock = {name: f'example.invalid/{name}@sha256:' + 'a' * 64
                     for name in generator.DEPENDENCIES}
        self.image = 'sha256:' + 'b' * 64
        self.destination = self.root / 'generated'

    def prepare(self):
        with patch.dict(generator.SOURCE_HASHES, self.hashes, clear=True):
            generator.prepare(self.source, self.image, self.lock, self.destination)

    def read(self, name):
        return json.loads((self.destination / name).read_text())

    def test_seven_services_are_loopback_bounded_and_persistent(self):
        self.prepare()
        compose = self.read('compose.json')
        services = compose['services']
        self.assertEqual(set(services), {'db', 'redis', 'rabbitmq', 'elastic', 'web', 'workers', 'celery'})
        self.assertEqual(services['web']['ports'], ['127.0.0.1:8000:8000'])
        self.assertEqual(services['web']['command'][0], 'gunicorn')
        self.assertEqual(services['workers']['command'], ['runworkers'])
        self.assertEqual(services['celery']['command'], ['celery', '--concurrency', '1'])
        self.assertEqual(services['db']['volumes'], ['postgres_data:/var/lib/postgresql'])
        self.assertEqual(services['rabbitmq']['hostname'], 'rabbitmq')
        for name, service in services.items():
            if name != 'web':
                self.assertNotIn('ports', service)
            self.assertNotIn('privileged', service)
            self.assertNotIn('network_mode', service)
            self.assertEqual(service['logging']['options']['max-file'], '3')
            self.assertNotIn('docker.sock', json.dumps(service))
            self.assertNotIn('runserver', json.dumps(service))
        self.assertEqual(set(compose['volumes']), {'postgres_data', 'redis_data', 'rabbitmq_data', 'elasticsearch_data', 'media_data'})
        self.assertEqual(services['redis']['volumes'], ['redis_data:/data'])
        self.assertEqual(services['redis']['command'], generator.REDIS_COMMAND)

    def test_configuration_and_private_secrets(self):
        self.prepare()
        config = self.read('conf/base.json')
        self.assertFalse(config['django']['DEBUG'])
        self.assertTrue(config['django']['STATIC_WHITENOISE'])
        self.assertEqual(config['django']['ALLOWED_HOSTS'], ['localhost', '127.0.0.1'])
        self.assertEqual(config['queues']['backend'], 'zentral.core.queues.backends.kombu')
        self.assertEqual(config['notifier']['url'], 'redis://redis:6379/15')
        self.assertNotIn('tls_privkey', config['api'])
        env = dict(line.split('=', 1) for line in (self.destination / 'runtime.env').read_text().splitlines())
        self.assertRegex(env['AZD_SANTA_SECURITY_STORE_ID'], r'^[0-9a-f]{64}$')
        self.assertNotIn(env['AZD_SANTA_SECURITY_STORE_ID'], (self.destination / 'provenance.json').read_text())
        for key in ('POSTGRES_PASSWORD', 'RABBITMQ_DEFAULT_PASS', 'ZENTRAL_DJANGO_SECRET'):
            self.assertGreaterEqual(len(env[key]), 48)
            self.assertNotIn(env[key], (self.destination / 'provenance.json').read_text())
            self.assertNotIn(env[key], (self.destination / 'compose.json').read_text())
            self.assertNotIn(env[key], (self.destination / 'conf/base.json').read_text())
        if os.name != 'nt':
            self.assertEqual((self.destination / 'runtime.env').stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.read('provenance.json')['upstream_commit'], generator.COMMIT)
        self.assertIn('evaluation license', (self.destination / 'EVALUATION-ONLY.txt').read_text())
        self.assertEqual((self.destination / 'LICENSE.upstream').read_bytes(),
                         (self.source / 'LICENSE').read_bytes())

    def test_refuses_existing_destination_without_touching_it(self):
        self.prepare()
        before = {p.relative_to(self.destination): p.read_bytes()
                  for p in self.destination.rglob('*') if p.is_file()}
        with self.assertRaises(FileExistsError):
            self.prepare()
        self.assertEqual(before, {p.relative_to(self.destination): p.read_bytes()
                                for p in self.destination.rglob('*') if p.is_file()})

    def test_refuses_changed_source_before_output(self):
        (self.source / 'Dockerfile').write_text('changed')
        with self.assertRaises(ValueError):
            self.prepare()
        self.assertFalse(self.destination.exists())

    def test_refuses_mutable_images_and_incomplete_lock(self):
        for bad in ('latest', 'sha256:short', 'sha256:' + 'G' * 64):
            self.image = bad
            with self.assertRaises(ValueError):
                self.prepare()
        self.image = 'sha256:' + 'b' * 64
        self.lock['redis'] = 'redis:7'
        with self.assertRaises(ValueError):
            self.prepare()
        del self.lock['redis']
        with self.assertRaises(ValueError):
            self.prepare()
        self.assertFalse(self.destination.exists())

    def test_new_evaluation_does_not_reuse_compose_project(self):
        self.prepare()
        first = self.read('compose.json')['name']
        self.destination = self.root / 'second'
        self.prepare()
        self.assertNotEqual(first, self.read('compose.json')['name'])

    def test_fresh_santa_profile_preserves_dependencies_and_telemetry(self):
        path = self.source / 'conf/start/zentral/base.json'
        config = json.loads(path.read_text())
        for name in (*generator.OPTIONAL_APPS, 'realms', 'zentral.core.compliance_checks',
                     'zentral.core.incidents', 'zentral.core.terraform', 'zentral.contrib.inventory'):
            config['apps'][name] = {'test-marker': name}
        path.write_text(json.dumps(config))
        self.hashes['conf/start/zentral/base.json'] = hashlib.sha256(path.read_bytes()).hexdigest()
        self.prepare()
        baseline = self.read('conf/base.json')
        baseline_compose = self.read('compose.json')
        self.destination = self.root / 'santa-fresh'
        with patch.dict(generator.SOURCE_HASHES, self.hashes, clear=True):
            generator.prepare(self.source, self.image, self.lock, self.destination,
                              'core-experiment', app_profile='santa')
        expected = {name: value for name, value in baseline['apps'].items()
                    if name not in generator.OPTIONAL_APPS}
        self.assertEqual(self.read('conf/base.json')['apps'], expected)
        self.assertTrue(all(name in baseline['apps'] for name in generator.OPTIONAL_APPS))
        self.assertEqual(set(self.read('compose.json')['services']), set(baseline_compose['services']))
        self.assertEqual(self.read('provenance.json')['app_profile'], 'santa')
        self.assertEqual(path.read_text(), json.dumps(config))

    def test_invalid_app_profile_is_rejected_before_output(self):
        with self.assertRaisesRegex(ValueError, 'Unknown evaluation app profile'):
            generator.prepare(self.source, self.image, self.lock, self.destination, app_profile='unknown')
        self.assertFalse(self.destination.exists())

    def test_core_variant_is_declared_not_license_clearance(self):
        with patch.dict(generator.SOURCE_HASHES, self.hashes, clear=True):
            generator.prepare(self.source, self.image, self.lock, self.destination, 'core-experiment')
        self.assertEqual(self.read('provenance.json')['declared_image_variant'], 'core-experiment')
        self.assertIn('verify actual image contents', (self.destination / 'EVALUATION-ONLY.txt').read_text())
        self.assertNotIn('image includes ee/', (self.destination / 'EVALUATION-ONLY.txt').read_text())

    @unittest.skipIf(os.name == 'nt', 'POSIX container configuration access')
    def test_restrictive_umask_keeps_nonsecret_container_config_readable(self):
        previous = os.umask(0o077)
        try:
            self.prepare()
        finally:
            os.umask(previous)
        self.assertEqual((self.destination / 'conf').stat().st_mode & 0o777, 0o755)
        self.assertEqual((self.destination / 'conf/base.json').stat().st_mode & 0o777, 0o644)
        self.assertEqual((self.destination / 'runtime.env').stat().st_mode & 0o777, 0o600)


if __name__ == '__main__':
    unittest.main()
