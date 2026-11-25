"""Controlled capture and daemon projections for retention selection."""
import hashlib
import json
from pathlib import Path
import sys
import unittest

SERVER = Path(__file__).resolve().parents[1] / 'experiments/server'
sys.path.insert(0, str(SERVER))
import retention_image_inventory as inventory


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.lock_raw = (SERVER / 'dependency-images.lock.json').read_bytes()
        self.lock = json.loads(self.lock_raw)
        self.lock_sha256 = hashlib.sha256(self.lock_raw).hexdigest()
        self.core = 'sha256:' + '1' * 64
        images = {name: {'id': self.core, 'reference': self.core} for name in inventory.CORE_SERVICES}
        self.inspected = {self.core: {'Id': self.core, 'Os': 'linux', 'Architecture': 'amd64'}}
        for digit, (service, name) in enumerate(inventory.DEPENDENCIES.items(), start=2):
            identifier = 'sha256:' + str(digit) * 64
            reference = self.lock[name]
            images[service] = {'id': identifier, 'reference': reference}
            self.inspected[identifier] = {'Id': identifier, 'Os': 'linux', 'Architecture': 'amd64',
                                          'RepoDigests': [reference]}
        self.capture = {'scope': 'azd-santa-cold-backup-v1', 'images': images,
                        'source_commit': 'a' * 40, 'selection': {'generation_sha256': 'b' * 64,
                                                               'runtime_manifest': {'sha256': 'c' * 64}}}

    def select(self, raw=None, **overrides):
        raw = encode(self.capture) if raw is None else raw
        hashes = {'compatibility_sha256': hashlib.sha256(raw).hexdigest(),
                  'dependency_lock_sha256': self.lock_sha256}
        hashes.update(overrides)
        return inventory.select_images(raw, self.lock_raw, self.inspected, **hashes)

    def test_selects_five_images_and_keeps_registry_and_local_digests_distinct(self):
        postgres = self.capture['images']['db']
        self.inspected[postgres['id']]['RepoDigests'] = ['docker.io/library/' + postgres['reference']]
        selected = self.select()
        self.assertEqual(selected['platform'], 'linux/amd64')
        self.assertEqual(selected['generation_sha256'], 'b' * 64)
        self.assertEqual(selected['runtime_manifest_sha256'], 'c' * 64)
        self.assertEqual(set(selected['images']), {'core', 'postgres', 'redis', 'rabbitmq', 'elasticsearch'})
        self.assertEqual(selected['images']['core'], {'id': self.core, 'reference': self.core,
                                                      'services': ['celery', 'web', 'workers']})
        self.assertEqual(selected['images']['postgres'], {**postgres, 'services': ['db']})
        self.assertNotEqual(postgres['reference'].partition('@')[2], postgres['id'])

    def test_rejects_missing_or_extra_services_locks_and_daemon_records(self):
        for case in ('missing_service', 'extra_service', 'extra_lock', 'missing_inspection', 'extra_inspection'):
            with self.subTest(case=case):
                self.setUp()
                if case == 'missing_service':
                    del self.capture['images']['celery']
                elif case == 'extra_service':
                    self.capture['images']['new'] = self.capture['images']['db']
                elif case == 'extra_lock':
                    self.lock_raw = encode({**self.lock, 'new': self.lock['redis']})
                    self.lock_sha256 = hashlib.sha256(self.lock_raw).hexdigest()
                elif case == 'missing_inspection':
                    del self.inspected[self.core]
                else:
                    self.inspected['sha256:' + '9' * 64] = self.inspected[self.core]
                with self.assertRaises(inventory.InventoryRejected):
                    self.select()

    def test_rejects_tag_other_repository_mismatched_digest_and_wrong_platform(self):
        for case in ('tag', 'repository', 'digest', 'different_core', 'daemon_id', 'os', 'arch', 'variant'):
            with self.subTest(case=case):
                self.setUp()
                postgres = self.capture['images']['db']
                observed = self.inspected[postgres['id']]
                if case == 'tag':
                    postgres['reference'] = 'postgres:18'
                elif case == 'repository':
                    postgres['reference'] = postgres['reference'].replace('postgres', 'other/postgres')
                elif case == 'digest':
                    observed['RepoDigests'] = ['postgres@sha256:' + 'd' * 64]
                elif case == 'different_core':
                    self.capture['images']['web'] = postgres
                elif case == 'daemon_id':
                    observed['Id'] = self.core
                elif case == 'os':
                    observed['Os'] = 'windows'
                elif case == 'arch':
                    observed['Architecture'] = 'arm64'
                else:
                    observed['Variant'] = 'v3'
                with self.assertRaises(inventory.InventoryRejected):
                    self.select()

    def test_requires_independent_hashes_and_rejects_ambiguous_documents(self):
        with self.assertRaises(inventory.InventoryRejected):
            self.select(compatibility_sha256='0' * 64)
        with self.assertRaises(inventory.InventoryRejected):
            self.select(dependency_lock_sha256='0' * 64)
        raw = encode(self.capture).replace(b'"images":', b'"images":{},"images":')
        with self.assertRaises(inventory.InventoryRejected) as error:
            self.select(raw)
        self.assertEqual(str(error.exception), 'Santa retention image selection rejected')
