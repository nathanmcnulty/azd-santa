"""Preparation/readback guards only; mocks are not fresh-runtime acceptance."""
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'experiments/server'))
import qualify_santa_profile as profile
import prepare_zentral_eval as generator
import test_zentral_eval as fixtures
import test_live_zentral_harness as devices


class FreshProfile(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.ZentralEvaluation()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        source = self.fixture.source / 'conf/start/zentral/base.json'
        config = json.loads(source.read_text())
        for name in generator.OPTIONAL_APPS:
            config['apps'][name] = {}
        source.write_text(json.dumps(config))
        self.fixture.hashes['conf/start/zentral/base.json'] = hashlib.sha256(source.read_bytes()).hexdigest()
        with patch.dict(generator.SOURCE_HASHES, self.fixture.hashes, clear=True):
            generator.prepare(self.fixture.source, self.fixture.image, self.fixture.lock,
                              self.fixture.destination, 'core-experiment')
        self.compose = self.fixture.destination / 'compose.json'
        self.project = json.loads(self.compose.read_text())['name']
        self.old_fixture = self.fixture.destination / 'fixture.json'
        machine = devices.Harness(); machine.setUp(); self.addCleanup(machine.doCleanups)
        value = machine.fixture
        value['compose_sha256'] = hashlib.sha256(self.compose.read_bytes()).hexdigest()
        self.old_fixture.write_text(json.dumps(value)); self.old_fixture.chmod(0o600)
        self.destination = self.fixture.root / 'fresh'

    def prepare(self, **changes):
        parameters = dict(source=self.fixture.source, previous_compose=self.compose,
                          previous_fixture=self.old_fixture, previous_project=self.project,
                          image=self.fixture.image, destination=self.destination)
        parameters.update(changes)
        with patch.dict(generator.SOURCE_HASHES, self.fixture.hashes, clear=True):
            return profile.prepare_fresh(**parameters)

    def test_preparation_preserves_old_files_and_separates_namespaces_without_runtime(self):
        before = {p.name: p.read_bytes() for p in self.fixture.destination.iterdir() if p.is_file()}
        with patch('subprocess.run') as run:
            plan = json.loads(self.prepare().read_text())
        run.assert_not_called()
        self.assertNotEqual(plan['candidate']['project'], plan['previous']['project'])
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.fixture.destination.iterdir() if p.is_file()})
        self.assertTrue(all(value == 'not_run' for value in plan['runtime_gates'].values()))
        self.assertIn('Not granted', plan['transition_authorization'])
        new = json.loads((self.destination / 'compose.json').read_text())
        old = json.loads(self.compose.read_text())
        self.assertEqual({key: value['image'] for key, value in new['services'].items()},
                         {key: value['image'] for key, value in old['services'].items()})
        config = json.loads((self.destination / 'conf/base.json').read_text())
        self.assertFalse(set(config['apps']).intersection(generator.OPTIONAL_APPS))
        text = json.dumps(plan)
        for device in json.loads(self.old_fixture.read_text())['devices']:
            self.assertNotIn(device['secret'], text)

    def test_explicit_previous_identity_and_private_fixture_are_required(self):
        for changes in ({'previous_project': 'wrong'}, {'image': 'sha256:' + 'f' * 64},
                        {'previous_fixture': self.fixture.root / 'missing.json'}):
            with self.assertRaises((ValueError, FileNotFoundError)):
                self.prepare(**changes)
        self.assertFalse(self.destination.exists())

    def test_cannot_nest_or_replace_existing_runtime(self):
        for destination in (self.fixture.destination, self.fixture.destination / 'nested', self.fixture.root):
            with self.assertRaises((ValueError, FileExistsError)):
                self.prepare(destination=destination)

    def test_shared_external_volumes_are_rejected(self):
        data = json.loads(self.compose.read_text())
        data['volumes']['postgres_data'] = {'external': True}
        self.compose.write_text(json.dumps(data))
        fixture = json.loads(self.old_fixture.read_text())
        fixture['compose_sha256'] = hashlib.sha256(self.compose.read_bytes()).hexdigest()
        self.old_fixture.write_text(json.dumps(fixture))
        with self.assertRaisesRegex(ValueError, 'project-local'):
            self.prepare()
        self.assertFalse(self.destination.exists())

    def test_existing_preparation_and_changed_candidate_fail_without_runtime_read(self):
        plan = self.prepare()
        with self.assertRaises(FileExistsError):
            self.prepare()
        compose = self.destination / 'compose.json'
        compose.write_text(compose.read_text() + '\n')
        with patch.object(profile, 'orm') as orm:
            with self.assertRaisesRegex(ValueError, 'binding changed'):
                profile.check_runtime(plan)
        orm.assert_not_called()

    def test_runtime_readback_cannot_claim_consumers_ui_sync_or_index(self):
        plan = self.prepare()
        readback = dict(apps=sorted(profile.APPS), empty_human_configuration_device_projection=True,
                        provisioned_admin_store='ELASTICSEARCH',
                        applied_migration_apps=sorted(name.rsplit('.', 1)[-1] for name in profile.APPS))
        with patch.object(profile, 'orm', return_value=readback) as orm:
            result = profile.check_runtime(plan)
        code = orm.call_args.args[1]
        self.assertIn('MigrationRecorder', code)
        self.assertIn('Configuration.objects.count() == 0', code)
        self.assertNotIn('objects.create', code)
        self.assertNotIn('.delete(', code)
        self.assertIn('remain separate', json.loads(result.read_text())['limitation'])
        with patch.object(profile, 'orm') as orm:
            with self.assertRaises(FileExistsError):
                profile.check_runtime(plan)
        orm.assert_not_called()

    def test_incomplete_migration_readback_is_not_receipted(self):
        plan = self.prepare()
        readback = dict(apps=sorted(profile.APPS), empty_human_configuration_device_projection=True,
                        provisioned_admin_store='ELASTICSEARCH', applied_migration_apps=[])
        with patch.object(profile, 'orm', return_value=readback):
            with self.assertRaisesRegex(ValueError, 'Incomplete'):
                profile.check_runtime(plan)
        self.assertFalse((self.destination / 'fresh-profile-runtime.json').exists())


if __name__ == '__main__':
    unittest.main()
