"""Image-only transition boundaries; no Docker, Azure or network execution."""
import copy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'experiments/server'))
import test_live_zentral_harness as harness
import upgrade_core_runtime as upgrade
import record_persistence as persistence


class Transition(unittest.TestCase):
    def setUp(self):
        self.harness = harness.Harness()
        self.harness.setUp()
        self.addCleanup(self.harness.doCleanups)
        self.harness.write_fixture()

    def test_preserves_original_inputs_and_changes_only_three_images_and_binding(self):
        h = self.harness
        before = h.compose.read_bytes(), h.fixture_path.read_bytes()
        target, fixture = upgrade.transition(h.compose, h.fixture_path, 'sha256:' + 'b' * 64, 'test-boot')
        self.assertEqual(before, (h.compose.read_bytes(), h.fixture_path.read_bytes()))
        expected = json.loads(before[0])
        for key in ('web', 'workers', 'celery'):
            expected['services'][key]['image'] = 'sha256:' + 'b' * 64
        self.assertEqual(json.loads(target.read_text()), expected)
        copied = json.loads(fixture.read_text())
        copied.pop('compose_sha256')
        original = copy.deepcopy(h.fixture)
        original.pop('compose_sha256')
        self.assertEqual(copied, original)
        with self.assertRaises(FileExistsError):
            upgrade.transition(h.compose, h.fixture_path, 'sha256:' + 'b' * 64, 'test-boot')

    def test_rejects_mutable_image_and_wrong_fixture_without_creating_transition(self):
        h = self.harness
        with self.assertRaises(ValueError):
            upgrade.transition(h.compose, h.fixture_path, 'latest', 'test-boot')
        h.fixture['compose_sha256'] = '0' * 64
        h.write_fixture()
        with self.assertRaises(ValueError):
            upgrade.transition(h.compose, h.fixture_path, 'sha256:' + 'b' * 64, 'test-boot')
        self.assertFalse((h.root / 'compose-stores.json').exists())

    def test_reboot_requires_changed_boot_and_identical_database_and_index_state(self):
        previous = dict(scope='private-synthetic-reboot-persistence', boot_id='old',
                        compose_sha256='hash', state={'rules': [1, 2], 'counter': 4}, indexed_events=2)
        expected = dict(boot='new', digest='hash', state=copy.deepcopy(previous['state']), count=2)
        persistence.check_previous(previous, **expected)
        for change in ({'boot': 'old'}, {'digest': 'different'},
                       {'state': {'rules': [], 'counter': 0}}, {'count': 0}):
            with self.assertRaises(ValueError):
                persistence.check_previous(previous, **{**expected, **change})


if __name__ == '__main__':
    unittest.main()
