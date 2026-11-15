"""Offline guards for negative live tests; no Docker or network execution."""
import sys
from pathlib import Path
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'experiments/server'))
import test_credential_lifecycle as lifecycle


class NegativeChecks(unittest.TestCase):
    def setUp(self):
        self.device = dict(uuid='00000000-0000-4000-8000-' + '1' * 12, serial='synthetic')

    def test_requires_all_stages_and_exact_database_state(self):
        observations = []
        with patch.object(lifecycle, 'state', return_value={'counter': 2}), patch.object(lifecycle.live, 'post', return_value=(403, None)) as post:
            self.assertTrue(lifecycle.reject_stages('unused', {}, self.device, 'private', 'expired', observations))
        self.assertEqual([call.args[0] for call in post.call_args_list], ['eventupload', 'preflight', 'ruledownload', 'postflight'])
        self.assertNotIn('private', str(observations))
        with patch.object(lifecycle, 'state', side_effect=[{'counter': 2}, {'counter': 3}]), patch.object(lifecycle.live, 'post', return_value=(403, None)):
            self.assertFalse(lifecycle.reject_stages('unused', {}, self.device, 'private', 'expired', []))

    def test_acceptance_failure_stops_before_other_stages_can_mutate_state(self):
        with patch.object(lifecycle, 'state', return_value={}), patch.object(lifecycle.live, 'post', return_value=(200, {})) as post:
            self.assertFalse(lifecycle.reject_stages('unused', {}, self.device, 'private', 'revoked', []))
            post.assert_called_once()


if __name__ == '__main__':
    unittest.main()
