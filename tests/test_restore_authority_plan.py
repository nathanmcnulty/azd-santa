"""Disposition tests for the private, in-memory restore authority plan."""

import copy
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import unittest
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'experiments/server'))
import restore_authority_plan as authority

KEY = b'fixture-key-not-an-authority-pin'
KEY = KEY.ljust(32, b'.')
CUTOFF = datetime(2026, 11, 25, 22, tzinfo=timezone.utc)
EARLIER = CUTOFF - timedelta(days=1)
LATER = CUTOFF + timedelta(days=1)


class AuthorityTests(unittest.TestCase):
    def setUp(self):
        self.rows = {
            'accounts.user': [dict(pk=2, is_active=True, password='private-hash-fixture'),
                              dict(pk=1, is_active=False, password='!previously-disabled')],
            'accounts.policy': [dict(pk=uuid.UUID(int=3), is_active=True)],
            'accounts.apitoken': [dict(pk=uuid.UUID(int=4), expiry=None),
                                  dict(pk=uuid.UUID(int=5), expiry=EARLIER),
                                  dict(pk=uuid.UUID(int=6), expiry=LATER)],
            'accounts.oidcapitokenissuer': [dict(pk=uuid.UUID(int=7), cel_condition='private-issuer-fixture')],
            'sessions.session': [dict(pk='private-session-fixture', expire_date=LATER)],
            'realms.realm': [dict(pk=uuid.UUID(int=8), enabled_for_login=True, user_portal=True, scim_enabled=True)],
            'realms.realmauthenticationsession': [dict(pk=uuid.UUID(int=9), expires_at=None)],
            'inventory.enrollmentsecret': [dict(pk=10, revoked_at=None), dict(pk=11, revoked_at=LATER)],
        }
        self.counts = {model: len(rows) for model, rows in self.rows.items()}

    def plan(self, **options):
        return authority.plan(self.rows, self.counts, **{
            'cutoff': CUTOFF, 'fingerprint_key': KEY, **options,
        })

    def test_plans_all_authority_changes_without_returning_old_secrets(self):
        original = copy.deepcopy(self.rows)
        result = self.plan()
        actual = {model: [row['fields'] for row in rows] for model, rows in result.updates.items()}
        self.assertEqual(actual, {
            'accounts.user': [{'is_active': False, 'password': '!'}],
            'accounts.policy': [{'is_active': False}],
            'accounts.apitoken': [{'expiry': CUTOFF}, {'expiry': CUTOFF}],
            'accounts.oidcapitokenissuer': [{'cel_condition': 'false'}],
            'sessions.session': [{'expire_date': CUTOFF}],
            'realms.realm': [{'enabled_for_login': False, 'user_portal': False, 'scim_enabled': False}],
            'realms.realmauthenticationsession': [{'expires_at': CUTOFF}],
            'inventory.enrollmentsecret': [{'revoked_at': CUTOFF}],
        })
        self.assertEqual([row['pk'] for row in result.updates['accounts.apitoken']],
                         [uuid.UUID(int=4), uuid.UUID(int=6)])
        self.assertEqual(result.updates['inventory.enrollmentsecret'][0]['pk'], 10)
        self.assertEqual(self.rows, original)
        self.assertFalse(result.receipt['performs_mutation'])
        self.assertFalse(result.receipt['restore_accepted'])
        self.assertFalse(result.receipt['current_authority_established'])
        for canary in ('private-hash-fixture', 'private-issuer-fixture', 'private-session-fixture'):
            self.assertNotIn(canary, repr(result))

    def test_normalized_order_and_bound_subject_detects_old_value_changes(self):
        expected = self.plan()
        self.rows['accounts.user'].reverse()
        self.rows['accounts.apitoken'][1]['expiry'] = EARLIER.astimezone(timezone(timedelta(hours=-9)))
        self.assertEqual(self.plan(), expected)
        self.rows['accounts.user'][1]['password'] = 'changed-private-hash'
        changed = self.plan()
        self.assertEqual(changed.updates, expected.updates)
        self.assertNotEqual(changed.receipt['subject_hmac_sha256'], expected.receipt['subject_hmac_sha256'])

    def test_rejects_missing_rows_unreviewed_fields_duplicate_ids_and_malformed_types(self):
        original = copy.deepcopy(self.rows)
        edits = (
            lambda: self.rows['accounts.user'].pop(),
            lambda: self.rows.pop('accounts.policy'),
            lambda: self.rows['accounts.user'][1].update(pk=2),
            lambda: self.rows['accounts.user'][0].update(is_active=1),
            lambda: self.rows['accounts.user'][0].update(is_superuser=True),
            lambda: self.rows['accounts.policy'][0].update(pk='uuid string'),
            lambda: self.rows['accounts.apitoken'][0].update(expiry=CUTOFF.replace(tzinfo=None)),
            lambda: self.rows['sessions.session'][0].update(expire_date=None),
        )
        for edit in edits:
            with self.subTest(edit=edit):
                self.rows = copy.deepcopy(original)
                edit()
                with self.assertRaises(authority.AuthorityPlanRejected):
                    self.plan()
        self.rows = original
        with self.assertRaises(authority.AuthorityPlanRejected):
            self.plan(limits=authority.Limits(rows=1))


if __name__ == '__main__':
    unittest.main()
