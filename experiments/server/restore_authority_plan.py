"""Plan in-memory authority changes for the pinned Zentral restore profile."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import re
import uuid

from restore_census import Limits, encoded, keyed

# The adapter must supply every original row in these projections and bind
# the counts to a separately reviewed census. Field values outside the
# projection are outside the update allowlist.
PROJECTIONS = {
    'accounts.user': (int, {'is_active': 'disable', 'password': 'unusable'}),
    'accounts.policy': (uuid.UUID, {'is_active': 'disable'}),
    'accounts.apitoken': (uuid.UUID, {'expiry': 'expire'}),
    'accounts.oidcapitokenissuer': (uuid.UUID, {'cel_condition': 'deny'}),
    'sessions.session': (str, {'expire_date': 'expire_required'}),
    'realms.realm': (uuid.UUID, {'enabled_for_login': 'disable', 'user_portal': 'disable',
                                 'scim_enabled': 'disable'}),
    'realms.realmauthenticationsession': (uuid.UUID, {'expires_at': 'expire'}),
    'inventory.enrollmentsecret': (int, {'revoked_at': 'revoke'}),
}
UNUSABLE_PASSWORD = '!'


class AuthorityPlanRejected(ValueError):
    pass


def require(condition):
    if not condition:
        raise AuthorityPlanRejected('Restore authority plan rejected; retain the original inputs')


@dataclass(frozen=True)
class AuthorityPlan:
    updates: dict = field(repr=False)
    receipt: dict


def timestamp(value):
    require(type(value) is datetime and value.utcoffset() is not None)
    return value.astimezone(timezone.utc)


def identity(value, kind):
    require(type(value) is kind)
    if kind is int:
        require(0 < value < 2**63)
        return f'{value:019d}'
    if kind is uuid.UUID:
        require(value.int != 0)
        return str(value)
    require(re.fullmatch(r'[A-Za-z0-9_-]{1,40}', value))
    return value


def planned_value(value, rule, cutoff, limit):
    if rule == 'disable':
        require(type(value) is bool)
        return value, False
    if rule in ('unusable', 'deny'):
        require(type(value) is str and len(value) <= limit and '\0' not in value
                and len(value.encode('utf-8')) <= limit)
        if rule == 'deny':
            return value, 'false'
        require(len(value) <= 128)
        return value, value if value.startswith(UNUSABLE_PASSWORD) else UNUSABLE_PASSWORD
    original = None if value is None else timestamp(value)
    require(original is not None or rule != 'expire_required')
    if rule == 'revoke':
        # The pinned model treats every non-null revocation as revoked.
        return original, cutoff if original is None else original
    return original, cutoff if original is None else min(original, cutoff)


def plan(rows, counts, *, cutoff, fingerprint_key, limits=Limits()):
    """Produce private, deterministic updates. This function performs no I/O."""
    try:
        require(type(rows) is dict and type(counts) is dict
                and set(rows) == set(counts) == set(PROJECTIONS))
        require(type(fingerprint_key) is bytes and len(fingerprint_key) == 32 and type(limits) is Limits)
        cutoff = timestamp(cutoff)
        require(all(type(counts[model]) is int and type(rows[model]) is list
                    and 0 <= counts[model] == len(rows[model]) for model in PROJECTIONS))
        require(sum(counts.values()) <= limits.rows)
        budget = 0
        updates = {}
        subjects = {}
        for model, (kind, rules) in PROJECTIONS.items():
            selected = {}
            for row in rows[model]:
                require(type(row) is dict and row.keys() == rules.keys() | {'pk'})
                key = identity(row['pk'], kind)
                require(key not in selected)
                observed = {}
                changes = {}
                for name, rule in rules.items():
                    old, new = planned_value(row[name], rule, cutoff, limits.value_bytes)
                    observed[name] = old.isoformat() if type(old) is datetime else old
                    if old != new:
                        changes[name] = new
                budget += len(encoded(observed))
                require(budget <= limits.bytes)
                digest = keyed(fingerprint_key, 'restore-authority-row:' + model, observed)
                selected[key] = (digest, row['pk'], changes)
            order = sorted(selected)
            subjects[model] = {key: selected[key][0] for key in order}
            updates[model] = [{'pk': selected[key][1], 'fields': selected[key][2]}
                              for key in order if selected[key][2]]
        return AuthorityPlan(updates, {
            'scope': 'restore-authority-plan-v1',
            'cutoff': cutoff.isoformat(),
            'subject_hmac_sha256': keyed(fingerprint_key, 'restore-authority-subject', subjects),
            'planned_rows': {model: len(changes) for model, changes in updates.items()},
            'observed_rows': dict(counts),
            'performs_mutation': False,
            'restore_accepted': False,
            'current_authority_established': False,
        })
    except (KeyError, TypeError, ValueError, OverflowError):
        raise AuthorityPlanRejected('Restore authority plan rejected; retain the original inputs') from None
