"""Guard the first administrator reissue on an isolated restore generation."""

import hashlib
import hmac

import restore_authority_transaction as authority
import restore_census as census
from restore_guest_job import Job
import restore_quarantine_journal as journal

SCOPE = 'santa-restore-admin-reissue-v1'
INTENT = 'administrator-reissue-intent.json'
COMMITTED = 'administrator-reissue-committed.json'


def records(fd, binding, key):
    intent = journal.read_record(fd, INTENT, binding, key, {'plan'})
    done = journal.read_record(fd, COMMITTED, binding, key, {'plan', 'artifact'})
    journal.require(done is None or (intent is not None and intent['plan'] == done['plan']))
    return intent, done


def inspect(job, *, directory, fingerprint_key, plan_sha256):
    """Read only the known plan, including a possible uncertain commit."""
    journal.require(type(job) is Job and journal.is_digest(plan_sha256))
    binding = job.binding(fingerprint_key)
    with journal.locked(directory) as fd:
        intent, done = records(fd, binding, fingerprint_key)
        result = dict(scope=SCOPE, plan_sha256=plan_sha256, state='pending', activation_allowed=False)
        if intent is None:
            return result
        journal.require(hmac.compare_digest(intent['plan'], plan_sha256))
        if done is None:
            return {**result, 'state': 'inspect'}
        return {**result, 'state': 'committed', 'artifact_sha256': done['artifact']}


def run(job, observer, registry, *, directory, fingerprint_key, username, email,
        runtime_sha256, recipient_sha256, approved_plan_sha256=None, authorize=None, create=None):
    """Preview or consume a new-identity approval against the exact quarantined database.

    The trusted launcher verifies the fresh runtime and setup recipient separately.
    Its creator must exclusively create one new human administrator and return the
    digest of its private sealed setup artifact after commit. Connections and the
    journal belong to an offline recovery environment with no other database writers.
    """
    applying = approved_plan_sha256 is not None
    journal.require(type(job) is Job and journal.is_digest(runtime_sha256)
                    and journal.is_digest(recipient_sha256)
                    and all(type(value) is str and 0 < len(value) <= limit
                            and value == value.strip() and not any(ord(char) < 32 for char in value)
                            for value, limit in ((username, 150), (email, 254)))
                    and ((applying and journal.is_digest(approved_plan_sha256)
                          and callable(authorize) and callable(create))
                         or (not applying and authorize is None and create is None)))
    key = fingerprint_key
    binding = job.binding(key)
    with journal.locked(directory) as fd:
        quarantine = journal.inspect_records(fd, binding, key)['quarantine']['done']
        intent, _ = records(fd, binding, key)
        # Any existing intent needs inspection. A missing response must never
        # create a second account or reissue a setup link implicitly.
        journal.require(quarantine is not None and intent is None)
        journal.require(authority.read_target(observer) == job.target)
        observed = census.collect(observer, registry, fingerprint_key=key)
        journal.require(observed.receipt['complete_supported_data'] is True
                        and hmac.compare_digest(observed.receipt['fingerprint'], quarantine['census']))
        request = dict(scope=SCOPE, binding=binding, quarantine_plan_sha256=quarantine['plan'],
                       quarantine_census_sha256=quarantine['census'], runtime_sha256=runtime_sha256,
                       recipient_sha256=recipient_sha256,
                       identity_sha256=census.keyed(key, SCOPE + ':identity', {'username': username, 'email': email}))
        plan = hashlib.sha256(journal.encode_record(request)).hexdigest()
        approval = {**request, 'plan_sha256': plan}
        result = {**approval, 'state': 'previewed', 'activation_allowed': False}
        if not applying:
            return result
        journal.require(hmac.compare_digest(plan, approved_plan_sha256) and authorize(approval.copy()) is True)
        journal.write_record(fd, INTENT, binding, key, plan=plan)
        try:
            artifact = create(username, email, approval.copy())
        except Exception:
            raise journal.JournalRejected('Administrator reissue outcome requires private inspection') from None
        journal.require(journal.is_digest(artifact))
        journal.write_record(fd, COMMITTED, binding, key, plan=plan, artifact=artifact)
        return {**result, 'state': 'committed', 'artifact_sha256': artifact}
