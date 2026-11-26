"""Initialize a new security store after the isolated restore quarantine."""

import hashlib
import hmac
import re

from restore_guest_job import Job
import restore_quarantine_journal as journal

SCOPE = 'santa-restore-security-store-v1'
INTENT = 'security-store-intent.json'
COMMITTED = 'security-store-committed.json'


def digest(value):
    return hashlib.sha256(journal.encode_record(value)).hexdigest()


def server_id(client):
    identity = client.info('server')['run_id']
    journal.require(type(identity) is str and re.fullmatch('[a-f0-9]{40}', identity) is not None)
    return identity


def run(job, observer, registry, *, directory, fingerprint_key, runtime_sha256, store_id,
        generation, approved_plan_sha256=None, authorize=None):
    """Use the selected fresh Redis endpoint from the pinned application settings.

    The launcher verifies fresh service credentials, isolation and the runtime
    configuration. No older application process may use the selected Redis
    instance. Only this journal and the selected empty Redis DB are written.
    """
    from azd_santa_operator import STORE_MARKER, _expected_store_id, _security_client, check_security_store
    from azd_santa_admission import CONFIG, state
    from santa_admission import CONFIG as recovery_config, initialize_fresh

    applying = approved_plan_sha256 is not None
    journal.require(type(job) is Job and journal.is_digest(runtime_sha256) and journal.is_digest(store_id)
                    and hmac.compare_digest(_expected_store_id(), store_id)
                    and CONFIG.fingerprint == recovery_config.fingerprint
                    and type(generation) is str and re.fullmatch('[a-f0-9]{32}', generation) is not None
                    and ((applying and journal.is_digest(approved_plan_sha256) and callable(authorize))
                         or (not applying and authorize is None)))
    key = fingerprint_key
    binding = job.binding(key)
    with journal.locked(directory) as fd:
        intent = journal.read_record(fd, INTENT, binding, key, {'plan'})
        done = journal.read_record(fd, COMMITTED, binding, key, {'plan', 'generation'})
        journal.require(intent is None and done is None)
        quarantine = journal.committed_quarantine(fd, binding, key, job.target, observer, registry)
        cache, client = _security_client()
        server = server_id(client)
        journal.require(client.dbsize() == 0)
        request = dict(scope=SCOPE, binding=binding, runtime_sha256=runtime_sha256, store_id=store_id,
                       redis_process_sha256=digest(server), admission_config_sha256=CONFIG.fingerprint,
                       generation=generation, quarantine_census_sha256=quarantine['census'])
        plan = digest(request)
        approval = {**request, 'plan_sha256': plan}
        result = {**approval, 'state': 'previewed', 'activation_allowed': False}
        if not applying:
            return result
        journal.require(hmac.compare_digest(plan, approved_plan_sha256) and authorize(approval.copy()) is True)
        journal.require(server_id(client) == server)
        journal.write_record(fd, INTENT, binding, key, plan=plan)
        try:
            journal.require(initialize_fresh(cache, client, store_id, 0, STORE_MARKER,
                                            require_empty_database=True, generation=generation) == 1)
            check_security_store()
            journal.require(server_id(client) == server and state() == {'generation': generation, 'active': 0})
        except Exception:
            raise journal.JournalRejected('Security-store initialization outcome requires private inspection') from None
        journal.write_record(fd, COMMITTED, binding, key, plan=plan, generation=digest(generation))
        return {**result, 'state': 'committed'}
