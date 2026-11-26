"""Continue database quarantine with a durable private journal and no service activation."""

from contextlib import contextmanager
from dataclasses import asdict
import hmac
import json
import os
import re
import stat

import restore_authority_transaction as authority
import restore_census as census
import restore_secret_transaction as secret

STAGES = ('rewrap', 'quarantine')
SCOPE = 'restore-quarantine-journal-v1'
OPTIONS = {'rewrap': {'expected_contexts', 'old_material', 'new_material', 'targets'},
           'quarantine': {'cutoff'}}


class JournalRejected(ValueError):
    pass


def require(condition):
    if not condition:
        raise JournalRejected('Restore journal rejected; retain it and inspect privately')


def is_digest(value):
    return type(value) is str and re.fullmatch(r'[0-9a-f]{64}', value) is not None


@contextmanager
def locked(directory):
    import fcntl

    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        meta = os.fstat(fd)
        require(meta.st_uid == os.geteuid() and stat.S_IMODE(meta.st_mode) == 0o700)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        parent = os.open('..', os.O_RDONLY | os.O_DIRECTORY, dir_fd=fd)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
        yield fd
    finally:
        os.close(fd)


def read_record(fd, name, binding, key, fields):
    try:
        record_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    except FileNotFoundError:
        return None
    with os.fdopen(record_fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
                and info.st_uid == os.geteuid() and info.st_nlink == 1 and 0 < info.st_size <= 1024)
        raw = stream.read(1025)
        os.fsync(stream.fileno())
    record = json.loads(raw)
    require(raw == census.encoded(record) and set(record) == fields | {'binding', 'seal'}
            and record['binding'] == binding and all(is_digest(value) for value in record.values()))
    seal = record.pop('seal')
    require(hmac.compare_digest(seal, census.keyed(key, name, record)))
    return record


def write_record(fd, name, binding, key, **fields):
    record = {'binding': binding, **fields}
    raw = census.encoded({**record, 'seal': census.keyed(key, name, record)})
    record_fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
    with os.fdopen(record_fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.fsync(fd)


def inspect_records(fd, binding, key):
    state = {}
    for stage in STAGES:
        intent = read_record(fd, stage + '-intent.json', binding, key, {'plan'})
        done = read_record(fd, stage + '-committed.json', binding, key, {'plan', 'census'})
        require(done is None or (intent is not None and done['plan'] == intent['plan']))
        state[stage] = dict(intent=intent, done=done)
    require(state['quarantine']['intent'] is None or state['rewrap']['done'] is not None)
    os.fsync(fd)
    return state


def binding_for(target, archive_sha256, generation, key):
    require(type(target) is authority.Target and is_digest(archive_sha256) and is_digest(generation)
            and type(key) is bytes and len(key) == 32)
    return census.keyed(key, SCOPE, {'target': asdict(target), 'archive': archive_sha256, 'generation': generation})


def status(state):
    stages = {stage: ('committed' if step['done'] else 'inspect' if step['intent'] else 'pending')
              for stage, step in state.items()}
    return dict(scope=SCOPE, stages=stages, activation_allowed=False, current_authority_established=False)


def inspect(directory, *, target, archive_sha256, generation, fingerprint_key):
    """Read private continuation status without connecting to the restored database."""
    try:
        binding = binding_for(target, archive_sha256, generation, fingerprint_key)
        with locked(directory) as fd:
            return status(inspect_records(fd, binding, fingerprint_key))
    except Exception:
        raise JournalRejected('Restore journal status unverified; retain it and inspect privately') from None


def run(writer, observer, registry, *, directory, target, archive_sha256, generation, fingerprint_key,
        stage, expected, dispositions, options, limits=census.Limits(), plan_digest=None):
    """Preview one named step, or apply its reviewed digest under a durable intent.

    The trusted caller selects one persistent private journal for the exact restored
    generation, authenticates its external authorization and supplies independently
    reviewed census/dispositions for each stage. Keep all other database clients,
    listeners and workers stopped. An intent without a receipt requires inspection.
    """
    try:
        require(stage in STAGES and (plan_digest is None or is_digest(plan_digest))
                and type(options) is dict and set(options) == OPTIONS[stage])
        binding = binding_for(target, archive_sha256, generation, fingerprint_key)
        with locked(directory) as fd:
            state = inspect_records(fd, binding, fingerprint_key)
            require(state[stage]['intent'] is None)
            if stage == 'quarantine':
                previous = state['rewrap']['done']
                require(previous is not None and previous['census'] == expected.receipt['fingerprint'])
            adapter = secret if stage == 'rewrap' else authority
            options = dict(**options, target=target, expected=expected, dispositions=dispositions,
                           fingerprint_key=fingerprint_key, limits=limits)
            preview = adapter.run(writer, observer, registry, **options)
            digest = census.keyed(fingerprint_key, stage + '-journal-review',
                                  {'binding': binding, 'plan': preview['plan_digest'],
                                   'dispositions': dispositions})
            if plan_digest is None:
                return {**status(state), 'stage': stage, 'plan_digest': digest, 'review': preview}
            require(hmac.compare_digest(plan_digest, digest))
            write_record(fd, stage + '-intent.json', binding, fingerprint_key, plan=digest)
            result = adapter.run(writer, observer, registry, **options, apply=True, plan_digest=preview['plan_digest'])
            flag = 'rewrap_committed' if stage == 'rewrap' else 'authority_updates_committed'
            require(result[flag] is True)
            observed = census.collect(observer, registry, fingerprint_key=fingerprint_key, limits=limits)
            require(observed.receipt['complete_supported_data'] is True)
            write_record(fd, stage + '-committed.json', binding, fingerprint_key, plan=digest,
                         census=observed.receipt['fingerprint'])
            return {**status(inspect_records(fd, binding, fingerprint_key)), 'stage': stage,
                    'plan_digest': digest, 'result': result}
    except Exception:
        raise JournalRejected('Restore step rejected or unverified; inspect the private journal before continuing') from None
