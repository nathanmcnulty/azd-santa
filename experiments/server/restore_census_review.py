"""Carry an independently reviewed census between isolated restore sessions."""

import hashlib
import hmac
import json
import re

import restore_authority_transaction as authority
import restore_census as census
import restore_quarantine_journal as journal

SCOPE = 'restore-census-review-v1'
MAX_REVIEW_BYTES = 32 * 1024**2


class ReviewRejected(ValueError):
    pass


def require(condition):
    if not condition:
        raise ReviewRejected('Restore census review rejected; preserve the private evidence')


def encode(record):
    return json.dumps(record, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def project_source_database(expected, dispositions, *, source_database, target, fingerprint_key):
    """Project the independently reviewed source census onto one reserved database name."""
    try:
        require(type(expected) is census.Census and type(target) is authority.Target
                and type(fingerprint_key) is bytes and len(fingerprint_key) == 32
                and type(dispositions) is dict and type(source_database) is str and bool(source_database)
                and re.fullmatch(r'azd_recovery_[a-f0-9]{24}', target.database)
                and source_database != target.database)
        manifest = expected.manifest
        require(hmac.compare_digest(expected.receipt['fingerprint'],
                                    census.keyed(fingerprint_key, 'census', manifest)))
        original, = manifest['catalog']['database']
        require(original['database'] == source_database and original['user'] == target.role)
        projected = dict(original, database=target.database)
        old_key = 'catalog:database:' + census.keyed(fingerprint_key, 'schema-fact', original)
        new_key = 'catalog:database:' + census.keyed(fingerprint_key, 'schema-fact', projected)
        require(old_key in dispositions and new_key not in dispositions)
        mapped = dict(dispositions)
        mapped[new_key] = mapped.pop(old_key)
        catalog = dict(manifest['catalog'], database=[projected])
        result = dict(manifest, catalog=catalog)
        receipt = dict(expected.receipt, fingerprint=census.keyed(fingerprint_key, 'census', result))
        return census.Census(result, receipt), mapped
    except Exception:
        raise ReviewRejected('Restore source database projection rejected') from None


def publish(expected, dispositions, *, target, archive_sha256, generation, fingerprint_key, stage,
            source_database=None):
    """Export the reviewer's selected dispositions and keyed census fingerprint.

    The reviewer establishes provenance, compares the original evidence, and
    transmits the resulting SHA-256 separately from the review document.
    """
    try:
        require(stage in journal.STAGES)
        binding = journal.binding_for(target, archive_sha256, generation, fingerprint_key)
        if source_database is not None:
            expected, dispositions = project_source_database(
                expected, dispositions, source_database=source_database, target=target, fingerprint_key=fingerprint_key)
        census.compare(expected, expected, dispositions, fingerprint_key=fingerprint_key)
        raw = encode(dict(scope=SCOPE, binding=binding, stage=stage,
                          census=expected.receipt['fingerprint'], dispositions=dispositions))
        require(len(raw) <= MAX_REVIEW_BYTES)
        return raw
    except Exception:
        raise ReviewRejected('Restore census review could not be published') from None


def load(raw, digest, *, binding, stage):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_REVIEW_BYTES and journal.is_digest(digest)
            and hmac.compare_digest(hashlib.sha256(raw).hexdigest(), digest))
    record = census.parse(raw)
    require(type(record) is dict and set(record) == {'scope', 'binding', 'stage', 'census', 'dispositions'}
            and record['scope'] == SCOPE and record['binding'] == binding and record['stage'] == stage
            and journal.is_digest(record['census']) and type(record['dispositions']) is dict
            and raw == encode(record))
    return record


def run(writer, observer, registry, *, directory, target, archive_sha256, generation, fingerprint_key,
        stage, review, review_sha256, options, limits=census.Limits(), plan_digest=None, authorize=None):
    """Use a pinned private review for preview or explicitly authorized apply.

    The trusted launcher supplies the digest from outside the backup and a
    current external authorization check for apply. The check receives only
    the exact reviewed operation binding. Keep service processes stopped and
    supply connections and rewrap material in memory.
    """
    try:
        require(stage in journal.STAGES and type(limits) is census.Limits
                and ((plan_digest is None and authorize is None)
                     or (journal.is_digest(plan_digest) and callable(authorize))))
        binding = journal.binding_for(target, archive_sha256, generation, fingerprint_key)
        record = load(review, review_sha256, binding=binding, stage=stage)
        require(authority.read_target(observer) == target)
        observed = census.collect(observer, registry, fingerprint_key=fingerprint_key, limits=limits)
        require(hmac.compare_digest(record['census'], observed.receipt['fingerprint']))
        dispositions = record['dispositions']

        def verify_authorization(digest):
            return authorize(dict(scope=SCOPE, binding=binding, stage=stage,
                                  plan_digest=digest, review_sha256=review_sha256)) is True

        return journal.run(writer, observer, registry, directory=directory, target=target,
                           archive_sha256=archive_sha256, generation=generation, fingerprint_key=fingerprint_key,
                           stage=stage, expected=observed, dispositions=dispositions, options=options, limits=limits,
                           plan_digest=plan_digest, before_apply=verify_authorization if authorize is not None else None)
    except journal.JournalRejected:
        raise
    except Exception:
        raise ReviewRejected('Restore census review or target did not match') from None
