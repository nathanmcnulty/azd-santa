"""Create one new local administrator after the isolated quarantine gate."""

import hashlib
import hmac
import secrets
import time

from restore_admin_approval import Verify
import restore_admin_reissue as reissue
import restore_authority_transaction as authority
import restore_census as census
import restore_quarantine_journal as journal
from retained_image_delivery import read_at, write_at
from sealed_setup import MAX_ENVELOPE_BYTES, origin, prepare_recipient


def artifact_name(plan):
    journal.require(journal.is_digest(plan))
    return plan + '.setup.json'


def apply(job, writer, observer, registry, *, directory, artifact_directory, fingerprint_key,
          username, email, runtime_sha256, recipient_sha256, recipient_public_key, setup_origin,
          approved_plan_sha256, approval, operator_public_key, operator_pin):
    """Commit a new account and sealed setup artifact without opening service admission."""
    from django.conf import settings
    from django.core.validators import validate_email
    from django.db import connections, transaction
    from django.db.models import Q
    from accounts.password_reset import handler

    journal.require(journal.is_digest(approved_plan_sha256) and journal.is_digest(recipient_sha256)
                    and type(email) is str and type(username) is str
                    and writer is connections['default'] and observer is not writer
                    and settings.PASSWORD_RESET_TIMEOUT == 600 and not settings.SECRET_KEY_FALLBACKS)
    user_model = registry.get_model('accounts', 'User')
    user_model._meta.get_field('username').clean(username, None)
    validate_email(email)
    recipient = prepare_recipient(recipient_public_key, approved_plan_sha256, 'bootstrap',
                                  username, email, setup_origin)
    journal.require(hmac.compare_digest(recipient.kid, recipient_sha256))
    authorize = Verify(job, fingerprint_key, approval, public_key=operator_public_key, operator_pin=operator_pin)
    users = user_model.objects.db_manager(writer.alias)

    def create(name, address, confirmed):
        plan = confirmed['plan_sha256']
        journal.require((name, address, plan, confirmed['recipient_sha256'])
                        == (username, email, approved_plan_sha256, recipient_sha256))
        authority.connection_ready(writer)
        authority.connection_ready(observer)
        with observer.cursor() as cursor:
            observed_target, observer_pid = authority.binding(observer, cursor)
        journal.require(observed_target == job.target)
        with journal.locked(artifact_directory) as output, transaction.atomic(using=writer.alias, durable=True):
            with writer.cursor() as cursor:
                cursor.execute("SET LOCAL statement_timeout = '15s'")
                cursor.execute("SET LOCAL lock_timeout = '2s'")
                target, writer_pid = authority.binding(writer, cursor)
                journal.require(target == job.target and writer_pid != observer_pid)
                authority.only_clients(cursor, writer_pid, observer_pid)
                cursor.execute('LOCK TABLE ONLY public.accounts_user IN SHARE ROW EXCLUSIVE MODE NOWAIT')
                observed = census.collect(observer, registry, fingerprint_key=fingerprint_key)
                journal.require(observed.receipt['complete_supported_data'] is True and
                                hmac.compare_digest(observed.receipt['fingerprint'], confirmed['quarantine_census_sha256']))
                journal.require(not users.filter(Q(is_active=True) | Q(username__iexact=name)
                                                 | Q(email__iexact=address)).exists())
                user = users.create_user(username=name, email=address, password=secrets.token_urlsafe(64),
                                         is_superuser=True, is_staff=False)
                journal.require(user.username == name and user.email == address and user.is_active
                                and user.is_superuser and not (user.is_remote or user.is_service_account))
                sealed = recipient.seal(dict(mode='bootstrap', target=dict(username=name, email=address, pk=user.pk),
                                             setup_url=handler.generate_password_reset_url(user),
                                             expires_at_unix=time.time() + settings.PASSWORD_RESET_TIMEOUT))
                raw = journal.encode_record(sealed)
                journal.require(len(raw) <= MAX_ENVELOPE_BYTES)
                write_at(output, artifact_name(plan), raw)
                authority.only_clients(cursor, writer_pid, observer_pid)
        return hashlib.sha256(raw).hexdigest()

    return job.reissue_admin(observer, registry, directory=directory, fingerprint_key=fingerprint_key,
                             username=username, email=email, runtime_sha256=runtime_sha256,
                             recipient_sha256=recipient_sha256,
                             setup_origin_sha256=hashlib.sha256(origin(setup_origin).encode('ascii')).hexdigest(),
                             approved_plan_sha256=approved_plan_sha256,
                             authorize=authorize, create=create)


def read_artifact(job, *, directory, artifact_directory, fingerprint_key, plan_sha256):
    """Read the verified original ciphertext after a confirmed account commit."""
    result = reissue.inspect(job, directory=directory, fingerprint_key=fingerprint_key, plan_sha256=plan_sha256)
    journal.require(result['state'] == 'committed')
    with journal.locked(artifact_directory) as output:
        raw = read_at(output, artifact_name(plan_sha256), MAX_ENVELOPE_BYTES)
    journal.require(hmac.compare_digest(hashlib.sha256(raw).hexdigest(), result['artifact_sha256']))
    return raw
