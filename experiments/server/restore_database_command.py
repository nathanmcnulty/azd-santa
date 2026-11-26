"""Prepare or apply a signed recovery step in an isolated Django worker."""

import argparse
from contextlib import ExitStack, contextmanager, redirect_stderr, redirect_stdout
from dataclasses import asdict
import os
from pathlib import Path
import re
import sys

import blob_retention as blob
from restore_arm_authorization import Selection
from restore_authority_transaction import Target
from restore_guest_job import Job
from restore_guest_readback import SCOPE as GUEST_SCOPE
from restore_quarantine_journal import STAGES, is_digest
from restore_census_review import MAX_REVIEW_BYTES, load as load_review
from restore_sealed_inputs import (BootRecipient, MAX_OPTIONS, RECIPIENT_ROOT, decode_options, encode_options, sha)
from retained_image_delivery import read_at
from retained_image_handoff import b64, boot, decode
from retained_image_parts import checked_document

SCOPE = 'santa-restore-database-command-v1'
MAX_REQUEST = 12 * 1024
PREVIEW_SCOPE = 'santa-restore-database-preview-v1'
MAX_PREVIEW = MAX_REQUEST + MAX_REVIEW_BYTES + MAX_OPTIONS + 40
COMMITTED = {'rewrap': 'rewrap_committed', 'quarantine': 'authority_updates_committed'}
COMMON = {'scope', 'action', 'job', 'host', 'step'}
APPLY = {'offer_sha256', 'plan', 'plan_sha256', 'receipt', 'approval', 'public_key'}
BOOT_ID = Path('/proc/sys/kernel/random/boot_id')


def host_receipt(path, *, boot_path=BOOT_ID):
    """Use a boot receipt staged by the trusted host for a network-isolated worker."""
    with ExitStack() as guards:
        parent, name = blob.parent(path, guards)
        raw = read_at(parent, name, 4096)
    receipt = checked_document(raw, sha(raw), 4096)
    blob.need(set(receipt) == {'scope', 'vm_id', 'vm_instance_id', 'boot_id'}
              and receipt['scope'] == GUEST_SCOPE)

    def observed(target):
        current = boot_path.read_text(encoding='ascii').strip()
        blob.need(re.fullmatch(blob.GUID, current) and receipt['boot_id'] == current
                  and blob.resource_id(receipt['vm_id']) == blob.resource_id(target.vm_id)
                  and receipt['vm_instance_id'] == target.instance_id)
        return current

    return observed


@contextmanager
def database_connections(job):
    """Connect only to the selected Unix socket using worker-local settings."""
    import django
    from django.apps import apps
    from django.conf import settings
    from django.db import connections

    target = job.target
    socket = Path(target.socket_dir)
    blob.need(socket.is_absolute() and str(socket.resolve(strict=True)) == target.socket_dir
              and socket.is_dir() and ',' not in target.socket_dir
              and re.fullmatch(r'azd_recovery_[a-f0-9]{24}', target.database)
              and not ({'PGHOSTADDR', 'PGSERVICE'} & os.environ.keys()))
    aliases = ('default', 'observer')
    for alias in aliases:
        config = settings.DATABASES[alias]
        blob.need(config['ENGINE'] == 'django.db.backends.postgresql'
                  and config['HOST'] == target.socket_dir and config['NAME'] == target.database
                  and config['USER'] == target.role
                  and set(config.get('OPTIONS', {})) <= {'connect_timeout', 'options', 'application_name'})
    blob.need(str(settings.DATABASES['default'].get('PORT', '')) ==
              str(settings.DATABASES['observer'].get('PORT', '')))
    django.setup()
    writer, observer = (connections[alias] for alias in aliases)
    try:
        writer.ensure_connection()
        with observer.cursor() as cursor:
            cursor.execute('SET default_transaction_read_only = on')
        yield writer, observer, apps
    finally:
        observer.close()
        writer.close()


def selection(request):
    job_input = request['job']
    blob.need(set(job_input) == {'selection', 'target', 'archive_sha256', 'generation', 'boot_id'})
    job = Job(Selection(**job_input['selection']), Target(**job_input['target']),
              job_input['archive_sha256'], job_input['generation'], job_input['boot_id'])
    return job, blob.SelectedTarget(**request['host'])


def parse_request(raw):
    request = checked_document(raw, sha(raw), MAX_REQUEST)
    action = request['action']
    blob.need(request['scope'] == SCOPE and action in ('offer', 'apply'))
    blob.need(set(request) == COMMON | ({'public_key_sha256'} if action == 'offer' else APPLY))
    job, host = selection(request)
    step = request['step']
    blob.need(set(step) == {'stage', 'binding', 'review_sha256', 'plan_digest'} and step['stage'] in STAGES)
    return request, job, host


def preview_request(job, host, *, stage, review_bytes, review_sha256, fingerprint_key, options):
    """Build input for the trusted local preview launcher. Keep these bytes private."""
    blob.need(type(job) is Job and type(host) is blob.SelectedTarget and stage in STAGES)
    load_review(review_bytes, review_sha256, binding=job.binding(fingerprint_key), stage=stage)
    identity = dict(selection=asdict(job.selection), target=asdict(job.target), archive_sha256=job.archive_sha256,
                    generation=job.generation, boot_id=job.verified_boot_id)
    header = blob.encoded(dict(scope=PREVIEW_SCOPE, action='preview', job=identity, host=asdict(host),
                               step=dict(stage=stage, review_sha256=review_sha256)))
    encoded_options = encode_options(stage, options)
    blob.need(len(header) <= MAX_REQUEST and 0 < len(encoded_options) <= MAX_OPTIONS)
    return (len(header).to_bytes(4, 'big') + header + fingerprint_key
            + len(review_bytes).to_bytes(4, 'big') + review_bytes + encoded_options)


def parse_preview(raw):
    blob.need(type(raw) is bytes and 40 < len(raw) <= MAX_PREVIEW)
    header_size = int.from_bytes(raw[:4], 'big')
    offset = 4 + header_size
    blob.need(0 < header_size <= MAX_REQUEST and offset + 36 < len(raw))
    header = raw[4:offset]
    request = checked_document(header, sha(header), MAX_REQUEST)
    blob.need(set(request) == COMMON and request['scope'] == PREVIEW_SCOPE and request['action'] == 'preview')
    step = request['step']
    blob.need(set(step) == {'stage', 'review_sha256'} and step['stage'] in STAGES)
    job, host = selection(request)
    key = raw[offset:offset + 32]
    size = int.from_bytes(raw[offset + 32:offset + 36], 'big')
    start = offset + 36
    blob.need(0 < size <= MAX_REVIEW_BYTES and 0 < len(raw) - start - size <= MAX_OPTIONS)
    review_bytes = raw[start:start + size]
    load_review(review_bytes, step['review_sha256'], binding=job.binding(key), stage=step['stage'])
    options = decode_options(step['stage'], raw[start + size:])
    return request, job, host, (key, review_bytes, options)


def preview(raw, *, directory, _boot=boot):
    request, job, host, (key, review_bytes, options) = parse_preview(raw)
    BootRecipient._verify_host(job, host, _boot)
    step = request['step']
    directory = Path(directory)
    with ExitStack() as guards:
        blob.parent(directory / 'intent.json', guards)
        writer, observer, apps = guards.enter_context(database_connections(job))
        result = job.run(writer, observer, apps, directory=directory, fingerprint_key=key, stage=step['stage'],
                         review_bytes=review_bytes, review_sha256=step['review_sha256'], options=options)
    blob.need(is_digest(result['plan_digest']) and result['stages'][step['stage']] == 'pending'
              and result['review'][COMMITTED[step['stage']]] is False
              and result['activation_allowed'] is False and result['current_authority_established'] is False)
    return dict(scope=PREVIEW_SCOPE, request_sha256=sha(raw), stage=step['stage'], state='previewed',
                plan_sha256=result['plan_digest'], activation_allowed=False, current_authority_established=False)


def dispatch(raw, *, directory=None, recipient_root=RECIPIENT_ROOT, carrier_root=None, _boot=boot):
    request, job, host = parse_request(raw)
    action, step = request['action'], request['step']
    reply = dict(scope=SCOPE, stage=step['stage'], request_sha256=sha(raw))
    if action == 'offer':
        blob.need(directory is None)
        offer = BootRecipient.prepare(job, host, request['public_key_sha256'],
                                      root=recipient_root, _boot=_boot, **step)
        return dict(**reply, state='offered', offer=b64(offer), offer_sha256=sha(offer))

    recipient = BootRecipient(job, host, request['offer_sha256'], root=recipient_root, _boot=_boot, **step)
    directory = Path(directory)
    with ExitStack() as guards:
        # Validate the configured durable journal path before opening the database.
        blob.parent(directory / 'intent.json', guards)
        writer, observer, apps = guards.enter_context(database_connections(job))
        result = recipient.apply(request['plan'], request['plan_sha256'], request['receipt'],
                                 decode(request['approval'], 4096), decode(request['public_key'], 32),
                                 writer, observer, apps, directory=directory, carrier_root=carrier_root)
    flag = COMMITTED[step['stage']]
    changed = result['result']['performs_mutation']
    blob.need(result['result'][flag] is True and type(changed) is bool
              and result['stages'][step['stage']] == 'committed' and result['activation_allowed'] is False
              and result['current_authority_established'] is False)
    return dict(**reply, state='committed', plan_sha256=step['plan_digest'], stages=result['stages'],
                database_changed=changed,
                activation_allowed=False, current_authority_established=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--journal-directory', type=Path)
    parser.add_argument('--host-receipt', type=Path)
    parser.add_argument('--local-preview', action='store_true')
    args = parser.parse_args()
    try:
        maximum = MAX_PREVIEW if args.local_preview else MAX_REQUEST
        raw = sys.stdin.buffer.read(maximum + 1)
        with open(os.devnull, 'w') as sink, redirect_stdout(sink), redirect_stderr(sink):
            get_boot = boot if args.host_receipt is None else host_receipt(args.host_receipt)
            run = preview if args.local_preview else dispatch
            result = run(raw, directory=args.journal_directory, _boot=get_boot)
        sys.stdout.buffer.write(blob.encoded(result) + b'\n')
    except Exception:
        parser.exit(1, 'Santa database recovery command rejected or interrupted. Preserve the private journal.\n')


if __name__ == '__main__':
    main()
