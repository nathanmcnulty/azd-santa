"""Prepare or apply a signed recovery step in an isolated Django worker."""

import argparse
from contextlib import ExitStack, contextmanager, redirect_stderr, redirect_stdout
import os
from pathlib import Path
import re
import sys

import blob_retention as blob
from restore_arm_authorization import Selection
from restore_authority_transaction import Target
from restore_guest_job import Job
from restore_guest_readback import SCOPE as GUEST_SCOPE
from restore_quarantine_journal import STAGES
from restore_sealed_inputs import BootRecipient, RECIPIENT_ROOT, sha
from retained_image_delivery import read_at
from retained_image_handoff import b64, boot, decode
from retained_image_parts import checked_document

SCOPE = 'santa-restore-database-command-v1'
MAX_REQUEST = 12 * 1024
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


def dispatch(raw, *, directory=None, recipient_root=RECIPIENT_ROOT, carrier_root=None, _boot=boot):
    request = checked_document(raw, sha(raw), MAX_REQUEST)
    action = request['action']
    blob.need(request['scope'] == SCOPE and action in ('offer', 'apply'))
    blob.need(set(request) == COMMON | ({'public_key_sha256'} if action == 'offer' else APPLY))
    job_input = request['job']
    blob.need(set(job_input) == {'selection', 'target', 'archive_sha256', 'generation', 'boot_id'})
    job = Job(Selection(**job_input['selection']), Target(**job_input['target']),
              job_input['archive_sha256'], job_input['generation'], job_input['boot_id'])
    host = blob.SelectedTarget(**request['host'])
    step = request['step']
    blob.need(set(step) == {'stage', 'binding', 'review_sha256', 'plan_digest'} and step['stage'] in STAGES)
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
    args = parser.parse_args()
    try:
        raw = sys.stdin.buffer.read(MAX_REQUEST + 1)
        with open(os.devnull, 'w') as sink, redirect_stdout(sink), redirect_stderr(sink):
            get_boot = boot if args.host_receipt is None else host_receipt(args.host_receipt)
            result = dispatch(raw, directory=args.journal_directory, _boot=get_boot)
        sys.stdout.buffer.write(blob.encoded(result) + b'\n')
    except Exception:
        parser.exit(1, 'Santa database recovery command rejected or interrupted. Preserve the private journal.\n')


if __name__ == '__main__':
    main()
