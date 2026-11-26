"""Deliver one signed administrator approval and read its original sealed artifact."""

from contextlib import ExitStack, contextmanager
from dataclasses import asdict
import json
import os
from pathlib import Path
import re
import uuid

import blob_retention as blob
import private_arm_adapter as arm
import restore_admin_account as account
import restore_arm_authorization as operator
from restore_guest_job import Job
from restore_quarantine_journal import is_digest
from restore_tooling_bundle import verify
from restore_worker_transport import WORKSPACE_ROOT
from retained_image_delivery import read_at, write_at
from retained_image_handoff import b64, boot, decode, sha
from retained_image_operator import journal_read, journal_root
from retained_image_parts import checked_document
from retained_image_run_command import build_script, submit_action
from retained_image_sas import sync_directory, write_record
from sealed_setup import MAX_ENVELOPE_BYTES

SCOPE = 'santa-restore-admin-transport-v1'
ADMIN_ROOT = 'administrator'
CONTEXT = 'context.json'
APPROVAL = 'approval.json'
OUTCOME = 'outcome.json'
CONTEXT_FIELDS = {'receiver', 'boot', 'plan_sha256', 'operator_pin'}

BOOTSTRAP = r"""import base64, hashlib, json, os, re, stat, sys, tempfile, zipfile
from pathlib import Path

def run():
    raw = base64.b64decode(os.environ.pop('SANTA_ADMIN_TRANSPORT'), validate=True)
    frame = json.loads(raw)
    assert os.geteuid() == 0 and re.fullmatch('[0-9a-f]{32}', frame['workspace'])
    root = Path(WORKSPACE_ROOT) / frame['workspace']
    for path in (root.parent, root):
        info = path.lstat()
        assert path.resolve(strict=True) == path and info.st_uid == 0 and stat.S_ISDIR(info.st_mode)
        assert stat.S_IMODE(info.st_mode) == 0o700
    with os.fdopen(os.open(root / 'tooling.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        info = os.fstat(stream.fileno())
        assert info.st_uid == 0 and stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
        bundle = stream.read(2097153)
    assert len(bundle) <= 2097152 and hashlib.sha256(bundle).hexdigest() == frame['tooling_sha256']
    doc = json.loads(bundle)
    assert doc['commit'] == frame['tooling_commit']
    with tempfile.TemporaryDirectory(prefix='admin-transport-', dir=root) as temporary:
        archive = Path(temporary) / 'modules.zip'
        with zipfile.ZipFile(archive, 'x') as output:
            for name, item in doc['files'].items():
                if re.fullmatch(r'experiments/server/[a-z_][a-z_0-9]*\.py', name):
                    output.writestr(name.rsplit('/', 1)[1], base64.b64decode(item['base64'], validate=True))
        sys.path.insert(0, str(archive))
        from restore_admin_transport import dispatch
        from blob_retention import encoded
        result = encoded(dispatch(raw, root))
    assert len(result) <= 3072
    print('SANTA_IMAGE_FRAME_JSON:' + result.decode('ascii'))

try:
    run()
except Exception:
    raise SystemExit(1) from None
""".replace('WORKSPACE_ROOT', repr(WORKSPACE_ROOT))


def context(job, plan_sha256, operator_pin):
    blob.need(type(job) is Job and is_digest(plan_sha256) and is_digest(operator_pin))
    return dict(receiver=job.selection.vm_instance_id, boot=job.verified_boot_id,
                plan_sha256=plan_sha256, operator_pin=operator_pin)


def read(folder, filename, maximum=3072):
    raw = read_at(folder, filename, maximum)
    return checked_document(raw, sha(raw), maximum)


@contextmanager
def mailbox(workspace):
    import fcntl

    with ExitStack() as stack:
        folder, _ = blob.parent(workspace / ADMIN_ROOT / CONTEXT, stack)
        fcntl.flock(folder, fcntl.LOCK_EX)
        yield folder


def prepare(workspace, job, plan_sha256, operator_pin):
    """Set the receiver-owned plan and key pin before the operator is sent a preview."""
    directory = workspace / ADMIN_ROOT
    with ExitStack() as stack:
        root, name = blob.parent(directory, stack)
        os.mkdir(name, 0o700, dir_fd=root)
        os.fsync(root)
        folder, name = blob.parent(directory / CONTEXT, stack)
        write_at(folder, name, blob.encoded(context(job, plan_sha256, operator_pin)))


def approved_request(frame, pin):
    public = decode(frame['public_key'], 32)
    approval = decode(frame['approval'], 2048)
    blob.need(len(public) == 32 and sha(public) == pin)
    packet = checked_document(approval, sha(approval), 2048)
    blob.need(packet['body']['request']['plan_sha256'] == frame['plan_sha256'])
    return approval, public


def consume(workspace, job, writer, observer, registry, *, directory, artifact_directory, fingerprint_key,
            username, email, runtime_sha256, recipient_sha256, recipient_public_key, setup_origin, plan_sha256):
    """Consume the receiver's mailbox inside the isolated Django worker."""
    with mailbox(workspace) as folder:
        greeting = read(folder, CONTEXT)
        blob.need(greeting == context(job, plan_sha256, greeting['operator_pin']))
        frame = read(folder, APPROVAL, 8192)
        blob.need(all(frame[name] == value for name, value in greeting.items()))
        approval, public = approved_request(frame, greeting['operator_pin'])
    result = account.apply(job, writer, observer, registry, directory=directory,
                           artifact_directory=artifact_directory, fingerprint_key=fingerprint_key,
                           username=username, email=email, runtime_sha256=runtime_sha256,
                           recipient_sha256=recipient_sha256, recipient_public_key=recipient_public_key,
                           setup_origin=setup_origin, approved_plan_sha256=plan_sha256, approval=approval,
                           operator_public_key=public, operator_pin=greeting['operator_pin'])
    submit_result(workspace, job, directory=directory, artifact_directory=artifact_directory,
                  fingerprint_key=fingerprint_key, plan_sha256=plan_sha256)
    return result


def submit_result(workspace, job, *, directory, artifact_directory, fingerprint_key, plan_sha256):
    """Publish only ciphertext verified against the receiver's committed account journal."""
    with mailbox(workspace) as folder:
        greeting = read(folder, CONTEXT)
        blob.need(greeting == context(job, plan_sha256, greeting['operator_pin']))
        request = read(folder, APPROVAL, 8192)
        approval, _ = approved_request(request, greeting['operator_pin'])
        blob.need(request['plan_sha256'] == plan_sha256)
        raw = account.read_artifact(job, directory=directory, artifact_directory=artifact_directory,
                                    fingerprint_key=fingerprint_key, plan_sha256=plan_sha256)
        sealed = checked_document(raw, sha(raw), MAX_ENVELOPE_BYTES)
        write_at(folder, OUTCOME, blob.encoded(dict(artifact=sealed, artifact_sha256=sha(raw),
                                                   approval_sha256=sha(approval))))


def dispatch(raw, workspace, *, _boot=boot):
    """Guest mailbox. The worker performs signature verification before changing PostgreSQL."""
    frame = checked_document(raw, sha(raw), 8192)
    action = frame['action']
    fields = CONTEXT_FIELDS | {'scope', 'action', 'workspace', 'tooling_commit', 'tooling_sha256', 'host'}
    blob.need(action in ('submit', 'readback') and frame['scope'] == SCOPE
              and set(frame) == (fields | {'approval', 'public_key'} if action == 'submit'
                                 else fields | {'approval_sha256'})
              and frame['workspace'] == workspace.name)
    host = blob.SelectedTarget(**frame['host'])
    blob.need(host.instance_id == frame['receiver'] and _boot(host) == frame['boot'])
    result = dict(scope=SCOPE, batch_sha256=sha(raw), plan_sha256=frame['plan_sha256'])
    with mailbox(workspace) as folder:
        greeting = read(folder, CONTEXT)
        blob.need(greeting == {name: frame[name] for name in CONTEXT_FIELDS})
        if action == 'submit':
            approved_request(frame, greeting['operator_pin'])
            write_at(folder, APPROVAL, raw)
            return {**result, 'state': 'submitted'}
        blob.need(is_digest(frame['approval_sha256']))
        try:
            submitted = read(folder, APPROVAL, 8192)
        except FileNotFoundError:
            return {**result, 'state': 'not-submitted'}
        approval, _ = approved_request(submitted, greeting['operator_pin'])
        blob.need(sha(approval) == frame['approval_sha256'])
        try:
            outcome = read(folder, OUTCOME)
        except FileNotFoundError:
            return {**result, 'state': 'pending'}
        blob.need(set(outcome) == {'artifact', 'artifact_sha256', 'approval_sha256'}
                  and outcome['approval_sha256'] == frame['approval_sha256']
                  and sha(blob.encoded(outcome['artifact'])) == outcome['artifact_sha256'])
        return {**result, **outcome, 'state': 'committed'}


class Operation:
    def __init__(self, selection, job, tooling, *, workspace, plan_sha256, operator_pin, commit, tooling_sha256, cli=None):
        self.identity = job.selection
        host = selection.verifier
        blob.need(host is not None and self.identity.tenant == selection.tenant
                  and self.identity.subscription == selection.subscription
                  and blob.resource_id(self.identity.vm_id) == blob.resource_id(host.vm_id)
                  and self.identity.vm_instance_id == host.instance_id and self.identity.region == host.region
                  and type(workspace) is str and re.fullmatch('[0-9a-f]{32}', workspace))
        verify(tooling, commit=commit, bundle_sha256=tooling_sha256)
        blob.need('experiments/server/restore_admin_transport.py' in json.loads(tooling)['files'])
        self.base = dict(scope=SCOPE, workspace=workspace, tooling_commit=commit, tooling_sha256=tooling_sha256,
                         host=asdict(host), **context(job, plan_sha256, operator_pin))
        self.cli, self.application = cli, None

    def call(self, arguments, seconds):
        if self.cli is not None:
            return self.cli(arguments, seconds)
        if self.application is None:
            self.application = arm.resolve_cli()
        return arm.bounded_cli(arguments, seconds, application=self.application)

    def send(self, frame):
        raw = blob.encoded(frame)
        blob.need(len(raw) <= 8192)
        nonce = uuid.uuid4().hex
        script = build_script(f"export SANTA_ADMIN_TRANSPORT='{b64(raw)}'\n", BOOTSTRAP, nonce)
        args = ['--subscription', self.identity.subscription, '--resource-group', self.identity.vm_id.split('/')[4],
                '--name', 'vm-santa-lab']
        before = operator.observe(self.identity, _cli=self.call)
        reply = submit_action(self.call, args, script, nonce, sha(raw), 90, scope=SCOPE)
        blob.need(operator.observe(self.identity, _cli=self.call) == before
                  and reply['plan_sha256'] == self.base['plan_sha256'])
        return reply

    def directory(self, root):
        return journal_root(root) / (sha(blob.encoded(self.base)) + '-administrator')

    def apply(self, root, approval, public_key):
        frame = dict(**self.base, action='submit', approval=b64(approval), public_key=b64(public_key))
        approved_request(frame, self.base['operator_pin'])
        directory = self.directory(root)
        directory.mkdir(mode=0o700)
        sync_directory(directory.parent)
        write_record(directory / 'intent.json', dict(**self.base, approval_sha256=sha(approval)))
        sync_directory(directory)
        reply = self.send(frame)
        blob.need(set(reply) == {'scope', 'batch_sha256', 'plan_sha256', 'state'} and reply['state'] == 'submitted')
        write_record(directory / 'submitted.json', reply)
        sync_directory(directory)
        return reply

    def observe(self, root):
        """Reconcile one known attempt without resubmitting its approval."""
        directory = self.directory(root)
        intent = journal_read(directory / 'intent.json')
        blob.need(intent == dict(**self.base, approval_sha256=intent['approval_sha256'])
                  and is_digest(intent['approval_sha256']))
        reply = self.send(dict(**self.base, action='readback', approval_sha256=intent['approval_sha256']))
        expected = {'scope', 'batch_sha256', 'plan_sha256', 'state'}
        if reply['state'] in ('pending', 'not-submitted'):
            blob.need(set(reply) == expected)
        else:
            blob.need(reply['state'] == 'committed'
                      and set(reply) == expected | {'artifact', 'artifact_sha256', 'approval_sha256'}
                      and reply['approval_sha256'] == intent['approval_sha256']
                      and type(reply['artifact']) is dict and len(blob.encoded(reply['artifact'])) <= MAX_ENVELOPE_BYTES
                      and sha(blob.encoded(reply['artifact'])) == reply['artifact_sha256'])
        return reply
