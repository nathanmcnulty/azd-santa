"""Deliver one recovery-worker request to an explicitly selected Azure VM."""

import argparse
import json
from pathlib import Path
import re
import sys
import uuid

import blob_retention as blob
import private_arm_adapter as arm
import restore_arm_authorization as operator
import restore_database_command as database
from restore_guest_readback import IDENTITY
from restore_quarantine_journal import is_digest
from restore_tooling_bundle import MAX_BUNDLE, WORKER_SCOPES, verify
from restore_worker import checked_reply
from retained_image_handoff import b64, sha
from retained_image_operator import journal_read, journal_root, read_bytes, selected_store
from retained_image_run_command import RECEIPT, build_script, submit_action
from retained_image_sas import sync_directory, write_record

SCOPE = 'santa-restore-worker-transport-v1'
READBACK_SCOPE = 'santa-restore-worker-transport-readback-v1'
WORKSPACE_ROOT = '/var/lib/azd-santa-qualification/restore-workspaces'

# This loader imports only Python files from the already staged, independently pinned bundle.
BOOTSTRAP = r"""import base64, hashlib, json, os, re, stat, sys, tempfile, zipfile
from pathlib import Path

def need(condition):
    if not condition:
        raise ValueError('Recovery workspace rejected')

def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('ascii')

def sha(value):
    return hashlib.sha256(value).hexdigest()

def read_bundle(path, transport):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as source:
        info = os.fstat(source.fileno())
        need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o077)
        raw = source.read(2097153)
    need(0 < len(raw) <= 2097152 and sha(raw) == transport['tooling_sha256'])
    bundle = json.loads(raw)
    need(bundle['commit'] == transport['tooling_commit'])
    return raw, bundle['files']

def run():
    frame = base64.b64decode(os.environ.pop('SANTA_WORKER_TRANSPORT'), validate=True)
    transport = json.loads(frame)
    value = base64.b64decode(transport['request'], validate=True)
    need(sha(value) == transport['request_sha256'] and os.geteuid() == 0)
    name = transport['workspace']
    need(type(name) is str and re.fullmatch('[0-9a-f]{32}', name))
    workspace = Path(WORKSPACE_ROOT) / name
    for directory in (workspace.parent, workspace):
        info = directory.lstat()
        need(directory.resolve(strict=True) == directory and info.st_uid == 0
             and stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700)
    bundle, files = read_bundle(workspace / 'tooling.json', transport)
    with tempfile.TemporaryDirectory(prefix='transport-', dir=workspace) as work:
        archive = Path(work) / 'modules.zip'
        with zipfile.ZipFile(archive, 'x') as output:
            for path, record in files.items():
                if re.fullmatch(r'experiments/server/[a-z_][a-z_0-9]*\.py', path):
                    output.writestr(path.rsplit('/', 1)[1], base64.b64decode(record['base64'], validate=True))
        sys.path.insert(0, str(archive))
        from contextlib import ExitStack
        import blob_retention as blob
        from restore_database_command import parse_request
        from restore_worker import launch
        from retained_image_handoff import boot

        _, job, host = parse_request(value)
        need(boot(host) == job.verified_boot_id)
        attempt = workspace / ('transport-' + transport['request_sha256'])
        with ExitStack() as guards:
            journal = blob.Journal(attempt, {'request_sha256': transport['request_sha256'], 'boot': job.verified_boot_id},
                                   guards)
            reply = launch(value, workspace=workspace, tooling=bundle, commit=transport['tooling_commit'],
                           tooling_sha256=transport['tooling_sha256'], image=transport['image'],
                           config_sha256=transport['config_sha256'], docker_socket=workspace / 'docker.sock')
            journal.write('outcome.json', reply)
    result = encode(dict(scope=TRANSPORT_SCOPE, batch_sha256=sha(frame), reply=reply))
    need(len(result) <= 3072)
    print('SANTA_IMAGE_FRAME_JSON:' + result.decode('ascii'))

try:
    run()
except Exception:
    raise SystemExit(1) from None
""".replace('WORKSPACE_ROOT', repr(WORKSPACE_ROOT)).replace('TRANSPORT_SCOPE', repr(SCOPE))

READBACK = IDENTITY + f'''
WORKSPACE_ROOT = {WORKSPACE_ROOT!r}
READBACK_SCOPE = {READBACK_SCOPE!r}
WORKER_SCOPE = {database.SCOPE!r}
RECEIPT = {RECEIPT!r}
''' + r"""
import stat


def need(condition):
    if not condition:
        raise ValueError('Recovery worker readback rejected')


def private_directory(path):
    info = path.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700
         and path.resolve(strict=True) == path)


def read_record(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
             and stat.S_IMODE(before.st_mode) == 0o600 and 0 < before.st_size <= 2048)
        raw = stream.read(2049)
        after = os.fstat(stream.fileno())
        need(len(raw) == before.st_size == after.st_size and before.st_mtime_ns == after.st_mtime_ns
             and before.st_ctime_ns == after.st_ctime_ns)
    return json.loads(raw, object_pairs_hook=unique)


def checked_outcome(request):
    root = Path(WORKSPACE_ROOT)
    private_directory(root)
    workspace = root / request['workspace']
    private_directory(workspace)
    attempt = workspace / ('transport-' + request['request_sha256'])
    try:
        private_directory(attempt)
        intent = read_record(attempt / 'intent.json')
        need(intent == {'request_sha256': request['request_sha256'], 'boot': request['boot']})
        reply = read_record(attempt / 'outcome.json')
    except FileNotFoundError:
        return None
    need(set(reply) == {'scope', 'stage', 'state', 'request_sha256', 'plan_sha256', 'stages',
                        'database_changed', 'activation_allowed', 'current_authority_established'})
    for name in ('stage', 'request_sha256', 'plan_sha256'):
        need(reply[name] == request[name])
    need(reply['scope'] == WORKER_SCOPE and reply['state'] == 'committed'
         and set(reply['stages']) == {'rewrap', 'quarantine'}
         and all(state in ('pending', 'committed') for state in reply['stages'].values())
         and reply['stages'][request['stage']] == 'committed' and type(reply['database_changed']) is bool
         and reply['activation_allowed'] is False and reply['current_authority_established'] is False)
    return reply


def readback():
    raw = base64.b64decode(os.environ.pop('SANTA_WORKER_READBACK'), validate=True)
    request = json.loads(raw, object_pairs_hook=unique)
    need(os.geteuid() == 0 and set(request) == {'vm_id', 'vm_instance_id', 'region', 'boot', 'workspace',
                                               'request_sha256', 'plan_sha256', 'stage'})
    need(re.fullmatch('[a-f0-9]{32}', request['workspace'])
         and all(re.fullmatch('[a-f0-9]{64}', request[name]) for name in ('request_sha256', 'plan_sha256'))
         and request['stage'] in ('rewrap', 'quarantine') and selected_boot(request) == request['boot'])
    reply = checked_outcome(request)
    result = dict(scope=READBACK_SCOPE, batch_sha256=hashlib.sha256(raw).hexdigest(), reply=reply)
    print(RECEIPT + json.dumps(result, sort_keys=True, separators=(',', ':')))


try:
    readback()
except Exception:
    raise SystemExit(1) from None
"""


class Operation:
    def __init__(self, selection, raw, tooling, *, workspace, image, commit, tooling_sha256, config_sha256=None,
                 cli=None):
        request, job, host = database.parse_request(raw)
        blob.need(selection.verifier == host and job.selection.tenant == selection.tenant
                  and job.selection.subscription == selection.subscription
                  and blob.resource_id(job.selection.vm_id) == blob.resource_id(host.vm_id)
                  and job.selection.vm_instance_id == host.instance_id and job.selection.region == host.region)
        blob.need(type(workspace) is str and re.fullmatch('[0-9a-f]{32}', workspace)
                  and type(image) is str and image.startswith('sha256:') and is_digest(image[7:]))
        blob.need((request['action'] == 'offer' and config_sha256 is None)
                  or (request['action'] == 'apply' and is_digest(config_sha256)))
        verify(tooling, commit=commit, bundle_sha256=tooling_sha256)
        blob.need(json.loads(tooling)['scope'] in WORKER_SCOPES)
        self.request, self.job, self.raw = request, job, raw
        self.cli, self._application = cli, None
        self.plan = dict(scope=SCOPE, action=request['action'], stage=request['step']['stage'],
                         receiver=host.instance_id, boot=job.verified_boot_id, workspace=workspace,
                         image=image, request_sha256=sha(raw), tooling_commit=commit,
                         tooling_sha256=tooling_sha256, config_sha256=config_sha256)
        self.plan_sha256 = sha(blob.encoded(self.plan))

    def preview(self):
        return {**self.plan, 'plan_sha256': self.plan_sha256, 'submits_run_command': False}

    def _directory(self, root, plan_sha256):
        blob.need(plan_sha256 == self.plan_sha256 == sha(blob.encoded(self.plan)))
        return journal_root(root) / (self.plan['request_sha256'] + '-worker')

    def _call(self, arguments, seconds):
        if self.cli is not None:
            return self.cli(arguments, seconds)
        if self._application is None:
            self._application = arm.resolve_cli()
        return arm.bounded_cli(arguments, seconds, application=self._application)

    def _checked(self, reply):
        return checked_reply(blob.encoded(reply) + b'\n', self.raw, self.request, self.job)

    def _vm_args(self):
        identity = self.job.selection
        return ['--subscription', identity.subscription, '--resource-group', identity.vm_id.split('/')[4],
                '--name', 'vm-santa-lab']

    def apply(self, root, plan_sha256):
        directory = self._directory(root, plan_sha256)
        blob.need(not directory.exists())
        identity = self.job.selection
        frame = blob.encoded({**self.plan, 'request': b64(self.raw)})
        nonce = uuid.uuid4().hex
        script = build_script(f"export SANTA_WORKER_TRANSPORT='{b64(frame)}'\n", BOOTSTRAP, nonce)
        before = operator.observe(identity, _cli=self._call)
        directory.mkdir(mode=0o700)
        sync_directory(directory.parent)
        write_record(directory / 'intent.json', self.preview())
        sync_directory(directory)
        received = submit_action(self._call, self._vm_args(), script, nonce, sha(frame), 270, scope=SCOPE)
        blob.need(set(received) == {'scope', 'batch_sha256', 'reply'})
        reply = self._checked(received['reply'])
        blob.need(operator.observe(identity, _cli=self._call) == before)
        write_record(directory / 'outcome.json', reply)
        sync_directory(directory)
        return reply

    def observe(self, root, plan_sha256):
        """Read the local outcome without resubmitting an uncertain recovery request."""
        directory = self._directory(root, plan_sha256)
        if not directory.exists():
            return dict(scope=SCOPE, state='not-attempted', request_sha256=self.plan['request_sha256'])
        blob.need(journal_read(directory / 'intent.json') == self.preview())
        result = directory / 'outcome.json'
        if not result.exists():
            return dict(scope=SCOPE, state='unknown', request_sha256=self.plan['request_sha256'])
        return self._checked(journal_read(result))

    def readback(self, root, plan_sha256):
        """Recover a signed apply receipt from the same boot with no worker launch."""
        blob.need(self.request['action'] == 'apply')
        directory = self._directory(root, plan_sha256)
        local = self.observe(root, plan_sha256)
        if local['state'] != 'unknown':
            return local
        identity = self.job.selection
        frame = blob.encoded(dict(vm_id=identity.vm_id, vm_instance_id=identity.vm_instance_id,
                                 region=identity.region, boot=self.job.verified_boot_id,
                                 workspace=self.plan['workspace'], request_sha256=self.plan['request_sha256'],
                                 plan_sha256=self.request['step']['plan_digest'], stage=self.plan['stage']))
        nonce = uuid.uuid4().hex
        script = build_script(f"export SANTA_WORKER_READBACK='{b64(frame)}'\n", READBACK, nonce)
        before = operator.observe(identity, _cli=self._call)
        received = submit_action(self._call, self._vm_args(), script, nonce, sha(frame), 180, scope=READBACK_SCOPE)
        blob.need(set(received) == {'scope', 'batch_sha256', 'reply'}
                  and operator.observe(identity, _cli=self._call) == before)
        if received['reply'] is None:
            return local
        reply = self._checked(received['reply'])
        result = directory / 'outcome.json'
        try:
            write_record(result, reply)
            sync_directory(directory)
        except FileExistsError:
            blob.need(self._checked(journal_read(result)) == reply)
        return reply


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('plan', 'apply', 'observe', 'readback'))
    for name in ('selection', 'operation', 'request', 'workspace', 'image', 'tooling', 'commit', 'tooling-sha256'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--config-sha256')
    parser.add_argument('--plan-sha256')
    parser.add_argument('--journal-root', type=Path)
    args = parser.parse_args()
    try:
        selection = selected_store(json.loads(read_bytes(args.selection, 8192), object_pairs_hook=blob.unique),
                                   args.operation)
        operation = Operation(selection, read_bytes(args.request, database.MAX_REQUEST),
                              read_bytes(args.tooling, MAX_BUNDLE), workspace=args.workspace, image=args.image,
                              commit=args.commit, tooling_sha256=args.tooling_sha256, config_sha256=args.config_sha256)
        if args.action == 'plan':
            result = operation.preview()
        else:
            blob.need(args.journal_root is not None)
            result = getattr(operation, args.action)(args.journal_root, args.plan_sha256)
        sys.stdout.buffer.write(blob.encoded(result))
    except Exception:
        parser.exit(1, 'Santa worker transport rejected or uncertain. Preserve the attempt and inspect its journal.\n')


if __name__ == '__main__':
    main()
