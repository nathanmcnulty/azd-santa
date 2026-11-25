"""Original Unlicense. Action Run Command adapter for the private image relay."""

import lzma
import os
from pathlib import Path
import re
import stat
import tempfile
import threading
import uuid

import blob_retention as blob
import private_arm_adapter as arm
import retained_image_delivery as delivery
import retained_image_handoff as handoff
from retained_image_parts import MAX_PARTS, checked_document
import retained_image_runner as runner
from retained_image_sas import sync_directory, write_record

RECEIPT = 'SANTA_IMAGE_FRAME_JSON:'
DONE = 'SANTA_IMAGE_FRAME_DONE:'
MAX_SCRIPT = 64 * 1024
GUEST_ROOT = runner.GUEST_ROOT
BOOTSTRAP = """import base64, contextlib, hashlib, json, os, stat
from pathlib import Path

def main():
    runner = Path(os.environ['SANTA_IMAGE_RUNNER'])
    for parent in runner.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError()
    with os.fdopen(os.open(runner, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077 or info.st_nlink != 1:
            raise ValueError()
        program = source.read(65537)
    if not 0 < len(program) <= 65536 or hashlib.sha256(program).hexdigest() != os.environ['SANTA_IMAGE_RUNNER_SHA']:
        raise ValueError()
    request = base64.b64decode(os.environ.pop('SANTA_IMAGE_REQUEST'), validate=True)
    namespace = {'__file__': str(runner), '__name__': 'santa_image_handler'}
    with open(os.devnull, 'w') as sink, contextlib.redirect_stdout(sink):
        exec(compile(program, str(runner), 'exec'), namespace)
        reply = namespace['handle'](request)
    response = json.dumps(reply, sort_keys=True, separators=(',', ':'), allow_nan=False)
    if not 0 < len(response.encode('ascii')) <= 3072:
        raise ValueError()
    print('SANTA_IMAGE_FRAME_JSON:' + response)

try:
    main()
except Exception:
    raise SystemExit(1) from None
"""
INSTALL_BOOTSTRAP = """import base64, contextlib, hashlib, json, lzma, os, sys, tempfile
from pathlib import Path

def main():
    compressed = base64.b64decode(os.environ.pop('SANTA_IMAGE_ARCHIVE'), validate=True)
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=32 * 1024 * 1024)
    raw = decoder.decompress(compressed, max_length=ARCHIVE_LIMIT + 1)
    digest = os.environ.pop('SANTA_IMAGE_ARCHIVE_SHA')
    if not decoder.eof or decoder.unused_data or not 0 < len(raw) <= ARCHIVE_LIMIT:
        raise ValueError()
    if hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError()
    with tempfile.TemporaryDirectory(prefix='santa-image-runner-', dir='/run') as folder:
        archive = Path(folder) / 'tools.zip'
        with archive.open('xb') as stream:
            stream.write(raw)
        sys.path.insert(0, str(archive))
        with open(os.devnull, 'w') as sink, contextlib.redirect_stdout(sink):
            from retained_image_runner import install
            result = install(raw, digest, apply=True)
    result.update(scope='azd-santa-image-delivery-v1', batch_sha256=digest)
    print('SANTA_IMAGE_FRAME_JSON:' + json.dumps(result, sort_keys=True, separators=(',', ':'), allow_nan=False))

try:
    main()
except Exception:
    raise SystemExit(1) from None
""".replace('ARCHIVE_LIMIT', str(runner.MAX_ARCHIVE))


def receipt(result, nonce, digest):
    values = result['value']
    blob.need(type(values) is list and 0 < len(values) <= 4)
    for item in values:
        blob.need(type(item['code']) is str and item['code'].endswith('/succeeded')
                  and type(item['message']) is str)
    lines = '\n'.join(item['message'] for item in values).splitlines()
    payloads = [index for index, line in enumerate(lines) if line.startswith(RECEIPT)]
    markers = [index for index, line in enumerate(lines) if line.startswith(DONE)]
    blob.need(len(payloads) == len(markers) == 1 and markers[0] == payloads[0] + 1
              and lines[markers[0]] == DONE + nonce)
    payload = lines[payloads[0]][len(RECEIPT):].encode('ascii')
    value = checked_document(payload, handoff.sha(payload), 3072)
    blob.need(value.get('scope') == delivery.SCOPE and value.get('batch_sha256') == digest)
    return value


class RunCommand:
    """Bind delivery.send's callback to one reviewed guest runner and VM instance."""

    def __init__(self, selection, transfer, permission, runner_sha256, *, cli=None):
        blob.need(type(selection) is arm.Selection and permission in ('c', 'r')
                  and re.fullmatch(blob.HEX, runner_sha256))
        selection.intent()
        self.target = selection.source if permission == 'c' else selection.verifier
        handoff.context(transfer, self.target, permission)
        blob.need(transfer.store == selection.store and transfer.source == selection.source)
        self.selection, self.runner_sha256 = selection, runner_sha256
        self.transfer, self.permission = transfer, permission
        self.runner = f"{GUEST_ROOT}/{handoff.offer_name(transfer, permission)}/run.py"
        self._cli = cli
        self._application = None
        self._busy = threading.Lock()

    def _call(self, arguments, seconds):
        if self._cli is not None:
            return self._cli(arguments, seconds)
        if self._application is None:
            self._application = arm.resolve_cli()
        return arm.bounded_cli(arguments, seconds, application=self._application)

    def offer(self):
        """Read or create the boot-bound public offer for this installed runner."""
        digest = self.transfer.pins['manifest_sha256']
        result = self(delivery.frame('offer', digest))
        blob.need(set(result) == {'scope', 'batch_sha256', 'state', 'offer'} and result['state'] == 'offered')
        raw = handoff.decode(result['offer'], 4096)
        handoff.check_offer(raw, handoff.sha(raw), self.transfer, self.target, self.permission)
        return raw

    def _read_target(self):
        target_id = self.target.vm_id
        subscription = self.selection.subscription
        segments = target_id.split('/')
        args = ['--resource-group', segments[4], '--name', segments[-1], '--subscription', subscription]
        account = self._call(['account', 'show', '--subscription', subscription], 30)
        blob.need(account['id'] == subscription and account['tenantId'] == self.selection.tenant
                  and account['environmentName'] == 'AzureCloud' and account['state'] == 'Enabled')
        vm = self._call(['vm', 'show', *args], 30)
        blob.need(blob.resource_id(vm['id']) == blob.resource_id(target_id)
                  and vm['vmId'].lower() == self.target.instance_id and vm['location'] == self.target.region)
        return args

    @staticmethod
    def _script(exports, bootstrap, nonce):
        script = ("set -eu\n" + exports + "python3 -I -B - 2>/dev/null <<'SANTA_IMAGE_PY'\n"
                  f"{bootstrap}SANTA_IMAGE_PY\nprintf '%s\\n' '{DONE}{nonce}'\n").encode('ascii')
        blob.need(len(script) <= MAX_SCRIPT)
        return script

    def _submit(self, args, script, nonce, digest, seconds):
        with tempfile.TemporaryDirectory(prefix='santa-image-command-') as folder:
            path = Path(folder) / 'frame.sh'
            blob.need(re.fullmatch(r'[A-Za-z0-9_ .:/\\~-]+', str(path)))
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, 'wb') as stream:
                stream.write(script)
            result = self._call(['vm', 'run-command', 'invoke', *args,
                                 '--command-id', 'RunShellScript', '--scripts', '@' + str(path)], seconds)
        return receipt(result, nonce, digest)

    def provision(self, raw, journal_root=None, *, apply=False):
        """Install the selected package before obtaining any short-lived credentials."""
        if not self._busy.acquire(blocking=False):
            raise blob.RetentionRejected('Santa VM image command already in progress')
        try:
            blob.need(type(apply) is bool and type(raw) is bytes and 0 < len(raw) <= runner.MAX_ARCHIVE)
            digest = handoff.sha(raw)
            transfer, target, permission, _ = runner.read_selection(raw, digest)
            blob.need(transfer.pins == self.transfer.pins and transfer.store == self.transfer.store
                      and transfer.source == self.transfer.source and target == self.target and permission == self.permission
                      and handoff.sha(runner.driver(digest)) == self.runner_sha256)
            nonce = uuid.uuid4().hex
            compressed = handoff.b64(lzma.compress(raw, preset=6))
            exports = f"export SANTA_IMAGE_ARCHIVE='{compressed}'\nexport SANTA_IMAGE_ARCHIVE_SHA='{digest}'\n"
            script = self._script(exports, INSTALL_BOOTSTRAP, nonce)
            if not apply:
                return {'state': 'planned', 'archive_sha256': digest, 'script_bytes': len(script)}
            root = Path(journal_root)
            blob.need(root.is_absolute() and root == root.resolve(strict=True) and root.is_dir())
            if os.name != 'nt':
                info = root.stat()
                blob.need(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700)
            args = self._read_target()
            journal = root / (handoff.offer_name(transfer, permission) + '-provision')
            journal.mkdir(mode=0o700)
            sync_directory(root)
            intent = {'archive_sha256': digest, 'runner_sha256': self.runner_sha256,
                      'vm_instance_id': target.instance_id}
            write_record(journal / 'intent.json', intent)
            sync_directory(journal)
            reply = self._submit(args, script, nonce, digest, 180)
            blob.need(reply == {'scope': delivery.SCOPE, 'batch_sha256': digest, 'state': 'installed',
                                'archive_sha256': digest, 'runner_sha256': self.runner_sha256})
            write_record(journal / 'installed.json', reply)
            sync_directory(journal)
            return reply
        except Exception:
            raise blob.RetentionRejected('Santa runner provisioning rejected or unknown; observe the selected runner') from None
        finally:
            self._busy.release()

    def observe_install(self, archive_sha256):
        blob.need(handoff.sha(runner.driver(archive_sha256)) == self.runner_sha256)
        digest = self.transfer.pins['manifest_sha256']
        reply = self(delivery.frame('runner', digest))
        blob.need(reply == {'scope': delivery.SCOPE, 'batch_sha256': digest,
                            'state': 'installed', 'archive_sha256': archive_sha256})
        return reply

    def __call__(self, raw):
        if not self._busy.acquire(blocking=False):
            raise blob.RetentionRejected('Santa VM image command already in progress')
        try:
            request = checked_document(raw, handoff.sha(raw), delivery.MAX_FRAME)
            action, digest = request['action'], request['batch_sha256']
            fields = {'scope', 'batch_sha256', 'action'}
            extras = {'begin': {'batch'}, 'part': {'index', 'packet'}, 'finish': set(),
                      'observe': set(), 'offer': set(), 'runner': set()}
            blob.need(request['scope'] == delivery.SCOPE and re.fullmatch(blob.HEX, digest)
                      and set(request) == fields | extras[action])
            if action == 'begin':
                handoff.decode(request['batch'], delivery.MAX_BATCH)
            elif action == 'part':
                handoff.decode(request['packet'], handoff.MAX_PACKET)
                blob.need(type(request['index']) is int and 0 <= request['index'] < MAX_PARTS)

            nonce = uuid.uuid4().hex
            exports = (f"export SANTA_IMAGE_RUNNER='{self.runner}'\n"
                       f"export SANTA_IMAGE_RUNNER_SHA='{self.runner_sha256}'\n"
                       f"export SANTA_IMAGE_REQUEST='{handoff.b64(raw)}'\n")
            script = self._script(exports, BOOTSTRAP, nonce)
            return self._submit(self._read_target(), script, nonce, digest, 1200 if action == 'finish' else 180)
        except Exception:
            raise blob.RetentionRejected('Santa VM image command rejected or unknown; do not replay') from None
        finally:
            self._busy.release()
