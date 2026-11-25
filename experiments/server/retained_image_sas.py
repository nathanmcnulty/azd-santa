"""Original Unlicense. Private operator issuance for one pinned image-part batch."""

import datetime as dt
import os
from pathlib import Path
import stat
import threading
import urllib.parse

import blob_retention as blob
import private_arm_adapter as arm
import retained_image_parts as parts
from retained_image_blob import capability


def write_record(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as output:
        output.write(blob.encoded(value))
        output.flush()
        os.fsync(output.fileno())


def sync_directory(path):
    if os.name != 'nt':
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


class IssuedBatch:
    """Private in-process result. The trusted caller delivers each token to its selected VM."""

    def __init__(self, target, permission, manifest_sha256, tokens, *, account_id):
        self.target, self.permission, self.manifest_sha256 = target, permission, manifest_sha256
        self.account_id = account_id
        self._tokens = tokens
        self._lock = threading.Lock()

    def __repr__(self):
        return '<private image SAS batch>'

    def __getstate__(self):
        raise arm.ArmRejected()

    def take(self, target, permission, manifest_sha256):
        with self._lock:
            arm.require(self._tokens is not None and (target, permission, manifest_sha256) ==
                        (self.target, self.permission, self.manifest_sha256))
            tokens, self._tokens = self._tokens, None
            return tokens


class ImageSasIssuer(arm.CachedStoreObservation):
    """One selected operation and role, with fresh store observations before POST."""

    def __init__(self, selection, manifest, completion, permission, *, manifest_sha256,
                 completion_sha256, operation, seconds=180, cli=arm.cached_cli, transport=arm.https):
        super().__init__(selection, seconds=seconds, cli=cli, transport=transport)
        self._pins = dict(manifest_sha256=manifest_sha256, completion_sha256=completion_sha256, operation=operation)
        manifest = parts.checked_manifest(manifest, completion, **self._pins)
        self._target = selection.source if permission == 'c' else selection.verifier
        arm.require(selection.store.blob.operation == operation and permission in ('c', 'r')
                    and self._target is not None)
        if permission == 'r':
            arm.require(self._target.vm_id.casefold() != selection.source.vm_id.casefold()
                        and self._target.instance_id != selection.source.instance_id)
        self._permission = permission
        account = selection.store.blob.account
        self._objects = tuple((part, f"/blob/{account}/native-captures/{part['object']}") for part in manifest['parts'])

    def issue(self, journal_root=None, *, apply=False):
        arm.require(type(apply) is bool)
        if not apply:
            return {'scope': 'santa-image-sas-plan-v1', 'permission': self._permission,
                    'objects': [path for _, path in self._objects], 'requests_sent': 0}
        arm.require(self._busy.acquire(blocking=False))
        try:
            return self._issue(journal_root)
        finally:
            self._state, self._token = 'closed', None
            self._busy.release()

    def _issue(self, journal_root):
        try:
            arm.require(self._state == 'new')
            root = Path(journal_root)
            arm.require(root.is_absolute() and root == root.resolve(strict=True) and root.is_dir())
            if os.name != 'nt':
                info = root.stat()
                arm.require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700)
            journal = root / (self._pins['operation'] + '-' + self._permission)
            journal.mkdir(mode=0o700)
            sync_directory(root)
            write_record(journal / 'intent.json', {**self._pins, 'permission': self._permission,
                'account_id': self._selection.store.blob.account_id, 'target_vm_id': self._target.vm_id,
                'vm_instance_id': self._target.instance_id, 'objects': [path for _, path in self._objects]})
            sync_directory(journal)
            self._initialize(live=True)
            arm.require(self._observe()['observation_sha256'] == self._observation_sha)
            self._state = 'post-attempted'
            now = dt.datetime.now(dt.timezone.utc)
            stamp = lambda value: value.strftime('%Y-%m-%dT%H:%M:%SZ')
            common = dict(signedResource='b', signedPermission=self._permission, signedProtocol='https',
                          signedStart=stamp(now-dt.timedelta(minutes=15)), signedExpiry=stamp(now+dt.timedelta(minutes=15)))
            tokens, signatures = {}, set()
            for part, canonical in self._objects:
                arm.require(blob.encoded(self._context()) == blob.encoded(self._context_initial))
                result = self._transport('POST', self._post, dict(common, canonicalizedResource=canonical),
                                         self._token, self._deadline)
                self._remaining()
                arm.require(type(result) is dict and set(result) == {'serviceSasToken'})
                token = result['serviceSasToken']
                validated = capability(self._selection.store, self._target, part, token, self._permission)
                query = urllib.parse.parse_qs(validated._token)
                signature = query['sig'][0]
                arm.require(query['st'] == [common['signedStart']] and query['se'] == [common['signedExpiry']]
                            and signature not in signatures)
                signatures.add(signature)
                tokens[part['object']] = validated._token
            arm.require(blob.encoded(self._context()) == blob.encoded(self._context_initial))
            write_record(journal / 'issued.json', {'state': 'issued', 'objects': len(tokens)})
            sync_directory(journal)
            return IssuedBatch(self._target, self._permission, self._pins['manifest_sha256'], tokens,
                               account_id=self._selection.store.blob.account_id)
        except Exception:
            # A journal with intent but no completion needs inspection, even
            # when only some responses were received. Nothing can be replayed.
            raise arm.ArmRejected() from None
