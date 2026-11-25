"""Original Unlicense. Transfer retained image parts with externally issued exact-blob SAS."""

import base64
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
import datetime as dt
import math
import os
from pathlib import Path
import re
import stat
import time
import urllib.parse

import blob_retention as blob
import retained_image_parts as parts


@dataclass(frozen=True)
class Object:
    account: str
    key: str

    @property
    def uri(self):
        return f'https://{self.account}.blob.core.windows.net/native-captures/{self.key}'


def capability(store, target, part, token, permission):
    blob.need(type(token) is str and 0 < len(token) <= 4096 and token.isascii()
              and all(ord(character) > 32 and ord(character) < 127 for character in token))
    values = blob.unique(urllib.parse.parse_qsl(token, keep_blank_values=True, strict_parsing=True))
    blob.need(set(values) == {'sv', 'sr', 'sp', 'spr', 'st', 'se', 'sig'} and values['sr'] == 'b'
              and values['sp'] == permission and values['spr'] == 'https'
              and dt.date.fromisoformat(values['sv']) >= dt.date(2015, 4, 5))
    signature = base64.b64decode(values['sig'], validate=True)
    blob.need(len(signature) == 32 and base64.b64encode(signature).decode() == values['sig'])
    start, expiry = (dt.datetime.strptime(values[key], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=dt.timezone.utc)
                     for key in ('st', 'se'))
    blob.need(start <= dt.datetime.now(dt.timezone.utc) < expiry and expiry - start <= dt.timedelta(minutes=30))
    # Encode parsed fields so reserved characters cannot become URL delimiters.
    return blob.Capability(Object(store.blob.account, part['object']), target, permission, part['sha256'],
                           expiry, urllib.parse.urlencode(values))


def timeout(deadline, limit=None):
    remaining = deadline - time.monotonic()
    if limit is not None:
        remaining = min(remaining, (limit - dt.datetime.now(dt.timezone.utc)).total_seconds())
    blob.need(remaining > 0)
    return remaining


class PartReader(blob.CountingReader):
    def read(self, size):
        return super().read(min(size, self.expected - self.total)) if self.total < self.expected else b''


class Transfer:
    """One pinned image plan, verified store and independently selected source.

    Apply requires a trusted issuer to bind each supplied token to the exact
    object, selected target and permission. SAS query parameters alone do not
    attest the signed resource, ownership or the issuer's authority. Callers
    must supply fresh verified store facts and a trusted persistent journal root.
    """

    def __init__(self, manifest, completion, store, source, *, manifest_sha256, completion_sha256, operation):
        self.pins = dict(manifest_sha256=manifest_sha256, completion_sha256=completion_sha256, operation=operation)
        self.selection = parts.checked_manifest(manifest, completion, **self.pins)
        blob.need(type(store) is blob.Store and type(store.blob) is blob.Blob and store.blob.operation == operation)
        self.manifest, self.completion, self.store, self.source = manifest, completion, store, source
        self.check_target(source)

    def check_target(self, target):
        account = self.store.blob.account_id
        blob.need(type(target) is blob.SelectedTarget and target.region == self.store.region
                  and target.subnet_id.casefold() in {value.casefold() for value in self.store.owned_subnets}
                  and target.vm_id.split('/')[2].casefold() == account.split('/')[2].casefold()
                  and target.vm_id.split('/providers/')[0].casefold() != account.split('/providers/')[0].casefold())

    def journal(self, root, target, permission, stack):
        return blob.Journal(Path(root) / self.pins['operation'], {**self.pins, 'permission': permission,
                            'account_id': self.store.blob.account_id, 'vm_id': target.vm_id,
                            'vm_instance_id': target.instance_id}, stack)

    def tokens_for(self, tokens, target, permission):
        rows = self.selection['parts']
        blob.need(type(tokens) is dict and set(tokens) == {part['object'] for part in rows})
        return {part['object']: capability(self.store, target, part, tokens[part['object']], permission) for part in rows}

    def upload(self, source_path, attempt_root, tokens=None, *, apply=False, seconds=900, transport=None):
        """Attempt one conditional PUT per planned part, stopping on ambiguity."""
        if not apply:
            return {'state': 'planned', 'parts': len(self.selection['parts']), 'performs_mutation': False}
        try:
            deadline = parts.start(seconds, self.pins['operation'])
            capabilities = self.tokens_for(tokens, self.source, 'c')
            blob.host_identity(self.source)
            transport = transport or blob.BlobHttp()
            with ExitStack() as stack:
                folder, name = blob.parent(source_path, stack)
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=folder)
                stream = stack.enter_context(os.fdopen(fd, 'rb'))
                info = os.fstat(fd)
                blob.need(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1
                          and not info.st_mode & 0o077 and info.st_size == self.selection['ciphertext_bytes'])
                expected = blob.identity(info)

                def stable():
                    blob.need(blob.identity(os.fstat(fd)) == expected ==
                              blob.identity(os.stat(name, dir_fd=folder, follow_symlinks=False)))

                plan = parts.plan(stream, self.completion, completion_sha256=self.pins['completion_sha256'],
                                  operation=self.pins['operation'], seconds=math.ceil(timeout(deadline)))
                blob.need(plan == self.manifest)
                stable()
                journal = self.journal(attempt_root, self.source, 'c', stack)
                confirmed = 0
                try:
                    for part in self.selection['parts']:
                        stable()
                        selected = capabilities[part['object']]
                        stream.seek(part['offset'])
                        reader = PartReader(stream, part['bytes'], deadline)
                        md5 = base64.b64encode(bytes.fromhex(part['md5'])).decode('ascii')
                        status, etag = transport.put(selected, reader, part['bytes'], md5, timeout(deadline, selected.expires))
                        stable()
                        blob.need(status == 201 and re.fullmatch(r'"[A-Za-z0-9._-]{1,128}"', etag or '')
                                  and reader.total == part['bytes'] and reader.sha.hexdigest() == part['sha256'])
                        journal.write(f"part-{part['index']:03d}.json", {'object': part['object'], 'etag': etag})
                        confirmed += 1
                    timeout(deadline)
                    state = 'uploaded'
                except Exception:
                    state = 'unknown'
                result = {'state': state, 'confirmed_parts': confirmed, 'automatic_replay': False,
                          'manifest_sha256': self.pins['manifest_sha256'], 'independent_bytes_verified': False}
                journal.write('outcome.json', result)
                return result
        except Exception:
            raise blob.RetentionRejected('Santa image upload requires inspection; preserve its journal') from None

    def download(self, attempt_root, verifier, tokens, *, apply=False, seconds=900, transport=None):
        """Independently verify exact objects and reassemble ciphertext on a different VM."""
        if not apply:
            return {'state': 'planned', 'parts': len(self.selection['parts']), 'performs_mutation': False}
        try:
            deadline = parts.start(seconds, self.pins['operation'])
            self.check_target(verifier)
            blob.need(verifier.vm_id.casefold() != self.source.vm_id.casefold()
                      and verifier.instance_id != self.source.instance_id)
            capabilities = self.tokens_for(tokens, verifier, 'r')
            blob.host_identity(verifier)
            transport = transport or blob.BlobHttp()
            expected = {part['object']: part['bytes'] for part in self.selection['parts']}

            @contextmanager
            def open_part(key):
                selected = capabilities[key]
                connection, response = transport.get(selected, timeout(deadline, selected.expires))
                try:
                    blob.need(response.status == 200 and response.getheader('Content-Length') == str(expected[key]))
                    yield response
                finally:
                    connection.close()

            with ExitStack() as stack:
                journal = self.journal(attempt_root, verifier, 'r', stack)
                destination = Path('/proc/self/fd') / str(journal.fd) / 'image.sealed'
                result = parts.assemble(self.manifest, self.completion, destination, open_part,
                                        seconds=math.ceil(timeout(deadline)), **self.pins)
                timeout(deadline)
                journal.write('verified.json', result)
                return result
        except Exception:
            raise blob.RetentionRejected('Santa image readback failed; preserve output and journal') from None
