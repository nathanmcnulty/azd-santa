"""Original Unlicense. Upload one completed native backup from its selected Azure VM."""

import argparse
from dataclasses import asdict
import io
import json
import lzma
from pathlib import Path
import re
import uuid
import zipfile

import blob_capability_relay as relay
import blob_retention as blob
from native_retention_upload_guest import MAX_PACKET, PROGRAMS, SCOPE
from private_arm_adapter import CachedArm
from retained_image_handoff import b64, sha
from retained_image_operator import journal_read, journal_root, read_bytes, selected_store
from retained_image_parts import checked_document
from retained_image_run_command import ARCHIVE_BOOTSTRAP, SelectedVmCommand
from retained_image_runner import MAX_ARCHIVE
from retained_image_sas import sync_directory, write_record
from restore_tooling_bundle import MAX_BUNDLE, SERVER, verify

BOOTSTRAP = ARCHIVE_BOOTSTRAP.replace('ARCHIVE_ACTION', """            from native_retention_upload_guest import dispatch
            request = base64.b64decode(os.environ.pop('SANTA_NATIVE_UPLOAD_REQUEST'), validate=True)
            result = dispatch(raw, request)""")


def guest_archive(bundle, config):
    blob.need(len(config) <= 8192 and sha(bundle[SERVER + PROGRAMS[0]]) == relay.RETENTION_SHA)
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w') as archive:
        for name in (*PROGRAMS, 'native_retention_upload_guest.py'):
            archive.writestr(zipfile.ZipInfo(name), bundle[SERVER + name])
        archive.writestr(zipfile.ZipInfo('selection.json'), config)
    raw = output.getvalue()
    blob.need(len(raw) <= MAX_ARCHIVE)
    digest = sha(raw)
    return digest, (f"export SANTA_IMAGE_ARCHIVE='{b64(lzma.compress(raw, preset=6))}'\n"
                    f"export SANTA_IMAGE_ARCHIVE_SHA='{digest}'\n")


def source_script(exports, request, nonce):
    raw = blob.encoded(request)
    exports += f"export SANTA_NATIVE_UPLOAD_REQUEST='{b64(raw)}'\n"
    return SelectedVmCommand._script(exports, BOOTSTRAP, nonce), sha(raw)


class UploadCommand(SelectedVmCommand):
    def __init__(self, selection, record, tooling, *, commit, tooling_sha256, cli=None):
        super().__init__(selection, selection.source, cli)
        selected = selection.store.blob
        blob.selection(record, selected, selection.store, self.target, 'c')
        self.environment = self.target.vm_id.split('/')[4].removeprefix('rg-azd-santa-vm-')
        relay.selection(self.environment, self.target, record)
        self.record = json.loads(blob.encoded(record))
        self.record_sha256 = sha(blob.encoded(record))
        bundle = verify(tooling, commit=commit, bundle_sha256=tooling_sha256)
        self.program_sha256 = sha(bundle[SERVER + PROGRAMS[1]])
        config = blob.encoded({'source': asdict(self.target), 'blob': asdict(selected), 'record': record})
        digest, self.exports = guest_archive(bundle, config)
        largest = {'action': 'submit', 'packet': 'x' * MAX_PACKET, 'offer_sha256': 'f' * 64}
        maximum_script = len(source_script(self.exports, largest, '0' * 32)[0])
        self.plan = {'scope': SCOPE, 'state': 'planned', 'permission': 'c', 'source': asdict(self.target),
                     'tenant': selection.tenant, 'subscription': selection.subscription,
                     'storage_account_id': selected.account_id, 'record_sha256': self.record_sha256,
                     'archive_sha256': digest, 'tooling_commit': commit, 'tooling_sha256': tooling_sha256,
                     'maximum_script_bytes': maximum_script}
        self.plan_sha256 = sha(blob.encoded(self.plan))

    def preview(self):
        return {**self.plan, 'plan_sha256': self.plan_sha256, 'performs_mutation': False}

    def _send(self, request):
        nonce = uuid.uuid4().hex
        script, digest = source_script(self.exports, request, nonce)
        envelope = self._submit(self._read_target(), script, nonce, digest, 210, scope=SCOPE)
        blob.need(set(envelope) == {'scope', 'batch_sha256', 'record_sha256', 'reply'}
                  and envelope['record_sha256'] == self.record_sha256)
        reply = envelope['reply']
        if request['action'] == 'offer':
            blob.need(set(reply) == {'state', 'offer'} and reply['state'] == 'offered')
            offer = reply['offer']
            target, _ = relay.check_offer(offer)
            selected = self.selection.store.blob
            blob.need(target == self.target and offer['environment'] == self.environment
                      and offer['account_id'] == selected.account_id and offer['blob_uri'] == selected.uri
                      and offer['operation'] == selected.operation
                      and offer['ciphertext_bytes'] == self.record['complete']['ciphertext_bytes']
                      and offer['ciphertext_sha256'] == self.record['complete']['ciphertext_sha256']
                      and offer['record_sha256'] == self.record_sha256
                      and offer['program_sha256'] == self.program_sha256
                      and offer['retention_sha256'] == relay.RETENTION_SHA)
            return offer
        return self._observation(reply, request.get('offer_sha256'))

    def _observation(self, reply, offer_digest):
        base = {'scope', 'operation', 'offer_sha256', 'state', 'automatic_replay',
                'independent_bytes_verified', 'restore_accepted', 'current_authority'}
        states = ('in-progress', 'unknown', 'uploaded-unverified')
        blob.need(reply['state'] in ('offered', *states)
                  and set(reply) == (base if reply['state'] == 'offered' else base | {'unit', 'intent_sha256'})
                  and reply['scope'] == 'blob-relay-observation-v1'
                  and reply['operation'] == self.record['operation_id']
                  and re.fullmatch(blob.HEX, reply['offer_sha256'])
                  and (offer_digest is None or reply['offer_sha256'] == offer_digest)
                  and all(reply[key] is False for key in
                          ('automatic_replay', 'independent_bytes_verified', 'restore_accepted', 'current_authority')))
        if reply['state'] in states:
            blob.need(re.fullmatch(r'azd-santa-blob-relay-[a-f0-9]{32}\.service', reply['unit'])
                      and re.fullmatch(blob.HEX, reply['intent_sha256']))
        return {'scope': SCOPE, 'plan_sha256': self.plan_sha256, **{k: v for k, v in reply.items() if k != 'scope'}}

    def _directory(self, root, plan_sha256):
        blob.need(plan_sha256 == self.plan_sha256)
        return journal_root(root) / (self.record['operation_id'] + '-upload')

    def apply(self, root, plan_sha256):
        blob.need(self._busy.acquire(blocking=False))
        try:
            directory = self._directory(root, plan_sha256)
            directory.mkdir(mode=0o700)
            sync_directory(directory.parent)
            write_record(directory / 'intent.json', self.plan)
            sync_directory(directory)
            offer = self._send({'action': 'offer'})
            offer_digest = sha(blob.encoded(offer))
            write_record(directory / 'offer.json', {'offer_sha256': offer_digest})
            sync_directory(directory)
            arm = CachedArm(self.selection, self.record, self.target, 'c')
            arm.initialize(live=True)
            packet = relay.seal_offer(offer, arm.mint(apply=True), self.record)
            blob.need(len(blob.encoded(packet)) <= MAX_PACKET)
            return self._send({'action': 'submit', 'packet': packet, 'offer_sha256': offer_digest})
        except Exception:
            raise blob.RetentionRejected('Native upload rejected or unknown; observe the existing attempt') from None
        finally:
            self._busy.release()

    def observe(self, root, plan_sha256):
        blob.need(self._busy.acquire(blocking=False))
        try:
            directory = self._directory(root, plan_sha256)
            blob.need(journal_read(directory / 'intent.json') == self.plan)
            try:
                offer = journal_read(directory / 'offer.json')
            except FileNotFoundError:
                offer = None
            reply = self._send({'action': 'observe'})
            blob.need(offer is None or offer == {'offer_sha256': reply['offer_sha256']})
            return reply
        except Exception:
            raise blob.RetentionRejected('Native upload observation rejected or unknown') from None
        finally:
            self._busy.release()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('plan', 'apply', 'observe'))
    for name in ('selection', 'capture-record', 'capture-record-sha256', 'tooling', 'commit', 'tooling-sha256'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--journal-root', type=Path)
    parser.add_argument('--plan-sha256')
    args = parser.parse_args()
    try:
        record = checked_document(read_bytes(args.capture_record, 8192), args.capture_record_sha256, 8192)
        blob.checked_record(record)
        receipt = json.loads(read_bytes(args.selection, 8192), object_pairs_hook=blob.unique)
        command = UploadCommand(selected_store(receipt, record['operation_id']), record, read_bytes(args.tooling, MAX_BUNDLE),
                                commit=args.commit, tooling_sha256=args.tooling_sha256)
        result = command.preview() if args.action == 'plan' else getattr(command, args.action)(args.journal_root, args.plan_sha256)
        print(blob.encoded(result).decode('ascii'))
    except (ValueError, KeyError, OSError, TypeError, RuntimeError):
        parser.exit(1, 'Native retention upload rejected or unknown. Preserve the journal and use observe.\n')


if __name__ == '__main__':
    main()
