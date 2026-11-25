"""Original Unlicense. Verify a retained native backup on one selected Azure VM."""

import argparse
from dataclasses import asdict
import io
import json
import lzma
from pathlib import Path
import uuid
import zipfile

import blob_retention as blob
import native_retention_verifier as verifier
from retained_image_handoff import b64, decode, sha
from retained_image_operator import journal_read, journal_root, read_bytes, selected_store
from retained_image_parts import checked_document
from retained_image_run_command import ARCHIVE_BOOTSTRAP, SelectedVmCommand
from retained_image_runner import MAX_ARCHIVE, SOURCES
from retained_image_sas import sync_directory, write_record
from restore_tooling_bundle import MAX_BUNDLE, SERVER, verify

BOOTSTRAP = ARCHIVE_BOOTSTRAP.replace('ARCHIVE_ACTION', """            from native_retention_verifier import dispatch
            request = base64.b64decode(os.environ.pop('SANTA_NATIVE_VERIFY_REQUEST'), validate=True)
            result = dispatch(raw, request)""")


class VerifyCommand(SelectedVmCommand):
    def __init__(self, selection, record, tooling, *, commit, tooling_sha256, cli=None):
        super().__init__(selection, selection.verifier, cli)
        self.job = verifier.Verifier(selection, record)
        config = blob.encoded({'tenant': selection.tenant, 'subscription': selection.subscription,
                               'source': asdict(selection.source), 'verifier': asdict(selection.verifier),
                               'store': asdict(selection.store), 'record': record})
        blob.need(len(config) <= 8192)
        files = verify(tooling, commit=commit, bundle_sha256=tooling_sha256)
        output = io.BytesIO()
        with zipfile.ZipFile(output, 'w') as archive:
            for name in (*SOURCES, 'native_retention_verifier.py'):
                if name != 'retained_image_runner.py':
                    archive.writestr(zipfile.ZipInfo(name), files[SERVER + name])
            archive.writestr(zipfile.ZipInfo(verifier.CONFIG), config)
        raw = output.getvalue()
        blob.need(len(raw) <= MAX_ARCHIVE)
        archive_sha256 = sha(raw)
        self.exports = (f"export SANTA_IMAGE_ARCHIVE='{b64(lzma.compress(raw, preset=6))}'\n"
                        f"export SANTA_IMAGE_ARCHIVE_SHA='{archive_sha256}'\n")
        largest = {'action': 'receive', 'packet': b64(bytes(verifier.MAX_PACKET)), 'offer_sha256': 'f' * 64}
        maximum_script = len(self._request_script(largest, '0' * 32)[0])
        self.plan = {**self.job.binding, 'tenant': selection.tenant, 'subscription': selection.subscription,
                     'archive_sha256': archive_sha256, 'tooling_commit': commit, 'tooling_sha256': tooling_sha256,
                     'maximum_script_bytes': maximum_script, 'state': 'planned'}
        self.plan_sha256 = sha(blob.encoded(self.plan))

    def preview(self):
        return {**self.plan, 'plan_sha256': self.plan_sha256, 'performs_mutation': False}

    def _request_script(self, request, nonce):
        raw = blob.encoded(request)
        exports = self.exports + f"export SANTA_NATIVE_VERIFY_REQUEST='{b64(raw)}'\n"
        return self._script(exports, BOOTSTRAP, nonce), sha(raw)

    def _send(self, request):
        nonce = uuid.uuid4().hex
        script, digest = self._request_script(request, nonce)
        seconds = 1020 if request['action'] == 'receive' else 180
        reply = self._submit(self._read_target(), script, nonce, digest, seconds, scope=verifier.SCOPE)
        blob.need(reply.pop('record_sha256') == self.job.binding['record_sha256'])
        del reply['batch_sha256'], reply['scope']
        if reply.get('state') == 'verified':
            blob.need(set(reply) == {'state', 'result'})
            self.job.check_result(reply['result'])
        elif reply.get('state') == 'offered':
            blob.need(set(reply) == {'state', 'offer'})
            self.job.check_offer(decode(reply['offer'], 4096), require_current=False)
        else:
            blob.need(set(reply) == {'state'} and reply['state'] in ('not-attempted', 'submitted-unknown'))
        return reply

    def _directory(self, root, plan_sha256):
        blob.need(plan_sha256 == self.plan_sha256)
        return journal_root(root) / (self.job.record['operation_id'] + '-verify')

    def _report(self, reply):
        report = {'scope': verifier.SCOPE, 'plan_sha256': self.plan_sha256, 'state': reply['state']}
        if reply['state'] == 'verified':
            report.update(result=reply['result'],
                          verifier_ciphertext=(self.job.path / 'download' / 'backup.sealed').as_posix())
        return report

    def apply(self, root, plan_sha256):
        blob.need(self._busy.acquire(blocking=False))
        try:
            directory = self._directory(root, plan_sha256)
            directory.mkdir(mode=0o700)
            sync_directory(directory.parent)
            write_record(directory / 'intent.json', self.plan)
            sync_directory(directory)
            offered = self._send({'action': 'offer'})
            blob.need(offered['state'] == 'offered')
            offer = decode(offered['offer'], 4096)
            packet = self.job.issue(offer, directory.parent, apply=True)
            reply = self._send({'action': 'receive', 'packet': b64(packet), 'offer_sha256': sha(offer)})
            blob.need(reply['state'] == 'verified')
            return self._report(reply)
        except Exception:
            raise blob.RetentionRejected('Native retention verification rejected or unknown; observe the existing attempt') from None
        finally:
            self._busy.release()

    def observe(self, root, plan_sha256):
        blob.need(self._busy.acquire(blocking=False))
        try:
            directory = self._directory(root, plan_sha256)
            blob.need(journal_read(directory / 'intent.json') == self.plan)
            return self._report(self._send({'action': 'observe'}))
        except Exception:
            raise blob.RetentionRejected('Native retention verification observation rejected or unknown') from None
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
        command = VerifyCommand(selected_store(receipt, record['operation_id']), record, read_bytes(args.tooling, MAX_BUNDLE),
                                commit=args.commit, tooling_sha256=args.tooling_sha256)
        if args.action == 'plan':
            result = command.preview()
        elif args.action == 'apply':
            result = command.apply(args.journal_root, args.plan_sha256)
        else:
            result = command.observe(args.journal_root, args.plan_sha256)
        print(blob.encoded(result).decode('ascii'))
    except (ValueError, KeyError, OSError, TypeError, RuntimeError):
        parser.exit(1, 'Native retention verification rejected or unknown. Preserve the journal and use observe.\n')


if __name__ == '__main__':
    main()
