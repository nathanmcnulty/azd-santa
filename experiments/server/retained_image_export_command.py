"""Original Unlicense. Export one selected source image through Azure Run Command."""

import argparse
from dataclasses import asdict
import io
import json
import lzma
from pathlib import Path
from tempfile import TemporaryDirectory
import uuid
import zipfile

import blob_retention as blob
import retained_image_export_job as jobs
from retained_image_handoff import b64, sha
from retained_image_operator import journal_read, journal_root, read_bytes, selected_store
from retained_image_parts import MAX_MANIFEST, checked_document
from retained_image_run_command import ARCHIVE_BOOTSTRAP, SelectedVmCommand
from retained_image_runner import MAX_ARCHIVE, SOURCES
from retained_image_sas import sync_directory, write_record
from restore_tooling_bundle import MAX_BUNDLE, SERVER, verify

BOOTSTRAP = ARCHIVE_BOOTSTRAP.replace('ARCHIVE_ACTION', """            from retained_image_export_job import dispatch
            request = base64.b64decode(os.environ.pop('SANTA_IMAGE_EXPORT_REQUEST'), validate=True)
            result = dispatch(raw, request)""")


class ExportCommand(SelectedVmCommand):
    def __init__(self, selection, inventory, image, recipient, tooling, *,
                 inventory_sha256, recipient_sha256, commit, tooling_sha256,
                 maximum=jobs.export.ARCHIVE_MAXIMUM, seconds=600, cli=None):
        super().__init__(selection, selection.source, cli)
        # The CLI waits up to 1,200 seconds. Reserve time for guest startup and readback.
        blob.need(type(seconds) is int and 0 < seconds <= 1080)
        self.job = jobs.ExportJob(self.target, selection.store.blob.operation, inventory, image, recipient,
            inventory_sha256=inventory_sha256, recipient_sha256=recipient_sha256, maximum=maximum, seconds=seconds)
        config = blob.encoded({'source': asdict(self.target), 'operation': self.job.operation,
            'inventory': b64(inventory), 'image_name': image, 'recipient': b64(recipient),
            'inventory_sha256': inventory_sha256, 'recipient_sha256': recipient_sha256,
            'maximum': maximum, 'seconds': seconds})
        blob.need(len(config) <= jobs.MAX_SELECTION)
        files = verify(tooling, commit=commit, bundle_sha256=tooling_sha256)
        output = io.BytesIO()
        with zipfile.ZipFile(output, 'w') as archive:
            for name in (*SOURCES, 'retained_image_export_job.py'):
                if name != 'retained_image_runner.py':
                    archive.writestr(zipfile.ZipInfo(name), files[SERVER + name])
            archive.writestr(zipfile.ZipInfo(jobs.REQUEST_FILE), config)
        raw = output.getvalue()
        blob.need(len(raw) <= MAX_ARCHIVE)
        self.archive_sha256 = sha(raw)
        packed = b64(lzma.compress(raw, preset=6))
        self.exports = f"export SANTA_IMAGE_ARCHIVE='{packed}'\nexport SANTA_IMAGE_ARCHIVE_SHA='{self.archive_sha256}'\n"
        largest_page = {'action': 'page', 'page': (MAX_MANIFEST - 1) // jobs.PAGE_BYTES, 'manifest_sha256': 'f' * 64}
        maximum_script = len(self._request_script(largest_page, '0' * 32)[0])
        self.plan = {**self.job.identity, 'state': 'planned', 'tenant': selection.tenant,
                     'subscription': selection.subscription, 'image': image, 'image_id': self.job.intent['image_id'],
                     'seconds': seconds, 'maximum_archive_bytes': maximum, 'tooling_commit': commit,
                     'tooling_sha256': tooling_sha256, 'archive_sha256': self.archive_sha256,
                     'maximum_script_bytes': maximum_script}
        self.plan_sha256 = sha(blob.encoded(self.plan))

    def preview(self):
        return {**self.plan, 'plan_sha256': self.plan_sha256, 'performs_mutation': False}

    def _request_script(self, request, nonce):
        raw = blob.encoded(request)
        exports = self.exports + f"export SANTA_IMAGE_EXPORT_REQUEST='{b64(raw)}'\n"
        return self._script(exports, BOOTSTRAP, nonce), sha(raw)

    def _send(self, request, *, args=None):
        nonce = uuid.uuid4().hex
        script, digest = self._request_script(request, nonce)
        timeout = self.job.seconds + 120 if request['action'] == 'start' else 180
        reply = self._submit(args if args is not None else self._read_target(), script, nonce, digest,
                             timeout, scope=jobs.SCOPE)
        reply.pop('batch_sha256')
        return reply

    def _directory(self, root, plan_sha256):
        blob.need(plan_sha256 == self.plan_sha256)
        return journal_root(root) / (self.job.operation + '-export')

    def _receipt(self, reply):
        identity = self.job.identity
        fields = {'state'}
        if reply.get('state') == 'completed':
            fields |= {'export_directory', 'completion_sha256', 'completion', 'manifest_sha256', 'pages'}
            blob.need(reply['export_directory'] == self.job.artifact.as_posix())
        else:
            blob.need(reply.get('state') in ('reserved', 'not-attempted'))
        blob.need(set(reply) == set(identity) | fields and all(reply[key] == value for key, value in identity.items()))
        return reply

    def apply(self, root, plan_sha256):
        blob.need(self._busy.acquire(blocking=False))
        try:
            directory = self._directory(root, plan_sha256)
            args = self._read_target()
            directory.mkdir(mode=0o700)
            sync_directory(directory.parent)
            write_record(directory / 'intent.json', self.plan)
            sync_directory(directory)
            reply = self._receipt(self._send({'action': 'start'}, args=args))
            blob.need(reply['state'] == 'completed')
            return reply
        except Exception:
            raise blob.RetentionRejected('Santa guest export rejected or unknown; observe the existing operation') from None
        finally:
            self._busy.release()

    def observe(self, root, plan_sha256, *, collect=False):
        blob.need(type(collect) is bool and self._busy.acquire(blocking=False))
        try:
            directory = self._directory(root, plan_sha256)
            blob.need(journal_read(directory / 'intent.json') == self.plan)
            reply = self._receipt(self._send({'action': 'observe'}))
            if not collect:
                return reply
            blob.need(reply['state'] == 'completed' and type(reply['pages']) is int
                      and 0 < reply['pages'] <= (MAX_MANIFEST + jobs.PAGE_BYTES - 1) // jobs.PAGE_BYTES)
            pages = (self._send({'action': 'page', 'page': page, 'manifest_sha256': reply['manifest_sha256']})
                     for page in range(reply['pages']))
            completion, manifest = jobs.collect(reply, pages)
            destination = directory / 'metadata'
            if destination.exists():
                blob.need(journal_read(destination / 'export.json') == reply
                          and read_bytes(destination / 'complete.json', 4096) == completion
                          and read_bytes(destination / 'parts.json', MAX_MANIFEST) == manifest)
            else:
                with TemporaryDirectory(prefix='metadata-', dir=directory) as folder:
                    pending = Path(folder)
                    write_record(pending / 'complete.json', checked_document(completion, reply['completion_sha256'], 4096))
                    write_record(pending / 'parts.json', checked_document(manifest, reply['manifest_sha256'], MAX_MANIFEST))
                    write_record(pending / 'export.json', reply)
                    sync_directory(pending)
                    pending.rename(destination)
                    sync_directory(directory)
            return {**reply, 'metadata_directory': str(destination)}
        except Exception:
            raise blob.RetentionRejected('Santa export observation rejected or unknown; preserve the existing journal') from None
        finally:
            self._busy.release()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('plan', 'apply', 'observe', 'collect'))
    for name in ('selection', 'operation', 'inventory', 'inventory-sha256', 'image', 'recipient',
                 'recipient-sha256', 'tooling', 'commit', 'tooling-sha256'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--maximum', type=int, default=jobs.export.ARCHIVE_MAXIMUM)
    parser.add_argument('--seconds', type=int, default=600)
    parser.add_argument('--journal-root', type=Path)
    parser.add_argument('--plan-sha256')
    args = parser.parse_args()
    try:
        receipt = json.loads(read_bytes(args.selection, 8192), object_pairs_hook=blob.unique)
        command = ExportCommand(selected_store(receipt, args.operation), read_bytes(args.inventory, 8192),
            args.image, read_bytes(args.recipient, 1024), read_bytes(args.tooling, MAX_BUNDLE),
            inventory_sha256=args.inventory_sha256, recipient_sha256=args.recipient_sha256,
            commit=args.commit, tooling_sha256=args.tooling_sha256, maximum=args.maximum, seconds=args.seconds)
        if args.action == 'plan':
            result = command.preview()
        elif args.action == 'apply':
            result = command.apply(args.journal_root, args.plan_sha256)
        else:
            result = command.observe(args.journal_root, args.plan_sha256, collect=args.action == 'collect')
        print(blob.encoded(result).decode('ascii'))
    except (ValueError, OSError, TypeError, KeyError, RuntimeError):
        parser.exit(1, 'Santa image export rejected or unknown. Preserve the journal and use observe.\n')


if __name__ == '__main__':
    main()
