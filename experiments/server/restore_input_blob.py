"""Carry a sealed recovery packet through one selected private Azure blob."""

import base64
from contextlib import ExitStack
from dataclasses import dataclass
import hashlib
import io
from pathlib import Path
import re

import blob_retention as blob
from restore_guest_job import Job
from restore_quarantine_journal import is_digest
from restore_sealed_inputs import MAX_PACKET, NONCE_BYTES, WRAPPED_BYTES, sha
from retained_image_blob import PartReader, capability, timeout
from retained_image_handoff import boot
from retained_image_parts import start

SCOPE = 'santa-restore-input-blob-v1'


@dataclass(frozen=True, repr=False)
class PacketTransfer:
    """Pin one object in an independently verified Santa backup store.

    The launcher supplies fresh store/target provenance and a trusted exact
    create-only or read-only SAS from that store. It keeps SAS values private
    and distributes the ciphertext digest and length independently.
    """

    job: Job
    store: blob.Store
    target: blob.SelectedTarget
    packet_sha256: str
    packet_bytes: int

    def __post_init__(self):
        blob.need(type(self.job) is Job and type(self.store) is blob.Store and type(self.store.blob) is blob.Blob
                  and type(self.target) is blob.SelectedTarget and is_digest(self.packet_sha256)
                  and type(self.packet_bytes) is int and WRAPPED_BYTES + NONCE_BYTES + 16 < self.packet_bytes <= MAX_PACKET)
        selected = self.job.selection
        blob.need(blob.resource_id(self.target.vm_id) == blob.resource_id(selected.vm_id)
                  and self.target.instance_id == selected.vm_instance_id
                  and self.target.region == selected.region == self.store.region
                  and blob.resource_id(self.target.subnet_id) in {blob.resource_id(s) for s in self.store.owned_subnets}
                  and self.store.blob.account_id.split('/')[2].casefold() == selected.subscription
                  and blob.resource_id(self.store.blob.account_id.split('/providers/')[0])
                  != blob.resource_id(self.target.vm_id.split('/providers/')[0]))

    def object_metadata(self):
        return {'object': f'{self.store.blob.operation}/restore-inputs/{self.packet_sha256}.sealed',
                'sha256': self.packet_sha256}

    def _capability(self, token, permission):
        return capability(self.store, self.target, self.object_metadata(), token, permission)

    def upload(self, packet, token, journal_root, *, seconds=120, _transport=None):
        """Make one create-only request after reserving the exact packet."""
        try:
            blob.need(type(packet) is bytes and len(packet) == self.packet_bytes and sha(packet) == self.packet_sha256)
            deadline = start(seconds, self.store.blob.operation)
            selected = self._capability(token, 'c')
            transport = _transport if _transport is not None else blob.BlobHttp()
            with ExitStack() as stack:
                intent = dict(scope=SCOPE, vm_instance_id=self.target.instance_id, blob_uri=selected.blob.uri,
                              packet_sha256=self.packet_sha256, packet_bytes=self.packet_bytes)
                state = blob.Journal(Path(journal_root) / self.packet_sha256, intent, stack)
                reader = PartReader(io.BytesIO(packet), self.packet_bytes, deadline)
                checksum = base64.b64encode(hashlib.md5(packet, usedforsecurity=False).digest()).decode('ascii')
                status, etag = transport.put(selected, reader, self.packet_bytes, checksum,
                                             timeout(deadline, selected.expires))
                blob.need(status == 201 and re.fullmatch(r'"[A-Za-z0-9._-]{1,128}"', etag or '')
                          and reader.total == self.packet_bytes
                          and reader.sha.hexdigest() == self.packet_sha256)
                timeout(deadline, selected.expires)
                result = dict(scope=SCOPE, packet_sha256=self.packet_sha256, packet_bytes=self.packet_bytes,
                              uploaded=True, independent_bytes_verified=False)
                state.write('completed.json', result)
                return result
        except Exception:
            raise blob.RetentionRejected('Restore packet upload rejected or unknown; inspect the reserved object') from None

    def download(self, token, *, seconds=120, _transport=None, _boot=boot):
        """Read and verify ciphertext on the selected recovery VM."""
        try:
            deadline = start(seconds, self.store.blob.operation)
            selected = self._capability(token, 'r')
            blob.need(_boot(self.target) == self.job.verified_boot_id)
            transport = _transport if _transport is not None else blob.BlobHttp()
            connection, response = transport.get(selected, timeout(deadline, selected.expires))
            try:
                expected = {'complete': {'ciphertext_bytes': self.packet_bytes, 'ciphertext_sha256': self.packet_sha256}}
                output = io.BytesIO()
                blob.download_bytes(response, output, expected, deadline)
                timeout(deadline, selected.expires)
                return output.getvalue()
            finally:
                connection.close()
        except Exception:
            raise blob.RetentionRejected('Restore packet readback did not verify') from None
