"""Issue the existing store's exact create-only or read-only recovery packet SAS."""

import private_arm_adapter as arm
from restore_input_blob import PacketTransfer
from retained_image_sas import ExactBlobSasIssuer


class RestoreInputSasIssuer(ExactBlobSasIssuer):
    """Use fresh cached ARM and a persistent reservation for one packet and role."""

    def __init__(self, selection, transfer, permission, *, seconds=180, cli=arm.cached_cli, transport=arm.https):
        super().__init__(selection, seconds=seconds, cli=cli, transport=transport)
        arm.require(type(transfer) is PacketTransfer and permission in ('c', 'r')
                    and selection.store == transfer.store and selection.verifier == transfer.target)
        job_selection = transfer.job.selection
        arm.require(selection.tenant == job_selection.tenant and selection.subscription == job_selection.subscription
                    and selection.source.vm_id.casefold() != selection.verifier.vm_id.casefold()
                    and selection.source.instance_id != selection.verifier.instance_id)
        part = transfer.object_metadata()
        canonical = f"/blob/{selection.store.blob.account}/native-captures/{part['object']}"
        self._objects = ((part, canonical),)
        self._target = selection.source if permission == 'c' else transfer.target
        self._permission = permission
        self._account = job_selection.account.casefold()
        self._digest = transfer.packet_sha256
        self._journal_name = transfer.packet_sha256 + '-restore-input-' + permission
        self._plan_scope = 'santa-restore-input-sas-plan-v1'
        self._pins = dict(scope='santa-restore-input-sas-v1', operation=selection.store.blob.operation,
                          packet_sha256=transfer.packet_sha256, packet_bytes=transfer.packet_bytes,
                          boot_id=transfer.job.verified_boot_id)

    def _context(self):
        context = super()._context()
        user = context['user']
        arm.require(user.get('type') == 'user' and user.get('name', '').casefold() == self._account)
        return context
