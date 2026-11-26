"""Run a reviewed Santa recovery step bound to a verified Azure guest boot."""

from dataclasses import dataclass, field
import hashlib
import re

import blob_retention as blob
import restore_arm_authorization as arm
import restore_authority_transaction as authority
import restore_census as census
import restore_census_review as review
import restore_guest_readback as guest
import restore_quarantine_journal as journal

SCOPE = 'santa-restore-guest-job-v1'


@dataclass(frozen=True, repr=False)
class Job:
    """The launcher supplies the verified guest receipt and reviewed database target.

    Keep the application and workers stopped during the job. Use the same
    private journal and original restore generation for both database steps.
    Confirmation and connection secrets remain with the trusted launcher.
    """

    selection: arm.Selection
    target: authority.Target
    archive_sha256: str
    generation: str
    verified_boot_id: str
    _generation: str = field(init=False)

    def __post_init__(self):
        review.require(type(self.selection) is arm.Selection and type(self.target) is authority.Target
                       and journal.is_digest(self.archive_sha256) and journal.is_digest(self.generation)
                       and type(self.verified_boot_id) is str and re.fullmatch(blob.GUID, self.verified_boot_id)
                       and self.verified_boot_id == self.target.boot_id)
        identity = dict(scope=SCOPE, tenant=self.selection.tenant, subscription=self.selection.subscription,
                        account=self.selection.account.casefold(),
                        vm_id=self.selection.vm_id.casefold(), vm_instance_id=self.selection.vm_instance_id,
                        boot_id=self.verified_boot_id, generation=self.generation)
        object.__setattr__(self, '_generation', hashlib.sha256(review.encode(identity)).hexdigest())

    @classmethod
    def from_readback(cls, selection, target, *, guest_receipt, archive_sha256, generation):
        """Use a receipt obtained by the trusted launcher from guest.readback."""
        review.require(type(selection) is arm.Selection and type(guest_receipt) is dict
                       and set(guest_receipt) == {'scope', 'vm_id', 'vm_instance_id', 'boot_id'}
                       and guest_receipt['scope'] == guest.SCOPE
                       and blob.resource_id(guest_receipt['vm_id']) == blob.resource_id(selection.vm_id)
                       and guest_receipt['vm_instance_id'] == selection.vm_instance_id)
        return cls(selection, target, archive_sha256, generation, guest_receipt['boot_id'])

    def _context(self, fingerprint_key):
        return dict(target=self.target, archive_sha256=self.archive_sha256,
                    generation=self._generation, fingerprint_key=fingerprint_key)

    def publish(self, expected, dispositions, *, fingerprint_key, stage, source_database=None):
        return review.publish(expected, dispositions, **self._context(fingerprint_key), stage=stage,
                              source_database=source_database)

    def binding(self, fingerprint_key):
        return journal.binding_for(self.target, self.archive_sha256, self._generation, fingerprint_key)

    def confirm(self, *, fingerprint_key, stage, review_sha256, plan_digest):
        """Use only after explicitly confirming the exact reviewed operation."""
        return arm.ConfirmedOperation(self.selection, stage=stage, binding=self.binding(fingerprint_key),
                                      review_sha256=review_sha256, plan_digest=plan_digest)

    def inspect(self, directory, *, fingerprint_key):
        return journal.inspect(directory, **self._context(fingerprint_key))

    def run(self, writer, observer, registry, *, directory, fingerprint_key, stage,
            review_bytes, review_sha256, options, limits=census.Limits(), plan_digest=None, authorize=None):
        """Check the live socket target and run the confirmed or previewed database step."""
        return review.run(writer, observer, registry, directory=directory, **self._context(fingerprint_key),
                          stage=stage, review=review_bytes, review_sha256=review_sha256,
                          options=options, limits=limits, plan_digest=plan_digest, authorize=authorize)
