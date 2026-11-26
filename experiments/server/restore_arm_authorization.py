"""Bind a confirmed Santa recovery operation to current cached Azure VM readback."""

from dataclasses import dataclass, fields
import re
import threading
import time

import blob_retention as blob
import private_arm_adapter as arm
import restore_census_review as review
import restore_quarantine_journal as journal

VM_PATH = (r'/subscriptions/(' + blob.GUID + r')/resourceGroups/(rg-azd-santa-vm-([a-z0-9-]{2,32}))'
           r'/providers/Microsoft\.Compute/virtualMachines/vm-santa-lab')
VM_QUERY = '{id:id,vmId:vmId,location:location,provisioningState:provisioningState,tags:tags}'


@dataclass(frozen=True, repr=False)
class Selection:
    tenant: str
    subscription: str
    account: str
    vm_id: str
    vm_instance_id: str
    region: str

    def __post_init__(self):
        arm.require(all(type(getattr(self, field.name)) is str for field in fields(self)))
        path = re.fullmatch(VM_PATH, self.vm_id, re.IGNORECASE | re.ASCII)
        arm.require(path is not None and path[1].lower() == self.subscription
                    and re.fullmatch(blob.GUID, self.tenant) and re.fullmatch(blob.GUID, self.vm_instance_id)
                    and re.fullmatch(r'[a-z0-9]{2,32}', self.region)
                    and re.fullmatch(r'[^\s@]{1,128}@[^\s@]{1,128}', self.account, re.ASCII))


def observe(selection, *, _cli=None):
    """Read one exact pilot VM through Azure CLI, using the selected cached user."""
    try:
        arm.require(type(selection) is Selection)
        deadline = time.monotonic() + 60
        application = arm.resolve_cli() if _cli is None else None

        def call(args):
            remaining = min(30, deadline - time.monotonic())
            arm.require(remaining > 0)
            if _cli is None:
                return arm.bounded_cli(args, remaining, application=application)
            return _cli(args, remaining)

        def account():
            row = call(['account', 'show', '--subscription', selection.subscription])
            user = row['user']
            arm.require(row['id'].lower() == selection.subscription and row['tenantId'].lower() == selection.tenant
                        and row['environmentName'] == 'AzureCloud' and row['state'] == 'Enabled'
                        and user['type'] == 'user' and user['name'].casefold() == selection.account.casefold()
                        and not user.get('cloudShellID') and not user.get('assignedIdentityInfo'))
            return row

        before = account()
        _, group, environment = re.fullmatch(VM_PATH, selection.vm_id, re.IGNORECASE | re.ASCII).groups()
        row = call(['vm', 'show', '--subscription', selection.subscription, '--resource-group', group,
                    '--name', 'vm-santa-lab', '--query', VM_QUERY])
        tags = blob.tags_by_key(row['tags'])
        arm.require(blob.resource_id(row['id']) == blob.resource_id(selection.vm_id)
                    and row['vmId'].lower() == selection.vm_instance_id and row['location'] == selection.region
                    and row['provisioningState'] == 'Succeeded'
                    and tags.get('azd-solution') == 'azd-santa' and tags.get('purpose') == 'synthetic-vm-lab'
                    and tags.get('azd-env-name') == environment.lower())
        arm.require(before == account() and time.monotonic() < deadline)
        return dict(scope='santa-restore-arm-readback-v1', vm_instance_id=selection.vm_instance_id,
                    account_verified=True, exact_vm_verified=True, cloud_write=False)
    except Exception:
        raise arm.ArmRejected() from None


class ConfirmedOperation:
    """One confirmed operation and selected context for the review callback.

    The trusted launcher supplies confirmation and validates the guest binding.
    ARM readback verifies the selected cached identity and VM. The VM execution
    transport must independently exercise its existing privileged permission.
    """

    def __init__(self, selection, *, stage, binding, review_sha256, plan_digest, _observe=observe):
        arm.require(type(selection) is Selection and stage in journal.STAGES
                    and all(journal.is_digest(value) for value in (binding, review_sha256, plan_digest)))
        self._selection = selection
        self._expected = dict(scope=review.SCOPE, stage=stage, binding=binding,
                              review_sha256=review_sha256, plan_digest=plan_digest)
        self._observe = _observe
        self._expires = time.monotonic() + 300
        self._lock = threading.Lock()
        self._attempted = False

    def __call__(self, request):
        try:
            with self._lock:
                arm.require(type(request) is dict and request == self._expected
                            and not self._attempted and time.monotonic() < self._expires)
                self._attempted = True
                readback = self._observe(self._selection)
                arm.require(readback == dict(scope='santa-restore-arm-readback-v1',
                            vm_instance_id=self._selection.vm_instance_id, account_verified=True,
                            exact_vm_verified=True, cloud_write=False) and time.monotonic() < self._expires)
                return True
        except Exception:
            raise arm.ArmRejected() from None
