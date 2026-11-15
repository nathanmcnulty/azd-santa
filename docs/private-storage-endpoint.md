# Optional owned-subnet Storage endpoint

Issue [90](https://github.com/nathanmcnulty/azd-santa/issues/90) supplies optional
creation-time VM template wiring and a read-only existing-network proposal.
The separate [guarded setter](private-storage-endpoint-update.md) adds an explicit
once-only operator API; its integration/live gates do not change this planner's
read-only behavior or make raw Bicep conditional.
Root Intune deployment remains compute-free. VM backend installation remains
separately disabled by default; no installer bundle, device assignment, storage
firewall, container, credentials, role grant or inbound rule changes here.

For a **new canonical VM network**, the optional VM azd environment variable
`SANTA_VM_STORAGE_ENDPOINT_ENABLED=true` selects the regional `Microsoft.Storage`
service endpoint. Unset/empty or `false` retains the disabled default. The string
parameters have empty defaults so this optional feature introduces no required
parameter value during initialization; only exact empty/false/true inputs are
accepted. The existing provisioning key hook and backend hooks are unchanged.
`SANTA_VM_HOST_SERVICE_ENDPOINTS_JSON` is a machine-produced preservation input,
empty by default; administrators need not author JSON. Other endpoint entries
are retained, and existing Storage entries are not duplicated, including aliases
that differ in case. The default and opted-in Bicep parameter fixtures compile
offline; they are synthetic inputs, not deployment instructions or usable keys.

The host template declares the whole VNet and subnet. It is **create-or-update**,
cannot discover existing endpoints and is not an ETag-conditional updater. Do not
use raw azd/template replay as approval to update an existing network. A default
empty preservation input is suitable for new canonical networks, not evidence
that an existing subnet has no endpoints. Changing the flag to false is not a
reviewed endpoint-removal workflow. Existing deployment/update orchestration and
actual provider concurrency behavior remain separate gates under issues90/85.

## Existing-network proposal

Import `experiments/vm/PrivateStorageEndpoint.psm1` on the operator machine and use
`New-SantaPrivateStorageEndpointPlan` with selected tenant/subscription GUIDs,
environment name and expected immutable VM instance GUID. The existing
`Get-SantaPrivateVmDeploymentTarget` helper can select that target through cached
authority. No command or script is copied onto a remote VM.

The default returns six exact GET URLs without invoking CLI or writing files.
`-ReadArm` explicitly reuses the bounded cached ARM reader, checks the enabled
AzureCloud subscription and tenant, reads all six selected resources twice, and
checks cached context again. `-EnableStorageEndpoint` proposes adding regional
Storage; without it the current endpoints are preserved. There is no Apply switch,
login, retry, permission fallback, deployment, provider registration or network
mutation. Missing, forbidden, changing or unsupported observations fail with a
fixed error and no successful proposal. The shared cached CLI reader now enforces
a 30-second default outer process deadline, finite concurrent stdout/stderr buffers
and process-tree termination with a bounded reap on failure. Timeout remains an
unknown observation, never permission to change or replay a network request.
The Windows batch-launcher shim streams/counts replies instead of collecting a
full output array. These are captured-reply bounds, not a memory/CPU sandbox for
Azure CLI itself. Unsupported batch metacharacters in arguments fail closed.

Checks include exact group/VM/network IDs and ownership markers, immutable VM
instance, VM-to-NIC-to-subnet backlinks, same-region resources, four network ETags,
one canonical VNet/subnet, its sole selected IP-configuration membership and the
deny-all inbound NSG. Unknown VNet/subnet property keys, nonempty peerings,
delegations, policies, custom DNS, routes, extra subnet members, unsupported
endpoint fields, duplicate service aliases, Storage.Global and pending states
reject. The proposal preserves other service endpoints, locations and supported
subnet policy values, stripping only known read-only endpoint provisioning fields
from the proposed request. Unknown properties are never silently flattened away.

The result contains selected `resourceIds`, the actual validated `observedSubnet`
(id, ETag and complete observed properties), ETags keyed by resource ID, an
observation digest, existing/desired endpoints, machine-generated suggested Bicep
parameters and a **subnet-only** proposed request. Read-only links remain in the
observation and are not blindly echoed into the request. No VNet, NIC, VM or NSG
write is proposed. `cloudWrite`, `mutationAuthorized`, `atomicPreconditionProven`,
live endpoint, retention and restore claims remain false.

A future explicitly authorized operator must invoke this producer fresh, inspect
the actual plan and revalidate ownership/ETags immediately before any write.
Copied receipts, tags and matching digests are not authority. Two readbacks detect
observed drift; they do not establish an atomic snapshot, a provider-enforced
If-Match condition or immunity to later changes. The provider's actual conditional
write behavior must be qualified separately. This source-only component cannot
claim that an existing network was changed safely.

Storage's authenticated public endpoint with exact subnet firewall rules is
distinct from public application ingress; this feature adds no inbound exception
or public-IP fallback. An independently owned backup store still needs default-deny
rules and the exact selected source/verifier subnets. If source infrastructure is
later deleted, a stale subnet rule requires explicit reconciliation. Do not silently
broaden the firewall or infer ciphertext loss from a failed network selection.

See the [VNet schema](https://learn.microsoft.com/en-us/azure/templates/microsoft.network/2024-05-01/virtualnetworks)
and [off-host retention gates](offhost-ciphertext-retention.md). Offline fixture
and compilation success proves no live endpoint enablement, retention or restore.

Offline validation passed all299 Pester checks with PowerShell7.6.9/Pester6.2.0,
including31 network/transport/template checks and compilation of both parameter
sets with the already installed Bicep0.42.1. Template/profile validation and the
canonical permission schema passed. No tenant/authentication or network mutation
was performed by this implementation task. Native azd initialization, actual
existing-plan consumption and endpoint delivery remain distinct live gates.
