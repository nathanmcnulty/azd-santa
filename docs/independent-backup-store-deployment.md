# Independent backup-store creation

This opt-in operator command reuses the existing independent Bicep template,
owned-network planner and store selector. It is not connected to root or VM
`azure.yaml`. **Source/offline implementation only: no actual store creation,
ARM token request, what-if, policy acceptance or retention was qualified here.**

```powershell
$selected = @{
    TenantId = '<current selected tenant GUID>'
    SubscriptionId = '<selected subscription GUID>'
    Location = '<source VM region, for example westus2>'
    SourceEnvironment = '<selected VM azd environment>'
    SourceVmInstanceId = '<current selected SANTA_VM_INSTANCE_ID>'
}
# Default: no cloud calls, child process or file writes.
./experiments/server/Invoke-SantaBackupStoreDeployment.ps1 @selected
# Explicit fresh operation; no resource names or parameter JSON to author.
$created = ./experiments/server/Invoke-SantaBackupStoreDeployment.ps1 @selected -Action Apply
# Pending, failed or uncertain: observe the SAME returned local directory.
./experiments/server/Invoke-SantaBackupStoreDeployment.ps1 `
    -Action Observe -StateDirectory $created.stateDirectory
```

Apply errors include the state-directory path when no result can be returned.
The default is a fresh `out/santa-backup-store-<ownerGUID>` under the operator's
current directory; `-StateDirectory` selects an absent local destination.
Administrators do not name the resource group, account, owner GUID or deployment.
Preview and Apply each generate a fresh identity; edited previews are not inputs
or authority. Optional verifier environment/instance parameters must form a
complete, distinct second target. At most two selected subnets are supported.

Use the current reviewed source and already installed PowerShell 7.6+, Azure CLI,
Bicep and maintained selector Python dependencies. The compiler is discovered
from `SANTA_BICEP_EXE`, PATH or the existing Azure CLI Bicep cache. Missing tools
fail without installation. `-Python` or `SANTA_CRYPTO_PYTHON` can select an existing
interpreter. There is no new service or duplicate template/runtime dependency.

## Apply

Apply rejects existing generated resource groups, unavailable global storage
names and existing deployment names. It validates current enabled commercial
Azure subscription/tenant, provider registration/API/region availability and an
actual owned-network plan. Each source/verifier needs a Succeeded regional
`Microsoft.Storage` endpoint for the selected region. Missing, pending, Global
or unsupported facts reject. No endpoint enablement, provider registration,
policy change, role grant or firewall broadening is performed.

The existing template is compiled locally. Provider-level ARM validation and
JSON what-if must succeed with only expected Create changes for the generated
group/account/blob service/container, optionally its known nested deployment.
Unsupported what-if shapes reject. Fresh creation/network/context checks run
again before submission and must match. These cloud requests occur only under
Apply; they are not deployment acceptance or atomic snapshots.

A bounded cached token read uses only the selected subscription and ARM resource;
returned tenant/subscription/type/expiry and current context must match. The token
stays in memory. An exclusive flushed local intent binds the exact generated
deployment, plan, template/parameter hashes and fresh preflight BEFORE a single
application `HttpClient.SendAsync` PUT to the fixed ARM deployment URI. There is
no Azure deployment SDK submission, retry loop, proxy, cookie, redirect or use of
response URLs. Only response status is recorded. Response bodies, bearer tokens,
SAS, account keys and plaintext backups are never written by this command.

Local records are exclusive and flushed, never overwritten. Any existing Apply
directory rejects, including one from a failed preflight. Timeout, disconnect or
nonaccepted response preserves intent; Observe that exact deployment, never
repeat PUT. Reconcile an earlier uncertain operation before deliberately starting
another fresh operation. Local state must remain on the trusted operator machine;
this is not protection against host rollback, lost state or malicious local admins.

## Observe and limits

Observe checks current source and local template/parameter hashes, then reads
the exact recorded deployment under fresh cached context. Missing/forbidden or
mismatched facts are failed/unknown, not submission authority. Pending and failed
states are reported without cleanup. Succeeded additionally requires matching
parameters/template hash and maintained `Get-SantaBackupStoreSelection -ReadArm`
validation of actual owned resources/source/verifier linkage. Observations create
new exclusive nonsecret receipts. No SAS or data capability is minted. Selection
does not prove upload, independent readback, retention, decryptability or restore.

ARM PUT remains create-or-update. High-entropy generated names, absence checks
and what-if reduce accidental adoption; they are **not atomic multi-resource
create-only preconditions**. External writers can race after preflight. No
provider CAS or immunity to policy/quota/network races is claimed. Server-side
ARM provisioning is separate asynchronous orchestration; one application send
does not establish exactly-once distributed effects. Partial/failed resources
remain preserved. There is no deletion or caller-supplied template/adoption fallback.

The store is independent of VM lifecycle/azd teardown. Its restricted public
Storage endpoint uses default-deny subnet rules, not Private Link or application
ingress. Policies prohibiting Shared Key/service-SAS prerequisites are not relaxed.
Root Monitor/Intune assignments, VM ingress and restore authority remain unchanged.

## Execution and remaining gates

The shared reader bounds startup, async stdin, finite concurrent reply capture
and exit: default 30 seconds, validation/what-if 180 seconds. ARM submission has a
60-second cancellation deadline. Failed children receive best-effort process-tree
kill and a bounded five-second reap. Owned local fixtures verify descendant PIDs
are gone after Windows wrapper timeout/overflow. Captured-reply limits are not a
memory/CPU sandbox for Azure CLI. Killing a client does not cancel accepted ARM
work. Child-only settings disable CLI file logs, telemetry, extension installation
and automatic upgrades; operator config is untouched. Unsupported Windows batch
metacharacters in arguments fail closed.

Actual provider/what-if response shapes, creation under tenant policy, deployment
observation/hash parity and protected selection need separate Azure acceptance.
Mocks, real local child processes and in-memory HTTP handlers are distinct gates.
No backup upload, independent retention, current-authority restore or public/native
Santa acceptance follows from creating this store.

On 2026-11-15 UTC the maintained read-only prerequisite path passed against the
selected two deallocated Santa lab VMs: current cached tenant/subscription,
registered providers, the supported Storage API/region, fresh generated-name
availability and both owned regional Storage endpoints were observed. This check
made no resource write, acquired no SAS and created no store. Validation/what-if,
submission and deployment observation remain separate live gates.

See [off-host retention](offhost-ciphertext-retention.md) and
[owned Storage endpoints](private-storage-endpoint.md). The Azure
[subscription deployment API](https://learn.microsoft.com/en-us/rest/api/resources/deployments/create-or-update-at-subscription-scope?view=rest-resources-2025-04-01)
and [what-if API](https://learn.microsoft.com/en-us/rest/api/resources/deployments/what-if-at-subscription-scope?view=rest-resources-2025-04-01)
are source contracts, not evidence that this candidate was deployed.
