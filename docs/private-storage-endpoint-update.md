# One guarded existing-subnet update

`experiments/vm/PrivateStorageEndpointUpdate.psm1` supplies an explicit operator
API for the existing-network step of issues #90/#85. It changes only the selected
owned subnet's regional Storage service endpoint. It does not provision a backup
store, modify a VNet/NSG/VM, grant roles, open ingress, deploy Bicep, stop services
or establish ciphertext retention/restore acceptance. Root Intune and VM backend
hooks remain unchanged.

The shared cached CLI reader and token capture path are integrated. Each CLI
child has a 30-second default deadline (maximum 300), finite captured stdout
(262,144 UTF-8 bytes) and stderr (4,096 bytes), streaming/count-bounded Windows
forwarding and best-effort process-tree termination/reap after failure. Token
replies return only into caller memory. These are per-call capture/process guards,
not an overall invocation deadline, a total CLI/OS memory quota or guaranteed
termination of arbitrary blocked kernel I/O. Actual selected-token acquisition
and subnet mutation/readback still require separate live qualification.

Import the module on the operator machine. `Set-SantaPrivateStorageEndpoint`
accepts selected tenant/subscription GUIDs, environment and immutable VM instance.
Its default returns a local no-CLI plan. Explicit `-Apply -AttemptDirectory <new
local path>` uses a stable caller-owned attempt location with an existing trusted
parent. No administrator authors JSON or runs a remote script. A future azd/operator
orchestrator must retain and reuse this same handle, rather than inventing a new
attempt after an unknown result.

Apply reserves the local attempt before any CLI call. It invokes the existing
ownership/topology planner fresh in-process; a caller cannot supply a plan or
copied receipt. An already configured supported endpoint needs no token/PUT.
Otherwise it obtains the exact selected cached ARM token in memory, repeats the
full plan, rejects graph/ETag/request drift, and flushes an exclusive submission
intent before one HTTPS subnet PUT with the exact observed `If-Match`. The public
API has no arbitrary URL/body/header input. The bearer token is neither a process
argument nor part of evidence, operator-visible stdout, receipts or raw exception
text. The CLI token reply travels only through a privately captured in-memory
pipe. There is no login, permission fallback, redirect, proxy or automatic retry.

The HTTP phase has a 1..120-second cancellation bound and discards at most 256 KiB of
response data; CloudError bodies are not logged. One fresh readback checks current
ownership, selected VM/instance, NSG/membership/policies, retained endpoints and
regional Storage. The provider may include the paired region in its returned
Storage locations; the selected region must be present. Unsupported/pending or
changed observations remain unknown. A process-level outer deadline must still
bound the complete CLI/HTTP/filesystem invocation and preserve its attempt after
termination. No power-loss or arbitrary blocked-kernel-I/O qualification follows
from local file flushing or in-memory cancellation tests.

The result distinguishes:

- `already-configured`: fresh supported state, no token acquisition/PUT.
- `applied`: HTTP 200/201 and successful fresh preservation readback.
- `precondition-rejected`: HTTP 412, no automatic refreshed retry.
- `unknown`: lost/malformed/oversized response, async 202, failed readback or other
  ambiguous state. `desiredStateObserved` can be true while the PUT result remains
  unknown; a matching GET does not retrospectively prove the lost response.

Every existing attempt path blocks Apply before another CLI/token/PUT. Partial
reservation/submission/output files are retained. Evidence contains only selected
nonsecret request/observation facts and fixed outcomes, with exclusive file writes
and file-data flushing; it contains no credentials. The caller must exclude
concurrent local writers, retain the journal independently as appropriate and
qualify its filesystem/power-loss durability before treating it as a disaster-
recovery journal. This module supplies no cleanup, reset or replay bypass. Choosing
a replacement path is not automated recovery or a new authorization decision.

`Get-SantaPrivateStorageEndpointUpdate` accepts the same typed target and attempt
location. By default it reads local recorded state without CLI; `-ReadArm` performs
a new read-only preservation observation. It never sends a PUT, changes the old
outcome, infers success from a missing journal or converts an unknown request into
an applied one. Copied local evidence is not current external authority.

A separate authorized empty-network probe observed the 2024-05-01 provider reject
a stale subnet ETag with 412 and preserve exact before/after state, then accept a
current ETag. That narrow evidence does not make raw Bicep conditional or make
multiple-resource observations atomic. The setter always leaves
`multiResourceAtomic=false`; actual selected-network delivery and independently
owned store/network/retention gates remain separate.

Offline tests use actual local evidence files and in-memory HTTP handlers, not
sockets or a tenant. They cover fresh-plan drift, exact header/body, token handling,
lost replies, one PUT, 412/202/redirect/error outcomes, response/cancellation bounds,
retained endpoint/policy checks and same-handle non-replay.

On 2026-11-15 UTC a bounded read-only preflight against the selected deallocated
private pilot passed the real ownership/network planner and cached ARM token
acquisition. The token response matched the selected tenant/subscription and
remained in memory; no token was printed or written to the evidence. Its observed
graph digest was
`8ffd056716d171d972db36e8c51751c6995ba1ab2559a8cf526568c09ef55992`.
This established that reader/token integration case, with no network PUT.
Live selected-subnet mutation/readback and power-loss qualification remain open.
See [the planner](private-storage-endpoint.md) and
[off-host retention](offhost-ciphertext-retention.md).
