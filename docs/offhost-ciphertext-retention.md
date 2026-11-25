# Optional encrypted ciphertext retention layer

The separate [independent-store creation command](independent-backup-store-deployment.md)
now supplies default no-cloud planning and explicit Apply/Observe orchestration
as source/offline implementation. Actual deployment/policy/retention acceptance
remains separate; the lower-level selector described below never creates resources.

This first layer for [issue85](https://github.com/nathanmcnulty/azd-santa/issues/85)
provides an independent backup-store template and private Python protocol APIs.
It does not wire a new administrator command, provision a store, change a subnet,
submit a VM job or establish live retention. Root and nested VM `azure.yaml`
files, the installer/controller and the active pilot are unchanged. The final
operator workflow must select completed captures and owned targets automatically;
administrators must not assemble receipt JSON or execute local paths remotely.

## Independent store and networking

`experiments/backup-store/main.bicep` is a separate subscription-scope template.
It creates a dedicated resource group, Standard_LRS StorageV2 account and private
`native-captures` container, with Hot block blobs, HTTPS/TLS1.2, no anonymous
access, no trusted-service bypass and default-deny network ACLs. It accepts at
most two explicitly selected owned subnet IDs. Those subnets must already have
the same-region `Microsoft.Storage` service endpoint. This template never enables
an endpoint, rewrites a subnet or weakens an existing policy.

The template uses `azd-santa-backup-owner` and an independent store marker. It
does not add `azd-env-name` or `azd-service-name`, and no `azure.yaml` references
it. This separation is intended to avoid normal VM-environment ownership, but
**actual preservation through VM recreation and `azd down` is an unqualified
lifecycle gate**. A different RG/name alone proves nothing. The future deployment
command must reject an existing unrelated RG/account before submitting ARM;
calling a raw template directly does not implement that ownership preflight.
There is no automatic deletion, lifecycle purge or irreversible immutability
policy. Versioning and seven-day blob/container soft delete provide limited
accidental-deletion recovery, not protection against account/subscription loss.
ARM resource-ID equality and tag keys are case-insensitive. Ambiguous duplicate
tag-key aliases reject; ownership GUIDs and marker values retain strict value
comparison. Mixed-case AZD lifecycle tags still reject adoption. A differently
cased source VM ID is the same VM and cannot qualify as an independent verifier.

The selected boundary is an authenticated, firewall-restricted **public Storage
service endpoint**, with no public application ingress. Service endpoints add no
endpoint charge. A policy requiring Private Link instead remains a prerequisite;
this code does not silently broaden it. A private endpoint needs separate DNS,
network reachability and pricing review. See Microsoft's [service endpoints](https://learn.microsoft.com/en-us/azure/virtual-network/virtual-network-service-endpoints-overview)
and [private endpoints](https://learn.microsoft.com/en-us/azure/storage/common/storage-private-endpoints).

Same-region Azure clients reach Storage using private Azure addresses. Their
public-IP firewall rules and SAS `signedIp` restrictions fail. This also applies
to an operator workstation running in an Azure VM in that region. The initial
API supports only owned same-region Santa/restore subnets, with no public-IP or
external-operator fallback. It never discovers/modifies unrelated operator
networks. Direct outside-Azure/different-region download needs a separately
reviewed provenance/IP path. See [Storage limitations](https://learn.microsoft.com/en-us/azure/storage/common/storage-network-security-limitations)
and [SAS IP behavior](https://learn.microsoft.com/en-us/rest/api/storageservices/create-service-sas#specify-an-ip-address-or-ip-range).

## Capability and transfer contract

`experiments/server/blob_retention.py` exposes private integration APIs:

- `capture_record` binds a strict completed-native-cipher receipt, token-free
  exact blob URI, capture operation, source VM instance, image and source bundle.
  The raw maintenance request must match the completion's SHA, operation, target,
  generation and recipient; spaced producer JSON is hashed without rewriting it.
  Inputs require independently trusted provenance; a caller-created dictionary
  does not establish it. Other artifact scopes, unknown fields and sizes above
  2GiB reject. A matching opaque envelope header is checked before upload; only
  the separate recipient-key authentication proves the encrypted contents.
- `mint_capability` defaults to a plan without ARM calls. Explicit `apply=True`
  uses the supplied cached-ARM callback to re-read exact account/container
  ownership, subnet/VNet tags/service endpoints, VM instance/NIC/subnet linkage
  and deny-all inbound before the fixed `listServiceSas` POST. No login, grants,
  account-key retrieval, provider registration or policy change exists here.
- Upload capabilities are exact-blob `b`, HTTPS-only `c`; verification uses a
  separately minted exact-blob `r` capability. No write/overwrite/list/delete
  permission or `signedIp` is accepted. SAS validity is a bounded 30-minute
  interval (15minutes clock-skew allowance plus 15minutes remaining). Unknown
  configured SAS policies reject pending integration rather than being changed.
  The service-SAS path explicitly requires Shared Key authorization to be allowed.
  A SAS remains a bearer credential usable from the allowed subnet; its token
  does not authenticate a VM identity. The attached target descriptor and IMDS
  check are separate client-side safeguards against accidental target mismatch.
- Capability objects suppress their secret in repr. The callback's raw response
  remains private; callers must not serialize capabilities or print raw callback
  errors. Fixed exceptions and public receipts omit SAS, headers, account keys,
  plaintext and arbitrary provider errors. A cached ARM adapter and confidential
  selected-VM delivery still need packaging; the VM must never receive ARM tokens.
- `upload_file` defaults to a plan. Apply requires an exact source-VM capability
  and IMDS match, a stable owner-private Linux `backup.sealed` descriptor with
  no symlinks/hardlinks, complete SHA/length and a fresh private attempt directory.
  It writes/fsyncs an exclusive token-free intent before one streaming `Put Blob`.
  Headers include exact length, MD5, `BlockBlob` and `If-None-Match:*`.
- A 201 requires all bytes sent, matching SHA, unchanged descriptor and bounded
  semantic deadline. A timeout, 412, expiry or ambiguous response records unknown.
  Only a bounded numeric HTTP status, when available, enters failure receipts.
  It never retries PUT or overwrites/deletes anything. An existing attempt cannot
  be reused. Interruption retains intent/partial evidence; a missing outcome
  always requires inspection of the same object.
- `verify_download` requires a different selected owned VM, IMDS match, exact-blob
  `r`, fresh private attempt and absent private output. It reads that same URI and
  verifies response length plus downloaded SHA, preserving failures/partial data.
  It returns independent-byte verification only, with sealed authentication,
  exact-image retention, current authority and application restore explicitly false.

The ARM callback is a deliberately supplied integration boundary, not proof of
permissions. `listServiceSas/action` can mint powerful account-scoped data
capabilities; code-level blob restriction does not narrow that RBAC authority.
Missing permissions/registration, disallowed Shared Key or unsupported network
provenance must stop the future operator command without automatic remediation.
See [ARM List Service SAS](https://learn.microsoft.com/en-us/rest/api/storagerp/storage-accounts/list-service-sas?view=rest-storagerp-2025-06-01)
and [Shared Key prevention](https://learn.microsoft.com/en-us/azure/storage/common/shared-key-authorization-prevent).

Every SAS request explicitly selects data-plane `api-version=2023-11-03`; its
authorization `sv` may be older. This avoids silently using old single-PUT size
limits. A modern single PUT permits 5,000MiB, above the native 2GiB cap. Create
permission `c` permits new block blobs; overwrite needs `w`. No redirects,
proxies, automatic HTTP retries or arbitrary endpoint hosts are supported.
See [Storage versioning](https://learn.microsoft.com/en-us/rest/api/storageservices/versioning-for-the-azure-storage-services)
and [Put Blob](https://learn.microsoft.com/en-us/rest/api/storageservices/put-blob).

Socket timeouts/time checks bound normal work, not blocked filesystem/kernel
operations. The final job wrapper must enforce a hard outer deadline, retain the
named job handle and validate actual terminal execution. Receipt files alone
are not process-terminal proof. The caller must exclude concurrent root/same-UID
writers. No stage should assume an uploaded MD5/metadata SHA equals independent
byte verification; download and compare with the separately retained expected SHA.

## Recovery artifacts and remaining integration

`experiments/server/retention_image_inventory.py` implements the image selection
for a separate retention contract. It checks the exact compatibility document
from an authenticated native capture and the reviewed dependency lock against
independently pinned SHA-256 values. It then verifies Docker image observations
keyed by immutable local image ID. For the current `linux/amd64` host selection,
the three core services must share one exact ID and each of the four dependencies
must match its own ID and pinned registry digest. Incomplete and unexpected
selections fail. The inventory carries the capture generation, runtime manifest
digest and source commit so later retention can bind the same selection.

Treat the capture document and inventory as private. Image exports may include
restricted source or configuration. `experiments/server/retained_image_archive.py`
checks an owned, stable, seekable plaintext Docker export against the archive
length, SHA-256 and local image ID from an independently authenticated receipt.
It caps each image archive at 16 GiB, streams the complete byte check, and rejects
wrong platforms, tagged or multiple images, missing layers, and conflicting OCI
metadata. It reads the image configuration and archive metadata without extracting
layers. Classic Docker identifies images by the configuration digest, while the
containerd image store can identify a single-platform image by its OCI manifest
digest. The verifier checks the selected identity against the corresponding
hashed bytes and binds both to the same configuration. A multi-platform index
as the selected ID requires separate qualification. Use an outer wall-clock
deadline to bound blocking disk I/O.

`experiments/server/retained_image_export.py` streams a single selected image by
exact ID and platform from the local Linux Docker socket. It needs Docker API
1.48 or later for platform selection. The caller pins the previously verified
inventory and the recipient's RSA public key. The exporter creates a fresh
private directory, records its intent first, and writes only encrypted output.
Docker may use its own temporary storage internally, so the daemon also needs
adequate private disk space and an external deadline. An interrupted or oversized
export leaves its directory for inspection. A successful export publishes a
receipt that binds the intent, plaintext image archive, and ciphertext hashes and
sizes. The receipt must be captured via a trusted producer channel before it can
be used as independent provenance. Anyone with the public key can encrypt bytes.

The envelope reuses the native RSA-OAEP and AES-GCM implementation. A separate
encrypted image marker and intent precede the Docker tar bytes. The image receipt
and payload are separate from native database capture and Blob transfer.
`experiments/server/retained_image_readback.py` checks a downloaded ciphertext
against an independently pinned producer receipt and image inventory. It verifies
the complete ciphertext before creating anonymous plaintext staging on the
selected owner-private Linux filesystem. A second authenticated pass stages the
bytes. The reader checks the encrypted intent and verifies the exact archive
before exposing a read-only file descriptor positioned at the Docker tar. The caller
consumes from that position within the context. The context closes the anonymous
file and leaves no plaintext path. The staging filesystem needs space for one
archive and protection appropriate for confidential data. A trusted isolated host
and an outer I/O deadline remain caller prerequisites.

The Ubuntu test exports a disposable `linux/amd64` image, independently verifies
a ciphertext copy, and loads the verified descriptor. It reads back the same
image ID without starting a container.

Retain an independently reviewed recovery toolset with
`experiments/server/restore_tooling_bundle.py`. Its `build` command accepts a
trusted local repository, the full reviewed commit ID, and a fresh destination
file. It reads exact Git blobs for a fixed inventory covering image readback,
native archive quarantine, restore census, offline rewrap, and their local
dependencies, locks, documentation, and license notices. Git working-tree
configuration, untracked files, and other committed paths are outside that
inventory. Retain the emitted commit and bundle SHA-256 through a trusted
channel alongside the recovery inventory.

On a separate recovery machine, run a trusted copy of the tool's `verify`
command with the bundle path and those external pins. `stage` accepts the same
inputs plus a fresh local directory and writes the verified bytes as files. It
does not run their contents. Failed staging leaves the partial directory for
inspection. The reviewed public-source toolset excludes tenant configuration,
images, workload data, private keys, and credential caches. Keep the historical
installer bundle and confidential image or source artifacts private and retain
their exact bytes independently. The bundled locks identify dependencies;
platform/runtime binaries, authenticated transfer, and live acceptance still
require qualification under [issue #97](https://github.com/nathanmcnulty/azd-santa/issues/97).

The optional VM creation-time Storage endpoint setting and GET-only existing
network proposal are described in [private Storage endpoint wiring](private-storage-endpoint.md).
They do not apply an existing-network change or close live retention/restore gates.

The native 2GiB artifact does not retain container images. The selected local core
image `sha256:8321d09e6b0904e39e282cf07e809fdfe7c8baeb3638d77e44ba51bf4d0ce43a`
was built locally, without an authoritative registry publication. Full restore
must separately retain/load exact image IDs and source/tooling provenance;
rebuilding the same source is not the same image. Image exports may exceed
2GiB or the single-PUT bound. This API rejects larger/different artifacts rather
than truncating them or treating them as native data captures.

Portable recipient-key recovery, independently retained trustworthy receipts,
account/region-loss protection, image/source artifacts and an independently
authorized restore target remain prerequisites. CurrentUser DPAPI is test-only.
LRS off-host retention does not establish regional disaster recovery or current
authority. Data retention, independent byte verification, envelope authentication,
inert quarantine, application restore and fresh authority remain separate gates.

The next integration must provide: independent-store
creation/registration/policy preflight before deployment; narrowly scoped endpoint
enablement compatible with future host provisioning; automatic capture selection;
confidential capability delivery to one selected source job; durable job-terminal
observation; an independently selected verifier/restore target; and teardown
preservation tests. None is enabled by root deployment or represented as complete.

### Cached ARM selection of an existing store

`experiments/server/BackupStoreSelection.psm1` now exports
`Get-SantaBackupStoreSelection`. It is a local operator component, independent of
both deployment entry points. Supply selected tenant/subscription, location,
backup resource-group/account names and the **independently retained expected
ownership GUID**, plus source environment and immutable VM instance GUID. Optional
verifier environment and instance must be supplied together and identify a
different owned VM. These are typed parameters; administrators never construct
ARM fact JSON or copy a script onto a remote VM. An existing target can be selected
using `Get-SantaPrivateVmDeploymentTarget` from `SetupTransport.psm1`.

The default returns a plan of exact GET URLs without invoking Azure CLI.
`-ReadArm` explicitly reads the existing cached CLI session, checks enabled
subscription, tenant and AzureCloud, collects two complete resource observations,
and checks cached context again. It reuses the bounded endpoint CLI reader and
passes nonsecret machine-generated observations through stdin to the isolated
Python bridge (`backup_store_selection.py`); observations are never command-line
arguments. `-Python` can select an already installed Python executable. The bridge
needs only the standard library; it installs nothing. The CLI reader bounds each
parsed response, while the bridge bounds aggregate input and its subprocess time.
When several Python applications match PATH, the bridge starts the first resolved
application, preserving ordinary command precedence. It never joins executable
paths or retries another interpreter after startup failure.
The inherited CLI invocation has no hard wall-clock timeout; a future job wrapper
must enforce and observe its own deadline. A killed or timed-out read is unknown,
never permission to provision or repair.

Selection validates exact resource IDs, strict ownership values and case-insensitive
tag keys; ambiguous tag aliases fail. The backup resource group must have independent
store ownership/purpose markers, no azd environment/service tags or managed owner,
and differ from both selected VM groups. The account must independently match the
retained ownership GUID. Source/verifier groups and VM/VNet/NIC/NSG identities,
provisioning, immutable instance, NIC backlink, same-region owned endpoint subnets,
deny-all inbound rule and exact default-deny Storage ACLs are verified through
the existing retention validator plus stronger producer linkage checks. Complete
before/after responses must match, including any ETags. This detects observed
changes; it is not an atomic ARM snapshot or a promise against later change.

Only the running cached-ARM producer supplies observation provenance. A standalone
bridge run, copied JSON, selected receipt or its digest cannot prove ARM authority
or authorize future SAS/deployment work. A selected receipt records only the
observed nonsecret IDs and observation digest; retention and restore remain false,
and fresh ARM readback is required before subsequent use. Missing, forbidden,
deleted, unsupported or changing resources fail with a fixed redacted error and
no successful receipt. If deleting a source VM group leaves a stale subnet ACL,
selection stays closed and requires explicit network reconciliation; the error
does not prove ciphertext was deleted. This layer cannot silently remove old
rules, enable endpoints or loosen ownership.

This is **existing-store inspection only**. It issues no PUT, POST, deployment,
SAS, role/provider/policy change or data-plane request, including for a preexisting
unrelated resource. Missing resources never trigger creation. The independent
Bicep templates remain create-or-update templates: calling them directly can
update an existing account. Their safe create lifecycle is still an open #85
gate. A GET-not-found or name-availability result followed by template submission
does not establish atomic create-only behavior; a concurrent resource could
appear between those calls. No overwrite-prevention or azd-down preservation
acceptance is claimed for template deployment by this reader.

Remaining #85 integration includes explicit safe provisioning, compatible endpoint
enablement and selected-job capability delivery/observation. #54 still owns actual
off-host recovery, independently retained key/image/source artifacts and lifecycle
proof. This component does not close either issue or authenticate any ciphertext.

## Offline evidence

Focused tests use the actual native producer's encryption sink, protocol mocks,
exact ARM fact fixtures and real hashing. They cover plan/no-side-effect behavior,
ownership/network/VM linkage, create/read-only SAS, modern protocol, start/expiry,
redaction, opaque envelope/size/SHA, 412/timeout/interruption/descriptor changes,
download mismatches and source preservation. Linux-only tests exercise actual
private descriptor/journal/no-overwrite behavior separately; Windows cannot prove
those filesystem boundaries. No tenant, host job or Storage request was performed.

Local qualification used PowerShell7.6.9/Pester6.2.0 and the existing Azure CLI
Python3.14.6/cryptography48.0.1 interpreter. All19 focused tests passed (17 executed,
two Linux filesystem cases explicitly skipped on Windows), followed by all241
integrated Pester checks. Template validation, canonical permission schema and
Bicep compilation passed. Actual Linux descriptor cases require hosted Linux
execution; no cloud or actual transfer acceptance follows from these results.

The subsequent GET-only selector passed six Python test groups and ten focused
Pester checks, including exact cached-reader argument dispatch, no-CLI default,
two complete readbacks, unrelated preexisting ownership, missing/forbidden/timeout
failure, context/resource drift, endpoint/identity/provisioning negatives and
redacted/duplicate/oversized bridge input. The full offline suite then passed all
251 Pester checks on PowerShell7.6.9/Pester6.2.0; template validation, unchanged
MONITOR profiles and the canonical permission schema also passed. These are
synthetic observations and local subprocess tests, with no live Azure requests.

The [confidential source capability relay](blob-capability-relay.md) now supplies a typed one-capture recipient envelope and durable once-only guest job protocol. It does not supply cached Azure orchestration or live transfer/retention/restore acceptance.
