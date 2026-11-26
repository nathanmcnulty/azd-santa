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
  plaintext and arbitrary provider errors. The VM receives the encrypted
  capability through the selected-VM command.
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

Use `experiments/server/native_capture_record_command.py` to collect the input
record for both transfers. Take the request SHA-256, ciphertext SHA-256 and
length, source bundle SHA-256, and image ID from independently retained capture
evidence. The planned read targets the original source instance. The guest
checks the original request, completion and ciphertext against those values
and returns only the transfer record. It creates no upload state and uses no
Storage capability.

```powershell
$recordInputs = @(
    '--selection', $selectionReceipt, '--operation', $captureOperation,
    '--request-sha256', $requestSha, '--ciphertext-sha256', $ciphertextSha,
    '--ciphertext-bytes', "$ciphertextBytes", '--source-bundle-sha256', $sourceBundleSha,
    '--image-id', $sourceImageId, '--tooling', $toolingBundle,
    '--commit', $reviewedCommit, '--tooling-sha256', $toolingSha
)
$recordPlan = python ./experiments/server/native_capture_record_command.py plan @recordInputs |
    ConvertFrom-Json
$recordRead = python ./experiments/server/native_capture_record_command.py read @recordInputs `
    --output $nativeCaptureRecord --plan-sha256 $recordPlan.plan_sha256 | ConvertFrom-Json
$nativeCaptureRecordSha = $recordRead.capture_record_sha256
```

Use a new output file in the existing private local journal directory. The
reported SHA-256 is the digest of the exact record file written for transfer.

`experiments/server/native_retention_upload_command.py` plans or submits one
create-only upload from the selected source VM. It accepts the backup-store
selection receipt, a capture record and its independently trusted digest, and
the reviewed tooling bundle with its commit and digest. The offline plan pins
the selected source and exact guest program. Apply writes a local intent, starts
one guest offer, and uses the cached ARM operator's existing rights to request
one exact-blob create capability. The bounded Run Command receives only the
sealed capability packet. The private systemd upload can outlive the command.

```powershell
$uploadInputs = @(
    '--selection', $selectionReceipt, '--capture-record', $nativeCaptureRecord,
    '--capture-record-sha256', $nativeCaptureRecordSha, '--tooling', $toolingBundle,
    '--commit', $reviewedCommit, '--tooling-sha256', $toolingSha
)
$uploadPlan = python ./experiments/server/native_retention_upload_command.py plan @uploadInputs |
    ConvertFrom-Json
python ./experiments/server/native_retention_upload_command.py apply @uploadInputs `
    --journal-root $journalRoot --plan-sha256 $uploadPlan.plan_sha256
```

After submission, use `observe` with the same arguments to check the saved
attempt, including after a lost reply. Wait for `uploaded-unverified` before
interpreting source-side terminal success. For an unknown upload result, preserve
the journal and use independent verification of the exact object with the
original expected SHA. The observation command never requests a SAS or resubmits
an upload.

If `observe` reports `offered` and the operator retained the original
`offer.json` receipt, wait for the guest offer to expire and use a different
source boot. Pass `--replace-unsubmitted-offer-sha256` with the original
`offer_sha256` to a fresh `plan` and `apply` using the same journal root and
capture record. Pass the new plan digest to `apply`. The guest rechecks the
capture and archives the original offer before issuing a new one. Any sign of
submission stops this path. A stopped replacement has its own journal for
`observe`, which takes the same replacement argument and plan digest.

`experiments/server/native_retention_verifier.py` connects the cached ARM
issuer to the native ciphertext download on one independently selected VM.
Its short-lived offer binds the exact blob, capture record, verifier instance
and current boot. The operator journals the request before requesting a
read-only SAS and returns only an encrypted packet. The verifier checks the
packet and signed permission, saves its exclusive submission marker, and
removes the ephemeral recipient key before requesting the blob.

After a lost reply, observation can read the existing byte-verification
receipt without issuing a second GET. The ciphertext is retained privately as
`download/backup.sealed` under the verifier operation directory. Sealed
authentication requires the separate, original capture recipient.

`experiments/server/native_retention_verify_command.py` uses the existing
Run Command channel to verify one capture on the selected verifier. It
accepts the backup-store selection receipt, the independently pinned native
capture record and the reviewed tooling bundle. The plan contacts no Azure
services.

```powershell
$verifyInputs = @(
    '--selection', $selectionReceipt, '--capture-record', $nativeCaptureRecord,
    '--capture-record-sha256', $nativeCaptureRecordSha, '--tooling', $toolingBundle,
    '--commit', $reviewedCommit, '--tooling-sha256', $toolingSha
)
$verifyPlan = python ./experiments/server/native_retention_verify_command.py plan @verifyInputs |
    ConvertFrom-Json
python ./experiments/server/native_retention_verify_command.py apply @verifyInputs `
    --journal-root $journalRoot --plan-sha256 $verifyPlan.plan_sha256
```

Use `observe` with the same arguments to inspect a lost reply. The report
gives the verified ciphertext path on the verifier for the compatibility
recovery command. The operator receives neither backup contents nor a
private key.

### Azure pilot upload and independent readback, 2026-11-25

In the first live upload attempt, the source offered the pinned native
ciphertext and Azure successfully issued the exact create-only SAS. The
issuer rejected the returned timestamps before delivering the capability
to the source. A separate provider probe confirmed Azure appends seven
fractional zeros to each requested whole-second UTC instant. The client
now accepts that representation while comparing the exact requested
instants and retaining the signed query bytes for transport. The source
observed the original upload attempt in the offered state and was
deallocated. The attempt was preserved and the verifier remained off.

The next attempt used the expired-offer recovery from
[#156](https://github.com/nathanmcnulty/azd-santa/pull/156) against the
[same native capture](private-native-capture-qualification.md#fresh-capture-and-actual-terminal-observation).
The source issued a fresh offer on a different boot, preserved the original
attempt, and reported `uploaded-unverified` after a create-only upload.
The source was deallocated before the independent verifier booted. Using a
read-only SAS, the verifier downloaded all 80,159,434 bytes and recomputed
SHA-256 `1f66f3f3907f8acdd42538a493ba84b0a27d76ac3b87014bad94945008199d01`,
matching the original source capture. The verifier was then deallocated.

| Retained evidence | SHA-256 |
| --- | --- |
| Source terminal upload observation | `57f1ed1aac6e61e12b144d750a4c1e545503c2e53d2f5f87a10d44e843b7d487` |
| Independent Azure readback receipt | `ecb1ebead8bd53a808fed1cdde6a192f296959c1ccc61d57a0589cf8c649ce8a` |

This qualifies off-host byte retention for the selected Azure pilot capture.
On the original Windows workstation, the CurrentUser DPAPI-protected recipient
key was recovered in memory and its public key fingerprint matched the native
capture receipt. The check establishes access from that Windows user profile.

### Authentication of the retained pilot archive

The original Windows key unwrapped the content key for the selected archive.
The Windows process encrypted that content key to a short-lived key from the
independent verifier. The handoff bound the archive digest and header to the
verifier's Azure VM instance and boot. The original recipient key stayed on
Windows, and the verifier kept the handoff key in memory-backed storage and
removed it before processing the archive.

The verifier reread all 80,159,434 bytes from its retained Blob download and
verified both the AES-GCM tag and the SHA-256 pinned above. It discarded
decrypted bytes in memory. The authentication receipt SHA-256 is
`3ea210b67bf3415bc668f2ec3c5e368916da99a31849dc6e2739b60e7a676c1c`.
The storage firewall kept its existing deny-by-default rules. Azure confirmed
deallocation of the existing verifier at the end of the run. Durable key
custody, independent image retention, durable quarantine, application restore,
and current authority remain open for this capture. The strict parser and
writer also passed [volatile extraction of the retained pilot archive](authenticated-archive-quarantine.md#extraction-of-the-retained-pilot-archive).

### Exact image retention

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

When an operation ID is supplied, the exporter records part hashes as it writes
ciphertext and commits the part manifest before publishing completion. It
does not reread the ciphertext to produce the manifest or create separate part
files. The uploader still independently checks the selected ciphertext before
its first write to Blob.

`retained_image_export_job.py` reserves the operation on the selected guest
after checking its Azure VM identity. It gives the operator a completion
record and bounded manifest pages with a shared SHA-256 pin. A failed export
preserves its reservation and cannot publish a complete receipt. The
encrypted image stays on the source VM for the upload workflow.

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

`experiments/server/retained_image_parts.py` plans ordered 512 MiB ciphertext
parts under `image-artifacts/<operation>/<index>.sealed-part`, with at most 33
parts per image. The plan binds the producer completion digest and the full
ciphertext length and SHA-256. Per-part lengths and SHA-256 support independent
readback, while per-part MD5 is available for transport integrity. Generation
reads at most 1 MiB at a time and creates no local part files. A receiver checks
the independently retained manifest and producer completion digests, streams
the validated object sequence to an exclusive new file, and verifies the full
length and SHA-256 before reporting success. An interrupted or invalid attempt
preserves partial output for inspection. Open each part through an exact-object
reader and apply an outer I/O deadline. The multipart image protocol does not
change native capture or its 2 GiB cap.

`experiments/server/retained_image_blob.py` provides the default-off HTTPS
transport. It accepts the pinned plan, independently selected store and VM
facts, and already issued exact-object SAS tokens through a trusted private
caller. Upload uses only create permissions, binds each request to one planned
part, and sends `If-None-Match: *`. It records intent before the first request,
stops on an ambiguous result, and refuses to replay an existing operation on
the same journal root. A separate VM instance with read-only tokens can verify
the exact parts and reconstruct the ciphertext in a fresh journal. Neither
role receives listing, overwrite, deletion, ARM or recipient-key credentials.
The transport checks signed permission and expiry fields, while binding the
token to the exact object depends on trusted issuance. The operator-side
`retained_image_sas.py` module can issue that batch explicitly using cached ARM
authority. A default plan sends no requests. Apply reserves a private journal,
checks current store and VM facts, and invokes `listServiceSas` once per exact
part for one role. The selected source receives create-only scope and a separate
verifier receives read-only scope. The private in-process batch can only be
taken once for the pinned manifest and target. The journal records no tokens.
Keep the persistent root and resolve unknown outcomes by readback.

`retained_image_handoff.py` creates a short-lived recipient offer on the selected
Linux VM. It encrypts one packet per blob and binds each packet to the shared
manifest, exact object, account, target VM instance, current boot and transfer
role. The guest consumes the offer once, unlinks the ephemeral private-key file,
and checks the entire packet set before calling the transfer code. Use the
trusted operator channel to obtain the offer and deliver the packets. Recipient
encryption protects the SAS in transit and relies on that channel for sender
authorization. The handoff has no ARM token or storage account key.

`retained_image_delivery.py` defines the bounded request/reply protocol for
that channel. The operator reserves the operation before the first request.
The operator groups consecutive encrypted packets in each request using
the serialized size. Each request is capped at 14 KiB before outer command
framing. The guest validates the complete group before staging any member,
then checks the full batch before starting a transfer. A 33-part fixture
with 1,600-byte packets needs six packet requests plus begin and finish.
Plan sends nothing. An uncertain reply stops the operator, who can observe
staged packet indexes or the saved transfer result without replay.

`retained_image_run_command.py` adapts that callback to Linux Azure Action
Run Command. Each frame checks the cached tenant and subscription and reads
back the selected VM resource ID, instance ID and region before submission.
The guest loads a digest-pinned, root-owned runner from the selected operation
and role directory. The adapter returns only a structured reply followed by
the current request's completion marker. It caps the JSON at 3 KiB to fit
within [Action Run Command's 4 KiB output limit][action-run-command].

`retained_image_runner.py` builds the selected guest package from the exact
reviewed recovery-tooling bundle. It binds the guest manifest, completion,
VM identities and transfer role into a private archive. Its Linux installer
validates guest identity, reserves a fresh operation directory and writes
the pinned entry point last. The operator can request the same boot-bound
public offer again after losing its reply. The runner uses the saved offer
and immutable selection for all subsequent frames.

The operator's Run Command adapter can provision the package in one request
before acquiring the short-lived offer or capabilities. It compresses the
complete archive with XZ and checks the full script against the adapter's
64 KiB bound. The Linux bootstrap limits the decoder memory and output
size and verifies the archive SHA-256 before importing the reviewed source.
The operator records the attempt before submission. Use the read-only
runner observation after a missing or inconclusive reply. The observation
requires the same VM and archive pins and leaves the offer and transfer
journals untouched.

CI exercises the full script size with a 33-part manifest. Maximum-size
transfer timing, actual Azure request limits and off-host journal retention
still require qualification.

### Run a selected image transfer

On the independent Linux recovery host, use the retained native ciphertext
and its independently obtained SHA-256 to recover the compatibility record.
Keep the recipient's private DER key and output in an owner-private
directory on that host.

```bash
python3 ./experiments/server/retained_image_compatibility.py \
  --ciphertext "$ciphertext" --ciphertext-sha256 "$ciphertextSha" \
  --recipient-key "$recipientPrivateDer" --output "$authenticatedCompatibility"
```

The command reads and authenticates the complete seal before parsing the
bounded first archive member. It writes only the verified
`compatibility.json` and prints its SHA-256 for the next command. Full
archive validation and application restore remain separate checks.

To collect a fresh source inventory, use
`experiments/server/retained_image_inventory_command.py`. It verifies the
independently authenticated `compatibility.json` and requires its source VM
instance to match the backup-store selection. It takes the dependency lock
from the reviewed tooling bundle. The plan shows the five expected IDs and
contacts no Azure services. During explicit readback, the selected guest uses
[`docker image inspect`][docker-image-inspect] for those exact IDs and
returns only the confirmed inventory. Container configuration and daemon
diagnostics stay on the guest.

```powershell
$inventoryInputs = @(
    '--selection', $selectionReceipt, '--operation', $operationId,
    '--compatibility', $authenticatedCompatibility,
    '--compatibility-sha256', $compatibilitySha, '--tooling', $toolingBundle,
    '--commit', $reviewedCommit, '--tooling-sha256', $toolingSha
)
$inventoryPlan = python ./experiments/server/retained_image_inventory_command.py plan @inventoryInputs |
    ConvertFrom-Json
$inventory = python ./experiments/server/retained_image_inventory_command.py read @inventoryInputs `
    --plan-sha256 $inventoryPlan.plan_sha256 --output $imageInventory | ConvertFrom-Json
$inventorySha = $inventory.inventory_sha256
```

For a fresh export, use `experiments/server/retained_image_export_command.py`.
It accepts the same backup-store selection and reviewed tooling bundle as the
transfer command, plus the reviewed image inventory and recovery recipient's
DER public key. The plan prints the exact source VM, image ID, maximum
archive size, and plan digest. It contacts Azure only during explicit apply
or readback. The selected archive and deadline limits must fit the lab's
disk and runtime budget.

```powershell
$exportInputs = @(
    '--selection', $selectionReceipt, '--operation', $operationId,
    '--inventory', $imageInventory, '--inventory-sha256', $inventorySha,
    '--image', 'core', '--recipient', $recipientPublicDer,
    '--recipient-sha256', $recipientSha, '--tooling', $toolingBundle,
    '--commit', $reviewedCommit, '--tooling-sha256', $toolingSha
)
$exportPlan = python ./experiments/server/retained_image_export_command.py plan @exportInputs |
    ConvertFrom-Json
python ./experiments/server/retained_image_export_command.py apply @exportInputs `
    --journal-root $journalRoot --plan-sha256 $exportPlan.plan_sha256
python ./experiments/server/retained_image_export_command.py collect @exportInputs `
    --journal-root $journalRoot --plan-sha256 $exportPlan.plan_sha256
```

The journal reserves export before submission. When its reply is lost, use
`observe` with the same inputs to inspect the guest without resubmitting.
`collect` checks every manifest page before publishing the local
`complete.json`, `parts.json`, and `export.json` files together. Its report
supplies `metadata_directory`, `export_directory` on the source VM, and both
hashes for the transfer below. This path is qualified against a synthetic
Azure response in CI. Live guest export and receipt delivery remain open.

`experiments/server/retained_image_operator.py` accepts the JSON output of
`Get-SantaBackupStoreSelection -ReadArm`, the pinned export completion and
part manifest, and the reviewed recovery-tooling bundle. Save the selection
producer's output with `ConvertTo-Json -Depth 12`. The receipt names the
owned store and the source and verifier VM instances. The operator refreshes
ARM facts before issuing the selected Blob capabilities.

Use `plan` first. This reads the local inputs and prints the intended target,
object count, script size and `plan_sha256` without calling Azure. The
following example reuses paths and hashes from an existing recovery
operation. Create the private journal directory once and retain it across
invocations.

```powershell
$inputs = @(
    '--role', 'upload', '--selection', $selectionReceipt,
    '--operation', $operationId, '--export-directory', $sourceExportDirectory,
    '--manifest', $partManifest, '--manifest-sha256', $manifestSha,
    '--completion', $exportCompletion, '--completion-sha256', $completionSha,
    '--tooling', $toolingBundle, '--commit', $reviewedCommit,
    '--tooling-sha256', $toolingSha
)
$plan = python ./experiments/server/retained_image_operator.py plan @inputs | ConvertFrom-Json
$plan
```

After reviewing the plan, run the same command with `apply` in place of
`plan`, adding `--journal-root $journalRoot --plan-sha256 $plan.plan_sha256`.
The command installs the runner, obtains the public offer, issues and seals
the exact-object capabilities in memory, and transfers the parts. A reported
upload outcome of `unknown` returns exit code 2. Use `observe` with the same
inputs and journal to inspect an interrupted run without resubmitting it.

Run an independent `verify` plan and apply with the same pinned image
inputs and the selected verifier. Omit `--export-directory` for this role.
The verifier reassembles and hashes the ciphertext. Authentication,
immutable image import and application restore remain separate operations.

While the original recipient DER key is still available, export a portable
encrypted copy on Linux. Use the recipient public-key fingerprint from the
original capture or export receipt. Use a fresh absolute output path under an
owner-private directory.

```bash
python3 ./experiments/server/restore_recipient_key.py \
  --recipient-key "$recipientPrivateDer" --recipient-sha256 "$recipientSha" \
  --output "$encryptedRecipientDer"
```

OpenSSL encrypts the PKCS#8 file. Enter the passphrase twice at the terminal.
Keep the passphrase in a recovery credential store. Store the encrypted key
and its reported `encrypted_key_sha256` through separate trusted channels.
The verify and load commands check that file digest before prompting, unlock
the key in memory and match it to the original capture. Use the same
`--recipient-key` and `--encrypted-key-sha256` options with
`retained_image_compatibility.py` to recover the native backup metadata.
Existing plaintext DER inputs omit `--encrypted-key-sha256`.

For a Windows pilot key protected with CurrentUser DPAPI, run the Windows
exporter under the original account. Use the original DPAPI purpose string and
the public-key fingerprint from the capture receipt. The exporter prompts for
a passphrase and returns the same encrypted-key digest used by the Linux
verification and load commands. The original and the exported file remain
encrypted on disk.

```powershell
./experiments/server/Export-SantaRecoveryRecipient.ps1 `
    -ProtectedKeyPath $originalDpapiKey -ProtectionPurpose $originalPurpose `
    -RecipientSha256 $recipientSha -OutputPath $encryptedRecipientDer
```

On the isolated Linux recovery host, `retained_image_load.py verify`
authenticates the image without contacting Docker. Use the same inputs
with `load` and add `--docker-socket` for the explicit local recovery daemon
and `--attempt` for a fresh directory under an owner-private parent.

```bash
python3 ./experiments/server/retained_image_load.py verify \
  --ciphertext "$imageCiphertext" --completion "$exportCompletion" \
  --completion-sha256 "$completionSha" --recipient-key "$encryptedRecipientDer" \
  --encrypted-key-sha256 "$encryptedKeySha" \
  --inventory-sha256 "$inventorySha" --image core --image-id "$expectedImageId" \
  --staging "$privateStaging"
```

The load checks for containers on that daemon, records an exclusive intent,
and passes only the verified anonymous archive to
[`docker image load --platform linux/amd64`](https://docs.docker.com/reference/cli/docker/image/load/).
It compares the resulting immutable image ID and platform and checks again
that the daemon has no containers. Keep the attempt after a timeout or
unverified reply. Docker may have received the archive, so inspect the same
isolated daemon before taking further action. The command never starts a
container or accepts application restore. Configure the daemon for isolated
recovery and apply a host-level deadline and disk limit to the Docker process
and its data directory.

Recovery tooling bundle v21 includes `retained_image_key_handoff.py` for
an operator workstation that already holds the original backup private key.
The selected recovery guest checks the entire independently downloaded
ciphertext hash before creating a boot-bound offer. The operator validates
the exact offer and completion pins, unwraps the archive's data key locally,
and seals that single key to the guest's temporary recipient. The original
private key stays on the workstation. Keep offers in an owner-private
boot-local directory and preserve the separate durable load attempt if its
result is unknown. The loader still verifies GCM, the archive digest and
the exact image ID before confirming import. The guest transport and
Azure load of the retained Zentral image remain live qualification gates.

[action-run-command]: https://learn.microsoft.com/en-us/azure/virtual-machines/linux/run-command
[docker-image-inspect]: https://docs.docker.com/reference/cli/docker/image/inspect/

The Ubuntu test exports a disposable `linux/amd64` image, reassembles a
ciphertext copy from a synthetic object store, and unlocks an encrypted
recipient key to load the verified descriptor. It reads back the same image
ID without starting a container.

Retain an independently reviewed recovery toolset with
`experiments/server/restore_tooling_bundle.py`. Its `build` command accepts a
trusted local repository, the full reviewed commit ID, and a fresh destination
file. It reads exact Git blobs for a fixed inventory covering image readback,
native archive quarantine, restore census, offline rewrap, and their local
dependencies, locks, documentation, and license notices. Git working-tree
configuration, untracked files, and other committed paths are outside that
inventory. Retain the emitted commit and bundle SHA-256 through a trusted
channel alongside the recovery inventory.

Use `build --version 2` to include the Windows recipient exporter, restore
authority planner and transaction adapter, and their reviewed design.
Use `build --version 3` to include the database secret rewrap transaction and
its documentation. Verification and staging accept each version's exact
inventory. Historical bundles retain their original commit and digest pins.

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

Portable custody of the original recipient key, trustworthy receipts,
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
