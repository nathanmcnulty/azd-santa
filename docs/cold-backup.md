# Native-snapshot encrypted capture component

Issue #54 remains open. `experiments/server/cold_backup.py` implements the first
offline-tested capture mechanism for the selected initialized private VM stack.
It has not captured a live stack, restored one, or established current authority.
The earlier frozen `656f851`/`698ec2a` raw Elasticsearch directory capture is
experimental byte preservation, **not** a supported Elasticsearch backup. Elastic
explicitly says filesystem copies are unsupported even with nodes stopped;
[native snapshots are required](https://www.elastic.co/docs/deploy-manage/tools/snapshot-and-restore#other-backup-methods).
The revised capture contract requires a completed native repository, excludes
raw Elasticsearch data and rejects the legacy selection scope. The current
five-volume layout cannot satisfy this contract. The offline candidate now
integrates the sixth volume, original generation and controller maintenance; no
real application-data capture should use the earlier raw-directory candidate.
The separately reviewed graceful-worker overlay is composed into the core build
and its source/current-instance/child-join proof gate is integrated offline.
Exit zero alone cannot bypass it. Maintenance tests execute the real strict proof
parser against mocked Docker/source/process observations; actual Linux/Kombu,
native snapshot and application capture remain unqualified.
It adds no service, Azure resource, grant, hook, automatic scheduling or cleanup.

This is a developer qualification component, not the final administrator flow.
The existing controller machine-produces selected bindings and owns the entire
stop/drain/snapshot/capture sequence. Its explicit completion-gated resume action
starts the original runtime; no administrator container commands are required.
Future customer/azd integration must package/check cryptography
automatically; asking administrators to install Python packages is not the
intended workflow. This developer host command is not an azd hook, public ingress
workflow, scheduler or supported restore. Original containers, volumes and failed
evidence are retained. One reserved backup request per generation is supported;
replacement/retention of completed requests and recurring backups remain open.

The qualification entry points are `runtime_service.py backup` with its normal
`--manifest`/`--sha256`, selected `--vm-id`/`--vm-instance-id`,
`--recipient-public-der` and absent `--destination`; `--maximum-bytes`,
`--maximum-files` and `--seconds` select bounded resource limits. The caller must
supply target facts from its already authorized machine selection, not fabricated
JSON. The producer verifies IMDS, the source-bound active unit/MainPID command,
all original containers, generation and known queue inventory, reserves the
private request exclusively and calls normal `systemctl stop` once. On timeout
observe existing evidence; do not repeat it. After independently inspecting the
complete result, `runtime_service.py backup-resume --manifest ... --sha256 ...`
verifies ciphertext hash/length, request/generation/stop receipts and the inactive
successful unit under the existing lock, releases that lock and starts the unit
once. An existing resume authorization prevents another submission. This is
resume of preserved originals, never restoration of archive contents.

## Selection and coldness

The explicit `capture` inputs are a private machine-produced selection file and
its independently trusted SHA-256, a canonical DER RSA-3072 public recipient key,
and an absent absolute destination under root-controlled, non-writable parents.
No private recipient key is sent to the guest. The producer must retain that key
independently and verify its public fingerprint. Losing it loses the backup.
Do not construct the selection JSON by hand or treat its scope/hash as an
attestation of its origin.

The strict `azd-santa-native-cold-backup-selection-v1` contract contains:

- `target`: selected `VmId` and immutable `VmInstanceId`.
- `runtime_manifest`: the exact existing manifest path and SHA-256.
- `controller_sha256` and `backup_program_sha256`: exact reviewed source hashes.
- `recipient_sha256`: the SHA-256 of the canonical public DER.
- `generation_sha256`: the existing controller/admission
  `container-generation.json` checksum. There is no second generation store.
- `maintenance_sha256`: the controller-owned explicit request checksum, binding
  the selected VM/boot/generation, source, recipient and destination. It is the
  native snapshot's metadata binding; a previous snapshot from the same
  generation is not interchangeable with this request.
- `native_snapshot`: the private completed native receipt path/SHA-256 and exact
  `native_snapshot.py` program checksum.
- `containers`: exactly seven original full Docker IDs keyed by `db`, `redis`,
  `rabbitmq`, `elastic`, `web`, `workers` and `celery`.

The tool runs as root under isolated Linux Python. It compares the selected VM
against read-only IMDS with redirects/proxies disabled; it requests no token and
makes no ARM/auth call. IMDS does not prove tenant identity or caller authority;
the trusted external producer must select and verify the deployment first.
Boot ID is recorded and rechecked. The controller and existing manifest/helper,
Compose, environment, image/source, command, privilege, network and mount checks
are reused. Existing controller source is pinned explicitly; a source upgrade
requires a deliberate new reviewed backup compatibility binding.

Capture holds the existing exclusive supervisor lock. Standalone capture requires
the exact bound unit inactive/dead with no pending job and seven previously
started containers exited zero. The controller-owned maintenance path instead
requires that same supervisor process/MainPID, held lock descriptor, original
generation and deactivating stop job. Only after its bound drain/native-success/
stop evidence exists can an unserialized process-local capability accept 143 for
the exact Elasticsearch container, whose raw data is excluded. Workers and all
other containers must exit zero;
all need PID zero and no OOM/error/pause/restart. No CLI/JSON exit-code bypass is
provided. Each local Docker
volume's name/project/driver/path is checked, initialized store sentinels are
required, and PostgreSQL must have no remaining `postmaster.pid`. This is a
dedicated-host contract: every foreign running, paused or restarting container
is rejected regardless of its mount paths, so symlink/bind aliases cannot hide
a concurrent container writer. Stopped foreign containers with known lexical
mount overlap are also rejected; this is not a general alias graph or permission
to start other containers during maintenance.
The previously observed 143 exits are TERM termination, not a general clean-stop
guarantee. Worker 143 is always rejected. Queue samples are insufficient to prove
that multiprocessing children joined and closed consumers. The private
`_worker_join_proof` gate verifies the separately reviewed worker lifecycle
module and command hashes against the source-bound runtime manifest. The request
producer checks installed bytes, the actual in-container parent command, original
CID/StartedAt and the single current startup nonce before mutation. Maintenance
rechecks that same instance before stopping, then requires its matching clean
marker with every current child joined, exited zero and acknowledging cleanup.
The parent PID is in the container namespace, not Docker's host State.Pid. There is
no CLI/JSON override. Only Elasticsearch's specific native-success stop phase is
eligible for 143; actual integrated behavior remains unqualified.

Bounded `/proc/self/mountinfo` readback binds each selected source tree/file to
its actual covering mount ID, device, filesystem root/source/options and source
inode. Only whole local ext4/XFS filesystems with a `/dev/` source and mountinfo
root `/` are supported. Mountpoints at or below any selected capture root are
rejected, including same-filesystem bind mounts. Overlay/network/tmpfs/subvolume
layouts and bind-mounted filesystem subtrees are unsupported and fail closed.
Directory traversal uses opened directory descriptors. Each opened directory
and regular file must retain the selected device and `/proc/self/fdinfo` mount
ID, preventing a nested mount from being followed silently. The complete original
volume path map and selected mount/inode identities are rechecked before writing
the GCM tag. These are actual-host qualification gates, not mocked mount proof.

The maintenance window must exclude concurrent privileged host/Docker writers.
The lock fences the existing cooperating supervisor; it cannot prevent a root
operator from bypassing it or booting an enabled unit later. Files are checked
against descriptor metadata before/after streaming; directory metadata and final
container state/timestamps, configuration bytes, unit and VM/boot bindings are
rechecked. This is not a general-purpose snapshot/fencing service.

## Contents and encryption

One streaming PAX tar captures PostgreSQL's entire selected volume (including
WAL), Redis's entire AOF directory/volume, RabbitMQ's cookie and node database,
shared media, and the entire completed native snapshot repository for this
operation from the dedicated sixth `elasticsearch_snapshots` volume. Raw
`elasticsearch_data` remains identity-checked but is never a restorable archive
root. Native receipt UUID/global metadata/index-generation files are required;
those sentinels alone do not prove a completed snapshot. Required bound
Compose/configuration/environment files, job-only `migration.env`, selection,
runtime manifest/unit/controller/helpers and this backup source are included.
Only the selected single `conf/base.json` layout is accepted. Required env files
remain private. File modes, UID/GID and modification times are preserved.
Symlinks, hard-linked regular files, devices, FIFOs and sockets are rejected;
external PostgreSQL tablespaces and other unsupported layouts fail closed.

The encrypted compatibility manifest records VM/boot, original container IDs,
immutable image references and resolved IDs, PostgreSQL major, broker node name,
volume paths, control-file map/hashes and source revision. This physical capture
is compatible only with a separately qualified matching runtime. Image layers
are not exported: exact images and source/build provenance must remain available
independently. No upgrade, cross-version or existing-volume merge is supported.

The tool generates a fresh AES-256 key and 96-bit GCM nonce for each attempt. RSA
OAEP with SHA-256/MGF1-SHA-256 wraps the key with label `AZDSANTABACKUP1\n`.
`backup.sealed` contains that magic, a four-byte big-endian header length, a
bounded canonical JSON header (algorithm, recipient fingerprint, base64 wrapped
key/nonce), streamed ciphertext, then the 16-byte GCM tag. Magic/length/header
are authenticated as AAD. Paths, credentials, store contents and compatibility
metadata are inside the ciphertext. There is no plaintext archive or secret
diagnostic output. Cryptographic keys exist in process memory; secure memory
erasure is not claimed.

Only after final cold readback and encryption finalization does the tool fsync
the ciphertext and exclusively write/fsync private `complete.json`, containing
ciphertext hash/length, recipient fingerprint and explicit unimplemented restore
and current-authority states. Partial files remain on any failure; an existing
destination is never overwritten, resumed or deleted. Unknown completion requires
inspection, not automatic replay. The receipt is local evidence, not sender
authentication, an external trust anchor or a restore authorization.

No compression is used. Tar writes are immediately encrypted in bounded chunks;
Backup Docker output is capped at 4 MiB per call. Ordinary metadata calls are
bounded to 30 seconds; stop and native-helper calls have explicit longer bounds
within the single maintenance deadline. Defaults are
8 GiB ciphertext, 100,000 entries and 30 minutes, with explicit hard ceilings of
32 GiB, 1,000,000 entries and two hours. Limits include archive overhead and cause
failure rather than omission. A Linux alarm covers the complete capture window;
filesystem reads/writes still depend on the selected local filesystem/host. A
conservative free-space preflight reserves each selected filesystem's maximum
snapshot/ciphertext allowance plus 128 MiB (twice the maximum when sharing a
device). The native helper rejects observed primary-store bytes plus 64 MiB
metadata allowance above its byte budget; native snapshot rate is capped at
20 MiB/s. These checks are not a filesystem quota or a proof of worst-case disk
amplification. Actual selected-host disk/resource behavior remains a gate; an
operator may choose a smaller explicit pilot bound rather than omit data. A
same-host backup is not independent disaster protection: copying ciphertext and
its trusted receipt to independently retained storage remains an integration gate.

## Qualification and remaining gates

`native_snapshot.py` supplies offline-tested protocol/drain primitives and a
bounded private-network client. It runs once in the existing pinned application
image as an owned read-only/cap-drop helper with only its private checkpoint bind
and read-only hash-checked helper source. It receives no runtime/migration env,
Docker socket or datastore volume and imports no Django/SQL code. HTTP JSON is
capped at 1 MiB with five-second calls, redirects/proxies disabled and a 600-second
native deadline. ES version/cluster UUID and full open-index/primary-shard
inventory are checked. The helper is
not an endpoint selector, generation attestor, standalone daemon or grant.
Its sequence runs in the existing supervisor under its existing
lock and original generation, triggered by an explicit reserved backup request
followed by normal `systemctl stop`:

1. Close new admission and stop the exact original web/Celery publishers.
2. Observe the complete known queue inventory with ready and unacknowledged
   counts both zero in two bounded samples, rechecking publisher termination.
   The known inventory includes preprocessing/Celery queues, not merely the
   three event-consumer readiness queues. The producer records the entire queue
   inventory before mutation. Known empty non-durable auto-delete control queues
   must disappear after publishers close; all durable queues remain. Unknown,
   missing durable or corrupt queues fail. No synthetic zero rows are substituted.
3. Stop the exact original worker processes, require exit zero and final empty
   known queues, then require source/current-instance-bound child-join proof.
   The proof gate blocks native submission on missing/mismatched/current-instance
   proof; never infer drain from exit 143 or queue samples alone.
4. Register one reserved native filesystem repository/name under fixed
   `/mnt/azd-santa-snapshots/<operation-id>`, then submit one native snapshot.
5. Observe native SUCCESS, exact snapshot UUID/plan metadata, full open-index
   inventory, global state, all primary shards successful and zero failures.
6. Stop the dependencies, prove the machine-bound stop outcome, then capture
   the completed repository and four ordinary data volumes with all writers gone.

The native API contract is pinned to Elasticsearch source
`4ad0ef0e98a2e72fafbd79a19fa5cae2f026117d` (9.2.1), independently of a live
result. GET `/` must still report exactly 9.2.1. Snapshot GET responses instead
serialize an index-format identity: `version_id: 9039001` and
`version: "9.2.0-9.2.1"`. The exact range follows
[SnapshotInfo's serializer](https://github.com/elastic/elasticsearch/blob/4ad0ef0e98a2e72fafbd79a19fa5cae2f026117d/server/src/main/java/org/elasticsearch/snapshots/SnapshotInfo.java#L545),
[the prior index-version mapping](https://github.com/elastic/elasticsearch/blob/4ad0ef0e98a2e72fafbd79a19fa5cae2f026117d/server/src/main/resources/org/elasticsearch/index/IndexVersions.csv#L186)
and [ReleaseVersions' current-release/range construction](https://github.com/elastic/elasticsearch/blob/4ad0ef0e98a2e72fafbd79a19fa5cae2f026117d/server/src/main/java/org/elasticsearch/ReleaseVersions.java#L50).
The snapshot request uses `indices: "*"`, `expand_wildcards: "all"` and
`include_global_state: true`, with no feature-state exclusions. This preserves
regular/hidden indices, streams and all feature/system state while avoiding
[the pinned server's rejection of explicit system-index names](https://github.com/elastic/elasticsearch/blob/4ad0ef0e98a2e72fafbd79a19fa5cae2f026117d/server/src/main/java/org/elasticsearch/snapshots/SnapshotsService.java#L2994).
The plan still records every observed concrete index and primary shard; missing,
extra or partial results fail rather than silently narrowing the backup.
Source-derived synthetic full-response fixtures include a GeoIP system index
and feature state. They are compatibility tests, not actual snapshot evidence.

Each repository/snapshot PUT has an exclusive fsynced intent before submission.
An ambiguous outcome may only GET the same reserved repository/snapshot; a 404
does not authorize another PUT/name. Unknown/failure retains state. Read-only
observation can continue; `submit` cannot be replayed over an existing plan.
Pending/unknown maintenance must block automatic startup/replay. Successful
completion may be followed by an explicit completion-gated resume wrapper;
normal stop without a request retains its existing behavior. Failed maintenance
still performs only the already authorized original-container cleanup. Startup
checks pending maintenance before selection/cleanup authorization, preserving
the admission fix that forbids stopping unbound inspected containers. The unit
stop timeout is 3,600 seconds; the request deadline is capped at 3,300 seconds.

The fresh-only private generator gives Elasticsearch one private sixth local
volume and fixed `path.repo`. Staging pulls/creates dependencies before starting
them, verifies the pinned image user `1000:0` and the exact empty local volume,
then initializes its ownership/mode to `1000:0`/0700. It does not repair nonempty
volumes. Exact mounts/path.repo propagate to runtime and host attestation; legacy
five-volume manifests are rejected. This adds no paid service. The existing
stopped VM lacks `path.repo`; it must not be reset or silently retrofitted.
Actual qualification needs a later fresh integrated namespace.

The backup helpers and `worker_lifecycle.py` are part of the controller's existing
source-hash inventory. Its machine-produced `worker_hashes` pins the exact installed
module and derived command, verified during staging and normal startup as well as
backup preflight. The unchanged `runworkers` Compose command uses that built overlay;
no privileged runtime env or listener is added. Worker stdout logs are read only
from the exact original CID with `--since StartedAt` and Docker timestamps, under
the bounded output cap. Missing/duplicate/old-nonce markers fail closed; long log
histories exceeding the cap also fail rather than silently dropping proof.

Packaging/upload callers must supply these files alongside the reviewed admission
helper and invoke `admission-bind-fresh` before unit installation. Fixed-source
installer inventories and any legacy uploader need corresponding integration
before they can deploy this layout. No source-only result qualifies a cold azd
installation. Full current-authority restore remains open.

The existing Ubuntu host was separately observed by the coordinator to have
Python 3.12.3 and distro `python3-cryptography 41.0.7-4ubuntu0.4`; no installation
was needed for that observation. The required streaming Cipher/AES-GCM and RSA
OAEP APIs exist in that API generation. The tool probes canonical RSA input and
the actual AES-GCM backend before Docker reads/output. Local offline tests use
an existing isolated cryptography 50 interpreter; execution of the revised
native-contract tests with the host's distro supplier remains a separate gate.
The coordinator did execute the earlier frozen `698ec2a` synthetic suite on that
Ubuntu host: 15 passed, zero skips/failures/errors. Its module SHA was
`b09c429552892817c19a2967e2ecedc9257ba006d6c320d6edd437eed6ec9dfa` and test SHA was
`17afe6161a80960e6266088e200327bc0565af28c0b68a924b763374934e7766`.
Those tests exercised real temporary-file crypto/FD paths; Docker/IMDS/cold-state
cases remained mocked, and the receipt explicitly recorded
`actual_application_backup=false`. That does not qualify the revised source or
any actual application backup. Neither a
version string nor API compatibility establishes security/support currentness;
review the selected OS package supplier, security updates and packaging before
integrating it. No mandatory extra venv or wheel-management path is introduced.

Offline tests cover real encryption/decryption of all five synthetic store
trees and secret files, authenticated tamper/truncation rejection, wrong keys,
limits, unsupported files, selection drift, mocked IMDS/cold-state boundaries,
foreign-running-container aliases, synthetic authoritative mount-table cases,
same-device descriptor mount-ID changes and final volume/mount/inode changes,
retained incomplete output after failed final readback, full mocked maintenance
phase ordering, worker 143/missing-child-proof denial before snapshot submission,
unknown-job retention/no replay and corrupt-ciphertext resume denial. Native
client tests mock every HTTP call, including actual request body/read limits and
single-submission behavior. They do not prove
actual database consistency, crash durability, Docker/systemd/IMDS ownership,
live backup, host resource consumption or restore.

Before closing #54, independently qualify actual capture and isolated restore,
image availability/compatibility, secret handling and integrity, selected runtime
readiness/Santa state, and security continuity. Authenticate the complete GCM tag
and independently trusted ciphertext hash before admitting any restored data;
this component deliberately supplies no decrypt/extract/restore command.
Restoring old Redis together with PostgreSQL can resurrect old consumed MFA or
recovery claims. A copied Redis marker, successful decrypt, old snapshot or
reboot does **not** prove current authority. Full current-authority restore needs
a separately designed external continuity/rollback guard, quiescence and
fail-closed restore admission with actual replay/rollback fault qualification.
