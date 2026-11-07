# Cold encrypted capture component

Issue #54 remains open. `experiments/server/cold_backup.py` implements the first
offline-tested capture mechanism for the selected initialized private VM stack.
It has not captured a live stack, restored one, or established current authority.
It adds no service, Azure resource, grant, hook, automatic scheduling or cleanup.

This is a developer qualification component, not the final administrator flow.
Future reviewed orchestration must machine-produce the selected bindings, stop
the runtime cleanly, verify/capture it, and resume it safely without requiring an
administrator to issue container commands. It must package/check cryptography
automatically; asking administrators to install Python packages is not the
intended workflow. No such producer or stop/capture/resume orchestration is
implemented here. Original containers, volumes and failed evidence are retained.

## Selection and coldness

The explicit `capture` inputs are a private machine-produced selection file and
its independently trusted SHA-256, a canonical DER RSA-3072 public recipient key,
and an absent absolute destination under root-controlled, non-writable parents.
No private recipient key is sent to the guest. The producer must retain that key
independently and verify its public fingerprint. Losing it loses the backup.
Do not construct the selection JSON by hand or treat its scope/hash as an
attestation of its origin.

The strict `azd-santa-cold-backup-selection-v1` contract contains:

- `target`: selected `VmId` and immutable `VmInstanceId`.
- `runtime_manifest`: the exact existing manifest path and SHA-256.
- `controller_sha256` and `backup_program_sha256`: exact reviewed source hashes.
- `recipient_sha256`: the SHA-256 of the canonical public DER.
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

Capture holds the existing exclusive supervisor lock. The exact bound systemd
unit must be loaded, inactive/dead with no pending job. All seven selected
containers must have previously started and exited with status zero, no OOM,
error, pause or restart. The tool never stops or starts them. Each local Docker
volume's name/project/driver/path is checked, initialized store sentinels are
required, and PostgreSQL must have no remaining `postmaster.pid`. This is a
dedicated-host contract: every foreign running, paused or restarting container
is rejected regardless of its mount paths, so symlink/bind aliases cannot hide
a concurrent container writer. Stopped foreign containers with known lexical
mount overlap are also rejected; this is not a general alias graph or permission
to start other containers during maintenance.
Actual clean-stop exit codes for the exact dependency images remain a live
compatibility gate; a nonzero code must not be relabeled clean without a
separately reviewed engine-specific proof.

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

One streaming PAX tar captures all five initialized volumes: PostgreSQL's entire
selected volume (including WAL), Redis's entire AOF directory/volume, RabbitMQ's
cookie and node database, Elasticsearch data, and shared media. Required bound
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
Docker command output is capped at 4 MiB per call and 30 seconds. Defaults are
8 GiB ciphertext, 100,000 entries and 30 minutes, with explicit hard ceilings of
32 GiB, 1,000,000 entries and two hours. Limits include archive overhead and cause
failure rather than omission. A Linux alarm covers the complete capture window;
filesystem reads/writes still depend on the selected local filesystem/host. A
same-host backup is not independent disaster protection: copying ciphertext and
its trusted receipt to independently retained storage remains an integration gate.

## Qualification and remaining gates

The existing Ubuntu host was separately observed by the coordinator to have
Python 3.12.3 and distro `python3-cryptography 41.0.7-4ubuntu0.4`; no installation
was needed for that observation. The required streaming Cipher/AES-GCM and RSA
OAEP APIs exist in that API generation. The tool probes canonical RSA input and
the actual AES-GCM backend before Docker reads/output. Local offline tests use
an existing isolated cryptography 50 interpreter; actual execution of these
frozen tests with the host's distro supplier remains a separate gate. Neither a
version string nor API compatibility establishes security/support currentness;
review the selected OS package supplier, security updates and packaging before
integrating it. No mandatory extra venv or wheel-management path is introduced.

Offline tests cover real encryption/decryption of all five synthetic store
trees and secret files, authenticated tamper/truncation rejection, wrong keys,
limits, unsupported files, selection drift, mocked IMDS/cold-state boundaries,
foreign-running-container aliases, synthetic authoritative mount-table cases,
same-device descriptor mount-ID changes and final volume/mount/inode changes,
and retained incomplete output after failed final readback. They do not prove
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
