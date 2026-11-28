# Authenticated archive quarantine primitive

`experiments/server/restore_quarantine.py` adds a narrow offline step toward
[issue54](https://github.com/nathanmcnulty/azd-santa/issues/54). Its only supported
entry point is the Python `extract()` function: an independently trusted
ciphertext SHA-256, in-memory RSA-3072 recipient key, private regular source
file and absent private destination. It has no CLI, SQL, service start, account
reissue, cloud connection, credential grant or automatic cleanup/retry.

Successful extraction is **not application restore or current authority**.
The complete [quarantine/reissue design](restore-quarantine-design.md), database
and migration census, physical PostgreSQL compatibility, isolated native ES
restoration, restricted role handling, secret rewrap, fresh authority and
administrator/device reissue remain separate unimplemented integration gates.
Archived images/configuration/roles/markers are preserved evidence, never
authorization to run their code, connect to their destinations or start services.

## Authenticate a locally retained archive

Once an authorized operator has the ciphertext and portable encrypted recipient
key on a private Linux recovery host, use the existing key and ciphertext
digests from independently retained records. Run as root with both inputs in
private root-owned files, using the reviewed repository and its recovery
dependencies on that same host.

```bash
python3 -B experiments/server/verify_retained_backup.py \
  --backup /root/santa-recovery/backup.sealed --backup-sha256 "$BACKUP_SHA256" \
  --portable-key /root/santa-recovery/recipient.der --portable-key-sha256 "$KEY_SHA256"
```

The command prompts for the key passphrase without echoing it. It authenticates
the complete file, discards decrypted bytes, and prints a JSON receipt with
the archive digest, byte count, and recipient fingerprint on success. This
local check can run after losing the source VM. Acquisition from the backup
store, portable key custody for the actual pilot, and application restoration
still need their own evidence. See [lab retirement](https://github.com/nathanmcnulty/azd-santa/issues/246).

## Authentication and private containment

The existing `restore_cipher.authenticate()` authenticate-and-discard API is
unchanged. The new function first runs it on one bounded open source descriptor,
checking its identity before/after. Bad digest, tag or recipient creates no
quarantine. It then exclusively reserves the destination and streams a second
decryption pass into `archive.authenticated.tar`, with a second complete digest
and GCM check and source identity check. **No tar parsing or member extraction
occurs before that second authentication succeeds.** Failed staging stays private
for inspection; a filename alone is never a completion claim.

The staging archive intentionally contains plaintext after authentication. All
outputs remain in a private quarantine: directories 0700, regular files 0600,
owned by the invoking Linux UID. No archived ownership, mode, setuid/setgid bit
or modification time is applied to the host. Original UID/GID/mode/mtime and
paths are retained only in private `metadata.json`. File contents, including
credentials, historical records and inert control files, remain byte-for-byte.
Neither plaintext, keys, control bytes, paths nor arbitrary exception details
are printed or returned in the public receipt.

Linux descriptor-relative opens use O_DIRECTORY/O_NOFOLLOW and exclusive
O_CREAT/O_EXCL writes. Parent directories must be root/current-UID owned and
not group/other writable; the immediate source/destination parents must be
current-UID owned and private. Source files must be owner-private regular files
with one link. Absolute canonical paths are required. Existing destinations,
symlink parents, links/devices in the archive, aliases/traversal and duplicate
members reject. The caller must prevent concurrent same-UID/root writers;
this primitive cannot fence a privileged process or untrusted filesystem.

On any error or interruption, original source and partial quarantine are retained;
no overwrite, deletion, automatic replay or completion marker is supplied. A
successful run writes/fsyncs private metadata and `completion.pending`, then
publishes `complete.json` using one exclusive hard link as its last mutation.
All receipt bytes were fsynced before publication. A crash may lose the final
directory link; its absence requires inspection and never authorizes retry.
The public return contains only the trusted ciphertext hash/length, bounded
entry count and false restore/current-authority flags. It is not a signed
receipt, external trust anchor or activation authorization.

## Exact producer format and bounds

The parser follows `cold_backup.archive()` and `_capture_locked()`, and
`native_snapshot.archive_roots()` from the reviewed integration merged into
base `960b2a4b9d2a50a7b81429bc03ba98fb20a309b7`, with the separately reviewed
network-namespace parser fix merged as
`513f58c832f599b6e7cc06565619852397108f74`. The backup source pin is
`790ec1696dc8533ccf85c01947a882b2f6188f3fe5d5a2017f456e8a0b711433`;
that fix changes host mount parsing, not the sealed/archive format. The earlier
source pin is not silently admitted; original artifacts must be retained for
separate compatibility review. It accepts the
`AZDSANTABACKUP1` RSA-OAEP-SHA256/AES256-GCM sealed envelope and the current
native-snapshot selection scope, never the earlier raw-Elasticsearch format.
The controller, backup, native helper and worker source hashes are explicit in
`PROGRAMS`. Upstream application provenance remains Zentral
`88e67b3ce49033aab028029937a6e14f7c489073`; this code is original Unlicense.

The producer-specific tar parser checks USTAR checksums/types and bounded local
PAX `path`, `size`, `uid`, `gid`, `mtime` records, including duplicate/unknown PAX
key denial. GNU/sparse/global-PAX extensions, links, devices, FIFOs, nonzero
padding, concatenated archives and trailing nonzero data reject. Paths are
bounded UTF-8 with no empty/dot/dot-dot components, control characters, colon,
backslash or absolute prefix. Directories may have the producer's single trailing
slash. Parents must precede children; original file bytes are never interpreted
as executable code or extracted via tarfile.extract/extractall.

`backup/compatibility.json` must be the first member; `backup/capture.json` must
be the last, with the exact source entry count. Only four ordinary data roots
(`volumes/postgres_data`, `redis_data`, `rabbitmq_data`, `media_data`),
`elasticsearch_snapshot_repository`, the two backup metadata members and the
exact 25 declared control files are accepted. Root directories and every control
file are mandatory. Raw `elasticsearch_data` is rejected. Complete native
metadata/global-state/index files must be present and nonempty.

Control inventory paths/indexes, SHA-256 values, selected runtime files,
capture-selection, manifest, container generation, request and native
plan/observation/completion cross-bindings are checked. The recipient fingerprint
must match the actual authenticated envelope key. These checks prove bounded
internal format consistency; they do not attest the old host's observations,
prove database contents complete, qualify migration/schema compatibility or
establish current external authority.

Defaults are 1 GiB ciphertext/staging, 512 MiB per member, 100,000 source entries
and 1,800 seconds. Explicit ceilings are 32 GiB, one million entries and 7,200
seconds; the member ceiling cannot exceed the total. Header/PAX/control JSON,
path/depth and an additional 16-MiB metadata budget are bounded independently.
No decompression, sparse allocation, archive omission or truncation is used.
Reserve enough disk for the original ciphertext, full plaintext staging and
all extracted files; the function is not a disk quota. The caller must enforce
an outer process deadline because a blocked filesystem syscall is not bounded
by Python time checks. Preserve the original ciphertext and independently held
recipient key regardless of extraction success.

## Offline validation and remaining evidence

Tests exercise the actual producer archive/encryption code and real crypto,
complete file preservation, spaced runtime JSON, PAX UTF-8/large IDs/setuid
metadata handling, tampered/truncated/wrong-key/wrong-digest ciphertext,
malicious paths/types/PAX, missing/mutated controls, incomplete native metadata,
trailing archives/padding, bounds/deadlines and interrupted partial output.

Windows executes the crypto/parser/preservation cases using a deliberate memory
writer. It does not prove Linux containment. Two separate Linux-only tests
exercise the real descriptor-relative extraction, private modes, no-overwrite,
symlink denial, unchanged ciphertext and interruption retention. Actual Linux
execution, crash/filesystem fault qualification, isolated database/ES restore,
complete census and fresh-authority admission must be reported independently.
No cloud operation or full restore acceptance follows from these offline tests.

Local validation on 2026-11-14 used PowerShell 7.6.9/Pester 6.2.0 and the existing
Azure CLI Python 3.14.6/cryptography 48.0.1 interpreter. Template validation and
all 232 Pester tests passed. The focused quarantine suite executed 12 tests and
explicitly skipped its two Linux-only cases on Windows; all eight unchanged
authenticate/discard tests passed. Linux containment and filesystem fault
acceptance are still required before treating this primitive as qualified there.

## Extraction of the retained pilot archive

The independent Linux verifier reauthenticated the retained 80,159,434-byte
pilot ciphertext before invoking the strict parser. The lab harness used the
original Windows recipient for a boot-bound handoff of the archive's content
key. It staged the authenticated tar in anonymous memory-backed storage and
used the maintained parser and descriptor-relative writer for extraction.

The parser accepted 2,295 archive members, including 2,293 payload entries
and two archive metadata records. The resulting tree held 76,600,634 bytes
in regular files. All five data roots were present, including the native
Elasticsearch repository. The verifier checked entry paths, sizes, ownership,
and private modes and removed the volatile quarantine. Azure confirmed VM
deallocation. The receipt SHA-256 is
`3495b598f39b1b4afd5be15f804354fd174706577a548e1445ecdb479405525e`.

This run exercises the parser and writer on the actual pilot bytes. Durable
quarantine through the public `extract()` entry point, application startup,
restored data verification, and current authority need separate evidence.
