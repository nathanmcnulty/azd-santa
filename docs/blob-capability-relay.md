# Confidential exact-capture Blob capability relay

`experiments/server/blob_capability_relay.py` is a bounded source/VM protocol layer
for issues85/54. It follows the existing sealed_setup recipient-envelope pattern
(RSA3072 OAEP/SHA256 plus AES256GCM with context AAD) and delegates transfer to the
existing Blob create-only PUT primitive. It adds no Azure adapter, authentication,
permission grant, backup request, service stop, cleanup or restore path. Original
installer/runtime/helper bundles, images, volumes and credentials are unchanged.

The typed operator APIs default to offline plans. Only explicit `apply=True`
creates an offer or submits its one job; `read_guest=True` explicitly reads guest
state. `seal_offer()` is local in-memory encryption, not an Azure call. No
administrator assembles remote paths or JSON. A future cached ARM/Run Command
adapter must call these APIs and carry only public offers, encrypted packets and
nonsecret receipts. It is not implemented by this module. The private CLI is
only the generated worker/ExecStopPost entry, with an operation UUID and intent
digest; it accepts no SAS, key, URL, arbitrary host path or remote shell command.

Before use, the current external operator must freshly validate cached selected
ARM authority, independent store ownership/network configuration and the exact
source VM, then mint the exact-blob create-only capability with existing rights.
Use the expected capture record retained from trusted producer evidence. A
copied record, guest offer, digest, envelope or receipt is not authority. No ARM
token or backup recipient private key enters any relay API or the guest. Service
SAS signature authenticity/rights are enforced by Azure, not inferred from local
query-shape validation. Restrictive policy is a stop condition, not permission
to change policy or grant access.

## One capture and one offer

`create_offer(environment, target, record, selected_blob, apply=False)` checks the
explicit source target and existing record; Apply verifies current IMDS identity,
region and boot. The fixed selector reads the canonical environment manifest,
backup request, maintenance/cipher completions and original generation/image.
It derives the immutable 25-file bundle from the exact runtime unit path and
verifies bundle/file/source bindings. Ciphertext is restricted to the request's
`ciphertext-*` child of the qualification root, with fixed `backup.sealed` and
`complete.json` names. Its private regular-file descriptor, length, sealed header
and full ciphertext hash must match the bound capture before an offer/submission.
No caller-supplied host path or arbitrary capture directory is accepted.

The guest reserves `blob-relay-v1/<capture-operation>` exclusively, writes a
durable offer intent, then generates a separate RSA recipient key. The private
DER key and records use mode0600 inside owner-private0700 directories, with
no-follow descriptor-relative state writes and no overwrites. Guest Apply
requires Linux root and reviewed source under the qualification root. A failure
retains partial state; no key regeneration, automatic reinitialization or cleanup
exists. The key is unrelated to the backup decryption recipient. Its accepted
use expires within30minutes; retained private key/evidence cleanup needs separate
review. Ephemeral here describes protocol lifetime, not automatic secure erasure.

The bounded public offer binds VM/instance/subnet/region, current boot, capture
operation, account/exact blob, ciphertext SHA/length, complete record digest,
recipient key ID and source continuity hashes. Lost offer responses can use
`get_offer(operation, read_guest=True)` to recover that same fresh offer without
regenerating its key. Once submitted, use observation instead. An existing
operation never silently becomes another offer.

## Confidential delivery and once-only upload

`seal_offer(offer, capability, record)` accepts only permissionc for the exact
source and blob/cipher binding. It rejects verifier permissionr, cross-target
values, unknown/duplicate SAS fields, ARM-token-shaped inputs and unsupported
expiry. The short-lived opaque SAS stays in memory and inside authenticated
ciphertext. Public context is AAD; recipient encryption does not authenticate
the sender or prove fresh ARM provenance. No plaintext SAS is emitted in a
script, command argument, stdout, journal, receipt or raw exception.

`submit(operation, expected_offer_sha256, packet, apply=False)` verifies the
current offer/boot/capture and decrypts/validates its exact token fields before
an atomic exclusive submit intent. It stores only the encrypted packet, then
launches one independent systemd oneshot with Restart=no, bounded execution,
NoNewPrivileges, PrivateTmp and ProtectHome. An unknown launch response means
observe the same handle; duplicate submission cannot launch another job.

The job requires its actual manager invocation/MainPID, reserves one execution
marker, repeats fresh binding checks, then passes the in-memory capability to
`blob_retention.upload_file`. That primitive validates/fingerprints the source
again and uses If-None-Match:* with no HTTP retry. A timeout, interruption, 412,
failed check or missing terminal proof is unknown, never overwrite/replay
permission. The relay's one-use guarantee is its private trusted execution
journal; a bearer SAS itself is not cryptographically single-use. A privileged
root/current-operator attacker is outside this recipient-confidentiality boundary.

Typed body and ExecStopPost receipts remain separate. Successful observation
requires authoritative terminal unit state/invocation plus the typed delegated
upload outcome, body hash, source/boot binding and retained evidence. A body file
alone is insufficient; a failed manager state overrides retained success.
Collected-unit handling is deliberately narrow: not-found must still report
inactive/dead, Result success, MainPID0, ExecMainStatus0 and empty Job,
InvocationID and ControlGroup. A failed, active, pending or contradictory manager
fact wins over retained success. Loaded terminal success requires its matching
invocation and the same quiescent fields. Both cases additionally require the
exact fixed job cgroup path to be absent under positively attested kernel
cgroup2fs, root/slice controllers and system.slice domain/events. An existing
empty/populated/symlink group is not absence; missing hierarchy facts stay closed.
The launch explicitly fixes system.slice, KillMode control-group and Delegate=no.
No missing manager field or arbitrary absent host path becomes a GC default.

Expiry blocks new capability use but does not erase a completed observation.
The outcome is `uploaded-unverified`, with independent byte verification,
restore acceptance and current authority explicitly false. Permissionr download
must use a separately selected verifier and is not relayed back to the source.

## Remaining integration and evidence

The current operator must stage an immutable reviewed program/dependency bundle
without ambient stale bytecode and retain its provenance before executing guest
code. Local source hashes provide continuity, not self-authentication. No current
ARM token or backup private key belongs in that bundle. Run all blocking offer,
crypto, file and transport work under an external deadline; systemd bounds the
submitted upload job, but typed local primitives cannot kill arbitrary blocked
I/O themselves. Concurrent same-UID/root writers must be excluded.

Tests use real RSA/OAEP/AESGCM and the actual sealed producer/fingerprint/PUT
protocol with controlled guest identity, installed-source, descriptor metadata,
systemd and HTTP adapters. They cover tamper, wrong keys, cross-VM/boot/expiry,
exact source versus verifier roles, unknown/duplicate fields, lost replies,
interruption, one intent/launch/PUT, terminal failure precedence and redaction.
The selector test exercises real hash/header checks with controlled installed
metadata; it is not an actual VM/source attestation. A Linux-only private-file
case checks exclusive modes/symlinks and skips on Windows.

On 2026-11-15 UTC the selected synthetic private VM ran all 27 protocol tests
with zero failures, errors or skips using Python 3.12.3 and its existing
cryptography 41.0.7. This exercised actual Linux descriptor-relative permissions;
the suite's identity, service-manager and HTTP adapters remained controlled.
The five-file test bundle SHA-256 was
`f12ebd7644097714188f938f490ba57cfe6e4d4870272b626e36f71ef1fec5fd`;
the relay program SHA-256 was
`eb6a5eee83ededf08e78c6203aeb7babc8e36129cf836f2af7ef80be0f6a9a1c`.

A separate bounded read-only invocation exercised the actual installed 25-file
bundle/controller, current IMDS/boot, completed native2 request/receipts and
generation through the real capture selector. It fingerprinted the retained
80,159,434-byte ciphertext and passed the real unified-cgroup hierarchy and
fixed absent-job-path checks. The capture bindings are recorded in the
[native capture qualification](private-native-capture-qualification.md).
This preflight used an undeployed Blob descriptor solely to exercise selection;
it created no offer, SAS, Storage object or service and changed no runtime.

Actual upload job/terminal and Run Command interruption behavior, confidential
cached ARM mint/delivery orchestration, Storage PUT and independent download
remain live gates. Off-host recoverability, portable backup key/image/source
retention and isolated full application restoration remain open. No new dependency
was installed for these checks; the source runtime and network were preserved.
