# Confidential independent-verifier download relay

`experiments/server/blob_verifier_relay.py` adds separate typed, default-off
recipient/submit/execute/observe APIs for an independently selected VM to receive
only an exact-blob `r` capability. The source upload relay executable is unchanged
and still rejects `r`. The verifier rejects the source VM ID (including case
aliases), the source VM instance ID, wrong environment and wrong subscription.
Fresh IMDS checks bind the complete target and region; the same boot is required
through completion observation. No source runtime, capture directory, native
services or private backup key is needed on the verifier.

The operator must independently authenticate the selected current tenant,
subscription, store, target and capture record/expected ciphertext SHA/length,
then mint `r` with existing cached authority and seal the private capability in
memory. An encrypted envelope proves recipient confidentiality/integrity, not
sender identity, complete capture provenance, ARM authority or restore acceptance.
The existing private cached ARM adapter can mint `r` for its separately selected
verifier; no token, SAS or backup private key is placed in argv, Run Command
scripts, stdout or diagnostics. This module does not implement Azure staging,
Run Command submission, operator authentication, grant or store/network changes.

`create_offer(environment, target, record, blob)` plans by default. Explicit
`apply=True` requires a protected root-owned staging path under
`/var/lib/azd-santa-qualification`, exact reviewed dependencies and current IMDS.
It creates one fresh operation directory using the existing descriptor-private
`State` implementation: `blob-relay-v1/<operation>`. This shared path convention
is safe only on the separately selected verifier: any existing operation is a
collision and rejects, never adopts or overwrites. The private recipient key is
RSA3072 PKCS8 mode 0600 in mode 0700 directories, and is retained with all evidence.
`get_offer(..., read_guest=True)` recovers a lost offer response before submission
without creating a new recipient. No cleanup or reinitialization is automatic.

Verifier offer, envelope and decrypted payload scopes are distinct from source
scopes. OAEP-SHA256 + AES256-GCM uses the separate
`azd-santa/blob-verifier/v1` AAD domain with the complete original verifier offer.
The envelope binds operation, canonical record digest, ciphertext SHA/length,
exact blob/account, target VM/instance/subnet/region, boot, source program digest,
recipient key digest and bounded offer expiry. Structural offer/packet and SAS
grammar helpers are reused through explicit local validation projections; only
the original verifier bytes are encrypted/hashed. Original `r` permission is
required before the SAS grammar projection, and is retained in the decrypted
capability. `c`, combined permissions, IP/policy fields and ARM-token payloads
reject. The offer lasts at most 1800 seconds; the capability may have at most 900
seconds remaining and must expire no later than the offer.

`seal_offer(offer, capability, record)` runs only in the operator's private
process. `submit(operation, expected_offer_sha256, packet, apply=True)` validates
fresh target/boot/expiry and decryption before an exclusive durable intent and
one systemd job launch. Lost launch replies are unknown: observe the same handle;
duplicate submission of identical bytes observes, never launches again. A
different packet cannot replace the reserved intent. The job has `Restart=no`,
control-group kill, `Delegate=no`, `system.slice`, `NoNewPrivileges`, `PrivateTmp`,
`ProtectHome`, private umask and bounded runtime/start timeout. Its argv contains
only the fixed operation and intent SHA; encrypted packets remain private files.

The job reserves one execution marker, creates exactly
`blob-relay-v1/<operation>/download/backup.sealed` in a fresh private directory,
and delegates the single GET to `blob_retention.verify_download`, with its
exclusive `get` journal, exact 200/ETag/length/SHA checks and no retry/overwrite.
No remote caller supplies a host path. Existing encrypted producer framing and
the retained file are rechecked through descriptor identity/private regular-file
guards and a bounded streaming fingerprint before a verified body is written,
again in terminal recording and final observation. File recheck is bounded to
60 seconds and the producer's 2 GiB maximum. Fingerprinting validates bytes/framing;
it does not authenticate/decrypt the sealed archive. Failure/interruption retains
the intent, partial file and an unknown body where execution reaches its handler.
A hard kill may leave no body/terminal; it still never allows replay.

Final `independent-bytes-verified` requires exact verified receipt/body/execution
and terminal bindings, successful recorder environment, quiet authoritative
systemd facts, correct invocation (or strict GC defaults), and the reviewed
positive unified-cgroup hierarchy/absent fixed job group proof. Not-found never
overrides failed/active/pending manager facts. Body/receipt files alone are not
terminal success. Expiry permits observation of existing evidence but cannot
authorize another GET; reboot rejects observation. The body/verified receipt retain `sealed_authenticated: false`;
`restore_accepted` and `current_authority` remain false in final observation. No SQL, application
activation, issuer reissue, full census/schema coverage, portable key/image
retention or VM/azd-down lifecycle acceptance is provided.

Offline tests use real cryptography with controlled IMDS, manager, HTTP and file
adapters. Linux-only cases exercise actual descriptor-private output, mode/link
rejection, duplicate/no-second-GET and retained partial ciphertext with controlled
identity/HTTP. A Windows skip is not Linux proof. These are source/protocol tests,
not actual VM, Storage delivery/download, RBAC, confidentiality of the complete
Azure orchestration or full restore acceptance. No cloud/guest/auth call is part
of this change; selected-VM staging/crypto/systemd and actual independent download
remain explicit live qualification gates.
