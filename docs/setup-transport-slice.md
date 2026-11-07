# Private setup transport preparation

`experiments/server/SetupTransport.psm1` is a reusable offline-tested transport
slice toward #53, not an azd hook or a complete operator bootstrap flow. It has
not called Azure, authenticated, changed a VM or opened a browser. It adds no
service, dependency or grant. No remote setup program is supplied or enabled.

The caller prepares one exact binding: tenant/subscription, tagged pilot RG and
VM ID, image ID, source/recovery/Compose/program hashes, remote Compose path and
HTTPS origin. A fresh 256-bit nonce, recipient fingerprint, exact identity digest
and operation mode enter a canonical context hash. Only public recipient material
and bounded UTF-8 JSON arguments are base64 encoded into the remote script. The
private RSA recipient remains in memory and must be disposed by the caller.

Submission uses existing cached Azure CLI credentials and explicit subscription
on every request; it never logs in, changes active subscription or requests a
grant. Read-only account/group/VM checks require the selected enabled tenant and
subscription, known pilot tags and exact VM ID. The separately supplied remote
program must match its pinned UTF-8 file-byte hash (no BOM, at most 16 KiB).
It executes in a `set -eu`
subshell; the transport completion marker is emitted only after successful exit.
Only a successful terminal Azure result with one complete ciphertext marker and
one subsequent exact context completion marker is returned.
The returned marker must first satisfy the exact opaque envelope schema, unique
fields, selected recipient/context/target/mode, canonical encoding and bounds;
Plaintext-shaped payloads are rejected. Cryptographic AAD/origin/expiry validation
remains the responsibility of
`Receive-SantaSetupEnvelope` before explicit private-file/browser delivery.

Before submitting, the module exclusively writes and flushes a nonsecret
`<request>-<operation>.submitted.json` checkpoint. Timeout, truncated output,
process termination or malformed response retain an unknown outcome. A second
create with that checkpoint fails before submission. No automatic retry occurs.
The caller must retain these files in a trusted directory that is not concurrently
modified; deleting checkpoints defeats their local replay guard. They are local
operation evidence, not a transactional Azure journal or a server-side lock.
`readback` is an explicitly selected separate invocation using the same context
and still-held recipient; it must retrieve only the original ciphertext artifact,
never rerun recovery. Checkpoints contain no private key, encoded identity/reason,
password or setup URL. If the private key is lost, ciphertext cannot be recovered;
an owner must inspect state before deliberate targeted reissue.

Remaining admission gates: implement and independently review the remote program
that checks actual source/image/Compose/recovery bindings before any mutation,
reserves a context-bound private artifact, invokes the installed command using
structured arguments, and validates ciphertext-only readback. Those bindings are
currently transported expectations, **not remote attestation**. Integrate this
with azd only after those checks, trusted HTTPS admission and permission inventory
are complete. The supplied module must not be used with an ad hoc remote script.
Actual Azure result shape/tail behavior, unknown-outcome readback, browser delivery
and operator password/MFA completion remain separate unverified live gates.
