# One-device enrollment profile export

`experiments/server/Invoke-SantaPilotEnrollment.ps1` is a default-no-cloud Plan
entry point. Provide the existing eleven-field deployment binding file, explicit
cached Azure account UPN, existing application operator username/email, serial,
hardware UUID and an absent local `PrivateOutputPath`. Only `-Action Create`
submits an enrollment attempt. There is no authentication, grant, ingress change,
operator creation/recovery, rule publication or Intune assignment in this command.

The command reads the existing generated `40-configuration.mobileconfig`, checks
Monitor mode, and refuses preexisting sync fields. It exports that complete
profile with the existing payload IDs, settings and static rules preserved, adding
only `SyncBaseURL=Origin/public/santa/sync/` and a
`SyncExtraHeaders.Zentral-Authorization` Bearer credential. Use the maintained
Intune one-device publishing path separately; file export is not device delivery.

Before creating anything remotely, all local output/intent/ciphertext paths must
be absent on an existing non-link private-files-compatible parent. The selected
cached commercial-Azure account, tenant, subscription, owned group and immutable
VM are verified. The existing target selector accepts an optional internal reader
callback here; existing callers retain their original default. This transport
supplies the bounded shared CLI reader, not the legacy unbounded setup helper.
No caller-supplied auth/reader setting is exposed by the enrollment entry point.

One ephemeral RSA3072 recipient comes from `New-SantaSetupTransportRequest`.
Its bootstrap label is a placeholder for read-only request validation ONLY.
The compressed/hash-bound host composer calls only the existing request parser,
IMDS/runtime attestors and captured Docker wrapper; it never calls the setup run
function or `operator_access`. The separate worker request binds the canonical
sorted actual deployment binding SHA, origin, source commit, serial, uppercase
hardware UUID, existing operator and recipient. The container checks the exact
existing username/email before the worker. Worker checks include the stored factor
and prior login prerequisites; these do not prove a current human MFA session.

A flushed exclusive local intent precedes the single Create Run Command. Keep
the same output path for the operation; later azd integration must use a stable
environment path, never generate another path/nonce on rerun. A repeated invocation
with that path refuses before cloud access. After a lost Create response, explicit
`-ReadbackOnUnknown` can send one Observe using the SAME in-memory request/key.
Observe never creates the checkpoint root or invokes worker Create. The root's
parent is fsynced after a new root directory; the worker independently fsyncs its
attempt reservation before database effects. Unknown outcomes never retry Create.
One CLI submission is not a claim that every SDK/distributed effect is exactly once.

C# first performs OAEP-SHA256 decryption, duplicate/extra-field rejection and
strict recipient/context/configuration/enrollment ID checks, then composes the
profile. Only a validated opaque response is saved in the owner-private
ciphertext-only receipt; invalid responses never become checkpoints.
The actual credential is never a PowerShell string, URI, argv, console value or
checkpoint field. Only private profile bytes are passed to `Write-SantaPrivateBytes`;
plaintext buffers are cleared and the ephemeral key disposed. Managed strings,
trusted process memory and crash dumps are not an erasure/security sandbox.
The output profile contains the real credential and must remain private.

Readback is bounded to this one running invocation. No private key is persisted;
a process exit loses its decryption capability, and receipts are not a cross-process
resume token. Preserve uncertain intent/ciphertext and reconcile the exact worker
attempt before deliberately authorizing anything new. Do not bypass a retained
intent by selecting a fresh output path. Filesystem flushing is not qualified
power-loss durability. Trusted local source/binding files and exclusion of
concurrent privileged writers remain prerequisites.

Offline tests use synthetic identities, real RSA/C# XML handling, actual Python
request validation, controlled host/Docker adapters and mocked Azure responses.
CLI process tripwires prevent real Azure CLI execution. Actual Run Command delivery, ORM creation, private output on
the selected operator host and native profile delivery remain separate gates.
See [the worker](pilot-enrollment.md).

Failure codes include the stage and Create status. `NoCreateSubmitted` directs
you to check local inputs, cached Azure identity, VM binding or intent, depending
on the stage. For `CreateMayHaveStarted`, keep the intent and reconcile the
existing attempt. `CreateVerified` means the sealed response verified before
writing the private export failed. Keep the existing attempt and receipts.
