# Operator setup transport candidate

The source now connects the PowerShell transport to an actual stdlib Linux host
program and installed `operator_access` command. This is an offline-tested
candidate, not completed azd integration or live acceptance. No Azure, VM,
authentication or browser operation was performed to implement it.

`experiments/server/Invoke-SantaOperatorSetup.ps1` is the one-command entrypoint:
select a reviewed deployment-binding artifact, mode (`bootstrap` or `recover`),
exact username/email, a nonsecret reason, a trusted checkpoint directory, and
either explicit `-PrivateOutputPath` or `-OpenBrowser`. It pins the bundled host
program and normalized installed recovery/sealer sources automatically. It checks
known invalid/colliding output paths before remote action. No private key or setup
URL is printed; the normal result is a nonsecret local delivery receipt.

The deployment-binding JSON has exactly these string fields: `TenantId`,
`SubscriptionId`, `EnvironmentName`, `ResourceGroup`, `VmName`, `VmId` (ARM resource
ID), `VmInstanceId` (immutable compute GUID), `ImageId`, `ComposePath`,
`ComposeSha256`, and `Origin`. Generation of this authoritative artifact from the
selected deployment remains an azd integration gate; customers must not assemble
it from guessed values. No automatic hook is enabled. A deployment with only the
current loopback listener does not establish reachable, trusted browser HTTPS.

The transport uses cached Azure CLI with explicit subscription on every command;
it never logs in, changes active account or grants permissions. It checks the
selected enabled subscription/tenant, tagged pilot RG and VM resource/instance
IDs. Fresh recipient fingerprint, 256-bit nonce, exact identity digest, mode and
all deployment/source bindings enter the canonical context. Preflight recomputes
the identity digest from actual encoded username/email and revalidates reason.
Only public recipient and bounded UTF-8 JSON arguments enter Azure Run Command.
The private RSA key remains in memory and is disposed when the command exits.

The source program cap is 24 KiB, request base64 cap 16 KiB and full shell payload
cap 44 KiB. The exact hash-pinned UTF-8 Python program is sent inline through a
fixed heredoc; no customer remote-file upload or shell interpolation of identity
values is needed. It runs only through the selected authenticated Run Command.
A final transport marker is emitted only after successful Python exit. The result
parser requires terminal successful Azure statuses, exactly one ciphertext
envelope followed by the exact context marker, strict duplicate-free schema and
selected recipient/context/target/mode. Actual decryption/AAD/expiry/origin checks
occur before explicit private-file/browser delivery. Encryption is not sender
identity; the selected authenticated Azure operation supplies that authority.

## Host checks and durable operation state

`operator_setup_host.py` requires root. It reads only fixed link-local IMDS compute
metadata, with proxies and redirects disabled, a two-second timeout and response
bound. It matches subscription, resource path, VM name/group and immutable vmId.
IMDS compute does not attest tenant: tenant comes from authenticated ARM preflight.
No MSI token is requested.

Before mutation it validates the canonical request, exact target/key fingerprints,
root-owned non-link private Compose and runtime-env files under
`/var/lib/azd-santa-qualification`, exact Compose bytes and private project-local
volumes. All seven actual containers must match declared images, project, service,
running state, private mounts and one actual project network.
Actual Docker configured and observed port bindings must publish exactly web
8000/tcp on 127.0.0.1:8000, with no other publication or publish-all setting.
Null unbound entries are allowed only for ports exposed by the pinned image.
Application image
labels and deployed source version must match the expected commit. Inside the
exact selected web container it verifies actual recovery/sealer file hashes,
DEBUG disabled, database/security-cache host bindings, configured HTTPS origin,
supported RSA recipient preparation and admitted durable security store. These
checks do not provision ingress/TLS, initialize a store or change services. They
assume the privileged host/Docker administrator is trusted and does not
concurrently replace checked configuration or container files.
The new per-service contract is required: `db.env` contains only PostgreSQL
database/user/password, `rabbitmq.env` only RabbitMQ default user/password, and
app-only `runtime.env` only database password, Django secret, metrics token,
security-store ID and queue URL. Each is root-owned 0600. Actual container
sensitive environment keys and values must match its own file; changing Compose
without recreating old shared-secret containers cannot pass this gate. Legacy
Compose is rejected rather than silently migrated. Runtime database-role
separation remains a separate concern.

A root-private `operator-setup/<context>/` directory is exclusively created and
fsynced before mutation. Its private original request and `attempt.json` are
written and fsynced before invoking the installed command with structured argv
and explicit `--name=value` identity/reason options. Only the exact inspected
container ID is executed. The command writes a new private sealed artifact in
its media volume; stdout/stderr remain in root-private host files. A success
marker requires successful command exit, one valid envelope and byte-equivalent
original container artifact. The durable context directory is never automatically
reused or repaired, including after timeout, failure, partial output or restart.
Concurrent creates for the same context permit only one mutation attempt.
The host process has a five-minute alarm and the mutating Docker client a
three-minute timeout. Killing a client does not prove the container command
stopped; the retained attempt remains authoritative against replay.

`readback` requires the exact original request and prior attempt checkpoint. It
never invokes `operator_access`; it reads the original context's bounded 0600
sealed artifact from the same verified deployment. It can recover delivery after
an unknown response, but does not assert successful audit submission/indexing or
original terminal exit. An incomplete/missing artifact fails closed. The caller
must explicitly select readback; `-ReadbackOnUnknown` opts into one attempt within
the same process while the original recipient exists. It does not retry mutation.
Without opt-in the command stops on unknown outcome. Losing the key makes original
ciphertext unusable; inspect state before deliberate targeted reissue with a new
key. Local delivery failures can occur after a real reset; no plaintext fallback
is attempted.

Local `<request>-<operation>.submitted.json` checkpoints are exclusively flushed
before submission; a terminal-ciphertext checkpoint follows result validation.
They contain no private key, encoded identity/reason or setup URL. Keep them in a
trusted directory: deleting them defeats the local replay guard. They are local
operation evidence, not an Azure transactional journal or server-side lock.

## Qualification remaining

Offline tests exercise real PowerShell/Python canonical-request interoperability,
source bounds, metadata/Docker guard shapes, concurrent reservation and timeout
state, readback with no second mutation, strict ciphertext parsing, and entrypoint
orchestration. Mocked metadata/Docker/Django output is not runtime proof. Real
target IMDS/Compose/image/module/config readback, bootstrap/recover, unknown-response
ciphertext readback, Azure tail behavior and native browser/password/MFA completion
require independent review and live qualification. Authoritative deployment-binding
generation, trusted reachable HTTPS admission and azd hook wiring remain required
before describing this as automated azd setup.
