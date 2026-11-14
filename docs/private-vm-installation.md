# Optional private VM azd installation

The nested `experiments/vm` template now has an explicit opt-in installation
path. With a selected fresh azd environment and `SANTA_PRIVATE_BACKEND_INSTALL`
set to `true`, `azd up` invokes the installation pipeline without manual source
builds, container commands, image IDs or JSON. Root Intune hooks, Monitor mode
and device/profile assignments are unchanged. No public ingress, tunnel, managed
identity or grant is added. The selected 2026-11-14 private candidate passed
first-attempt cold installation and client finalization. Backup, recovery faults,
trusted browser access and native-device acceptance remain separate gates.

Preprovision automatically supplies Azure Linux's public provisioning key. It
generates RSA-3072 in memory, exports only the OpenSSH public portion and disposes
the throwaway private key. A stable nonsecret `.pub` artifact prevents incidental
key changes across reruns. Existing user-supplied public input is retained. This
does not provide SSH access or a private-key download; explicit SSH would require
a separate operator choice and network review.

In azd 1.34.1, `up` initializes the Bicep provider before its provisioning graph
runs `preprovision`. The outer key parameter therefore has an empty default
solely to reach this hook. The graph's hook node reloads environment writes
before creating the layer snapshot; deployment resolves parameters again. The
same hook serves standalone `provision`. The nested host parameter remains
required with `minLength: 40`, so missing hook output cannot create a VM with an
empty key. Existing public-key overrides remain authoritative. See the pinned
[Bicep provider](https://github.com/Azure/azure-dev/blob/azure-dev-cli_1.34.1/cli/azd/pkg/infra/provisioning/bicep/bicep_provider.go),
[provision graph](https://github.com/Azure/azure-dev/blob/azure-dev-cli_1.34.1/cli/azd/internal/cmd/provision_graph.go)
and [hook runner](https://github.com/Azure/azure-dev/blob/azure-dev-cli_1.34.1/cli/azd/pkg/ext/hooks_runner.go),
plus the [`up` entry](https://github.com/Azure/azure-dev/blob/azure-dev-cli_1.34.1/cli/azd/cmd/up.go)
and [up graph](https://github.com/Azure/azure-dev/blob/azure-dev-cli_1.34.1/cli/azd/internal/cmd/up_graph.go).
Source inspection and compiled-template checks are separate from the actual
CLI results below.

## Selected private deployment results

### Fresh six-volume candidate, 2026-11-14

The first `azd up --environment privatehook3-20261107 --no-prompt` completed
successfully in25m28s using azd1.34.1 in sub-patriot-lab / West US2. No manual
guest task, finalizer retry or initialization replay was needed. The normal hook
created the installation receipt and recorded its operator-binding path after
all seven initialized readiness gates passed.

An unchanged-source `azd up` rerun then passed in1m39s with no infrastructure
changes. Its normal hook observed the completed installer and produced another
readback/binding without replaying initialization. This rerun still used the
same content-addressed source bundle; later offline restore additions do not
change that bundle.

- Source bundle: `b6331a08e5352f8c5d962cda0e2c36d62e22187ff641aaddb3f3dbb2cd7f0741`.
- Actual private image: `sha256:8321d09e6b0904e39e282cf07e809fdfe7c8baeb3638d77e44ba51bf4d0ce43a`.
- Compose SHA256: `8fb3b5a5f21be74ac6ca7942c9ec5c9b8689adf18eac4ed18efb1275e753f1fc`.
- VM instance: `597dbfce-436e-4e15-a987-e53d78b4d283` in
  `rg-azd-santa-vm-privatehook3-20261107`.

Independent readonly guest inspection found the active source-bound runtime,
seven running original containers, six local volumes including the dedicated
snapshot repository, no OOM kills and no container restarts. Manifest SHA256 was
`f98de5c3f99fed4e8bad869aa099a796d57d28d61c1fa2f665d37759792229c8`;
the original generation file SHA256 was
`c323d9018309b52d858246f4540b91009529c061448e7b4e06828520db826659`.
Host cryptography41.0.7 was available, with approximately20.8GB free. Its presence
is a selected-host observation, not an installer dependency guarantee or backup
crypto preflight. The NSG denied all inbound traffic; automatic shutdown was
enabled. This proves private cold installation, not native snapshot/capture,
restore, reachable HTTPS, operator enrollment or real-Mac behavior.

The new image then passed24 synthetic loopback sync HTTP requests, including
exact six-rule receipt/commit for two synthetic Monitor machines and two event
counter increments. A controlled Azure restart changed boot ID from
`a71b1764-e942-4f54-9f0d-815fc40941dc` to
`21f522fe-937b-41fa-ae22-e09a3ddbc84f`. The original seven container IDs, image
and generation were preserved. Before new HTTP traffic, the selected database
projection matched SHA256
`b846eedb21749ab9d08351eccf6ad01e4a7eaacba27ca804a2b9e9db1f654b3f`.
Another24 requests passed after reboot, raising the synthetic event counter
from2 to4; both sessions needed no rate-limit retries. This is selected
PostgreSQL/client-reported state, not a full database comparison, indexed-event
search, held-handler fault, native Mac or application backup proof.

The initial qualification invocation failed before fixture creation or ORM
execution because isolated Python had not loaded the helper's compiler module.
The failure was reproduced readonly and retained; loading the exact verified
dependency bytes allowed qualification without changing the deployed source.
Retained guest receipts are under
`/var/lib/azd-santa-qualification/http-cold3-20261114-verified-loader`:
initial HTTP receipt SHA256
`9e3948359a165e67a581cc0d7c04696e424d8ed059c2b4a96ca6b198ae1b4cde`,
post-reboot HTTP receipt SHA256
`3a93d56b56faf820cfef9e5656c00b04c4854eaf70a4640d0beb710ade598f30`,
and `reboot-after.json` SHA256
`b0258ad15008f6b393f321dfa4375954ced704dac8533a01aff9d4b190aa641b`.

### Historical five-volume candidate, 2026-11-07

On 2026-11-07, a genuine cold `azd up` in
`rg-azd-santa-vm-privatehook2-20261107` provisioned the selected VM and completed
the guest installation, including pinned prerequisites, source build, fresh
initialization and runtime startup. The content-addressed guest bundle was
`8aec7cd6262a9780b563310f9dc065fa517f6c7eb84ec00cf66f81f28098c197`.
The client finalizer failed after guest success; its cause remains unexplained.
This cold invocation therefore did **not** pass end to end.

Separate readback produced the installation receipt and operator binding.
The normal postprovision hook then succeeded, followed by a genuine unchanged-
source `azd up` rerun in1m49s without ARM changes or initialization replay.
Standalone `azd provision` also succeeded after clearing only the local public-
key environment value: the preprovision hook restored the same saved public
key without a manual remote task. These successful reruns do not replace the
missing first-attempt cold finalization evidence.

Controlled reboot subsequently returned the same seven containers and selected
credential/rule state, followed by seventeen HTTP checks; see
[credential rotation qualification](credential-rotation-qualification.md).
This selected image predates admission and native-snapshot candidates, which
need their own build and live qualification.

## Installation flow

Postprovision verifies authoritative Bicep VM resource/instance/deployment outputs
against cached selected account/group/VM readback. Every azd command explicitly
targets this nested project and selected environment. Postprovision validates
the exact VM and configures a two-hour UTC auto-shutdown schedule for both
host-only and private-backend runs. Private backend installation still requires
the explicit opt-in. When enabled, installation creates a content-addressed source bundle,
gzip-compresses it and transfers bounded 24-KiB encoded chunks,
each acknowledged before submission. Compressed and uncompressed hashes plus
per-file checks protect assembly; no arbitrary archive paths are extracted.
Different compression attempts have independent staging directories. The full
raw command is capped at 64 KiB, below the large packets that failed silently in
earlier qualification. No setup credential or private key enters this transport.

The selected VM reserves a root-private durable installation context before
submitting one named, nonrestarting systemd job. Unknown submission is observed
through that same unit. Neither a new hook invocation nor a service failure can
rerun initialization. Existing runtime units, containers/volumes or a different
source binding are rejected rather than repurposed. Public source staging can
resume missing identical files before job reservation; application state cannot.
An exclusive terminal receipt is recorded by systemd's post-exit process only
for an actual successful main-process exit. It binds the invocation, context,
source bundle and completion hashes. After reboot removes the transient unit,
readback requires this retained proof and an active runtime before the normal
six readiness gates run again. A missing proof or a currently failed installer
unit cannot be accepted just because a completion file exists.

The job verifies immutable IMDS VM/subscription identity and pilot tags, then:

1. Installs the exact qualified Ubuntu packages `docker.io=29.1.3-0ubuntu3~24.04.2`
   and `docker-compose-v2=2.40.3+ds1-0ubuntu1~24.04.1` through signed apt metadata.
   It checks the actual selected distro Compose plugin path and binary SHA-256.
   Override plugin suppliers are rejected before bootstrap can execute Compose;
   a fresh private Docker config excludes inherited extra plugin directories.
2. Acquires the pinned/checksummed upstream archive, applies the existing core
   compiler and builds through the qualified classic builder lane. The actual
   local image ID is derived by code after successful build. Images are not pushed.
3. Pulls the committed dependency digests and calls the existing fresh-stage API,
   including its bounded Elasticsearch wait before owner initialization. Owner
   and runtime credentials remain separated; initialization is never replayed.
4. Explicitly admits a genuinely fresh durable security store, then creates the
   three stopped application containers. It prepares/installs the existing
   seven-container runtime supervisor, whose backing/source/schema/store/security,
   consumer and HTTP gates control listener admission and boot behavior.
   The installer includes the admission module, binds its reviewed bytes in the
   runtime manifest and creates the first exact-container generation anchor
   before installing or enabling the unit. A binding failure cannot start the
   unit. Existing installations are never automatically adopted or rebound.
   The candidate also uploads the worker compiler/helper and native/encrypted
   backup helpers. The generated runtime manifest binds the exact installed
   worker module and derived command; helper omissions fail offline bundle
   validation. Its fresh layout includes the dedicated sixth snapshot volume.
   Existing five-volume installations are retained rather than upgraded in place.
5. Returns nonsecret source/image/Compose/VM facts only after unit readiness.
   The client calls `Complete-SantaBackendInstallation` for seven initialized-state
   readbacks and machine-produced installation receipt/operator binding. It records
   only the local binding path in azd state. No human operator is created/reset.

The installer has a 105-minute process limit within the two-hour cost guard.
Subprocesses have smaller limits and private diagnostics. A killed Docker client
does not prove its daemon-side operation stopped; immutable context/unit handles
remain for inspection. The controller never treats an observation timeout as
permission to restart a build or database job. Failed/partial output is retained;
no automatic deletion, data repair, grant or credential rotation occurs.

Normal reruns observe the existing job before uploading. A completed same-source
deployment can generate new nonsecret readback/binding receipts without touching
operator/data state. A failed or unknown job produces an actionable retained-state
failure; a deliberate repair/upgrade workflow remains future work. The normal
flow does not ask administrators to execute local scripts on the remote VM or
edit configuration/receipt JSON.

Finalizer failures identify a fixed phase: input, source-program, request,
azure-selection, transport, readback, readiness, receipt, local-persistence or
binding. Preserve existing files and inspect that same installation. A failed
readiness check does not authorize rebuilding or reinitializing; a failure while
writing a binding may leave an installation receipt that must be retained.
Messages omit underlying exceptions and command output. These phase labels
classify where verification failed; they do not diagnose a cause or qualify a
retry as successful. Guest preflight diagnostics remain tracked separately in
[#71](https://github.com/nathanmcnulty/azd-santa/issues/71).

This remains a private lab: the configured HTTPS origin is bound to
`https://localhost:8000`, while the actual listener is loopback HTTP. It does not
establish reachable trusted admin TLS, native Santa enrollment or customer
password/MFA completion. Do not open that placeholder as a qualified browser URL.
Those remaining gates must be qualified independently before promotion. The
selected private cold-finalization result above does not qualify them.
`azd down` retains its normal
destructive infrastructure semantics; stopping/restarting the runtime is not a
backup or restore qualification.
