# Optional private VM azd installation

The nested `experiments/vm` template now has an explicit opt-in installation
path. With a selected fresh azd environment and `SANTA_PRIVATE_BACKEND_INSTALL`
set to `true`, `azd up` invokes the installation pipeline without manual source
builds, container commands, image IDs or JSON. Root Intune hooks, Monitor mode
and device/profile assignments are unchanged. No public ingress, tunnel, managed
identity or grant is added. The new complete hook/ARM/cold-install path is
**unqualified live**; source/offline checks are not a live deployment receipt.

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
Source inspection and compiled-template checks do not prove either real CLI
entry point; genuine cold `azd up` and `azd provision` remain separate gates.

Postprovision verifies authoritative Bicep VM resource/instance/deployment outputs
against cached selected account/group/VM readback. Every azd command explicitly
targets this nested project and selected environment. The hook requests a
two-hour auto-shutdown guard before long work. It creates a content-addressed
source bundle, gzip-compresses it and transfers bounded 24-KiB encoded chunks,
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
Those gates, actual ARM/hook delivery and cold host/package/build/boot acceptance
must be qualified independently before promotion. `azd down` retains its normal
destructive infrastructure semantics; stopping/restarting the runtime is not a
backup or restore qualification.
