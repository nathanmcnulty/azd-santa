# Exact pre-snapshot failed-request recovery

This opt-in operation handles only the reviewed `368c81c41b584311b3e3cafe73264dd5`
failed backup request (`a6386505...38a16`) on the same boot and original seven
containers. It is not a recurring upgrade, backup resume, new backup request,
or restore acceptance path. The failed worker exited 1; this is not clean worker
or native backup qualification.

The failure happened before snapshot submission: a storage fingerprint included
namespace-local mount IDs. The replacement uses a versioned physical projection
that retains canonical volume paths, inode/device and covering mount point,
root, filesystem, source and options. It excludes only mount ID, parent ID and
propagation metadata. Every process still validates its full local mount snapshot,
descriptor mount IDs and nested/bind/unsupported filesystem rejection.

From the repository on the operator machine (PowerShell 7.6+), select the existing
subscription/environment and inspect the offline plan:

```powershell
./experiments/vm/Repair-PrivatePreSnapshotFailure.ps1 -SubscriptionId $subscription -EnvironmentName privatehook3-20261107
```

Explicit `-Apply` uses cached Azure CLI transport and current ARM VM facts. It
observes first, stages the immutable public source bundle, then submits one durable
job. Use the same command with `-Observe` after a timeout; never resubmit or edit
remote JSON. Failed and unknown outcomes require review of retained evidence.
There are no user-supplied remote paths or shell commands.

Before reserving recovery, the guest requires current IMDS identity, the exact
same boot/request/generation/source bindings, unchanged original installer and
helper-upgrade terminal history, both exact failed systemd invocations, their
complete profiles, positively attested kernel cgroup-v2 hierarchy and either empty
unit cgroup events or authoritative terminal empty ControlGroup plus absent exact
unit path, exact original stopped container inventory and
exit statuses. It verifies the caller fragment, context and reviewed recorder
bytes. It requires exactly the two known maintenance failure files, no native
checkpoint, an empty native repository and absent ciphertext destination. Missing
fields are errors, not evidence of no effect. The original recorder cannot invoke
helpers: it only verifies successful receipts and writes its terminal receipt.

The job records a separate durable intent, preserves all old bytes, disables the
runtime boot start, takes the existing flock, then repeats the proof. It journals
and renames the unchanged request into its private recovery directory on the
same filesystem. This explicit retirement preserves the original failed request;
it does not mark it completed. Old maintenance files, credentials, counters,
container IDs, volume data, immutable bundles and installer receipts remain.
Only the cold helper and its manifest/generation/unit bindings change. The job
resets the reviewed runtime failure only after all checks, enables and starts the
same runtime once. It never issues another stop or backup request.

A failure before the enable transition retains the boot hold. Every failure retains evidence; there is no
rollback or replay automation. Successful observation requires authoritative
systemd terminal state/invocation proof plus current source, identity, generation
and running-container bindings. A completion file alone is insufficient.

Offline tests exercise synthetic protocol transitions and byte preservation;
they do not prove Azure authority, Linux cgroups/systemd behavior, live recovery,
native Elasticsearch/Kombu capture, clean worker shutdown, off-host ciphertext,
full-stack restore and complete application/schema census or current-authority reissue. Those remain separate
live acceptance gates. The authenticated archive primitive only updates its cold
producer source pin; its format and restore limitations are unchanged.

A separate read-only VM probe of the exact new source-selected functions passed
with PrivateTmp, ProtectHome and NoNewPrivileges enabled: six physical bindings
matched despite mount IDs 28 versus 310 in distinct namespaces. The probe changed
no installed source or request and establishes namespace portability only.

The first eligibility-only guest probe rejected before reservation because it
required root cgroup.events. Kernel v2 exposes that file on nonroot cgroups. The
revised guard requires the attested root/controller set, system.slice domain and
events, then the exact unit checks above; missing fields still fail closed.

A second eligibility-only probe also rejected before reservation: systemctl
omits empty Exec command arrays, so the runtime has no scalar ExecStopPost line.
The runtime now requires its exact observed 12-field profile and typed D-Bus
ExecStopPost empty-array proof. The caller still requires its pinned nonempty
recorder field. Neither failed preflight reserved or retired a request.

The third eligibility-only probe passed on the selected VM with recovery source
`379ea274ebef9247428d7dc1c53593a4e75746be04aaba6c1b8e032b3d75b2bd`.
It verified the exact failed invocations, same boot, original seven stopped
containers and no-native-effect conditions. Its proof digest was
`f4fc852d1c6ecee2cee05be8697f658bc22a56d3411cfb4ffd18d4c5f5e79787`.
This was eligibility evidence only: no recovery reservation, request retirement,
helper rebind or runtime start was performed by that probe.


## Explicit disable-only continuation

The first recovery Apply reserved operation
`82e634d7656945f08c7eb02708089329` with intent
`a4781fb605f036d7b24f1abbaa28f60d645a0437e253cad6ce174f518edb00eb`.
It failed after disabling boot start, before request retirement, file promotion or
runtime start. `systemctl disable` implicitly reloaded systemd; the manager cleared
ExecStart execution history for the runtime and both command histories for the
failed caller. The original full-profile guard rejected the changed observation.
Original request/source/generation/unit and seven stopped service containers were
preserved. This is a failed recovery with a persistent disabled boot hold, not a
completed backup or restart.

`-ContinueDisableOnly` selects a separate, explicit continuation of this exact
failed reservation. Without `-Apply` or `-Observe`, it returns a local plan and
makes no target/transport calls. `-ContinueDisableOnly -Observe` observes the new
namespace. `-ContinueDisableOnly -Apply` may reserve one new operation only after
current cached ARM selection and the same-boot guest checks. It requires no manual
remote JSON, request deletion or shell task. Ordinary Apply still observes the
original failed reservation and cannot replay it.

The continuation binds the immutable predecessor program bytes (`379eaâ€¦`),
original ACTIVE/intent/proof, exact sixteen-file operation inventory and failure/
disable hashes. It independently checks all three failed invocations and positive
terminal cgroups: original recovery transient, backup caller and runtime. Current
runtime/caller full profiles must match their separately reviewed post-reload
observations. Typed D-Bus ExecStart and ExecStopPost definitions must match exact
path/argv/ignore-error tuples; execution timestamps/PIDs/status are not substituted
for command definitions. Empty hooks remain positive typed empty arrays. The
original full historical profiles are retained and validated separately. All
original tuple, stopped-container/data/mount and no-native-effect checks repeat.

The operator bundle must equal the predecessor candidate bundle. The continuation
verifies and reuses its exact immutable twenty-five-file candidate; it performs
no redundant source-chunk uploads or candidate replacement. New continuation
program bytes are still independently transported and hash-bound.

The new intent/ACTIVE and journal live under `disable-only-continuations`.
Original ACTIVE, failure, intent, snapshots and source remain unchanged. The job
skips disable entirely, takes the existing supervisor flock, and repeats the
predecessor/new-operation inventory and current eligibility proof before one
request retirement/rebind/start. The later daemon-reload may clear predecessor
execution history too; final checks still require exact typed loaded commands,
original failed scalar status/invocation, terminal cgroups and immutable original
files. Any unknown marker or outcome leaves retained evidence and prohibits replay.
There is no automatic continuation or rollback; this adds no backup request.

The reviewed program now has a 64KiB source/decompression cap. The actual complete
transport body still has its separate 64KiB cap, checked before Azure invocation.
A maximum source chunk is exercised through that sender; oversized source and
incompressible combined envelopes reject before transport. Observe modes execute
the supplied verified source without staging a program on the guest.

Synthetic tests cover reload-cleared runtime/caller and predecessor histories,
changed typed commands/hooks, terminal cgroups, unknown markers, under-lock drift,
retirement/start unknown outcomes and byte preservation. They establish no live
continuation, runtime restart, native backup or full-stack restore acceptance.
The continuation's read-only guest preflight passed with exact program bytes
`c27dd335c6a49b7ecf9215180d9f3e7294c162e742ba86d18babdda998430e10`.
It verified all sixteen preserved predecessor files and returned predecessor
proof digest `1a7ea1ee69a0cb6e4307ddac7f5019db25b95ce20d91d54ce8694e041f06d879`.
The probe created no continuation reservation or application mutation. Applying
and observing the continuation remain separate live gates.
