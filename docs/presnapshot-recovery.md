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
full seven-application restore or current-authority reissue. Those remain separate
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
