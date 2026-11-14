# Explicit host-only nsfs helper upgrade

This is one supported maintenance transition: `cold_backup.py` SHA-256
`7c6f0b25bc090b5c4efa03c47565e5a28e64a3eef2823e667885e951262a539a`
to reviewed `790ec1696dc8533ccf85c01947a882b2f6188f3fe5d5a2017f456e8a0b711433`.
It fixes unrelated Docker `nsfs net:[inode]` inventory parsing while retaining
protected mount rejection. It does not capture a backup or qualify restore.
The controller stays `f0a8961f64e48471eed71757805ae4e29ee080aef30c6ab9ec040eafaf443099`.
Application/dependency images, security policies, worker code, seven original
container IDs, volume/configuration bindings and generation token stay unchanged.

The separate operator command needs only the selected subscription/environment;
administrators do not edit JSON or run paths on the VM:

```powershell
# Offline source/bundle plan: no Azure request.
./experiments/vm/Update-PrivateBackendHelper.ps1 `
  -SubscriptionId <selected-subscription> -EnvironmentName <existing-environment>

# One explicit maintenance request after reviewing the plan/source.
./experiments/vm/Update-PrivateBackendHelper.ps1 `
  -SubscriptionId <selected-subscription> -EnvironmentName <existing-environment> -Apply

# Continue observing that same durable operation after a timeout or pending result.
./experiments/vm/Update-PrivateBackendHelper.ps1 `
  -SubscriptionId <selected-subscription> -EnvironmentName <existing-environment> -Observe
```

This command is never an azd hook or an automatic postprovision upgrade. It
reuses the existing deterministic 25-file bundler, cached Azure CLI Run Command
transport and `Get-SantaPrivateVmDeploymentTarget` selection. It does not log in,
switch accounts, grant roles, alter assignments or create an image. A normal
cached-session failure is a blocker; there is no device-code fallback.

## Required selection and source gates

- The original installer `ACTIVE`, context, full bundle, completion and terminal
  proof must match the selected ARM VM/immutable instance. The verified original
  relay's actual `status()` guards are reused, including loaded-unit failure and
  invocation checks. IMDS rechecks guest identity without requesting a token.
- The original runtime must be active, ready and **enabled**, with its exact unit
  bytes/MainPID command, expected effective properties/no drop-ins, old manifest, original seven-container generation,
  source/configuration/mount/image bindings and old helper hash. The new bundle
  must contain exactly those same 25 files, with only the reviewed helper bytes
  changed. Unknown suppliers, other source changes and differing targets reject.
- Any `backup-request.json`, including an unknown or completed request, blocks
  upgrade. It is never removed, modified, ignored or bypassed. The caller must
  exclude competing privileged lifecycle writers during maintenance; flock does
  not fence arbitrary root commands or backup producers before supervisor exit.
- Provide sufficient time before VM shutdown. Staging is bounded to 64 chunks,
  1 MiB compressed/2 MiB expanded and 256 KiB per source file. The immutable
  utility is separately hash-bound and at most 32 KiB. Each Run Command payload
  stays below 64 KiB; its bounded JSON receipt needs a matching terminal nonce.

The new utility and full candidate bundle are staged in separate immutable
directories. Old source, original installer `ACTIVE`/context/terminal/completion
receipts and operator bindings remain historical. The fresh installer's paths
and refusal to reinitialize retained state are unchanged.

## One durable maintenance operation

The host machine-produces old/new manifest, generation-anchor and unit snapshots
and checksums. The new manifest changes only the backup helper hash; the new
anchor changes only `manifest_sha256`. Its original generation token, IDs,
project and image binding are retained. The new unit changes its immutable
source path/manifest digest while retaining the existing service policy.

An exclusive fsynced upgrade intent/reservation exists before one independent
systemd oneshot submission. No Restart policy is added. The job then:

1. Rechecks original target/boot/MainPID/source, candidate bundle and all planned
   snapshot bytes. It records one disable intent, disables the originally
   enabled runtime and confirms that persistent boot hold. No stop occurs on
   a failed preflight.
2. Records one normal stop intent and stops the old unit once. It requires
   inactive/dead/success, no MainPID/job, then acquires the **existing** supervisor
   flock and proves all seven exact originals have stopped PIDs.
3. Rechecks the no-backup and immutable-source gates. Under that lock, it
   compare/replaces the manifest, anchor and unit, retaining originals and a
   durable intent for each promotion. No container/volume creation, replacement,
   deletion, migration, initialization, pull/build or admission binding occurs.
4. Reloads systemd and verifies the complete new source/configuration/ID tuple
   and unchanged historical bytes. Only then does it record one enable intent,
   restore the original enabled state, record one start intent, release flock
   and submit one normal start. Enabling is never used to admit a partial tuple.
5. Requires normal source-bound runtime readiness and the same seven IDs/token.
   It retains a separate nonsecret completion. Actual systemd successful exit0
   is recorded by ExecStopPost, bound to intent/completion/invocation. A
   completion file alone never establishes terminal success.

Stop is bounded to 240 seconds, start to 450, and the outer oneshot to 900.
The existing runtime's own bounded restart policy remains unchanged. After a
confirmed disable, pre-start failures retain the disabled runtime and every
partial file. A failed/unknown disable can leave the unchanged original runtime
enabled or active. There is no
automatic rollback to an old binding. If start/enable has an unknown result,
the fully checked new tuple may already be active or enabled. Upgrade acceptance
remains unconfirmed until terminal and current-binding observation pass; the
tool never guesses a second stop/start. External reboot/root actions remain
outside this cooperating maintenance protocol.

## Observation and recovery boundary

`-Observe` reads the same durable handle and authoritative named upgrade unit.
Hard kill, timeout or failed Result is actionable `failed`, even without a
failure file. Active/activating/deactivating jobs are `in-progress`. Missing unit
or missing terminal proof stays `unknown`; it is never permission to submit
again. Loaded unit failure overrides retained proof; invocation must match.
Completed observation additionally verifies current source, manifest/anchor/unit,
enabled runtime command, original IDs and unchanged installer-history bytes.

The public result contains only bounded hashes, unit handle, phase/submission
flags and a typed nonsecret completion. Private evidence retains old/new binding
snapshots and failure types. Credentials, raw Docker output and arbitrary
exception details are not exported by the upgrade receipt. The machine intent
is evidence of this explicit request, **not external authorization or a new
grant**. ARM operator authority must already exist.

Never rerun `-Apply` to recover an unknown operation. Repeated requests against
the retained reservation become observation only; execution markers forbid a
second disable/stop/start even if someone tries to restart the upgrade unit.
Recurring upgrades, rollback/resume of a failed partial transition and cleanup
of retained operations are deliberately unsupported. They need a separately
reviewed state-specific recovery procedure. Do not manually restart a disabled
partial tuple or replay fresh installation.

## Offline evidence and untested boundaries

Tests cover exact one-file preservation, immutable candidate rejection,
original relay invocation/failure negatives, durable ordering, one stop/start,
backup-request races, compare/replace drift, corrupt snapshots, partial
promotion retention, reboot hold, unknown start, real terminal-proof rules and
authoritative observer failure precedence. PowerShell tests exercise offline
planning, opt-in choreography, no resubmission and actual bounded public program/
nonce envelope construction with Azure mocked.

These are protocol/source tests. Actual privileged Linux/systemd durability,
Run Command delivery, shutdown timing, interruption/reboot faults and end-to-end
operator maintenance still require separately authorized VM qualification.
Preserving original volume/container identities is not an application-data
consistency, native ES/Kombu backup, restore or current-authority claim. Monitor,
one-Mac and private-ingress boundaries remain unchanged.

Local validation on 2026-11-14 passed template validation, the canonical permission
schema and all 239 Pester tests under PowerShell 7.6.9/Pester 6.2.0. The final
focused Python protocol suite passed 19 tests; the eight focused PowerShell
tests passed with Azure transport mocked. None executed a live stop/start or
qualified real Linux/systemd/Run Command behavior.
