# Self-hosted Azure backend status

The intended administrator experience is one optional azd deployment, guided
MFA setup and Intune-delivered Mac configuration, with automated maintenance and
recovery. That complete experience is still being built. The default Intune-only
deployment remains independent of this backend and Azure compute.

The current candidate uses pinned community Zentral core on a private Azure VM.
No public sync endpoint or customer browser setup is ready for use. The nested
[VM template](../experiments/vm/README.md) is the private qualification path.
Administrators should not assemble containers, receipt JSON or remote scripts.

## Evidence and remaining work

As of 2026-11-15 UTC, these are separate gates:

| Gate | Current evidence | Still required |
| --- | --- | --- |
| Automated installation | Fresh six-volume private candidate passed first-attempt cold azd deployment/finalization and unchanged-source rerun; seven running containers verified | Recovery faults and supported upgrade lifecycle |
| Reboot persistence | New six-volume admission/worker image preserved all seven container IDs and selected synthetic database state across reboot;24 post-reboot HTTP requests passed | Held requests, database tails, failed dependencies, delayed jobs and retry exhaustion |
| Credential rotation | Earlier selected private server passed all76 observations | Repeat on the new candidate; supported admin lifecycle and Intune/native delivery |
| Admission and proxy | Source-bound hosted Redis passed37 fenced Lua families; held-closed proxy source exists | Integrated HTTP overload/failure/recovery, proxy limits, native retries and public TLS |
| Worker shutdown | Actual standalone Linux TERM/forkserver idle, held and forced-deadline cases passed | Real Kombu/broker callback and acknowledgement behavior in the selected image |
| Backup | One private synthetic stack completed native snapshot, worker drain, encrypted capture and original-runtime resume; independent Storage deployment succeeded and its protected configuration was selected | Off-host transfer, independent byte verification, portable keys/images, full restore and failure qualification; deployment observer normalization fix remains #102 |
| Restore | Authority/encryption inventory; ciphertext authentication and bounded offline secret-rewrap primitives with actual synthetic crypto tests | Strict extraction, complete schema/row census, isolated application restoration, current-authority reconciliation and complete fault testing |
| Operator access | Private application-level MFA and recovery tests on earlier selected images | Trusted browser flow, customer enrollment and controlled recovery |
| Native Mac | Intune baseline and one-device pilot are separate from server tests | Actual sync, rules, events, rotation and recovery on the selected Mac in Monitor mode |
| Container Apps | Tracked comparison requirements | Equivalent full backend deployment, persistence/failure tests and measured cost comparison |

Detailed evidence: [private installation](private-vm-installation.md),
[rotation](credential-rotation-qualification.md), [Redis Lua](admission-redis-qualification.md),
[worker signals](worker-posix-qualification.md), [backup](cold-backup.md) and
[restore design](restore-quarantine-design.md). Historical receipts remain bound
to their exact source, image and layout; passing source tests does not qualify
a rebuilt image or a physical Mac.

The selected VM's existing Azure-managed hostname has also passed actual ARM
ownership/linkage/DNS-property readback. That does not establish DNS resolution,
trusted TLS, public admission or native Mac sync. The HTTPS candidate remains
held closed. The successful native capture is recorded in
[its qualification report](private-native-capture-qualification.md).

## Development order

The next acceptance milestone is the one-Mac Monitor-mode policy/event loop.
Prioritize its guarded HTTPS/admission and operator-MFA prerequisites, then
Intune delivery and actual device receipt. Keep public ingress disabled until
the admission requirements in #58 are qualified; do not bypass the held proxy.
Administrators must not assemble JSON or copy local scripts to remote machines.

Retain full backup/restore, current-authority recovery, supported upgrades and
Container Apps parity as open requirements. Complete recovery before production
or wider rollout, while deferring additional generic recovery machinery until
the bounded native pilot demonstrates the core experience. Reuse the VM and
existing Redis, keep idle test VMs deallocated, and include storage/recovery
costs in the eventual comparison.
