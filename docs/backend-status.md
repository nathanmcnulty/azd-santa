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

As of 2026-11-14 UTC, these are separate gates:

| Gate | Current evidence | Still required |
| --- | --- | --- |
| Automated installation | Fresh six-volume private candidate passed first-attempt cold azd deployment/finalization and unchanged-source rerun; seven running containers verified | Recovery faults and supported upgrade lifecycle |
| Reboot persistence | New six-volume admission/worker image preserved all seven container IDs and selected synthetic database state across reboot;24 post-reboot HTTP requests passed | Held requests, database tails, failed dependencies, delayed jobs and retry exhaustion |
| Credential rotation | Earlier selected private server passed all76 observations | Repeat on the new candidate; supported admin lifecycle and Intune/native delivery |
| Admission and proxy | Source-bound hosted Redis passed37 fenced Lua families; held-closed proxy source exists | Integrated HTTP overload/failure/recovery, proxy limits, native retries and public TLS |
| Worker shutdown | Actual standalone Linux TERM/forkserver idle, held and forced-deadline cases passed | Real Kombu/broker callback and acknowledgement behavior in the selected image |
| Backup | Native snapshot/drain/encryption/controller source and offline guards | Actual application snapshot, encrypted capture, resume, failures and off-host retention |
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

## Development order

Finish the fresh VM installation and recovery gates, qualify native backup and
isolated restore, then enable trusted operator/device access and validate the
single Mac. Build Container Apps against the same acceptance criteria afterward.
Reuse the VM and existing Redis, keep idle test VMs deallocated, and include
storage and recovery costs in the eventual comparison.
