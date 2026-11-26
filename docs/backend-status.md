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

The evidence below includes the November 25 native pilot follow-up.

| Gate | Current evidence | Still required |
| --- | --- | --- |
| Automated installation | Fresh six-volume private candidate passed cold deployment/finalization and unchanged-source rerun; a fresh hostname-enabled candidate also passed cold azd installation/finalization with seven containers | Recovery faults and supported upgrade lifecycle |
| Reboot persistence | New six-volume admission/worker image preserved all seven container IDs and selected synthetic database state across reboot;24 post-reboot HTTP requests passed | Held requests, database tails, failed dependencies, delayed jobs and retry exhaustion |
| Credential rotation | Earlier selected private server passed all76 observations | Repeat on the new candidate; supported admin lifecycle and Intune/native delivery |
| Admission and proxy | Hosted Redis passed37 fenced Lua families; host cap accepted16/rejected4 connections; fresh private TLS passed24 synthetic sync requests, capacity429, Redis503/recovery200 and body413/header431 cases | Sustained-load containment, held-work/dependency fault matrix, native retries and broader application ingress qualification |
| Worker shutdown | Actual standalone Linux TERM/forkserver idle, held and forced-deadline cases passed | Real Kombu/broker callback and acknowledgement behavior in the selected image |
| Backup | A private stack completed a native encrypted capture and resumed its original runtime. A separate VM downloaded the capture from Azure Blob Storage and authenticated all 80,159,434 bytes against the pinned digest using the original Windows recipient. | Durable key custody, retained image verification and failure qualification |
| Restore | The retained pilot archive passed strict extraction and page checksum verification. Its PostgreSQL 18.6 cluster started in isolation and returned 121 public tables and 236 Django migration records before clean shutdown. | Durable quarantine, complete schema/row census, native Elasticsearch and application restore, current-authority reconciliation and fault testing |
| Operator access | Private application-level MFA/recovery tests; selected HTTPS pilot completed human password/TOTP enrollment and administrator login through a source-IP-restricted window, then restored deny-all ingress | Automated customer setup and controlled recovery on the current candidate; deferred Entra Easy Auth roadmap #108 |
| Hostname TLS | Selected Azure hostname passed staging/production issuance; ordinary Windows and Linux trust verified the held endpoint; same certificate survived service restart; original deny policy restored | Renewal, DNS retirement/rate constraints, automated customer deployment and actual browser/Mac acceptance |
| Native Mac | One Monitor-mode Mac enrolled, synced and received a synthetic rule. A separate signed test executable ran before the fixture rule, was denied after sync, and ran after removal. The backend verified the committed rule, one matching blocked-event counter and an empty fixture ledger after rollback. The listener was stopped, deny-all was restored and the VM was deallocated. | Fresh Intune status and full payload evidence, event indexing and retention, credential rotation and recovery on the selected Mac |
| Container Apps | Tracked comparison requirements | Equivalent full backend deployment, persistence/failure tests and measured cost comparison |

Detailed evidence: [private installation](private-vm-installation.md),
[fresh hostname/TLS policy loop](fresh-https-qualification.md),
[Azure-hostname certificate trials](azure-hostname-tls-qualification.md),
[selected native-pilot delivery](native-pilot-delivery-qualification.md),
[rotation](credential-rotation-qualification.md), [Redis Lua](admission-redis-qualification.md),
[worker signals](worker-posix-qualification.md), [backup](cold-backup.md) and
[restore design](restore-quarantine-design.md). Historical receipts remain bound
to their exact source, image and layout; passing source tests does not qualify
a rebuilt image or a physical Mac.

The selected VM's existing Azure-managed hostname has also passed actual ARM
ownership/linkage/DNS-property readback and resolved to the expected IP. The
restricted pilot verified TLS and one native sync. General ingress remains held
closed; separately authorized bounded source-IP trials have their own evidence
and explicit closure requirements. The successful native capture is recorded in
[its qualification report](private-native-capture-qualification.md). The
[off-host retention report](offhost-ciphertext-retention.md#azure-pilot-upload-and-independent-readback-2026-11-25)
records the independent byte verification and subsequent archive authentication.

## Development order

The one-Mac Monitor-mode pilot passed its controlled policy and event-counter
loop. Continue with native credential rotation and off-host recovery
qualification. Keep general public ingress disabled
until the admission requirements in #58 are qualified. Bounded source-IP pilot
windows require fresh target/runtime checks, retained application safeguards,
a listener deadline and explicit network restoration.
Administrators must not assemble JSON or copy local scripts to remote machines.

Retain full backup/restore, current-authority recovery, supported upgrades and
Container Apps parity as open requirements. Complete recovery before production
or wider rollout, while deferring additional generic recovery machinery until
the bounded native pilot demonstrates the core experience. Reuse the VM and
existing Redis, keep idle test VMs deallocated, and include storage/recovery
costs in the eventual comparison.

Administrator sign-in should move toward Entra Easy Auth rather than separate
application password/OTP enrollment. [Roadmap #108](https://github.com/nathanmcnulty/azd-santa/issues/108)
records the deferred evaluation for the VM and Container Apps options; no Easy
Auth integration or tenant authentication changes have been investigated yet.
