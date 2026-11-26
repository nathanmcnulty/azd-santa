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

The evidence below includes the native pilot follow-up and the isolated Zentral image recovery trial.

| Gate | Current evidence | Still required |
| --- | --- | --- |
| Automated installation | Fresh six-volume private candidate passed cold deployment/finalization and unchanged-source rerun; a fresh hostname-enabled candidate also passed cold azd installation/finalization with seven containers | Recovery faults and supported upgrade lifecycle |
| Reboot persistence | New six-volume admission/worker image preserved all seven container IDs and selected synthetic database state across reboot;24 post-reboot HTTP requests passed | Held requests, database tails, failed dependencies, delayed jobs and retry exhaustion |
| Credential rotation | Earlier selected private server passed all76 observations | Repeat on the new candidate; supported admin lifecycle and Intune/native delivery |
| Admission and proxy | Hosted Redis passed37 fenced Lua families; host cap accepted16/rejected4 connections; fresh private TLS passed24 synthetic sync requests, capacity429, Redis503/recovery200 and body413/header431 cases | Sustained-load containment, held-work/dependency fault matrix, native retries and broader application ingress qualification |
| Worker shutdown | Actual standalone Linux TERM/forkserver idle, held and forced-deadline cases passed | Real Kombu/broker callback and acknowledgement behavior in the selected image |
| Backup | A private stack completed a native encrypted capture and resumed its original runtime. A separate VM downloaded the capture from Azure Blob Storage and authenticated all 80,159,434 bytes against the pinned digest using the original Windows recipient. | Durable key custody and failure qualification |
| Retained images | A separate Azure VM verified 1.34 GB of encrypted Azure Blob copies and imported the exact pinned Linux amd64 images for Zentral, PostgreSQL, Redis, RabbitMQ and Elasticsearch. Each passed a network-isolated execution check. [Complete image-set evidence](https://github.com/nathanmcnulty/azd-santa/issues/97#issuecomment-7189943210) | Independently retained tooling distribution |
| Restore | The independently retained PostgreSQL 18.6 image booted the archived database over a Unix socket. Page checksums passed and the expected 236 migrations and 121 public tables were present. The signed recovery drill matched the separately reviewed source census across 227 relations and 838 rows. An earlier drill restored 26 Elasticsearch documents. [Database recovery evidence](https://github.com/nathanmcnulty/azd-santa/issues/97#issuecomment-7188335571) | Durable recovery orchestration, integrated activation, current-authority reissue and fault testing |
| Recovery state | The retained Redis AOF and RabbitMQ files stayed intact in quarantine. Fresh Redis rejected the archived identity. Fresh RabbitMQ authenticated its new user and reported zero queues. | Current-authority reissue |
| Integrated dependency check | A non-serving Zentral process used all five recovered images from one private Docker store. A later 4 GiB VM drill indexed one audit event alongside 26 restored documents through fresh RabbitMQ and the pinned event workers. The queues drained and the retained snapshot stayed intact. A separate sequential phase ran one task through Celery and verified its exact result in restored PostgreSQL. [Restored event delivery](https://github.com/nathanmcnulty/azd-santa/issues/53#issuecomment-7199797115) [Restored Celery task](https://github.com/nathanmcnulty/azd-santa/issues/53#issuecomment-7200272734) | HTTPS administrator recovery, simultaneous service activation, sustained-load and failure qualification, and native device recovery acceptance |
| Archived authority | The Azure receiver committed separate signed rewrap and quarantine plans on one isolated restore clone. Rewrap preserved the baseline. Quarantine neutralized two authority rows in one relation and preserved all 838 rows, the catalog, applied migrations and the other 226 relations. Activation remained closed and the receiver was deallocated. [Signed recovery evidence](https://github.com/nathanmcnulty/azd-santa/issues/53#issuecomment-7195096868) | Durable recovery orchestration and fault testing |
| Restored administrator | Azure Run Command delivered the signed approval and returned the original encrypted setup link. A later isolated Azure run initialized fresh Redis, used that run's original link in the app's Django request handlers, rejected reset replay and blocked profile access until TOTP verification. The test stubbed static asset resolution and intercepted audit delivery. [Live reissue evidence](https://github.com/nathanmcnulty/azd-santa/issues/53#issuecomment-7196648755) [Restored MFA evidence](https://github.com/nathanmcnulty/azd-santa/issues/53#issuecomment-7197526783) | TLS browser setup and device credentials |
| Secret coverage | The retained pilot had zero secret fields across the three covered models. A separate synthetic Fernet rewrap passed in the pinned image. | Apply and verify rewrap on a restored database with populated secret fields |
| Operator access | Private application-level MFA/recovery tests; selected HTTPS pilot completed human password/TOTP enrollment and administrator login through a source-IP-restricted window, then restored deny-all ingress | Automated customer setup and controlled recovery on the current candidate; deferred Entra Easy Auth roadmap #108 |
| Hostname TLS | Selected Azure hostname passed staging/production issuance; ordinary Windows and Linux trust verified the held endpoint; same certificate survived service restart; original deny policy restored | Renewal, DNS retirement/rate constraints, automated customer deployment and actual browser/Mac acceptance |
| Native Mac | Intune reported the app installed and all five Santa profiles succeeded for the pilot. The Monitor-mode Mac enrolled, synced and received a synthetic rule. A separate signed test executable ran before the fixture rule, was denied after sync, and ran after removal. The backend verified the committed rule, one matching blocked-event counter and an empty fixture ledger after rollback. The listener was stopped, deny-all was restored and the VM was deallocated. | Full installed payload evidence, event indexing and retention, credential rotation and recovery on the selected Mac |
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
