# Machine-produced backend installation receipt

`Complete-SantaBackendInstallation` is a bounded finalization slice toward the
real azd VM installer. It consumes the selected installer's eleven nonsecret
deployment/runtime outputs as an in-memory object, observes the initialized
private backend, creates the installation receipt and passes its original
checksum to `New-SantaOperatorDeploymentBinding`. No administrator constructs
JSON or downloads a remote local-file script to complete those steps.

This does not install Docker, acquire/build images, generate a runtime, migrate,
provision, initialize the security store or start services. Those actual installer
steps and an azd hook remain unimplemented. The existing VM-lab azd template
provisions a private test host only. Its outputs are intentionally insufficient;
missing runtime facts or incomplete initialization return deployment-not-ready.
No source implementation or mocked test establishes a live azd deployment.

The selected installer must supply exact image ID, Compose path/hash, configured
HTTPS origin, tenant/subscription/environment and resource/immutable-VM IDs from
its own deployment context. These expectations never come from a setup mutation
or arbitrary Docker discovery. The function pins bundled source commit and
recovery/sealer hashes itself, creates a fresh context and public-only recipient,
and reuses cached ARM account/group/VM checks. It never authenticates, grants
permissions, changes active subscription or mutates azd state.

The observer carries a compressed, checksum-pinned copy of the existing host
attestor inline, loaded under a module name that cannot execute its setup main.
Its stdlib producer runs under isolated Python and calls only attestation and
readiness operations. No installed human account is created, reset or queried as
a mutation target. The structural recipient probe uses fixed synthetic identity
strings solely to verify supported crypto preparation. Its private key stays in
local process memory and is disposed; no setup URL is generated or returned.

The host attestor checks selected IMDS subscription/resource/immutable VM,
private Compose/source/image/env/port/mount/network identities and the admitted
security store. It returns the exact seven already-inspected container IDs.
Readiness keeps those IDs throughout; it never re-resolves, starts or restarts a
service. The selected web process must demonstrate:

- The restricted runtime database identity and effective privileges, using the
  installed read-only `check_runtime` check; no owner credential is used.
- No pending migration plan, using read-only migration inspection.
- Exactly one provisioned Elasticsearch admin Store targeting the private
  `http://elastic:9200` backend.
- A responsive one-node search cluster in yellow/green state, without proxy or
  redirect use. No index is created by the observer.

The exact RabbitMQ container must report active consumers for the selected
Store queue, `enrich_events` and `process_events`. Missing schema/store/security
state, zero consumers, unhealthy search or any source/identity mismatch emits no
ready marker. The observer never repairs initialization to make a probe pass.
The process has a 150-second alarm and each child command a smaller timeout.

Source caps are 24 KiB for the host attestor, 8 KiB for the producer, 24 KiB for
their compressed composite, 8 KiB for the public request and 44 KiB for the full
shell payload. A successful terminal Run Command must contain exactly one bounded
3200-byte receipt and a later exact context completion marker. The client checks
source fingerprints, all six readiness gates and every selected output before
persisting anything. Only nonsecret metadata enters Azure output; no credential,
private key or setup link is involved. Raw failure output is never echoed.

The machine-produced installation receipt uses exclusive, flushed local creation
in a trusted environment directory. Its original checksum flows immediately to
the binding consumer, which performs a fresh read-only target check before the
exclusive binding write. Two preflight boundaries protect selection before
remote observation and again before binding publication. The returned metadata
also records context/program/attestor/producer/recovery/sealer hashes and source
commit for the installer to retain in its deployment journal.

The initialized readiness projection is not browser/TLS/native-Mac, synthetic
HTTP sync, event-index receipt, backup/restore or production acceptance proof.
The existing consumer therefore still labels runtime acceptance not-performed.
Actual installer lifecycle integration, authoritative azd output wiring and
trusted reachable HTTPS remain required. Selected private finalization passed
the independent live qualification below. Offline
tests execute no Azure, VM, Docker or authentication action; they cover source
compilation/bounds, read-only scope, readiness failures, receipt tampering and
automatic producer-to-consumer file flow using mocked Azure/Docker results.

## Actual private finalization, 2026-11-06

The selected cached ARM context and the role-separated VM runtime passed the
real inline observer, including all six gates and the current restricted SQL
identity. Machine-created installation expectations were passed in memory;
the function produced the installation receipt and operator binding without
manually constructing the binding artifact. The deployed image and Compose
identities are recorded in the
[database-role qualification](database-role-separation.md#actual-private-qualification-2026-11-06).

Attestor SHA-256:
`0b0fe20a28e99fb2455d2e311d60d397f274ef617072836f7116364254501dc8`;
producer SHA-256:
`935db2716c89c78bb0c5ace4b330589c75ca00b28db8bcc0d76f128c2b27b602`;
composite program SHA-256:
`c791a54c49c9cd2dbbe63d5f3bd77803c4d2402d29d8dbc15ab352cbcc727478`.
The observed context SHA-256 was
`ffc64cce0677914d9489e92b3a45962a6b6bc38d9c30ac98a19c73e56880ec94`.

The resulting binding was then consumed by the supported operator setup
entrypoint. It privately delivered first-human bootstrap and targeted recovery
for one synthetic operator using normal application credentials. Independent
database and event-store readback verified preserved flags, a changed password
fingerprint and the expected bootstrap/recovery audit records. The producer's
read-only probe itself issued no operator mutation. No browser was opened and
no plaintext setup URL was exported into Azure, Git or these docs.

The selected local private qualification directory retains `installation.json`,
`operator-binding.json`, `finalization-receipt.json` and setup checkpoints.
Private server evidence includes `operator-role-recovery-receipt.json` under the
role-separated runtime. Recipient keys were disposed rather than persisted.
This qualifies the private finalizer and its handoff, not an azd provision/deploy
hook, public TLS, a native endpoint or real-user browser/password/MFA completion.
