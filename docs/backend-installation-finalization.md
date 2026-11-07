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
Actual installer lifecycle integration, authoritative azd output wiring, trusted
reachable HTTPS and independent live qualification remain required. Offline
tests execute no Azure, VM, Docker or authentication action; they cover source
compilation/bounds, read-only scope, readiness failures, receipt tampering and
automatic producer-to-consumer file flow using mocked Azure/Docker results.
