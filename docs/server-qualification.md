# Real-server qualification and low-resource delivery

Updated 2026-11-06. The intended end state is a low-cost self-hosted Santa backend
that a small organization's administrator can deploy and maintain without becoming
a distributed-systems specialist. Both VM and Container Apps paths remain in scope,
VM first. Synthetic host tests are prerequisites, not delivery of that end state.

## Current decision: evaluate maintained software, do not adopt blindly

| Candidate | Actual operating footprint | Current finding |
| --- | --- | --- |
| Zentral | PostgreSQL, Redis, broker, event store, web, event worker, Celery | Active protocol work; evaluate real runtime and UI before committing. Standard image includes evaluation-licensed enterprise files. |
| Moroz | Go executable, TOML rules, event files | Small, but inspected source lacks device authentication, has legacy sync handling and old image/dependencies. Exposing it is not a secure low-maintenance deployment. |
| Rudolph | AWS Lambda/API Gateway/DynamoDB/Kinesis/S3 | An Azure port is a rewrite, not a VM deployment. Inspected authorizer leaves authentication unfinished. |

Exact source pins inspected:

- [Zentral 88e67b3ce49033aab028029937a6e14f7c489073](https://github.com/zentralopensource/zentral/tree/88e67b3ce49033aab028029937a6e14f7c489073),
  substantive upstream update 2026-11-02.
- [Moroz e82dacb3329ce0144bc74f5366785455067fe4b3](https://github.com/groob/moroz/tree/e82dacb3329ce0144bc74f5366785455067fe4b3),
  latest inspected master commit 2025-05-19.
- [Rudolph 34f5ebbd9950520c5c84024d9fca23faafba13ba](https://github.com/airbnb/rudolph/tree/34f5ebbd9950520c5c84024d9fca23faafba13ba),
  latest inspected master commit 2026-07-27.

Zentral's database-backed Celery **result storage is not an event queue**.
The inspected server has no built-in PostgreSQL event store/queue replacing its
broker and search store. Redis also supplies notification pub/sub. Omitting those
services without supported substitutes would hide functionality and maintenance
work, not demonstrate equivalent low-cost operation. Omit nginx and Prometheus
only for private loopback evaluation; they are not required to test the app itself.

The pinned [Docker workflow](https://github.com/zentralopensource/zentral/blob/88e67b3ce49033aab028029937a6e14f7c489073/.github/workflows/docker.yml)
sets `push: false`; declared image names do not prove published images exist.
Build exact source privately, record the resulting local image ID, and pin
dependency images by registry digest. Do not invent an official image digest.

## Evaluation packet, not a production template

`experiments/server/` provides original qualification tooling:

- `zentral-source.lock.json` pins the full archive URL, commit and SHA-256.
- `prepare_source.py` verifies downloaded bytes before safe extraction and
  refuses existing destinations. It executes no upstream code.
- `bootstrap-host.sh` installs distribution Docker tooling on the isolated VM.
- `Start-ZentralQualification.ps1` validates the tagged host, stages verified
  source, sets a two-hour lab shutdown guard, derives a core-experiment
  Dockerfile without proprietary `ee/` or dev/AWS/GCP runtime stages, and
  submits a named systemd build. Inspect that same unit after a
  timeout; never treat a missing observation as permission to start over.
- `prepare_zentral_eval.py` accepts the built local image ID and four
  digest-pinned dependency references. It derives non-debug configuration from
  inspected upstream bytes, generates private secrets and seven-service Compose,
  binds web to localhost and reserves a new destination exclusively. It does
  not start services, enroll devices or publish images. Memory limits are test
  constraints, not capacity evidence.
- `dependency-images.lock.json` records actual registry digests acquired on the
  Linux evaluation host on 2026-11-06 from PostgreSQL 18, Redis 7.2, RabbitMQ 3
  and Elasticsearch 9.2.1. The pull unit completed successfully. These are
  compatibility-reference inputs, **not approved production versions**: lifecycle,
  vulnerability and license review remain required, especially replacing the old
  RabbitMQ line before a production recommendation. Do not silently substitute
  newer tags while interpreting a test receipt against this lock.

The new lab uses `sub-patriot-lab`, freshly Enabled on 2026-11-06, group
`rg-azd-santa-vm-qualify-20261106`. All inbound NSG traffic is denied. The earlier
`sub-mvp` synthetic host remained deallocated at readback. No real Mac settings,
credentials, profiles, assignments or rules were changed by this evaluation.

The standard upstream build copies `ee/`. Our first intended artifact instead
uses `prepare_core_build.py` to derive a separate `Dockerfile.core` from verified
canonical archive bytes, omit those copies, retain upstream license/build
notices, and assert core app presence/EE tree absence. Reviewed core registry
files omit unavailable enterprise OIDC/SAML and store imports, registrations,
and serializer fields. Their input/output hashes and in-file modification
notices travel with the image; Elasticsearch and other core stores remain.
No proprietary functionality is reimplemented or license check bypassed. That
exclusion is not a complete dependency-license inventory or production clearance.
The upstream
[license](https://github.com/zentralopensource/zentral/blob/88e67b3ce49033aab028029937a6e14f7c489073/LICENSE)
permits development/testing of those components without a commercial agreement,
not production use or publication of that resulting image. Keep evaluation
artifacts private and retain upstream notices. A validated community-only image,
its dependency inventory and allowed production feature set remain separate
gates. Our own code's Unlicense does not replace third-party terms.

The current canonical backlog validator caught an older in-progress item with
no owner claim; a new truthful coordinator claim is now recorded, without
rewriting its historical evidence. Markdown was rendered with the canonical
renderer under a call-local `ConvertFrom-Json -DateKind String` wrapper so that
existing ISO timestamps retain their offsets/fractional precision. The current
renderer otherwise localizes timestamps; no canonical files were modified.

## Acceptance before selecting the backend

1. Build, migrate and provision the real app; record local image identity,
   complete build logs, dependency digests, runtime versions and upstream notices.
2. Measure idle/startup/load RAM, CPU, disk and OOM state on the actual VM.
   If 4 GiB is insufficient, report it; do not silently resize or drop telemetry.
3. Exercise authenticated real HTTP sync with synthetic identities and an
   explicit Monitor configuration: missing/wrong credentials, current sync type,
   exact rule bytes, paging, retries and persisted postflight receipt. Do not run
   upstream example clients with old external URLs or disabled TLS verification.
4. Restart and verify the same app/database/event state. Test backup restoration,
   including protection against reviving revoked credentials or old policy.
5. Qualify a production-usable community package and security model: operator
   MFA, least privilege, explicit rule approval, uniquely authenticated device
   enrollment, rotation/revocation and trusted TLS ingress. A DN HTTP header is
   not certificate validation or binding to a claimed device ID.

## Full delivery still required

After qualification, integrate the selected backend into optional azd modes with
automated setup, health checks, patch/upgrade and backup/restore tooling. Admins
should choose subscription/region, initialize their admin account/MFA, and enroll
approved devices—not manually assemble containers, certificate files or JSON.
No Sentinel, Kubernetes, commercial PKI or paid SSO dependency is assumed.

Then close the separate one-Mac Monitor gates in #33 using MDM-delivered
configuration and credentials. A completed HTTP request is not proof of local
rule application. Do not promote to Lockdown. Finally implement #46 against the
same backend and acceptance tests, comparing full running/idle/storage/network/
backup costs rather than unequal bare-compute figures.

No production readiness, core-only license clearance, native Mac interoperability
or Container Apps parity is claimed by this document. The active goal remains
open until these end-to-end delivery gates are actually verified.

## Actual test findings, 2026-11-06

- Docker/Compose installation initially failed to complete package downloads
  from the Azure Ubuntu mirror. State was checked before each retry. A scoped
  installer source list using Canonical's HTTPS archive fixed the demonstrated
  issue without changing the VM's global repository configuration.
- Verified installed Docker 29.1.3 and Compose 2.40.3. The independent image-pull
  job completed and recorded the four immutable dependency references above.
- First core image build completed successfully as local image
  `sha256:7144154a1a27c5c27d85064df5b52a9eb05a31ca11e0111ae09ddd4d50ca34b9`.
  This image was **not** accepted as a working backend: actual Django checks
  failed with `ModuleNotFoundError: server.settings`.
- Runtime inspection proved source directories were root-only: Python's safe
  tar filter ignores directory modes, and the transport's umask 077 became
  image directory permissions after Docker COPY. The source acquirer now
  preserves a private parent but normalizes verified source directories to 0755;
  a POSIX regression test and non-root image read guard cover this boundary.
- Source review additionally found unconditional core-registry imports of the
  omitted enterprise modules. The derived build removes only those registrations,
  retains core LDAP support and marks the modified file. The fixed image rebuild
  is a separate named job; its build/startup results are not inferred from the
  original image's successful compilation.
- The permission-fixed image
  `sha256:c8e4299f9fd46416ffbc2541a73f6bdcc97ee513c33484e9f08f00d2c6bce43b`
  passed actual Django checks and ran all seven services. One idle container
  memory sample totaled approximately 1.4 GiB on the 4-GiB VM. This is not a
  startup/load/fleet capacity guarantee.
- Real loopback HTTP passed with two synthetic devices and separate restricted
  credentials: missing/wrong credentials and cross-device requests rejected,
  explicit Monitor preflight, six exact rules paged 5+1, empty and positive
  event uploads, and committed postflight/database counters. No native Mac was
  contacted. These counters alone did not prove event storage.
- Elasticsearch initially had no index because no Store record was provisioned.
  A direct import exposed an unavailable enterprise store serializer. Upstream
  module discovery suppressed the ImportError, and provisioning success status
  did not prove that a Store had been saved. The build now narrows the two exact
  Apache/core store files; staging explicitly imports the required provisioner.
- The resulting image
  `sha256:9e3a64912091812d7f2eede5a34b96c83d53839e7cd48b96b511e22a00bf90bf`
  built successfully. `upgrade_core_runtime.py` verified the existing fixture
  before changing anything, retained original files and volumes, and recorded an
  explicit image-only Compose/fixture hash transition. Actual serial migration,
  provisioning, one expected Elasticsearch Store and active store/enrich/process
  queue consumers passed before the listener restarted. Existing credentials,
  six-rule ledger and committed postflight state then passed database readback.
- The two earlier acknowledged samples are not claimed as indexed. A fresh
  reopened-fixture HTTP probe after consumer readiness passed, and a separate
  Elasticsearch query found exactly two `santa_event` records for the fixture's
  two synthetic serials. The upgraded Compose SHA-256 is
  `50e6be64ec5fa78122fabc334ef4f47065aba54758ffed8fa24e4df3bdeee846`.
  A post-probe sample used approximately 1.6 GiB of container memory in total;
  no fleet-scale or peak-load capacity claim follows from that sample.
- Actual Azure restart completed successfully. Boot ID changed from
  `7730f5ff-f8de-4032-9091-ac703d1b3239` to
  `be42f48c-6769-49b0-ab7a-7d928fc87d32`. After explicit manual resume with
  store/consumer readiness checks, database state (including credentials/rule
  ledger/postflight/counters) matched the pre-reboot readback exactly, and the
  same two indexed events remained. `record_persistence.py` compares these gates
  before sending any additional sync traffic; it cannot initialize the fixture.
  This proves private restart persistence, not automatic service recovery.

Backup/restore, mandatory MFA (#51), credential lifecycle (#52), native Mac
behavior (#33) and equivalent Container Apps operation (#46) remain open gates.
