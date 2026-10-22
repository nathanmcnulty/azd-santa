# Self-hosted Azure public-sync spike (#37)

Assessment: **2026-10-19**. Offline, synthetic evidence only. The selected direction
is self-hosted Azure; **no implementation, SKU, auth flow or deployment is selected**.
No Workshop subscription or credentials are prerequisites. No Azure resources,
accounts, grants, ingress, device credentials, profiles or rules were created.
The default Intune-only baseline remains compute-free, Monitor, one device, and
byte-for-byte unchanged. This document is not an exact-target execution packet.

For the subsequent minimal-total-cost community and optional Workshop direction,
see [the research addendum](community-and-workshop.md). It preserves this spike's
historical test claims and does not qualify a production implementation.

## Decision before implementation

**Go:** an original, loopback-only public-v1 contract/security model, plus the
bounded evaluation below. **No-go:** committing to a production custom server,
deploying Zentral unchanged, or connecting the pilot based on these tests.
Prefer a maintained compatible server if its auth adapter and operating burden
prove smaller than owning a server. Zentral remains a reuse candidate, not a
qualified compatible implementation for this client. A custom backend remains a
conditional alternative if measured footprint and required identity isolation
justify the substantially larger maintenance responsibility.

This spike implements neither production option. The local model has no cloud
SDK, persistence, enrollment, approval or publication endpoint. Test fixture
approval labels and credentials have no real-world authority. The tests exercise
our model over HTTP, not Santa, Zentral, TLS, Azure or a generated protobuf client.
No native interoperability or enforcement is claimed.

## Reconciliation and ownership

Read main `b636b4c10cf2947348114839a3c4b226558c6de5`, all open drafts (only #31
at assessment), and issues #32/#33/#36/#37 plus their comments before editing.
This branch stacks on reviewed #31 `4b837cd9447fcf231706b72005545bbe4092f25d`.
Reuse its 111-test/eight-check receipt and #32 review; do not redo SANTA-003
provider discovery or change its candidate/profile bytes. SANTA-008 maps only to
#37. #36 owns non-mutating provider-profile planning; #33 owns real-Mac receipt
and selected-server qualification; #32 owns the unchanged #31 review. Their live
gates remain open. The previously pending Defender Live Response action must be
resumed by its owner, never resubmitted by this spike.

## Immutable public contract

Client: Santa **2026.8.244**, source
[`dbe97b0aa0f5929feece5f4cbd2c69362c271abc`](https://github.com/northpolesec/santa/tree/dbe97b0aa0f5929feece5f4cbd2c69362c271abc).
Its [MODULE.bazel](https://github.com/northpolesec/santa/blob/dbe97b0aa0f5929feece5f4cbd2c69362c271abc/MODULE.bazel)
pins public protos to **`68fc3caa33bbdf14a980229f50a25d80bfc72a33`**.
The authoritative public message/enum/JSON annotations and HTTP bindings are
[`sync/v1.proto`](https://github.com/northpolesec/protos/blob/68fc3caa33bbdf14a980229f50a25d80bfc72a33/sync/v1.proto),
SHA-256 `1414f060c8014b6199bd3794b2794301532cd9a16411820e972eca3c3dbea00d`.
The model supports only the explicitly tested JSON subset, not the whole schema.

| Contract | Immutable implementation evidence and consequence |
| --- | --- |
| Methods/routes | Each stage's `stageURL` appends `preflight/{machineID}`, `eventupload/{machineID}`, `ruledownload/{machineID}`, `postflight/{machineID}` relative to SyncBaseURL. `SNTSyncStage.requestWithData` uses POST. Public proto agrees. Keep a trailing-slash base URL in future plans; never place a secret in it. |
| Serialization | `SNTSyncStage.requestWithMessage` uses protobuf JSON by default (`application/json`); explicitly enabled binary transfer uses `application/x-protobuf`. Proto `json_name` overrides matter: machine_id, serial_num, rules_received; unannotated fields serialize lowerCamelCase (syncType, clientMode, batchSize). Protobuf JSON accepts proto field names too, explaining legacy snake_case responses. The model emits valid JSON spellings and explicitly rejects binary. |
| Compression | `SNTConfigurator.syncClientContentEncoding`: default **zlib-wrapped deflate**, optional gzip or none. `SNTSyncStage` sets Content-Encoding only when compression returns data. Raw DEFLATE is not the default. Our bounded decoder accepts zlib/gzip/none and rejects other encodings, incomplete/trailing streams and expansion beyond 64 KiB. |
| Authentication | `SNTSyncManager.createSyncStateWithStatus` supplies filtered SyncExtraHeaders at session level, HTTPS server roots and client-certificate file/CN/issuer options, refuses redirects. Client cert validation/identity binding must occur at the server. The machine ID is caller controlled and is never authentication. Public-v1 XSRF fallback POSTs `xsrf/{machineID}`; it is not enrollment. |
| Retry/error | `SNTSyncStage.dataFromRequest`: at most five attempts; exponential waits 4/8/16/32 seconds. A 200 plus transport error is failure. No-network exits; most 4xx exit except 408/429; 403/cert-required/cannot-parse can fetch XSRF then retry. XSRF fetch timeout 10s; normal stage requests 30s. No Retry-After handling in this path. Do not assume instant scale-from-zero or unlimited retries. |
| Events | `SNTSyncEventUpload`: batches (default 50), optional if none. Clean sync skips upload unless EnableCleanSyncEventUpload; successful handling still removes local event IDs even when upload was skipped, so skip does not mean preserve. Public v1 has **no event_id**. The old clean-sync fixture's event_id values are internal fixture IDs, not the wire contract. |
| Rule pages | `SNTSyncRuleDownload`: machine_id plus optional opaque cursor; all pages collected before database update. Empty cursor ends paging. Page error returns nil, so no partial apply. Bad rules can be ignored; received and processed counts differ. No signed revision or rollback guard is enforced by this public client protocol. |
| Empty clean | Source `SNTSyncRuleDownload.sync` returns YES before database cleanup when *all converted/accepted* rule lists are empty (including when every wire rule was rejected). The general sync guide describes empty-set deletion differently. Pin source over that prose: an empty clean response is **not a reliable deletion mechanism** for this pin. Our model refuses all empty snapshots, even intentionally labeled ones; deliberate deletion requires a separately tested REMOVE-rule/native plan. |
| Postflight | `SNTSyncPostflight` calls performRequest but ignores the returned error, updates settings and returns YES. Therefore a client success message is not proof that the server recorded completion. Server receipt, downloaded rule application and controlled execution are separate evidence. |

Source files, all at the client commit above:
[stage transport](https://github.com/northpolesec/santa/blob/dbe97b0aa0f5929feece5f4cbd2c69362c271abc/Source/santasyncservice/SNTSyncStage.mm),
[configuration](https://github.com/northpolesec/santa/blob/dbe97b0aa0f5929feece5f4cbd2c69362c271abc/Source/common/SNTConfigurator.mm),
[session/auth](https://github.com/northpolesec/santa/blob/dbe97b0aa0f5929feece5f4cbd2c69362c271abc/Source/santasyncservice/SNTSyncManager.mm),
[preflight](https://github.com/northpolesec/santa/blob/dbe97b0aa0f5929feece5f4cbd2c69362c271abc/Source/santasyncservice/SNTSyncPreflight.mm),
[events](https://github.com/northpolesec/santa/blob/dbe97b0aa0f5929feece5f4cbd2c69362c271abc/Source/santasyncservice/SNTSyncEventUpload.mm),
[rules](https://github.com/northpolesec/santa/blob/dbe97b0aa0f5929feece5f4cbd2c69362c271abc/Source/santasyncservice/SNTSyncRuleDownload.mm),
[postflight](https://github.com/northpolesec/santa/blob/dbe97b0aa0f5929feece5f4cbd2c69362c271abc/Source/santasyncservice/SNTSyncPostflight.mm).
No Workshop-only push/commands, network extension, private sync-v2 behavior,
proprietary server implementation or parity is reproduced. Public-v1 ordinary
polling is the selected *spike scope*, not a production feature promise.

## Existing server versus minimal implementation

Maintained candidate: **Zentral v2026.5.16**, peeled immutable commit
[`feede7e0c28226ae25df87339cdda24f704ecf6f`](https://github.com/zentralopensource/zentral/commit/feede7e0c28226ae25df87339cdda24f704ecf6f),
2026-10-16, which fixes Santa target-ID exhaustion. Tag and source are pinned;
no container image digest, deployed release or dependency license inventory has
been qualified. Do not deploy an unpinned image based on this source pin.

- Reuse advantage: existing Santa rule, enrollment, inventory and administration
  implementation with active fixes; much less protocol ownership than custom.
- At this exact pin, [profile generation](https://github.com/zentralopensource/zentral/blob/feede7e0c28226ae25df87339cdda24f704ecf6f/zentral/contrib/santa/utils.py)
  uses a clean URL plus `Zentral-Authorization: Bearer <enrollment secret>`.
  Secret URLs are deprecated compatibility routes. This updates the dated #31
  discovery for this newly pinned candidate; its historical guidance is retained.
- [Authentication/lookup](https://github.com/zentralopensource/zentral/blob/feede7e0c28226ae25df87339cdda24f704ecf6f/zentral/contrib/santa/public_views.py)
  still scopes that bearer to an enrollment. A claimed hardware UUID/serial does
  not prove per-device possession. Optional certificate auth checks a parsed
  X-SSL-CLIENT-S-DN; the inspected sync path does not bind that DN to the UUID.
- Azure Container Apps [forwards client certificates](https://learn.microsoft.com/en-us/azure/container-apps/client-certificate-authorization)
  in X-Forwarded-Client-Cert, not Zentral's header. A trusted adapter must validate
  chain, time, revocation and registered device binding, strip spoofed headers,
  and isolate the backend. A require-certificate toggle alone is insufficient.
- [Compose](https://github.com/zentralopensource/zentral/blob/feede7e0c28226ae25df87339cdda24f704ecf6f/docker-compose.yml)
  includes PostgreSQL, Redis, Elasticsearch, RabbitMQ, web/workers/Celery, nginx
  and Prometheus. Its [deployment guide](https://github.com/zentralopensource/zentral/blob/feede7e0c28226ae25df87339cdda24f704ecf6f/docs/content/deployment/docker-compose.md)
  is an evaluation/simple-deployment reference. Django runserver and disabled
  Elasticsearch security in development settings are not a production recipe.
  An Azure evaluation VM with durable disks is possible; managed decomposition
  adds resources and operating cost. No minimum Azure size is established.

Minimal custom candidate: one stateless sync/auth container plus durable device,
snapshot/session/cursor/receipt state and a bounded event queue/store. Azure
Container Apps Consumption with durable Storage is one candidate, not a SKU
selection; avoid in-memory state across replicas/cold starts. State changes need
atomic conditional writes and tenant/device partitioning. A separate authenticated
operator service publishes only immutable approved snapshots, with readers lacking
write permission. It removes general-purpose inventory/search components, but
owns every protocol edge above, admission limits, enrollment, revocation, backup,
upgrade and compatibility testing. Four routes are not four simple CRUD methods.

### Licensing/provenance gate

Zentral's [pinned LICENSE](https://github.com/zentralopensource/zentral/blob/feede7e0c28226ae25df87339cdda24f704ecf6f/LICENSE)
is Apache-2.0 except `ee/` and explicitly marked ZPEL files, which use Zentral Pro
Evaluation License 1.0. The inspected `zentral/contrib/santa/` sources are outside
`ee/`; this does not clear an entire image, enterprise feature or dependency.
Before reuse: inventory the exact image contents and dependencies, retain required
LICENSE/NOTICE/attribution, mark modifications, assess redistribution/hosting terms
and obtain clarification for unresolved commercial use. Do not call this legal
clearance. Santa and public protos have Apache-2.0 source notices; this model is
original code and vendors neither upstream. No Workshop code or assets are copied.

## Enrollment, operator and rule authority proposal

These are requirements for a later implementation, not implemented grants:

1. Operator signs into a separate Entra-protected admin audience with explicit
   least-privilege roles. Device sync never accepts an operator JWT, and an
   enrolled device never gains admin access. Validate tenant/issuer/audience and
   role server-side; separate enrollment, approval and publication duties.
2. Enrollment is an authenticated, one-device out-of-band transaction bound to
   the exact approved managed Mac and its generated key/CSR. Do not auto-enroll
   a presented machine ID, serial, first contact, or client telemetry. Avoid
   global bootstrap secrets. Select certificate issuance/MDM delivery only in
   an explicit exact-target packet, with consent/credential gates satisfied.
3. Prefer a unique per-device client certificate mapped by validated issuer and
   serial/key fingerprint to a server-owned device record and allowed wire ID.
   Check path AND body against that binding on every stage. Certificate identity
   must survive only through trusted authenticated ingress; never trust incoming
   arbitrary identity headers. A unique opaque per-device header token is an
   alternative to evaluate (hash-at-rest, narrow audience, no URL), with weaker
   replay resistance and managed-profile exposure explicitly accepted first.
4. Rotation uses a short, recorded overlap for the same device, then disables the
   old key/token and all outstanding sessions/cursors. Revocation is checked on
   every request; bound caches to a documented short maximum (proposal: 60s),
   fail closed if revocation state is unavailable, and prove old-key failure.
   An offline device retains prior rules; revocation is not remote erasure.
5. Only a separate explicitly approved immutable publication can change rules.
   Bind approval to content digest, exact device/cohort, prior revision and
   rollout/rollback packet. Use monotonic server revisions; rollback publishes
   a new higher revision containing the approved prior content. Never silently
   lower the revision. Telemetry, AI output and candidate drafts never authorize
   allow rules. Monitor-to-Lockdown remains an independent approval.

The harness uses in-memory ephemeral fake bearers to test path/body binding and
rotation/revocation decisions only; no real credentials are issued. It does not
implement TLS, Entra, certificate verification, issuance, admin authorization or
production policy publication.

## Threat model and data lifecycle

| Threat | Required production control; model coverage/limit |
| --- | --- |
| Compromised client / forged telemetry | Per-device isolation, quotas, distrust every reported field; no automated approval. A stolen device key can impersonate that device until revoked; server receipts cannot prove honest endpoint enforcement. Model rejects cross-device path/body mismatch. |
| Replay / duplicate upload | TLS and short credential lifetime; per-device bounded dedupe window. Public v1 lacks a stable event ID. Model hashes canonical whole events, demonstrating bounded replay suppression, not exactly-once delivery; identical legitimate executions may collide semantically. Production must document this and keep telemetry non-authoritative. |
| Cursor tampering / mixed revisions | Opaque authenticated cursor binds device, immutable revision, session and offset; server TTL and revocation. Model pins snapshot, repeats pages deterministically, rejects cross-device/tampered/expired cursors, and withholds receipt until all pages served and counts agree. Public-v1 postflight carries no session/revision identifier: a stale same-count report arriving after newer pages were served can be mistaken for that newer delivery. The model cannot distinguish it; a receipt is only server-observed delivery plus an untrusted count report, never session-specific processing proof. Concurrent sessions and multi-replica transactions remain unimplemented. |
| Rollback/downgrade | Monotonic approved server publication, durable per-device high-water mark, protected restores. Public client does not authenticate snapshot revisions independently, so compromised server/TLS trust remains a residual risk. Model refuses lower acknowledged revisions. |
| Interrupted/empty clean sync | Never advance server completion on partial pages; restart a bounded snapshot after expiry. Refuse accidental empty publication. Pinned native empty-set behavior and lost postflight are explicit qualification cases, not erased by a green model test. |
| Resource exhaustion | Enforce compressed and expanded bytes, event count, JSON depth/schema, timeouts, connection and identity/global rate limits at ingress and application. Model bounds bodies (64 KiB), batches (50), dedupe (256/device), rules (100), cursor length (512), sessions (two fake devices), TTL (300s), audit (128); production fair scheduling, distributed rate limits and load/cold-start tests remain open. |
| Secret / personal-data leakage | No tokens or enrollment secrets in URLs; strip authorization/certificate headers and payloads from access/error/tracing systems. Log nonsecret random request ID/outcome, bounded metrics and approved pseudonymous audit keys. Model stores only request ID/status audit; no complete profiles or raw event logging. |

Proposed production retention, subject to operator/privacy approval: raw events
7 days, dedupe digests 7 days, nonsecret operational audit 30 days, approved
snapshot/approval receipts 90 days minimum plus the currently active rollback
pair, bounded sync sessions 15 minutes. Event payloads can contain usernames,
paths, signing metadata and URLs: minimize collection and redact on ingestion;
do not put real payloads in Git. Capacity/retention expiry must reject new work
rather than deleting active approval evidence or silently acknowledging lost data.

Backups: encrypted daily state/snapshot backups retained 30 days, proposed RPO
24h/RTO 4h (unproven targets). Keep keys in a separately controlled store; use
managed identity and least-privilege service data access where selected. Restore
to an isolated environment, verify hashes/approvals and monotonic publication
high-water marks, reconcile newer device state and revoke expired credentials
before reconnecting. Routine restore must not publish stale allow rules. A deletion
request removes active event/device records and credential mappings, records only
necessary nonsecret deletion evidence, and expires backup copies within 30 days;
restore must replay deletion tombstones. No backup/restore guarantee is made.

## Azure resources and dated cost assumptions

Primary pricing checked **2026-10-19**, East US, USD retail PAYG, 730 h/month, no
negotiated discount. These are illustrations, not a quote, selected capacity,
performance result or total bill. [Retail Prices API](https://learn.microsoft.com/en-us/rest/api/cost-management/retail-prices/azure-retail-prices)
queries and chosen meter IDs are retained in `tools/sync_spike/cost-assumptions.json`.

- Minimal custom illustration: Container Apps Standard active CPU
  $0.000024/vCPU-second, memory $0.000003/GiB-second; idle CPU $0.000003/vCPU-second;
  requests $0.40/million. Meters effective 2022-06-01. At 0.25 vCPU/0.5 GiB
  continuously active, gross compute is **$19.71/month**; **$14.31** if the entire
  subscription-shared 180,000 vCPU-second/360,000 GiB-second grant remains unused.
  [Pricing/grants](https://azure.microsoft.com/en-us/pricing/details/container-apps/).
- Existing-server evaluation illustration: Linux Standard_D2as_v5 regular
  non-Spot VM $0.086/h, meter `1b68f892-2b90-52b4-b5da-5c106f0be4f4`, effective
  2021-12-01: **$62.78/month compute only**. Its
  [2 vCPU/8 GiB specification](https://learn.microsoft.com/en-us/azure/virtual-machines/sizes/general-purpose/dasv5-series)
  is not a tested Zentral minimum or recommendation.
- Both exclude persistent disks/storage, transactions, backups, logs, registry,
  egress, DNS, certificates, network features and engineering/on-call. Managed
  [PostgreSQL](https://azure.microsoft.com/en-us/pricing/details/postgresql/flexible-server/)
  adds provisioned compute/storage and excess backup usage; HA adds a secondary.
  No apples-to-apples total exists until a topology and workload are measured.
- Container Apps [HTTP scale-to-zero](https://learn.microsoft.com/en-us/azure/container-apps/scale-app)
  can reduce idle compute; persistence/logs/other resources are not free. Cold
  startup must fit the pinned request/retry budget. Keeping minimum replicas
  avoids some cold starts but incurs idle/active cost. No latency guarantee.
- Default deployment has **no Azure compute or backend bill** added by this PR.

## Permission review

`azd-permissions.json` retains existing implemented Intune requirements. Proposed
sync features and unknown exact roles/principals/scopes are recorded as **gaps**,
not invented requirements or automatic grants. Reviewed against canonical
`azd-reference` permission schema 1.0 at
[`d3da9b0bd0d2df50bf55f736fd5f8986b3751341`](https://github.com/nathanmcnulty/azd-reference/blob/d3da9b0bd0d2df50bf55f736fd5f8986b3751341/schemas/permission-requirements.schema.json),
SHA-256 `2edf036af36b07a7c161a908590613334440aac2ee955ac5f164b4f81d698483`.
Future resource deployment, storage data access, Entra admin audience/app roles,
certificate issuance and MDM profile delivery require separate selected-target
permission review. Local HTTP testing adds no cloud permission.

## Running and interpreting the evidence

From repository root, with Python 3.10+ (stdlib only):

```sh
python tools/sync_spike/test_conformance.py
```

This binds only 127.0.0.1 on an ephemeral port, sends synthetic requests and closes
all listeners. It reuses rule pages from the existing sync fixture; it does not
pretend the old fixture event IDs are native fields. `tests/Santa.SyncSpike.Tests.ps1`
registers the same command in the existing PowerShell 7.6+/Pester 6.2.0 suite.
Existing template/profile checks must also pass after these changes.

Coverage: preflight, optional batched events, duplicate/retried uploads, three
encodings, stable paged snapshots/cursors, interruption/expiry/restart, repeated
postflight, empty-clean and rollback refusal, tampered/cross-device cursors,
malformed/duplicate/oversized JSON, compression bombs, auth failures and synthetic
rotation/revocation. Limits: no network TLS, native retries, actual process crash,
durable restart, multi-replica race, native rule application/deletion, production
DoS resistance or server compatibility. A green test means only this model behaved
as asserted. Never expose `http.server` to production ingress.

## Bounded next steps and stopping gates

An optional [local durability continuation](sync-durability-spike.md) now tests
synthetic snapshot/report/revocation restart behavior. It is not a production
database adapter, selected Azure storage service or native interoperability proof.

1. Independently review exact source trace, model and final diff; run offline suite
   and registered HTTP harness; leave a draft PR. No implementation selection is
   implicit in that receipt.
2. Evaluate the pinned Zentral auth-binding adapter and minimum supported topology
   versus estimated custom operational ownership. Pin image digest/dependency
   terms; choose only after identity-isolation tests and measured sizing. A later
   implementation task must choose one option explicitly, retain public-v1 scope,
   and add persistence/fault/replay/rollover tests before any live request.
3. Coordinate #36's plan with the selected credential/profile contract. Exact
   device, domain, operator audience, managed objects, collection policy, immutable
   rules and cleanup ownership remain in a separately approved private packet.
4. #33 proves pinned native preflight, optional events, paging, auth failure,
   interruption, postflight loss, explicit deletion and rollback on the one-Mac
   Monitor pilot. A server receipt and control-plane success cannot close it.
5. Azure provisioning/cost, account creation, permission grants, credential issuance,
   ingress, profile/rule publication, merge and release require separate authority.

## Offline validation receipt

PowerShell 7.6.6 / Pester 6.2.0: template validation and 112/112 repository tests
passed, including the registered Python HTTP wrapper. Python independently passed
20/20 local HTTP cases. Canonical permission schema and backlog/render checks
passed. Generated profile bytes, package and existing candidate contracts are
unchanged. Independent source and model review findings were corrected before
final-diff review. Hosted checks, native/Azure compatibility and live gates are
separate from this offline receipt.
