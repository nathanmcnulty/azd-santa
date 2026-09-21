# Execution plan

## 1. Outcome and scope

Deliver an independently consumable `azd` template with three separable tiers:

| Tier | Required capabilities | External dependencies |
| --- | --- | --- |
| Deploy | Pin package, deploy profiles and PKG in Monitor mode, verify health, remove safely | Intune and managed Macs |
| Connect | Send events and receive rules through a compatible Santa sync service | Workshop, Zentral, or optional Azure service |
| Operate | Convert telemetry into Git-reviewed rules and verify client application | GitHub or Azure DevOps plus a sync service |

Explicit non-goals for the first release:

- silently rebuilding or re-signing upstream Santa;
- requiring SIP to be disabled outside a disposable development Mac;
- defaulting to Lockdown mode;
- promising Windows-equivalent script control;
- autonomous AI approval;
- implementing a custom sync server before compatibility and threat-model gates pass;
- enabling Santa’s Workshop-dependent network extension by default.

## 2. Architecture decisions to validate first

### 2.1 Package acquisition versus source build

Default path:

- retrieve a selected upstream GitHub release asset during a controlled preparation step;
- verify release tag/commit, expected asset name, SHA-256 lock, Developer ID package signature, Gatekeeper assessment, notarization, bundle identifiers, Team ID, and versions;
- upload the exact verified PKG to Intune;
- re-run verification during upgrades and fail on signing-identity drift.

Advanced source-build path:

- macOS runner with Xcode and Bazelisk pinned to Santa’s repository configuration;
- exact tagged source commit and dependencies;
- organization-owned Apple Developer ID identities, notarization credentials, and approved Endpoint Security/system-extension entitlements;
- universal architecture checks, tests, package signing, notarization, stapling, and independent verification;
- SBOM/provenance and immutable build artifact.

Decision gate: if the organization cannot obtain the required Apple entitlements and validate the resulting system extension on a SIP-enabled managed Mac, do not advertise custom builds as deployable. The upstream release remains the supported path.

### 2.2 Intune deployment contract and order

Validate the exact current Graph/UI behavior for:

1. System Extension allow-list profile for `com.northpolesec.santa.daemon` and upstream Team ID.
2. TCC/PPPC Full Disk Access entries for required Santa components and exact code requirements.
3. Service Management/background-item profile.
4. Santa configuration custom profile with `ClientMode=MONITOR`, machine identity, user messaging, privacy-conscious logging, and optional `SyncBaseURL`.
5. Optional notification profile.
6. Optional network-extension profiles only for a compatible Workshop subscription.
7. Required macOS PKG app, dependencies/order, assignments, detection, update, and uninstall.
8. Health/verification shell script or Intune reporting path.

Do not assume assignment order equals device receipt order. Implement readiness checks, package retry behavior, and a report that distinguishes each prerequisite.

### 2.3 Central-management profiles

#### Workshop

Treat as the recommended managed production integration when commercial service use is acceptable. The template should generate the Intune-side configuration and validate connectivity, but it must not claim to provision or configure Workshop unless supported APIs and authorization exist.

#### Zentral

Evaluate as the primary open-source integration because it manages Santa configurations/rules and collects events. Confirm current North Pole Santa protocol support, deployment complexity, APIs, database/event-store dependencies, security maintenance, and Azure hosting fit.

#### Moroz

Treat as a lab/simple configuration option unless current evidence shows production telemetry, API, scoping, and protocol compatibility. Its file-backed rules are useful for a bounded compatibility fixture, not automatically a recommended fleet backend.

#### Azure-native sync service

Run a spike before committing to implementation. Validate the exact selected Santa client’s wire protocol, protobuf/JSON behavior, endpoints, batching, cursors, clean sync, rule precedence, configuration overrides, event semantics, client authentication, and version negotiation.

If pursued, keep the first service intentionally small:

- implement only documented preflight, event upload, rule download, and postflight contracts;
- use client-initiated synchronization and normal intervals rather than a real-time push channel;
- support mTLS or another documented per-device authentication method with rotation/revocation;
- persist append-only raw events separately from normalized views;
- keep approved rules versioned and scoped with monotonic cursors;
- expose health and compatibility metrics;
- reject unsupported client/protocol versions safely;
- avoid embedding rule approval or AI decisions inside the sync endpoint.

Potential hosting (Function/App Service, Container Apps, or Kubernetes) and storage (PostgreSQL, Cosmos DB, or other) should be selected only after load, query, consistency, certificate, and operations requirements are measured.

### 2.4 Git-backed rules

Use one provider-neutral schema for:

- raw-event reference and digest;
- candidate rule;
- approved rule and scope;
- Santa rule types/policies and precedence;
- server target and minimum compatible version;
- lifecycle state, expiry/review date, and rollback.

Support GitHub Actions and Azure Pipelines with equivalent validation. Provider adapters may create pull requests, but only a post-merge publisher can update the sync server.

## 3. Rule candidate and approval contract

Capture at least:

- candidate/event/batch identifiers;
- Santa client version, sync-server profile, event schema version, and observation window;
- raw-event digest and retention reference;
- SHA-256/CDHash, file path privacy classification, bundle metadata, signing ID, Team ID, certificate chain, notarization/Gatekeeper information where available, and process ancestry where supported;
- execution decision and decision source;
- device/user/scope counts, first/last seen, recurrence, and current rule result;
- proposed rule type, policy, scope, custom message/URL, and precedence analysis;
- counterfactual fleet query showing other binaries/bundles affected by broader rules;
- risk flags, missing evidence, expiry, and reviewer notes;
- deterministic tool/version/output digest;
- optional AI explanation marked non-authoritative.

CI must reject ambiguous rule type/policy mappings, unexpected scope expansion, stale evidence, invalid identifiers, precedence conflicts, unreviewed clean-sync behavior, unsupported CEL, or manual generated-artifact drift.

## 4. Phased delivery

### Phase 0 — release, platform, and protocol discovery

Deliver:

- selected release lock and provenance report;
- offline package-signature/notarization verification script design;
- release-specific profile/code-requirement manifest;
- current Intune macOS Graph contract capture;
- current Santa configuration and sync-protocol compatibility matrix;
- threat model for package supply chain, MDM deployment, client identity, sync service, telemetry, and Git publication;
- fixtures for profiles, Intune states, Santa status/events, and sync transactions.

Exit criteria:

- exact supported macOS/Santa/Intune versions are declared;
- protocol/server claims are verified against current code or a real compatibility test;
- no Intune or external-service mutation occurs;
- all unavailable capabilities fail closed.

### Phase 1 — deployment-only MVP

Deliver:

- `azure.yaml` with idempotent setup/deploy/verify/teardown commands;
- pinned package acquisition and verification;
- generated, release-specific mobileconfig/plist artifacts;
- dry-run showing exact app/profile/group changes;
- pilot assignment and prerequisite/readiness model;
- health script/report and endpoint verification runbook;
- recoverable uninstall and profile-removal ordering.

Exit criteria:

- profiles validate with `plutil` and relevant schema/static checks;
- two deployments are idempotent;
- only an explicitly selected pilot group is assigned;
- on an authorized test Mac, the system extension is active, Full Disk Access is effective, Santa is in Monitor mode, and controlled executions produce expected events;
- teardown removes only template-owned Intune objects and follows safe extension/package ordering.

### Phase 2 — managed-server adapters

Deliver:

- provider-neutral sync-server adapter contract;
- Workshop configuration/integration guide and read-only health probe;
- one validated open-source server adapter if compatible;
- connection/authentication, rule, event, health, and version capability reports;
- explicit unsupported-feature handling.

Exit criteria:

- test clients complete preflight, upload, rule download, and postflight;
- server receipt is distinguished from client rule application;
- stale/offline clients and authentication failures are visible;
- a rule change can be rolled back without a clean-sync surprise.

### Phase 3 — evidence and candidate engine

Deliver:

- append-only event ingestion contract;
- normalized-event/candidate schemas;
- deduplication, privacy redaction, retention, clustering, and rule-precedence analysis;
- deterministic narrow-rule proposals and counterfactual checks;
- local review report.

Exit criteria:

- identical input produces byte-stable output;
- malicious path/message/event fields cannot alter commands, profiles, rules, or PR content;
- unsigned/ambiguous/multi-signed cases and missing bundle data do not result in unsafe broad proposals;
- Team ID/certificate/compiler/path/CEL rules require explicit elevated review.

### Phase 4 — GitHub and Azure DevOps approval backends

Deliver:

- common repository layout and schemas;
- equivalent GitHub Actions and Azure Pipelines checks;
- protected-branch/CODEOWNERS/environment guidance;
- federated identity where the server API supports it, otherwise a documented short-lived credential broker or bounded secret strategy;
- PR creation and post-merge publisher adapters.

Exit criteria:

- collection/PR identity cannot publish rules;
- publisher accepts only a merged commit and matching artifact digest;
- equivalent fixtures generate equivalent changes on both Git platforms;
- concurrent PR and precedence conflicts fail safely.

### Phase 5 — optional Azure-native sync service

Proceed only if Phase 0 shows a clear need not met by Workshop or an existing server.

Deliver:

- protocol conformance suite against pinned Santa versions;
- authenticated, rate-limited sync API;
- event and rule stores, cursor/clean-sync logic, scope evaluation, audit trail, metrics, backup/restore, and upgrade strategy;
- infrastructure-as-code, cost controls, and teardown;
- security review focused on device impersonation, event poisoning, rule tampering, privacy, denial of service, and tenant separation.

Exit criteria:

- conformance tests and real Mac sync tests pass;
- incompatible clients fail safely;
- certificate/key rotation and revocation work;
- restore preserves rule ordering/cursors and does not trigger unsafe clean sync;
- operational value justifies owning a security-critical service.

### Phase 6 — optional source-build pipeline

Deliver:

- pinned macOS build environment, tests, universal binaries, signing, notarization, stapling, SBOM, provenance, and verification;
- upgrade/migration procedure from upstream-signed to organization-signed builds;
- Intune/package/profile changes for the organization’s Team ID and code requirements.

Exit criteria:

- Apple entitlements are approved and documented;
- a SIP-enabled pilot Mac loads the signed system extension without manual workarounds;
- independent verification confirms signing and notarization;
- rollback to a known-good package is tested.

### Phase 7 — Lockdown readiness (manual decision)

Provide readiness reports and runbooks only. Lockdown promotion must be explicitly authorized outside the normal template deployment.

Evidence should cover business-cycle duration, device/persona coverage, unknown-event backlog, server/client health, management and recovery tools, user communication, exception SLA, offline behavior, failsafe rules, break-glass Macs, and rollback drills.

## 5. Repository layout target

```text
/
  azure.yaml
  README.md
  SECURITY.md
  infra/
  src/
    Core/
    Intune/
    Sync/
    GitHub/
    AzureDevOps/
  package/
    santa.lock.json
  profiles/
    manifests/
    templates/
    generated/
  rules/
    bootstrap/
    approved/
  schemas/
  scripts/
  tests/
    fixtures/
    unit/
    integration/
    conformance/
  docs/
    architecture.md
    permissions.md
    package-provenance.md
    deployment.md
    operations.md
    server-options.md
    cleanup.md
```

Keep generated mobileconfig files reproducible from reviewed manifests/templates. Do not hand-edit generated artifacts.

## 6. Security and authorization boundaries

- Separate Intune deployer, event reader, PR writer, reviewer, and rule publisher identities.
- Never use device-code authentication.
- Pin all GitHub Actions/Azure tasks and external components to immutable revisions.
- Do not expose signing/notarization credentials to pull-request workflows.
- Treat package download, event fields, device identifiers, usernames, paths, URLs, and server responses as untrusted.
- Minimize and redact telemetry; document data residency and retention for every server option.
- Bind rule publication to reviewed commit/artifact digests.
- Log rule provenance, approver, scope, server result, client adoption, and rollback.
- Require mutual authentication or an equally strong documented mechanism for any custom sync service.
- Never equate a macOS serial number or URL path machine ID with authenticated device identity.
- Keep failsafe rules and management reachability under dedicated review.

## 7. Validation matrix

Test at least:

- supported Intel and Apple silicon Macs and each macOS major version in scope;
- Automated Device Enrollment and any other supported enrollment modes;
- fresh install, profile delay, app delay, retry, upgrade, downgrade/rollback, and uninstall;
- upstream signature/Team ID drift and tampered downloads;
- system extension, Full Disk Access, background items, notifications, and optional network profile behavior;
- Monitor decisions for signed, unsigned, notarized, quarantined, bundled, command-line, and script-related cases;
- sync offline/reconnect, partial stages, duplicates, batching, cursors, clean sync, incompatible versions, expired client credentials, and server restore;
- rule precedence, scope leakage, stale approvals, and simultaneous changes;
- GitHub/Azure DevOps pull-request threat boundaries;
- local Santa status, event creation, server receipt, rule download, and observed execution decision as separate checkpoints.

## 8. Questions to resolve with evidence

1. Which current Santa release is the first supported pin, and what exact signing identities/profiles does it require?
2. Which Intune Graph resources are sufficiently supported for reliable custom-profile and PKG automation?
3. How can the package deployment depend on profile readiness rather than only assignment timing?
4. Which current community servers fully support the selected North Pole Santa version and wire protocol?
5. Is Workshop provisioning automatable, or should the template provide integration artifacts only?
6. Is an Azure-native server valuable enough to justify long-term protocol, authentication, privacy, and availability ownership?
7. What client authentication method works across Intune-enrolled Macs with safe enrollment, rotation, and revocation?
8. Which rule types and event fields are supported consistently across selected server profiles?
9. Can organization-built Santa obtain the required Apple entitlements, and how will Team ID/profile migration avoid downtime?
10. What reliable endpoint evidence proves that a specific approved rule version produced the intended decision?

## 9. Definition of done for the first public release

- A new tenant can deploy a pinned upstream Santa release in Monitor mode without optional services.
- Prerequisite profiles, package provenance, and endpoint health are verifiable.
- Cleanup and upgrades are safe and scoped.
- At least one managed sync-server integration is proven on real Macs, or the initial release clearly limits itself to deployment-only operation.
- GitHub and Azure DevOps provide equivalent approval-gated rule management where central sync is enabled.
- No unreviewed event or AI output can become a fleet rule.
- Documentation distinguishes Intune assignment, package installation, extension health, sync success, rule receipt, and actual execution behavior.
