# Backlog: nathanmcnulty/azd-santa

> Generated from `docs/backlog.json`. Edit the JSON source and regenerate this file.
> Standard: [azd agent backlog standard](https://github.com/nathanmcnulty/azd-reference/blob/main/standards/agent-backlogs.md). This link is review guidance, not a runtime dependency.

- **Schema version:** 1.0.0
- **Repository:** nathanmcnulty/azd-santa
- **Source revision:** `4b837cd9447fcf231706b72005545bbe4092f25d`
- **Captured:** 2026-10-19
- **Items:** 8

## SANTA-001: Reconcile this backlog with current source and active work

- **Kind:** discovery
- **Priority:** P1
- **Status:** done
- **Wave:** 0
- **Authorization:** local-only
- **Blocker:** _none_
- **Claim:** _none_

**Problem:**

Plans and implementation evidence are spread across files; the captured source can change while other tasks work.

**Scope:**

- docs/backlog.json
- docs/backlog.md
- Existing roadmap, execution status, open issues and pull requests &lpar;read-only&rpar;

**Acceptance:**

- Classify each candidate as implemented, still open, superseded or awaiting evidence; retain source links and reasons.
- Inspect dirty state, remotes, worktrees and local environment presence without reading secrets; avoid duplicate work with active owners.
- Resolve the actual offline validation commands and record exact current default-branch/working-tree provenance; do not copy historical live passes to newer code.

**Validation:**

- git status --short
- git remote -v
- git worktree list --porcelain
- Read the applicable instructions and validation workflow; read gh issue list and gh pr list for the named repository using nathanmcnulty. Do not create or modify issues/PRs.

**Dependencies:**

- _none_

**Components:**

- _none_

**Sources:**

- README.md
- EXECUTION&lowbar;PLAN.md
- https&colon;//github.com/nathanmcnulty/azd-santa/pull/23
- https&colon;//github.com/nathanmcnulty/azd-santa/issues/24
- https&colon;//github.com/nathanmcnulty/azd-santa/pull/25

**Evidence:**

- Reconciled reviewed tracking tip 47242ce384f98e80b6b6f218d13388bc0ee02d54 against freshly fetched origin/main bc9c9a4124796a11db677aea90c038727da46f4f in a clean owned worktree. No dirty canonical bytes, source files or unrelated branch history were copied.
- Current main adds pull request &num;25, which closes issue &num;24 and resolves the paginated profile-status read defect. The repository has no open issues; open dependency pull request &num;23 does not overlap these tracking paths. SANTA-002 remains proposed because the source fix does not prove effective Monitor-profile delivery on the test Mac.
- Items SANTA-002, SANTA-003, SANTA-004, SANTA-005, SANTA-006 remain proposed because their existing acceptance gates are not satisfied by the current source changes alone.
- Exact current-source offline validation generated a mutation-free what-if plan, validated five MONITOR profiles and package/cleanup fixtures, passed 39/39 Pester tests, and left committed generated profiles unchanged. No package upload, assignment, Graph/Azure mutation or real-Mac endpoint operation occurred.

**Review and authorization note:**

Review SANTA-001 against the current repository state. Its status or authorization class is not eligible for an actionable generated handoff. Do not claim or execute it without explicit selection, satisfied dependencies, and every required authorization. Never interpret this generated view as approval.

## SANTA-006: Evaluate delegated Graph session coordinator for Intune publishing

- **Kind:** discovery
- **Priority:** P2
- **Status:** done
- **Wave:** 1
- **Authorization:** local-only
- **Blocker:** _none_
- **Claim:** _none_

**Problem:**

The registered Santa consumer has no component locks; its Graph bootstrap is a candidate for compatible delegated-auth reuse.

**Scope:**

- scripts/
- tests/
- azd-components.lock.json &lpar;new if absent&rpar;

**Acceptance:**

- Compare the actual Intune publisher session shape with graph-delegated-authentication 0.1.1.
- Preserve exact-tenant scope/token proof and one-device Monitor mode; do not broaden permissions or start device-code authentication.
- Keep Santa package/profile receipt semantics solution-owned and retain a compute-free baseline.

**Validation:**

- ./scripts/Test-SantaTemplate.ps1
- Invoke-Pester ./tests -CI
- With separate authorization collect real-Mac evidence and per-device Intune profile status; retain redacted evidence outside Git.

**Dependencies:**

- _none_

**Components:**

- graph-delegated-authentication

**Sources:**

- README.md
- docs/graph-coordinator-assessment.md
- scripts/Invoke-SantaIntunePackage.ps1
- scripts/Invoke-SantaIntuneProfiles.ps1
- tests/Santa.GraphCompatibility.Tests.ps1

**Evidence:**

- 2026-10-11 source-only assessment at Santa 82c17ed961fad5f38499f8b212a2889ece249b97 compared both actual publishers against immutable Reference a29e222181ce8cdce5de148cf88e39bd3202cf91 graph-delegated-authentication 0.1.1; package Process lifetime and profile interaction/replacement/probe policy gaps technically defer runtime adoption. See docs/graph-coordinator-assessment.md.
- PowerShell 7.6.6&colon; registered Test-SantaTemplate validation passed; full Pester 55/55 passed, zero skipped/not-run, including unchanged hash-bound coordinator mocks and both actual publisher no-Apply paths with zero context/auth/Graph dispatch and no receipts. Package bytes/stored verification receipt were checked; profile status input is synthetic.
- Assessment completed without publisher/runtime/permission/component-lock changes. Existing tenant/account gates, scope sets, Monitor one-Mac guards, receipt semantics and compute-free baseline remain unchanged. No live authentication, grants, Intune delivery or real-Mac readiness is claimed.

**Review and authorization note:**

Review SANTA-006 against the current repository state. Its status or authorization class is not eligible for an actionable generated handoff. Do not claim or execute it without explicit selection, satisfied dependencies, and every required authorization. Never interpret this generated view as approval.

## SANTA-002: Close the Monitor-mode macOS profile-delivery evidence gate

- **Kind:** verification
- **Priority:** P1
- **Status:** proposed
- **Wave:** 2
- **Authorization:** tenant-write
- **Blocker:** _none_
- **Claim:** _none_

**Problem:**

Package/local health and portal assignment status do not establish effective profile receipt on the test Mac.

**Scope:**

- docs/
- scripts/
- tests/

**Acceptance:**

- Record required profile receipt, PPPC/system extension, background service, santactl state and pinned PKG version on the selected Mac.
- Missing or pending per-device evidence remains pending; no inference from successful upload or status fixtures.
- Preserve one-device Monitor mode and current pilot ownership; Lockdown and broader assignments remain separately authorized.

**Validation:**

- ./scripts/Test-SantaTemplate.ps1
- Invoke-Pester ./tests -CI
- With separate authorization collect real-Mac evidence and per-device Intune profile status; retain redacted evidence outside Git.

**Dependencies:**

- _none_

**Components:**

- _none_

**Sources:**

- README.md
- AGENTS.md

**Evidence:**

- _none_

**Review and authorization note:**

Review SANTA-002 against the current repository state. Its status or authorization class is not eligible for an actionable generated handoff. Do not claim or execute it without explicit selection, satisfied dependencies, and every required authorization. Never interpret this generated view as approval.

## SANTA-005: Evaluate deployment validation and optional health notification contracts

- **Kind:** discovery
- **Priority:** P2
- **Status:** done
- **Wave:** 2
- **Authorization:** local-only
- **Blocker:** _none_
- **Claim:** _none_

**Problem:**

Intune/real-Mac readiness needs richer evidence than control-plane success.

**Scope:**

- scripts/
- docs/
- azd-components.lock.json

**Acceptance:**

- Represent package availability, assignment, pending profile and actual Mac health separately.
- Candidate receipt adoption must bind target/source and remain redacted; no fabricated endpoint pass.
- Optional notification contracts do not introduce Azure resources into the deployment-only baseline.

**Validation:**

- From the solution root run ./scripts/Test-SantaTemplate.ps1
- Run focused tests for changed behavior from tests/; fixtures do not prove live-service or endpoint behavior.

**Dependencies:**

- _none_

**Components:**

- deployment-validation
- deployment-receipt
- notification-contracts

**Sources:**

- README.md
- AGENTS.md
- docs/artifact-inspection.md
- scripts/Inspect-SantaArtifacts.ps1
- tests/Santa.ArtifactInspection.Tests.ps1

**Evidence:**

- 2026-10-11 source-only discovery/adaptation against Santa main9bd95c94fcf80c0bbc128896bfb7d8188f17cfaa and immutable Reference df93f3ea099780c3767068ecf6b6ab44af8f7440. Local inspector represents package artifact availability, saved profile assignment, required-profile status and saved Mac-health artifact conformance independently; currentMacReadiness remains pending even when all four checks conform. See docs/artifact-inspection.md.
- Adopted exact vendored deployment-validation1.1.1 core check/report/schema files with an immutable hash lock. Management evidence binding is deferred because it requires an Azure subscription absent from the compute-free baseline. Candidate deployment-receipt0.2.1 replacement and notification-contracts1.0.0 producer/transport adoption are technically deferred; existing publishers, Graph scopes, cleanup/ownership receipts, Monitor one-device guards and optional compute remain unchanged.
- PowerShell7.6.6 registered New-DeploymentPlan/Test-SantaTemplate validation and full91/91 Pester cases passed, including55 unchanged baseline cases and36 inspector cases. Actual CLI/helper fixtures cover independent missing/pending domains, target/source byte binding, malformed/oversize/foreign/stale/future/duplicate/type inputs, privacy canaries, zero network/auth/CLI dispatch, preserved input bytes, real private-copy package corruption and vendor-drift refusal. A real Git checkout with core.autocrlf=true preserves all three immutable vendor hashes and runs the actual inspector after adding the missing LF rule for PowerShell manifests. All artifact checks stay distinct from current service or endpoint proof.
- Discovery acceptance completed locally; SANTA-002 retains real-Mac/profile/package delivery evidence and separate authorization. No authentication, Graph/Azure/Defender call, assignment, package upload, notification, remediation, resource creation, cleanup or collector authenticity/current endpoint pass is claimed. Partial source-hashed azd-permissions.json inventories existing manually invoked Graph paths and gaps, not approval to grant authority.

**Review and authorization note:**

Review SANTA-005 against the current repository state. Its status or authorization class is not eligible for an actionable generated handoff. Do not claim or execute it without explicit selection, satisfied dependencies, and every required authorization. Never interpret this generated view as approval.

## SANTA-003: Evaluate managed/existing-server sync profiles before custom Azure hosting

- **Kind:** discovery
- **Priority:** P2
- **Status:** done
- **Wave:** 3
- **Authorization:** local-only
- **Blocker:** _none_
- **Claim:** _none_

**Problem:**

Santa native sync is required for scalable rules; custom Azure hosting is only an advanced candidate.

**Scope:**

- docs/
- config/
- azd-permissions.json

**Acceptance:**

- Document Workshop and compatible existing-server setup with version/protocol evidence and secret boundaries.
- Azure-native service stays a scoped protocol/security spike until compatibility and lifecycle are proven.
- Baseline remains usable without Azure compute, GitHub, Azure DevOps or sync; no component adds a mandatory dependency.

**Validation:**

- From the solution root run ./scripts/Test-SantaTemplate.ps1
- Run focused tests for changed behavior from tests/; fixtures do not prove live-service or endpoint behavior.

**Dependencies:**

- _none_

**Components:**

- _none_

**Sources:**

- README.md
- docs/sync-profiles.md
- package/santa.lock.json
- https&colon;//github.com/northpolesec/santa/blob/dbe97b0aa0f5929feece5f4cbd2c69362c271abc/docs/docs/features/sync.md
- https&colon;//northpole.security/docs/workshop/settings
- https&colon;//www.zentral.com/docs/zentral/apps/santa/

**Evidence:**

- 2026-10-16 discovery against repository b636b4c10cf2947348114839a3c4b226558c6de5 and pinned Santa 2026.8.244 source dbe97b0aa0f5929feece5f4cbd2c69362c271abc. docs/sync-profiles.md describes Workshop and existing Zentral setup packets, independently selected provider revisions, protocol/version evidence, secret-bearing enrollment profiles and MDM ownership boundaries. No particular live server/client pair is claimed compatible.
- The Azure-native option remains an unimplemented scoped protocol/security spike. Baseline profiles and runtime retain Monitor mode and no SyncBaseURL; no provider profile is generated, merged, uploaded or assigned by this discovery change. SANTA-002 and SANTA-007 retain real-Mac/profile/provider/rule/rollback qualification.

**Review and authorization note:**

Review SANTA-003 against the current repository state. Its status or authorization class is not eligible for an actionable generated handoff. Do not claim or execute it without explicit selection, satisfied dependencies, and every required authorization. Never interpret this generated view as approval.

## SANTA-004: Design deterministic Git-reviewed rule candidates

- **Kind:** discovery
- **Priority:** P2
- **Status:** in-progress
- **Wave:** 3
- **Authorization:** local-only
- **Blocker:** _none_
- **Claim owner:** codex-santa-candidates
- **Claim worktree:** C&colon;&bsol;azd-reconciliation-20261015&bsol;santa-action-maintenance
- **Claim base revision:** `b636b4c10cf2947348114839a3c4b226558c6de5`
- **Claim started:** 2026-10-16T11&colon;20&colon;41.8010717+00&colon;00

**Problem:**

Optional telemetry must never directly authorize allow rules.

**Scope:**

- docs/
- scripts/Santa.Candidates.psm1
- scripts/New-SantaRuleCandidate.ps1
- schemas/candidate-1.1.schema.json
- tests/

**Acceptance:**

- Normalized events produce deterministic candidate manifests with evidence digests, exact rules, expiry and human approval.
- GitHub/Azure DevOps transports remain optional adapters and cannot publish telemetry-derived rules automatically.
- Define conflict, rollback and Monitor-to-Lockdown gates with real endpoint proof.

**Validation:**

- From the solution root run ./scripts/Test-SantaTemplate.ps1
- Run focused tests for changed behavior from tests/; fixtures do not prove live-service or endpoint behavior.

**Dependencies:**

- nathanmcnulty/azd-santa&colon;SANTA-003

**Components:**

- _none_

**Sources:**

- README.md
- docs/candidate-drafts.md
- scripts/New-SantaRuleCandidate.ps1
- scripts/Santa.Candidates.psm1
- schemas/event.schema.json
- schemas/candidate-1.1.schema.json
- tests/Santa.Candidates.Tests.ps1

**Evidence:**

- Source implementation adds a local-only deterministic 1.1 draft generator with an explicit binary policy, bounded normalized input, evidence/identity/output digests, review expiry, aggregate-only output and unperformed-counterfactual null. The existing 1.0 candidate/rule contracts remain unchanged. docs/candidate-drafts.md defines evidence, approval, conflict, publication and rollback boundaries.
- Partial progress only&colon; normalization/provenance, performed counterfactuals against effective rules, bound human approval, optional GitHub/Azure DevOps transports, authorized publisher and real endpoint/rollback/Monitor-to-Lockdown gates remain open. A generated draft is not approval, rule delivery, effective enforcement or a live rule expiry mechanism.
- PowerShell 7.6.6/Pester 6.2.0 required offline validation passed all 111 repository tests &lpar;14 candidate cases&rpar;, with zero parser/analyzer findings. Independent review recomputed all three digest stages and exact output bytes outside the production implementation. Existing generated Monitor profiles, package and 1.0 contracts remain unchanged; no service, Graph, assignment, rule publication or endpoint operation occurred.

**Review and authorization note:**

Review SANTA-004 against the current repository state. Its status or authorization class is not eligible for an actionable generated handoff. Do not claim or execute it without explicit selection, satisfied dependencies, and every required authorization. Never interpret this generated view as approval.

## SANTA-007: Qualify a selected sync provider on the one-device Monitor pilot

- **Kind:** verification
- **Priority:** P2
- **Status:** proposed
- **Wave:** 3
- **Authorization:** tenant-write
- **Blocker:** _none_
- **Claim:** _none_

**Problem:**

Provider documentation and protocol fixtures do not prove pinned-client compatibility, actual rule application or rollback on the selected Mac.

**Scope:**

- docs/sync-profiles.md
- Private provider configuration and one-device endpoint evidence
- Owned pilot profiles, credentials and rule receipts

**Acceptance:**

- Select and authorize the exact provider release/configuration, pilot Mac, authentication, MDM objects/assignment and harmless test rule before mutation; preserve one-device Monitor mode.
- Prove effective profile delivery, prerequisites, authenticated preflight, event handling, complete paged rule download, postflight and controlled client behavior separately; source/fixtures/server acceptance do not prove endpoint application.
- Exercise authentication failure, interrupted download, stale/offline client and provider switching with a reviewed preservation plan; prove exact owned-rule/configuration rollback and effective client state.
- Remove or rotate only confirmed owned unshared pilot credentials, rules, profiles and assignments; retain redacted source/provider/target-bound receipts. No broader assignment or Lockdown promotion is authorized by this item.

**Validation:**

- ./scripts/Test-SantaTemplate.ps1
- Invoke-Pester ./tests -CI
- Follow docs/sync-profiles.md with separately selected provider/target and authorization; retain private service and endpoint evidence.

**Dependencies:**

- nathanmcnulty/azd-santa&colon;SANTA-002
- nathanmcnulty/azd-santa&colon;SANTA-003

**Components:**

- _none_

**Sources:**

- docs/sync-profiles.md
- docs/candidate-drafts.md
- AGENTS.md
- package/santa.lock.json

**Evidence:**

- _none_

**Review and authorization note:**

Review SANTA-007 against the current repository state. Its status or authorization class is not eligible for an actionable generated handoff. Do not claim or execute it without explicit selection, satisfied dependencies, and every required authorization. Never interpret this generated view as approval.

## SANTA-008: Spike self-hosted Azure public sync architecture and protocol security

- **Kind:** discovery
- **Priority:** P2
- **Status:** in-progress
- **Wave:** 3
- **Authorization:** local-only
- **Blocker:** _none_
- **Claim:** _none_

**Problem:**

The operator selected self-hosted Azure, but server implementation, identity binding, cost and native compatibility remain unqualified.

**Scope:**

- docs/azure-sync-spike.md
- tools/sync&lowbar;spike/
- tests/Santa.SyncSpike.Tests.ps1
- azd-permissions.json

**Acceptance:**

- Compare a pinned maintained server with a minimal custom design before selecting implementation; preserve default compute-free baseline.
- Trace pinned public client/proto behavior and exercise synthetic local HTTP stages and adversarial cases without claiming native interoperability.
- Separate per-device enrollment, operator administration and explicitly approved immutable rule publication; record remaining deployment/native gates.

**Validation:**

- python tools/sync&lowbar;spike/test&lowbar;conformance.py
- ./scripts/Test-SantaTemplate.ps1
- Invoke-Pester ./tests -CI

**Dependencies:**

- nathanmcnulty/azd-santa&colon;SANTA-003

**Components:**

- _none_

**Sources:**

- https&colon;//github.com/nathanmcnulty/azd-santa/issues/37
- https&colon;//github.com/nathanmcnulty/azd-santa/pull/31
- docs/azure-sync-spike.md
- tools/sync&lowbar;spike/model.py

**Evidence:**

- 2026-10-19 reconciled main and all open drafts; reuse exact reviewed PR &num;31 4b837cd9447fcf231706b72005545bbe4092f25d and &num;32 receipt. &num;36 retains profile planning; &num;33 retains native and selected-provider qualification.
- Original loopback-only public-v1 subset models bounded synthetic authentication, compressed JSON, replay handling, immutable paging and empty/rollback refusal. This is not a production server, native Santa test, permission grant or deployment.
- Offline template validation passed on PowerShell 7.6.6/Pester 6.2.0 with 112/112 repository tests, including the registered 20-case local HTTP harness. Canonical permission schema and backlog rendering checks passed; generated baseline profiles remain unchanged. Native/Azure qualification, deployment and publication are not authorized or completed.

**Review and authorization note:**

Review SANTA-008 against the current repository state. Its status or authorization class is not eligible for an actionable generated handoff. Do not claim or execute it without explicit selection, satisfied dependencies, and every required authorization. Never interpret this generated view as approval.
