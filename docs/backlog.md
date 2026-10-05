# Backlog: nathanmcnulty/azd-santa

> Generated from `docs/backlog.json`. Edit the JSON source and regenerate this file.
> Standard: [azd agent backlog standard](https://github.com/nathanmcnulty/azd-reference/blob/main/standards/agent-backlogs.md). This link is review guidance, not a runtime dependency.

- **Schema version:** 1.0.0
- **Repository:** nathanmcnulty/azd-santa
- **Source revision:** `bc9c9a4124796a11db677aea90c038727da46f4f`
- **Captured:** 2026-10-04
- **Items:** 6

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
- **Status:** proposed
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

**Evidence:**

- _none_

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
- **Status:** proposed
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

**Evidence:**

- _none_

**Review and authorization note:**

Review SANTA-005 against the current repository state. Its status or authorization class is not eligible for an actionable generated handoff. Do not claim or execute it without explicit selection, satisfied dependencies, and every required authorization. Never interpret this generated view as approval.

## SANTA-003: Evaluate managed/existing-server sync profiles before custom Azure hosting

- **Kind:** discovery
- **Priority:** P2
- **Status:** proposed
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

**Evidence:**

- _none_

**Review and authorization note:**

Review SANTA-003 against the current repository state. Its status or authorization class is not eligible for an actionable generated handoff. Do not claim or execute it without explicit selection, satisfied dependencies, and every required authorization. Never interpret this generated view as approval.

## SANTA-004: Design deterministic Git-reviewed rule candidates

- **Kind:** discovery
- **Priority:** P2
- **Status:** proposed
- **Wave:** 3
- **Authorization:** local-only
- **Blocker:** _none_
- **Claim:** _none_

**Problem:**

Optional telemetry must never directly authorize allow rules.

**Scope:**

- docs/
- config/
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

**Evidence:**

- _none_

**Review and authorization note:**

Review SANTA-004 against the current repository state. Its status or authorization class is not eligible for an actionable generated handoff. Do not claim or execute it without explicit selection, satisfied dependencies, and every required authorization. Never interpret this generated view as approval.
