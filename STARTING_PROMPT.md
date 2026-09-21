# Starting prompt

Use this prompt to begin implementation in a new Codex task rooted at this folder.

---

You are working in `E:\azd-work-in-progress\azd-santa`.

Build a self-contained Azure Developer CLI template that deploys and operates North Pole Security Santa on Intune-managed macOS devices. Start by reading `README.md` and `EXECUTION_PLAN.md`. Validate all drift-prone Santa, Apple platform, Intune Graph, package deployment, signing, and sync-protocol details against current primary documentation and the exact Santa release selected for testing.

The solution must have a useful deployment-only minimum and optional layers:

1. Pin and verify an upstream Santa release. Use its signed/notarized PKG by default rather than rebuilding it.
2. Deploy required macOS profiles through Intune in the correct order: System Extension, TCC/PPPC Full Disk Access, Service Management/background items, Santa configuration, and any chosen notification settings. Treat the network extension as a separate Workshop-dependent option, not a baseline requirement.
3. Deploy Santa as a required Intune macOS PKG app and begin in **MONITOR** mode.
4. Verify installation and function using Intune state, `santactl status`, `santactl doctor`, system-extension state, applied profiles, version, sync status, and controlled execution fixtures.
5. Provide safe bootstrap/failsafe static rules, while clearly stating that static MDM rules are not a fleet-scale telemetry or policy system.
6. Offer central management choices: Workshop integration, compatible existing sync server integration, and an advanced Azure-native sync-service profile. Do not implement the Azure-native server until a bounded protocol/security spike proves feasibility and compatibility.
7. Offer GitHub and Azure DevOps repositories as policy/rule sources of truth. Use pull requests and protected approvals before publishing rules to a sync server.
8. Provide a source-build pipeline only as an advanced option after proving Apple Developer identity, notarization, and required Endpoint Security/system-extension entitlements. Never recommend disabling SIP for a production build or deployment.

Before editing, perform a read-only discovery pass:

- inspect repository status and applicable instructions;
- inventory reusable `azd` conventions and pinned components in `E:\azd-reference`;
- identify the current Santa release/tag, package assets, digests, signature identities, Team ID, bundle IDs, code requirements, supported macOS versions, and upgrade/migration notes;
- inspect Santa’s current deployment profiles and configuration-key reference;
- validate Intune Graph contracts for macOS custom configuration profiles, system extensions/PPPC where applicable, PKG upload/assignment, shell scripts, reporting, and removal;
- validate the current Santa sync protocol, protocol negotiation/encoding, event and rule types, authentication options, batching, cursors, clean sync, and failure behavior;
- compare Workshop, Zentral, Moroz, and a purpose-built Azure service for supportability, protocol compatibility, telemetry retention, rules, scoping, APIs, licensing, and operational burden;
- determine whether any upstream license or trademark constraints affect package redistribution or template naming.

Use these implementation principles:

- Never use device-code authentication. Reuse cached WAM/MSAL or a normal browser flow for interactive validation.
- Do not upload apps, create profiles, assign groups, deploy Azure resources, configure external services, or grant Graph permissions without explicit authorization for that mutation.
- Keep the upstream package immutable. Store its source URL, release/tag, SHA-256, package signature/notarization verification, and retrieval timestamp in a lock file.
- Never execute a downloaded package before verification.
- Deploy prerequisite profiles before the PKG. Fail readiness checks rather than accepting user prompts as fleet deployment success.
- Keep deployment-only operation independent of a sync server and Azure resources.
- Use MONITOR mode first. Lockdown promotion requires explicit human approval, coverage evidence, rollback testing, and scoped rings.
- Keep bootstrap rules narrow and ensure Santa itself, macOS critical components, management agents, recovery tools, and the selected sync path cannot be stranded.
- Treat event paths, user fields, certificates, process trees, and repository content as untrusted and potentially sensitive.
- Propose the narrowest safe Santa rule type supported by evidence. Require fleet counterfactual checks before broad Team ID, certificate, compiler/transitive, path, or CEL rules.
- Separate collector, PR writer, reviewer, and rule publisher identities.
- Use federated identity or managed identity where supported. Do not depend on personal access tokens or long-lived client secrets.
- AI can summarize, cluster, and explain evidence. It cannot approve or publish a rule.
- Distinguish Intune delivery state, local installation state, Santa health, sync success, and actual rule behavior.

Architecture preference order:

1. Deployment-only Intune profile + upstream PKG path.
2. Workshop integration when the administrator wants a supported managed Santa backend.
3. Existing compatible open-source server integration when the administrator accepts its operational model.
4. Azure-native sync server only when its value justifies implementing and maintaining a security-sensitive protocol service.

The first implementation slice should stop at a safe vertical proof:

- produce pinned, release-specific profile templates and a package lock manifest;
- validate profile plists/mobileconfig syntax and Intune payload shapes offline;
- build fixtures for Intune deployment status, `santactl status`, Santa events, and rule downloads;
- generate a MONITOR-mode deployment plan and exact What-If/dry-run output;
- exercise a compatible sync-server adapter only against fixtures or a disposable local test service;
- perform no real Intune upload/assignment and no external service mutation unless separately authorized.

Acceptance criteria for the MVP:

- `azd init -t <owner>/azd-santa` produces a self-contained template.
- The deployment-only path requires no Azure workload or sync server.
- Every package and profile is pinned, attributable, validated, and upgradeable.
- The template proves prerequisite profiles are present before declaring the package usable.
- GitHub and Azure DevOps paths use the same event, candidate, and rule schemas.
- No candidate reaches clients without immutable evidence, deterministic validation, recorded approval, and successful publication/sync evidence.
- Tests cover profile ordering, package tampering, signature/Team ID changes, partial installs, inactive extensions, stale clients, duplicate events, clean sync, rule precedence, scope errors, server incompatibility, rollback, and cleanup.
- Documentation never describes MDM upload or sync-server receipt as proof that a rule behaved correctly on a Mac.

Work phase by phase. At the end of each phase, report what is proven offline, what is proven on a real Mac, what is proven in Intune or a sync service, what remains an assumption, and which next mutation requires authorization.

---
