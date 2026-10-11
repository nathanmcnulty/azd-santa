# Local artifact inspection and component assessment

`Inspect-SantaArtifacts.ps1` inspects saved files on PowerShell 7.6+. It performs no authentication, CLI or service queries, uploads, assignments, Live Response calls, notifications or cleanup. Its four independent checks cover local package availability, a saved profile assignment receipt, saved required-profile status and a saved Mac health payload. Missing evidence in one domain does not erase another domain's artifact result.

Every result is **artifact conformance**. `environment.metadata.currentMacReadiness` is always `pending`, even when all four artifact checks pass. The report's `passed` outcome means the saved artifacts conform. It does not authenticate the collector, establish present Intune assignment/delivery, prove installed package state, or establish current Mac health. Package verification checks current vendored bytes against the lock and stored macOS receipt; it does not rerun Gatekeeper or notarization. Package-app assignment remains unobserved; the assignment check covers the exact five profile IDs in the saved profile receipt.

## Inputs and output

```powershell
./scripts/Inspect-SantaArtifacts.ps1 -Plan
./scripts/Inspect-SantaArtifacts.ps1 `
  -TargetPath ./tests/fixtures/inspection/target.json `
  -ProfileReceiptPath ./tests/fixtures/intune/profile-receipt.json `
  -ProfileStatusPath ./tests/fixtures/intune/profile-status-success.json
```

The first command plans four checks without reading the supplied target/evidence files. The second inspects synthetic fixtures; their old status timestamp remains stale. Neither writes a receipt or evidence file. Redirect stdout to a new local file if a report is needed. The package check uses the existing pinned package/verification receipt, independently of a selected tenant.

The target schema fixes release, environment, tenant, group, Entra object/AAD device and managed-device IDs. It deliberately has no Azure subscription. These values are caller-selected local expectations, not independently observed authority. Paths must be local, without UNC, URLs, alternate streams or reparse-point traversal. User-supplied JSON is capped at 1MiB and parsed with bounded depth. Target/source identities and raw file paths, profile names, serial numbers, UPNs, result messages and unknown fields are not copied into reports. Stable codes and byte digests identify artifacts. Legacy validator exceptions and failure strings remain inside the adapter.

For optional endpoint artifact inspection, use `-EndpointEvidencePath` with the closed `schemas/artifact-inspection-endpoint.schema.json` wrapper. It contains `schemaVersion: "1.0"`, `targetSha256` (actual UTF-8 target-file bytes), `sourceSha256` (from `Get-SantaInspectionSourceHash`), explicit-offset `collectedAt`, and the legacy endpoint fixture shape as `payload`. The source hash binds the inspector/domain validator, release lock, baseline manifest and relevant schemas. Dates must be no later than inspection and no older than 24 hours. This only checks consistency of asserted metadata with actual local bytes; a forged but internally consistent wrapper still cannot promote current Mac readiness. The original unbound healthy fixture remains insufficient. Strict payload types, unique profile IDs, nonnegative bounded integer age and Monitor/version/extension/doctor gates run before or through the existing endpoint validator.

Profile status has the same 24-hour saved-artifact freshness bound and explicit UTC/offset requirement, plus the existing exact-set/per-device/status-after-profile-modification checks. Matching status JSON remains a saved assertion. A pending required profile, foreign target, missing/unsupported record, stale/future time, digest mismatch or invalid type produces a closed warning, never a fresh service or endpoint pass. Optional notification-profile status cannot stand in for a required profile. Existing publisher and cleanup receipts are not rewritten or treated as authenticated evidence.

## Component decisions at immutable Reference df93f3ea099780c3767068ecf6b6ab44af8f7440

| Component | Decision and compatibility |
| --- | --- |
| deployment-validation 1.1.1 | Adopt exact vendored core check/report/schema files for a local structured artifact report, with actual hash checks and immutable lock. Keep schema1.0 core output. Optional management evidence binding requires an Azure subscription; defer it for this compute-free baseline rather than inventing one. The solution-owned local target/source contract stays separate. |
| deployment-receipt 0.2.1 (candidate) | Defer adoption. Existing profile/package ownership IDs, content and assignment receipts drive exact cleanup. A generic management receipt cannot replace those semantics or authenticate saved observer JSON. No publisher/cleanup receipt changes. |
| notification-contracts 1.0.0 (pilot) | Defer producer/transport adoption. A future envelope may summarize anonymous per-domain state using exact event/source identity and safe per-route results, but aggregate artifact checks are not delivery results. Recipient configuration, transport/retry policy and live receipt are separate gates. No schemas are repurposed as grant approval, and this assessment adds no Azure monitor, workspace or callback dependency. |

The baseline remains usable without Azure compute, GitHub, Azure DevOps, sync or Reference at runtime. Vendored files execute locally; deployment does not fetch Reference. `azd-permissions.json` is a source-hashed partial inventory of existing manually invoked Graph paths, with explicit gaps. The inspector adds no grants and makes no effective-authority or licensing claim.

## Acceptance and validation boundary

SANTA-005 is a local discovery/adaptation item: separate the four domains, compare/adopt/defer components with target/source/privacy constraints, and preserve the resource-free notification baseline. The new inspector gives that assessment an executable consumer. SANTA-002 still needs separately authorized real-Mac and Intune evidence. Monitor mode, one-device targeting, package/publisher/collector/cleanup behavior and existing functional artifacts are unchanged. Hosted CI selects hash-pinned 64-bit PowerShell 7.6.6 before running PowerShell on both Windows and Linux. Local tests and CI do not establish live service or endpoint acceptance.

Immutable component sources: [validation1.1.1](https://github.com/nathanmcnulty/azd-reference/blob/df93f3ea099780c3767068ecf6b6ab44af8f7440/components/powershell/deployment-validation/component.json), [candidate receipt0.2.1](https://github.com/nathanmcnulty/azd-reference/blob/df93f3ea099780c3767068ecf6b6ab44af8f7440/components/powershell/deployment-receipt/component.json), [notification contracts1.0.0](https://github.com/nathanmcnulty/azd-reference/blob/df93f3ea099780c3767068ecf6b6ab44af8f7440/components/contracts/notification-contracts/component.json).
