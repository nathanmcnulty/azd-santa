# Phase 0 evidence snapshot

Captured 2026-09-21 as an offline evidence snapshot. Subsequent live-pilot
evidence is recorded below without changing the boundary of the original
offline results.

## Live pilot update

- All five profiles reported remediated on the exact pilot Mac.
- Intune reported Santa 2026.8 installed on `C02GF7BBQ6L4` at
  `2026-09-22T00:37:18Z`.
- On 2026-09-21, the operator reported that `santactl version`,
  `santactl status`, `santactl doctor`, and
  `systemextensionsctl list com.apple.system_extension.endpoint_security` all
  completed without errors and appeared healthy.
- The original operator report did not retain raw output. Subsequent managed
  checks did: Defender Live Response succeeded against `ASDF2`, which reported
  local name `C02GF7BBQ6L4`, and Intune's assigned shell script reported
  `success` for that exact managed Mac at `2026-09-22T06:41:26Z`. Both outputs
  showed Santa `2026.8` in Monitor mode, no doctor configuration errors, and
  an activated, enabled Santa Endpoint Security extension. These are endpoint
  health results, not proof of sync-server compatibility or controlled rule behavior.
- On 2026-09-26, the health script was tightened to require Santa's own extension
  row to have the expected Team ID and active state. Defender Live Response
  passed with the revised script. The revision was published to the same Intune
  pilot assignment; its new Intune execution is pending as of this snapshot.

## Selected release

- Santa `2026.8`, source commit `dbe97b0aa0f5929feece5f4cbd2c69362c271abc`.
- Standard upstream PKG `santa-2026.8.pkg`, 53,569,367 bytes, SHA-256 `0aaa970c7ddc63fe6a55c3144c825acb7f6bfa9cb15bcba1bffcaf2b5efc952a`.
- Installer metadata: package ID `com.northpolesec.santa`, package version `2026.8.244`, bundle version `2026.8`, universal `arm64` and `x86_64`.
- Build source minimum target is macOS 14.0. The pinned release supports macOS
  14, 15, and 26; its [release notes](https://github.com/northpolesec/santa/releases/tag/2026.8)
  also report validation on macOS 27.0. Intune reported the pilot Mac on 27.0
  at its 2026-09-26 check-in.
- Upstream Team ID is `ZMCG7MLDV9`. Baseline Endpoint Security extension is `com.northpolesec.santa.daemon`. `com.northpolesec.santa.netd` is excluded because the network extension requires Workshop.

The downloaded bytes were hash-verified on Windows. Apple package signature, Gatekeeper, notarization, installed bundle signature, and entitlement verification remain mandatory on macOS and are deliberately not marked proven in the lock. Notarization evidence may be either a stapled ticket or an online ticket accepted by Gatekeeper; the verification receipt records which path succeeded.

## Profile and Intune contract

The baseline generates, in order: System Extension, TCC/PPPC, Service Management, Santa configuration, and optional notifications. The configuration sets `ClientMode` to integer `1` (MONITOR) and contains explicit Signing ID bootstrap rules for the release's Santa components. It deliberately avoids a broader Team ID rule. The package operation appears only after a device-level readiness gate.

Custom profiles use the Microsoft Graph v1.0 `macOSCustomConfiguration` resource at `/deviceManagement/deviceConfigurations` with UTF-8 profile bytes encoded in `payload`. PKG automation uses the beta `macOSPkgApp` contract and its multi-stage content upload; this beta dependency is isolated and must be revalidated before live use. No Graph requests are sent by this slice.

## Sync protocol snapshot

The selected client documents ordered preflight, optional event upload, rule download, and postflight stages. JSON is the compatibility default; protobuf transfer is opt-in with `SyncEnableProtoTransfer`. A non-200 stage fails the sync; preflight settings are reverted if a later stage fails before postflight, while already downloaded rules are not reverted. Rule pages use an opaque string cursor and a clean sync replaces rules transactionally after all pages are collected. Release 2026.8 fixed interrupted clean-sync responses that could previously apply a partial rule set.

The fixture adapter only proves local handling of stage order, duplicates, cursors, clean-sync intent, and incompatible protocol rejection. It is not a wire-level conformance test.

The `schemas/` directory defines provider-neutral event, candidate, and approved-rule artifacts. GitHub and Azure DevOps adapters must consume these same contracts; neither provider is allowed to introduce a shortcut around evidence digest, immutable reviewed commit, recorded reviewer, publication status, or receipt digest.

## Server choices

| Option | MVP position | Evidence boundary |
| --- | --- | --- |
| Workshop | Preferred managed option | Official service with current Santa-specific features, host/group scoping, telemetry, rule APIs, and managed operations. Commercial terms, data residency, retention, and tenant provisioning still require customer review; provisioning automation is not assumed. |
| Zentral | Candidate existing server | Active open-source project with Santa configuration/rules/events, scoping, API and event-store integrations. Its documented enrollment URL contains a secret and it can use client-certificate authentication. Santa 2026.8 JSON/protobuf and new rule-policy compatibility still require a version-specific disposable test. |
| Moroz | Lab fixture only | Simple file-backed rules and event log, but its documentation still centers the legacy Google Santa model and lists only BINARY/CERTIFICATE/TEAMID/SIGNINGID plus older policies. The repository last pushed in May 2025. Do not infer current North Pole Santa protocol, CEL/CDHASH/new-policy, retention, API, or production support. |
| Azure-native | Deferred | Could offer Azure-native identity, retention, APIs, and operations, but would make this project responsible for a security-sensitive evolving protocol, authenticated device enrollment, cursors, clean sync, privacy, availability, and recovery. No implementation until conformance and value gates pass. |

## License and name

Original work in this repository is released under the Unlicense. Santa remains
Apache-2.0 licensed; that license permits redistribution under its conditions
but does not grant trademark rights. The workflow can retain the exact,
unchanged upstream PKG as a private short-lived artifact, and an authorized
deployment can redistribute those unchanged bytes internally through Intune.
The tagged upstream license and dependency notices are retained in
`third_party/santa-2026.8` and accompany the workflow artifact. North Pole
Security and Santa are named only to identify origin and compatibility; this
project does not claim affiliation or endorsement.

## Primary sources

- https://github.com/northpolesec/santa/releases/tag/2026.8
- https://github.com/northpolesec/santa/tree/2026.8
- https://northpole.dev/deployment/getting-started/
- https://northpole.dev/deployment/profile-system-extension/
- https://northpole.dev/deployment/profile-tcc/
- https://northpole.dev/deployment/profile-background/
- https://northpole.dev/deployment/profile-configuration/
- https://northpole.dev/deployment/profile-notifications/
- https://northpole.dev/deployment/install-package/
- https://northpole.dev/features/sync/
- https://northpole.dev/features/binary-authorization/
- https://learn.microsoft.com/graph/api/resources/intune-deviceconfig-macoscustomconfiguration?view=graph-rest-1.0
- https://learn.microsoft.com/graph/api/resources/intune-apps-macospkgapp?view=graph-rest-beta
- https://developer.apple.com/documentation/devicemanagement/systemextensions
