# azd-santa

Azure Developer CLI template for preparing and, in later authorized phases, deploying [North Pole Security Santa](https://github.com/northpolesec/santa) to Intune-managed macOS devices.

The project will make the safe path easy: deploy Santa in Monitor mode, install the required macOS profiles before the package, verify health, and optionally add centralized telemetry plus approval-gated rules. It will not require customers to build Santa from source or operate a custom sync server for the minimum deployment.

## Proposed product shape

### Required: deployment-only baseline

- Acquire a pinned upstream Santa release package, verify its digest and signing/notarization state, and upload it to Intune as a macOS PKG app.
- Deploy the required System Extension and TCC/PPPC Full Disk Access profiles before the package.
- Deploy Service Management/background-item and Santa configuration profiles, plus optional notification settings.
- Start in Santa **MONITOR** mode.
- Use small bootstrap/failsafe static rules only; do not pretend static MDM rules are a scalable policy service.
- Verify `santactl status`, system-extension activation, configuration receipt, version, and MDM installation state.

The deployment-only path must work without Azure compute, a sync server, GitHub, or Azure DevOps.

### Optional: central telemetry and rules

Santa’s native sync protocol is the correct central path for event upload, settings, and rule download. Offer profiles rather than forcing one server:

1. **Workshop integration** — official managed service; recommended production option when an external service is acceptable.
2. **Existing compatible server** — document integration with mature servers such as Zentral after version/protocol validation.
3. **Azure-native sync service** — an advanced project profile, implemented only after a protocol compatibility and security spike.

For Git-backed operation, normalized Santa events produce deterministic candidate rule manifests. GitHub or Azure DevOps pull requests carry the proposed rule changes. Human approval gates publication to the selected sync server. Telemetry or AI output must never become an allow rule directly.

## Recommended architecture

```text
Intune
  |-- required macOS profiles
  |-- pinned signed/notarized Santa PKG
  `-- health/installation reporting
                 |
            Santa MONITOR
                 |
       optional native sync protocol
                 |
      Workshop / Zentral / Azure profile
                 |
       events + fleet/rule inventory
                 |
       deterministic candidate engine
                 |
      GitHub PR or Azure DevOps PR
                 |
       approval + protected branch
                 |
           rule publication
                 |
         client sync + verification
```

## Important design constraints

- The upstream signed and notarized release should be the default. Building a deployable custom Santa package requires macOS build infrastructure, Apple Developer signing/notarization, and system-extension entitlements; an ad-hoc build that requires disabling SIP is for development only.
- MDM profiles must arrive before the installer to prevent approval prompts and an inactive system extension.
- Santa’s Endpoint Security extension requires Full Disk Access. Exact Team IDs, bundle IDs, and code requirements must be pinned to the selected release/source and revalidated on upgrades.
- Monitor mode permits unknown binaries while recording them; Lockdown changes the default decision and must be a separate, manually approved promotion.
- Santa intentionally does not provide equivalent script control to Windows App Control. The product must state this coverage difference.
- Static rules are acceptable for bootstrap and failsafe access. Fleet telemetry and dynamic rules require a compatible sync server.
- The current North Pole Santa sync protocol and release compatibility must be validated. Older community servers may implement an earlier JSON/v1 protocol while current Santa supports newer protobuf behavior.
- AI may summarize and cluster events, but cannot authorize a Team ID, Signing ID, certificate, CDHash, path, or CEL rule.

## Starting documents

- [Starting prompt](STARTING_PROMPT.md)
- [Execution plan](EXECUTION_PLAN.md)

## Implemented offline slice

The current slice pins Santa `2026.8` (`2026.8.244`) and its standard upstream PKG, generates the ordered baseline mobileconfig files, validates their structure and identity bindings, emits exact Microsoft Graph request shapes as a non-mutating deployment plan, binds deployable package readiness to a macOS verification receipt, produces exact-ID cleanup plans, binds read-only delivery evidence to the one authorized Intune managed device, checks endpoint-state fixtures, and exercises clean-sync behavior against a local fixture adapter.

```powershell
azd init -t nathanmcnulty/azd-santa
cd azd-santa
azd hooks run preprovision
```

For direct local validation, run the scripts from this checkout:

```powershell
./scripts/New-SantaProfiles.ps1 -Organization 'Example Corp'
./scripts/New-DeploymentPlan.ps1 -Organization 'Example Corp' -PilotGroupId '<pilot-group-object-id>'
./scripts/Test-SantaTemplate.ps1
Invoke-Pester ./tests -CI
```

After deployment, `./scripts/Test-SantaEndpoint.sh 2026.8` runs the health gates
when the repository is present on the Mac and retains a private timestamped
evidence bundle under `.azure/azd-santa/endpoint-evidence/`. For a remote Mac,
use the self-contained Defender Live Response script documented in the
[deployment guide](docs/deployment.md#remote-verification-with-defender-live-response).

The hook is deliberately offline. It writes `out/deployment-plan.json` and performs no Azure, Intune, Graph, GitHub, Azure DevOps, Workshop, or other external mutation. See [deployment preparation](docs/deployment.md) and the [Phase 0 evidence snapshot](docs/phase-0-evidence.md).

## Primary references

- [Santa repository](https://github.com/northpolesec/santa)
- [Santa deployment: getting started](https://northpole.dev/deployment/getting-started/)
- [Install the Santa package](https://northpole.dev/deployment/install-package/)
- [System Extension profile](https://northpole.dev/deployment/profile-system-extension/)
- [TCC/PPPC profile](https://northpole.dev/deployment/profile-tcc/)
- [Santa configuration profile](https://northpole.dev/deployment/profile-configuration/)
- [Building Santa](https://northpole.dev/development/building/)
- [Santa sync protocol](https://northpole.security/docs/santa/features/sync)
- [Deploy macOS PKG apps with Intune](https://learn.microsoft.com/en-us/intune/app-management/deployment/add-unmanaged-pkg-macos)

## License

Original work in this repository is released under the [Unlicense](LICENSE).
Santa remains licensed by North Pole Security under Apache-2.0, and its bundled
dependencies retain their respective terms. See [third-party notices](THIRD_PARTY_NOTICES.md).

## Status

Phase 0 one-device deployment is in progress. The immutable upstream PKG passed SHA-256, installer-identity, Gatekeeper online-notarization, and package-metadata verification on macOS; the upstream artifact has no stapled ticket, so offline installability is not claimed. All five profiles reported remediated on the exact pilot Mac. The verified PKG was uploaded to Intune, published as `Santa 2026.8 (azd-santa pilot)`, and assigned Required only to the one-member pilot group. Intune reported the app installed on `C02GF7BBQ6L4` at `2026-09-22T00:37:18Z`. On 2026-09-21, the operator reported that `santactl version`, `santactl status`, `santactl doctor`, and the Endpoint Security extension check all completed without errors and appeared healthy. Raw endpoint output was not retained, so this is user-observed health evidence rather than a reproducible endpoint receipt. Sync-server compatibility and controlled rule behavior remain unproven.
