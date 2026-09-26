# Offline deployment preparation

This slice prepares exact artifacts and a mutation-free Intune plan. Live profile apply can be explicitly enabled in `azd up`; the standalone apply command remains guarded by `-Apply` and PowerShell confirmation. PKG upload remains a separate guarded step until macOS verification and exact-device profile readiness are available.

```powershell
./scripts/New-SantaProfiles.ps1 -Organization 'Example Corp'
./scripts/New-DeploymentPlan.ps1 -Organization 'Example Corp' -PilotGroupId '<pilot-group-object-id>'
./scripts/Test-SantaTemplate.ps1
```

Download and hash-check the package on Windows for inspection only:

```powershell
./scripts/Get-SantaPackage.ps1 -AllowUnverifiedPlatform
```

For deployable evidence, run the same script on macOS without `-AllowUnverifiedPlatform`. It then requires `pkgutil`, Gatekeeper, and notarization checks to pass before moving the package into its final path. The receipt distinguishes a stapled ticket from an online ticket validated by Gatekeeper; an online-only ticket means offline installation is not proven.

Successful macOS verification also writes `.azure/azd-santa/package-verification-receipt.json`. The receipt binds the selected release, package hash and metadata, Team ID, installer certificate, and digests of each Apple verification result. `New-DeploymentPlan.ps1` keeps package upload blocked unless both that receipt and the immutable package bytes match the lock.

The plan's zero GUID is an intentional non-deployable placeholder. Assignment is not readiness: the PKG must not be uploaded until the System Extension, TCC, Service Management, and configuration profiles report success on the exact target device.

The guarded profile-only apply command is:

```powershell
./scripts/Invoke-SantaIntuneProfiles.ps1 `
  -TenantId '<tenant-id>' `
  -PilotGroupId '<pilot-group-object-id>' `
  -ExpectedGroupDisplayName '<exact-name>' `
  -ExpectedDeviceName '<exact-device-name>' `
  -ExpectedAccount '<expected-upn>' `
  -Organization '<organization>' `
  -Apply -Confirm
```

Without `-Apply`, it only prints a what-if summary and does not authenticate. With `-Apply`, it uses a normal WAM/browser Microsoft Graph connection, verifies the tenant/account/group and exact single macOS device, preflights all existing assignments before any mutation, and refuses display-name collisions or broader assignments. Existing payload changes require the separate `-AllowProfileUpdate` switch after reviewing the drift; an unchanged profile is only verified, not patched. Exact object IDs are recorded under `.azure/azd-santa/`. Its package status is deliberately `unknown`: profile publication cannot prove the package is absent, so this receipt cannot authorize a cleanup plan by itself.

Collect current assignment and per-profile device status without changing Intune or requesting a device sync:

```powershell
./scripts/Get-SantaIntuneProfileStatus.ps1 `
  -TenantId '<tenant-id>' `
  -ExpectedAccount '<expected-upn>' `
  -ExpectedDeviceName '<exact-device-name>'
```

The collector requests read-only Graph scopes, reads the five exact object IDs from the apply receipt, and writes `.azure/azd-santa/intune-profile-status.json`. It verifies that the pilot group still contains exactly the recorded Entra device, resolves that identity to exactly one Intune managed device, and reads that device's configuration-state inventory. Assignment proof and device delivery are reported separately. Package readiness remains false until every required profile has a successful state on that exact managed device and no failed or error count; the optional notifications profile does not gate readiness.

After macOS verification and exact-device profile readiness, upload and assign the verified bytes with:

```powershell
./scripts/Invoke-SantaIntunePackage.ps1 `
  -PackagePath '<verified-pkg>' `
  -PackageVerificationReceiptPath '<macos-verification-receipt>' `
  -ProfileStatusPath '<current-exact-device-profile-report>' `
  -TenantId '<tenant-id>' `
  -PilotGroupId '<pilot-group-object-id>' `
  -ExpectedPilotGroupName '<exact-name>' `
  -ExpectedDeviceName '<exact-device-name>' `
  -ExpectedAccount '<expected-upn>' `
  -Apply -Confirm
```

The command validates the immutable bytes and macOS receipt before authentication,
requires a profile status report collected within 30 minutes for the same tenant,
account, group, and device, and recomputes prerequisite readiness. It then
revalidates the one-device target, encrypts and commits the package through
Intune's content service, waits for publication, creates one Required assignment,
and verifies that exact assignment by read-back. Interrupted uncommitted objects
are resumed only when their ownership marker, release, hash, and unassigned state
match exactly.

Generate a non-mutating cleanup plan from the exact profile object IDs recorded by the apply receipt:

```powershell
./scripts/New-CleanupPlan.ps1
```

The cleanup planner works only with a separately established `not-uploaded` package status. The profile publisher now records `unknown` and cannot supply that proof. The planner rejects missing or duplicate profile IDs, assignment-group drift, release drift, and package-present teardown. Package or endpoint removal requires separate evidence before profile cleanup can safely proceed.

After an authorized deployment, run `scripts/Test-SantaEndpoint.sh` locally on
the pilot Mac from the repository root. The first argument optionally overrides
the expected version, and the second optionally overrides the evidence root:

```zsh
./scripts/Test-SantaEndpoint.sh 2026.8
```

The script may prompt for administrator approval when running `santactl doctor`.
It writes a private timestamped bundle under
`.azure/azd-santa/endpoint-evidence/`, including raw command output, a result
receipt, and `SHA256SUMS`. Failed runs retain their partial evidence and a failed
receipt. The `.azure` directory is ignored by Git; review the bundle before
sharing it because profile output can contain organization-specific settings.

### Remote verification with Defender Live Response

Do not use the checkout-oriented script when the repository is not present on
the Mac. `azd up` can publish the self-contained
`scripts/live-response/Get-SantaHealth.sh` to both Intune and the Defender Live
Response library, and can execute it through Live Response against one exact
MDE machine. Configure the explicit bindings before deployment:

```powershell
azd env set AZD_SANTA_DEPLOY_INTUNE_HEALTH_SCRIPT true
azd env set AZD_SANTA_DEPLOY_INTUNE_PROFILES true
azd env set AZD_SANTA_ORGANIZATION '<organization-for-profile-payloads>'
azd env set AZD_SANTA_PUBLISH_LIVE_RESPONSE_LIBRARY true
azd env set AZD_SANTA_RUN_LIVE_RESPONSE_HEALTH true
azd env set AZD_SANTA_PILOT_GROUP_ID '<entra-device-group-guid>'
azd env set AZD_SANTA_PILOT_GROUP_NAME '<exact-group-name>'
azd env set AZD_SANTA_INTUNE_DEVICE_NAME '<exact-intune-device-name>'
azd env set AZD_SANTA_INTUNE_ACCOUNT '<intune-admin-upn>'
azd env set AZD_SANTA_MDE_MACHINE_ID '<40-character-mde-machine-id>'
azd env set AZD_SANTA_MDE_MACHINE_NAME '<exact-mde-machine-name>'
azd env set AZD_SANTA_MDE_ACCOUNT '<mde-admin-upn>'
azd up
```

The profile flag makes `azd up` create or update the five pilot-only profiles,
then collect their exact-device status. It is opt-in and requires the named
organization and pilot bindings above. To permit reviewed profile changes, set
`AZD_SANTA_ALLOW_PROFILE_UPDATE=true`; leave it unset for a new deployment or
an unchanged rerun. The status may initially be pending
while Intune delivers the profiles; a later `azd up` refreshes it. The hook
also automates the health channels. PKG publication still uses the guarded
command earlier in this guide: package signing/notarization must be verified
on macOS, and the required profiles must first report ready on the exact device.
The current pilot's configuration profile lacks one payload UUID present in
this checkout; the other four differ only by a trailing newline. Leave the
update setting unset until that configuration difference is reviewed; the
hook will fail before changing any profile.

The Intune publisher uses the beta `deviceShellScripts` API, runs the script as
System, assigns it only to the verified one-member macOS pilot group, and
requires `DeviceManagementScripts.ReadWrite.All` plus the documented assignment
permissions. The Defender publisher uses Azure CLI's cached browser/WAM session,
the legacy `https://api.securitycenter.microsoft.com` token audience required by
the current API, and the `https://api.security.microsoft.com` REST endpoint. It
requires `Library.Manage`; automatic execution requires `Machine.LiveResponse`.

After Intune has processed the assignment, collect its exact-device execution
result without changing tenant state. `postprovision` does this once; this
command refreshes the result after a later check-in:

```powershell
./scripts/Get-SantaIntuneHealthStatus.ps1 `
  -TenantId '<tenant-id>' `
  -ExpectedAccount '<intune-reader-upn>' `
  -EnvironmentName '<azd-environment-name>'
```

The collector verifies the publication hash, the one-member pilot group, the
Entra-to-Intune device binding, the unfiltered assignment, and the script's
`deviceRunStates` record. Its private `.azure/<environment>/santa-intune-health-result.json`
receipt is `passed` only when a successful run contains the expected computer
name, Santa version, and pass marker and happened after the script's last update.
A pending result means Intune has not yet reported execution of those exact
bytes. The Graph endpoint is a beta API and may change.

The script writes no persistent files when run through either managed channel.
The Live Response result is downloaded immediately into the selected AZD
environment under `.azure/`. It includes the computer name, capture time,
enrollment state, Santa version, Monitor-mode status, doctor output, Endpoint
Security extension state, and an explicit pass/fail boundary. It intentionally
omits the full profile inventory to avoid collecting unrelated organization
settings.

For testing only, an operator can still upload the script to the Defender
library and run `run Get-SantaHealth.sh` manually. That fallback is not part of
the AZD deployment contract.

Keep these checkpoints separate:

1. Intune profile/app delivery state.
2. Local package version and receipt.
3. Active Endpoint Security extension and effective Full Disk Access.
4. `santactl status` and `santactl doctor` health.
5. Sync completion, when configured.
6. A controlled execution's observed decision.

For the current one-device pilot, Intune reported the package installed. A
subsequent Defender Live Response action retained a successful result for the
exact MDE machine: the script identified `C02GF7BBQ6L4`, verified Santa `2026.8`
in Monitor mode, confirmed no doctor configuration errors, and confirmed the
Santa Endpoint Security extension was activated and enabled. Intune subsequently
reported a successful health-script run on the bound pilot managed device at
`2026-09-22T06:41:26Z`, with the same computer name, Santa version, Monitor
status, doctor output, and activated Santa extension. Preserve sync and
controlled-rule evidence as separate gates.

Removing Santa requires the inverse safety order: remove any non-removable system-extension constraint as part of an approved removal profile, use the upstream-supported uninstall procedure, verify extension/package removal, and only then remove remaining template-owned profiles. Never delete unrelated Intune objects by display-name similarity.
