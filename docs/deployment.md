# Offline deployment preparation

This slice prepares exact artifacts and a mutation-free Intune plan. Live profile and package apply commands remain separately guarded and require `-Apply` plus PowerShell confirmation.

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
  -ExpectedAccount '<expected-upn>' `
  -Organization '<organization>' `
  -Apply -Confirm
```

Without `-Apply`, it only prints a what-if summary and does not authenticate. With `-Apply`, it uses a normal WAM/browser Microsoft Graph connection, verifies the tenant/account/group and single macOS member, refuses display-name collisions or broader assignments, and records exact object IDs under `.azure/azd-santa/`.

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

The command validates the immutable bytes and macOS receipt before authentication, revalidates the one-device target, encrypts and commits the package through Intune's content service, waits for publication, creates one Required assignment, and verifies that exact assignment by read-back. Interrupted uncommitted objects are resumed only when their ownership marker, release, hash, and unassigned state match exactly.

Generate a non-mutating cleanup plan from the exact profile object IDs recorded by the apply receipt:

```powershell
./scripts/New-CleanupPlan.ps1
```

The cleanup planner works only while the receipt says the package was never uploaded. It rejects missing or duplicate profile IDs, assignment-group drift, release drift, and package-present teardown. Package or endpoint removal requires separate evidence before profile cleanup can safely proceed.

After an authorized deployment, run `scripts/Test-SantaEndpoint.sh` locally on the pilot Mac. Keep these checkpoints separate:

1. Intune profile/app delivery state.
2. Local package version and receipt.
3. Active Endpoint Security extension and effective Full Disk Access.
4. `santactl status` and `santactl doctor` health.
5. Sync completion, when configured.
6. A controlled execution's observed decision.

Removing Santa requires the inverse safety order: remove any non-removable system-extension constraint as part of an approved removal profile, use the upstream-supported uninstall procedure, verify extension/package removal, and only then remove remaining template-owned profiles. Never delete unrelated Intune objects by display-name similarity.
