# Offline deployment preparation

This slice prepares exact artifacts and a mutation-free Intune plan. It does not authenticate to Microsoft Graph, upload the package, create profiles, or assign a group.

```powershell
./scripts/New-SantaProfiles.ps1 -Organization 'Example Corp'
./scripts/New-DeploymentPlan.ps1 -Organization 'Example Corp' -PilotGroupId '<pilot-group-object-id>'
./scripts/Test-SantaTemplate.ps1
```

Download and hash-check the package on Windows for inspection only:

```powershell
./scripts/Get-SantaPackage.ps1 -AllowUnverifiedPlatform
```

For deployable evidence, run the same script on macOS without `-AllowUnverifiedPlatform`. It then requires `pkgutil`, Gatekeeper, and notarization-staple checks to pass before moving the package into its final path.

The plan's zero GUID is an intentional non-deployable placeholder. A future live apply command must require a specific non-zero pilot group, explicit mutation authorization, successful per-device prerequisite state, and separately granted Graph scopes. Assignment is not readiness: the PKG must not be treated as usable until the System Extension, TCC, Service Management, and configuration profiles report success on the target device.

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

Without `-Apply`, it only prints a what-if summary and does not authenticate. With `-Apply`, it uses a normal WAM/browser Microsoft Graph connection, verifies the tenant/account/group and single macOS member, refuses display-name collisions or broader assignments, and records exact object IDs under `.azure/azd-santa/`. It cannot upload the PKG.

After an authorized deployment, run `scripts/Test-SantaEndpoint.sh` locally on the pilot Mac. Keep these checkpoints separate:

1. Intune profile/app delivery state.
2. Local package version and receipt.
3. Active Endpoint Security extension and effective Full Disk Access.
4. `santactl status` and `santactl doctor` health.
5. Sync completion, when configured.
6. A controlled execution's observed decision.

Removing Santa requires the inverse safety order: remove any non-removable system-extension constraint as part of an approved removal profile, use the upstream-supported uninstall procedure, verify extension/package removal, and only then remove remaining template-owned profiles. Never delete unrelated Intune objects by display-name similarity.
