[CmdletBinding()]
param(
    [string] $Organization = $(if ($env:SANTA_ORGANIZATION) { $env:SANTA_ORGANIZATION } else { 'Contoso' }),
    [string] $PilotGroupId = $(if ($env:SANTA_PILOT_GROUP_ID) { $env:SANTA_PILOT_GROUP_ID } else { '00000000-0000-0000-0000-000000000000' }),
    [string] $PackagePath,
    [string] $PackageVerificationReceiptPath = (Join-Path (Split-Path -Parent $PSScriptRoot) '.azure/azd-santa/package-verification-receipt.json'),
    [string] $OutputPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'out/deployment-plan.json')
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Santa.Template.psm1') -Force
$lock = Get-SantaLock
if (-not $PackagePath) { $PackagePath = Join-Path (Split-Path -Parent $PSScriptRoot) ('package/downloads/' + $lock.package.assetName) }
$profilePaths = New-SantaProfileSet -Organization $Organization
Test-SantaProfileSet | Out-Null
$packageExists = Test-Path -LiteralPath $PackagePath -PathType Leaf
$packageReceiptExists = Test-Path -LiteralPath $PackageVerificationReceiptPath -PathType Leaf
$packageVerificationState = if ($packageExists -and $packageReceiptExists) {
    Test-SantaPackageVerificationReceipt -Path $PackageVerificationReceiptPath -PackagePath $PackagePath | Out-Null
    'verified'
}
elseif ($packageExists -or $packageReceiptExists) {
    'incomplete'
}
else {
    'missing'
}
$packageUploadBlocked = $packageVerificationState -ne 'verified'
$operations = @()
foreach ($profilePath in $profilePaths) {
    $name = Split-Path -Leaf $profilePath
    $id = $name -replace '^\d+-','' -replace '\.mobileconfig$',''
    $required = $id -ne 'notifications'
    $operations += [ordered]@{
        order = [int]($name.Substring(0,2))
        action = 'create-or-update-custom-profile'
        mutatesTenant = $true
        required = $required
        graph = [ordered]@{
            apiVersion = 'v1.0'
            method = 'POST'
            path = '/deviceManagement/deviceConfigurations'
            permission = 'DeviceManagementConfiguration.ReadWrite.All'
            body = [ordered]@{
                '@odata.type' = '#microsoft.graph.macOSCustomConfiguration'
                displayName = "Santa 2026.8 - $id"
                description = "azd-santa owned profile; release 2026.8; order $($name.Substring(0,2))"
                payloadName = $name
                payloadFileName = $name
                payload = [Convert]::ToBase64String([IO.File]::ReadAllBytes($profilePath))
            }
        }
    }
}
$operations += [ordered]@{ order = 60; action = 'wait-for-profile-readiness'; mutatesTenant = $false; requires = @('system-extension','tcc','service-management','configuration'); successEvidence = 'per-device profile state succeeded' }
$operations += [ordered]@{ order = 70; action = 'create-upload-commit-required-pkg'; mutatesTenant = $true; blocked = $packageUploadBlocked; requires = @('macOS verification receipt','matching immutable package bytes','per-device prerequisite profile success'); graph = [ordered]@{ apiVersion = 'beta'; path = '/deviceAppManagement/mobileApps'; permission = 'DeviceManagementApps.ReadWrite.All'; resourceType = '#microsoft.graph.macOSPkgApp'; asset = $lock.package.assetName; sha256 = $lock.package.sha256; primaryBundleId = $lock.package.bundleIdentifier; primaryBundleVersion = $lock.package.bundleShortVersion; uploadContract = 'create app -> content version -> file/Azure Storage upload -> commit -> poll -> assign required' } }
$operations += [ordered]@{ order = 80; action = 'assign-pilot-group'; mutatesTenant = $true; targetGroupId = $PilotGroupId; guard = 'non-zero explicit group id required for live execution' }
$operations += [ordered]@{ order = 90; action = 'verify-endpoint'; mutatesTenant = $false; evidence = @('Intune app state','santactl version','santactl status','santactl doctor','systemextensionsctl','profiles show','controlled execution fixture') }
$plan = [ordered]@{
    schemaVersion = '1.0'
    mode = 'what-if'
    performsMutation = $false
    release = $lock.release.tag
    packageVersion = $lock.package.packageVersion
    organization = $Organization
    pilotGroupId = $PilotGroupId
    authorizationRequiredForApply = $true
    packageVerification = [ordered]@{
        state = $packageVerificationState
        packagePath = $PackagePath
        receiptPath = $PackageVerificationReceiptPath
        uploadBlocked = $packageUploadBlocked
    }
    operations = $operations
    rollback = [ordered]@{
        available = $false
        reason = 'No previously verified package lock is present in this first slice.'
        requiredEvidence = @('prior package lock','prior profile set','pilot rollback result')
    }
    cleanup = @(
        [ordered]@{ order = 10; action = 'remove-template-package-assignment'; guard = 'exact template-owned object id' },
        [ordered]@{ order = 20; action = 'make-system-extension-removable'; guard = 'approved removal profile reaches target' },
        [ordered]@{ order = 30; action = 'run-upstream-supported-uninstall'; guard = 'pilot only' },
        [ordered]@{ order = 40; action = 'verify-package-and-extension-absent'; guard = 'endpoint evidence required' },
        [ordered]@{ order = 50; action = 'remove-template-owned-profiles-reverse-order'; guard = 'exact recorded object ids only' }
    )
}
New-Item -ItemType Directory -Path (Split-Path -Parent $OutputPath) -Force | Out-Null
$json = $plan | ConvertTo-Json -Depth 20
[IO.File]::WriteAllText($OutputPath, $json + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
Write-Information "WHAT-IF only; no Microsoft Graph or Azure mutation occurred." -InformationAction Continue
Write-Information "Plan: $OutputPath" -InformationAction Continue
$plan.operations | ForEach-Object { [pscustomobject]$_ } | Select-Object order,action,mutatesTenant | Format-Table -AutoSize
