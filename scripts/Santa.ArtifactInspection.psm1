#Requires -Version 7.6
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:Root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $PSScriptRoot 'Santa.Template.psm1') -Force

function Read-SantaInspectionJson {
    param([string] $Path, [string] $Schema)
    if (-not $Path) { throw 'MissingArtifact' }
    if ($Path -match '^[a-z]+://' -or $Path -match '^[\\/]{2}' -or
        ($IsWindows -and $Path -match ':(?![\\/])')) { throw 'NonLocalArtifact' }
    $full = [IO.Path]::GetFullPath($Path)
    $current = $full
    while ($current) {
        if (([IO.File]::GetAttributes($current) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'LinkedArtifact' }
        $current = [IO.Path]::GetDirectoryName($current)
    }
    $stream = [IO.File]::OpenRead($full)
    try {
        $bytes = [byte[]]::new(1048577)
        $count = 0
        while ($count -lt $bytes.Length) {
            $read = $stream.Read($bytes, $count, $bytes.Length - $count)
            if ($read -eq 0) { break }
            $count += $read
        }
        if ($count -gt 1048576) { throw 'OversizeArtifact' }
    } finally { $stream.Dispose() }
    $raw = [Text.UTF8Encoding]::new($false, $true).GetString($bytes, 0, $count)
    if ($Schema -and -not (Test-Json -Json $raw -SchemaFile (Join-Path $script:Root $Schema) -ErrorAction SilentlyContinue)) { throw 'InvalidArtifact' }
    $value = ConvertFrom-Json -InputObject $raw -Depth 32 -DateKind String -ErrorAction Stop
    [pscustomobject]@{ value = $value; sha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData(([byte[]]$bytes[0..($count - 1)]))).ToLowerInvariant() }
}

function Get-SantaInspectionSourceHash {
    $paths = @('scripts/Santa.ArtifactInspection.psm1','scripts/Santa.Template.psm1','package/santa.lock.json',
        'profiles/manifests/baseline.json','schemas/artifact-inspection-target.schema.json',
        'schemas/intune-profile-receipt.schema.json','schemas/intune-profile-status.schema.json','schemas/package-verification.schema.json','schemas/artifact-inspection-endpoint.schema.json')
    $lines = foreach ($path in $paths) { $path + ':' + (Get-FileHash -LiteralPath (Join-Path $script:Root $path) -Algorithm SHA256).Hash.ToLowerInvariant() }
    [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes(($lines -join "`n")))).ToLowerInvariant()
}

function Assert-SantaInspectionComponent {
    $lock = Get-Content -LiteralPath (Join-Path $script:Root 'azd-components.lock.json') -Raw | ConvertFrom-Json
    $components = @($lock.components)
    if ($lock.manifestVersion -cne '1.0' -or $components.Count -ne 1 -or $components[0].id -cne 'deployment-validation' -or
        $components[0].version -cne '2.0.0' -or $components[0].sourceRepository -cne 'https://github.com/nathanmcnulty/azd-reference' -or
        $components[0].sourceRevision -cne 'fbb521e468ed129f951e7e13ecf0134986fdbd75') { throw 'ComponentContractMismatch' }
    $targets = @('scripts/vendor/Azd.DeploymentValidation/Azd.DeploymentValidation.psd1',
        'scripts/vendor/Azd.DeploymentValidation/Azd.DeploymentValidation.psm1',
        'scripts/vendor/Azd.DeploymentValidation/deployment-validation.schema.json')
    if (@($components[0].files).Count -ne 3) { throw 'ComponentContractMismatch' }
    foreach ($target in $targets) {
        $entry = @($components[0].files | Where-Object target -CEQ $target)
        if ($entry.Count -ne 1 -or (Get-FileHash -LiteralPath (Join-Path $script:Root $target)).Hash.ToLowerInvariant() -cne $entry[0].sha256) { throw 'ComponentBytesMismatch' }
    }
}

function Test-SantaInspectionDomain {
    param([ValidateSet('package','assignment','profiles','endpoint')][string] $Domain,
        [AllowNull()][object] $Target, [string] $TargetHash, [string] $SourceHash,
        [string] $ProfileReceiptPath, [string] $ProfileStatusPath, [string] $EndpointEvidencePath, [datetimeoffset] $Now)
    $code = 'ArtifactUnavailable'
    try {
        if ($Domain -eq 'package') {
            $lock = Get-SantaLock
            $path = Join-Path $script:Root ('package/vendor/' + [string] $lock.package.assetName)
            Test-SantaPackageVerificationReceipt -Path (Join-Path $script:Root ('package/verification/santa-' + [string]$lock.release.tag + '.json')) -PackagePath $path | Out-Null
            return New-AzdCheckOutcome -Status pass -Summary 'Package bytes and stored verification receipt conform to the pinned artifact contract.' -Actual @{ artifactConforms=$true; code='PackageArtifactConforms' }
        }
        if ($null -eq $Target) { return New-AzdCheckOutcome -Status warning -Summary 'A valid local target contract is required.' -Actual @{ artifactConforms=$false; code='TargetUnavailable' } }
        if ($Domain -eq 'assignment') {
            $file = Read-SantaInspectionJson -Path $ProfileReceiptPath -Schema 'schemas/intune-profile-receipt.schema.json'
            $receipt = $file.value
            if ($receipt.tenantId -ine $Target.tenantId -or $receipt.release -cne $Target.release -or $receipt.pilotGroup.id -ine $Target.pilotGroupId -or
                @($receipt.profiles | Where-Object assignmentGroupId -INE $Target.pilotGroupId).Count -gt 0 -or
                @($receipt.profiles.id | Sort-Object -Unique).Count -ne 5) { throw 'TargetMismatch' }
            return New-AzdCheckOutcome -Status pass -Summary 'Saved profile assignment receipt conforms to the selected target; current assignment is unobserved.' -Actual @{ artifactConforms=$true; code='AssignmentArtifactConforms'; sha256=$file.sha256 }
        }
        if ($Domain -eq 'profiles') {
            $file = Read-SantaInspectionJson -Path $ProfileStatusPath -Schema 'schemas/intune-profile-status.schema.json'
            $state = $file.value
            if ($state.tenantId -ine $Target.tenantId -or $state.release -cne $Target.release -or $state.pilotGroup.id -ine $Target.pilotGroupId -or
                $state.pilotDevice.entraObjectId -ine $Target.entraObjectId -or $state.pilotDevice.aadDeviceId -ine $Target.aadDeviceId -or
                $state.pilotDevice.managedDeviceId -ine $Target.managedDeviceId) { throw 'TargetMismatch' }
            if ([string]$state.collectedAt -cnotmatch '(?:Z|[+-]\d{2}:\d{2})$') { throw 'InvalidArtifact' }
            $time = [datetimeoffset]::Parse([string]$state.collectedAt, [Globalization.CultureInfo]::InvariantCulture)
            if ($time -gt $Now -or $time -lt $Now.AddHours(-24)) { throw 'StaleArtifact' }
            $result = Test-SantaIntuneProfileReport -State $state
            if (-not $result.deliveryReadiness) { return New-AzdCheckOutcome -Status warning -Summary 'Saved required-profile evidence is pending or inconsistent; current delivery remains unobserved.' -Actual @{ artifactConforms=$false; code='ProfilesPending'; sha256=$file.sha256 } }
            return New-AzdCheckOutcome -Status pass -Summary 'Saved required-profile report conforms; this is not fresh Intune delivery proof.' -Actual @{ artifactConforms=$true; code='ProfileArtifactConforms'; sha256=$file.sha256 }
        }
        $file = Read-SantaInspectionJson -Path $EndpointEvidencePath -Schema 'schemas/artifact-inspection-endpoint.schema.json'
        $e = $file.value
        # This small local wrapper binds saved JSON, never authenticates its collector.
        $keys = @($e.PSObject.Properties.Name | Sort-Object)
        if (($keys -join ',') -cne 'collectedAt,payload,schemaVersion,sourceSha256,targetSha256' -or $e.schemaVersion -cne '1.0' -or
            $e.targetSha256 -cne $TargetHash -or $e.sourceSha256 -cne $SourceHash) { throw 'UnboundArtifact' }
        $time = [datetimeoffset]::Parse([string]$e.collectedAt, [Globalization.CultureInfo]::InvariantCulture)
        if ($time -gt $Now -or $time -lt $Now.AddHours(-24)) { throw 'StaleArtifact' }
        $state = $e.payload
        if (@($state.profiles.id | Sort-Object -Unique).Count -ne @($state.profiles).Count) { throw 'InvalidArtifact' }
        if ($state.santa.doctorHealthy -isnot [bool] -or $state.santa.syncConfigured -isnot [bool] -or $state.santa.lastSyncSucceeded -isnot [bool] -or
            $state.lastCheckAgeMinutes -isnot [ValueType] -or $state.lastCheckAgeMinutes -lt 0) { throw 'InvalidArtifact' }
        $result = Test-EndpointState -State $state
        if (-not $result.ready) { return New-AzdCheckOutcome -Status warning -Summary 'Saved Mac health payload does not conform; current endpoint state is unobserved.' -Actual @{ artifactConforms=$false; code='EndpointArtifactPending'; sha256=$file.sha256 } }
        New-AzdCheckOutcome -Status pass -Summary 'Saved Mac health payload conforms; its metadata is asserted, not authenticated, and current Mac readiness remains pending.' -Actual @{ artifactConforms=$true; code='EndpointArtifactConforms'; sha256=$file.sha256 }
    } catch {
        # Never copy caller/provider text, paths, identity, or raw DTOs into the report.
        if ($_.Exception.Message -cin @('TargetMismatch','StaleArtifact','UnboundArtifact','InvalidArtifact','OversizeArtifact','NonLocalArtifact','LinkedArtifact')) { $code = $_.Exception.Message }
        New-AzdCheckOutcome -Status warning -Summary 'Local artifact is missing, unsupported, inconsistent or refused.' -Actual @{ artifactConforms=$false; code=$code }
    }
}

function Invoke-SantaArtifactInspection {
    [CmdletBinding()]
    param([string] $TargetPath, [string] $ProfileReceiptPath, [string] $ProfileStatusPath, [string] $EndpointEvidencePath,
        [datetimeoffset] $Now = [datetimeoffset]::UtcNow, [switch] $Plan)
    Assert-SantaInspectionComponent
    Import-Module (Join-Path $PSScriptRoot 'vendor/Azd.DeploymentValidation/Azd.DeploymentValidation.psd1') -Force
    $source = Get-SantaInspectionSourceHash
    $domainCommand = Get-Command Test-SantaInspectionDomain
    $target = $null; $targetHash = $null
    if (-not $Plan) {
        try {
            $file = Read-SantaInspectionJson -Path $TargetPath -Schema 'schemas/artifact-inspection-target.schema.json'
            if ($file.value.release -cne (Get-SantaLock).release.tag) { throw 'ReleaseMismatch' }
            $target = $file.value; $targetHash = $file.sha256
        } catch { $target = $null }
    }
    $domainParameters = @{ Target=$target; TargetHash=$targetHash; SourceHash=$source; ProfileReceiptPath=$ProfileReceiptPath; ProfileStatusPath=$ProfileStatusPath; EndpointEvidencePath=$EndpointEvidencePath; Now=$Now }
    $definitions = foreach ($domain in 'package','assignment','profiles','endpoint') {
        $action = { & $domainCommand -Domain $domain @domainParameters }.GetNewClosure()
        New-AzdValidationCheckDefinition -Id "artifact.$domain" -Phase configuration -Title "Saved $domain artifact" -Summary 'Local artifact conformance only; current service and Mac readiness are unobserved.' -Action $action -SideEffect readOnly
    }
    $checks = @(Invoke-AzdValidationSet -Definitions $definitions -Plan:$Plan)
    $report = New-AzdValidationReport -TemplateName 'azd-santa-artifacts' -TemplateVersion '1.0' -Mode $(if ($Plan) {'plan'} else {'verify'}) -StartedAt $Now -Checks $checks -Environment @{ metadata=@{ evidence='savedArtifactsOnly'; currentMacReadiness='pending'; sourceSha256=$source; targetSha256=$targetHash } } -NextSteps @('Obtain separately authorized, exact-target current service and Mac evidence; local JSON does not attest collector authenticity.')
    $json = $report | ConvertTo-Json -Depth 32
    if (-not (Test-Json -Json $json -SchemaFile (Join-Path $PSScriptRoot 'vendor/Azd.DeploymentValidation/deployment-validation.schema.json') -ErrorAction SilentlyContinue)) { throw 'InspectionReportInvalid' }
    $report
}
Export-ModuleMember -Function Invoke-SantaArtifactInspection, Get-SantaInspectionSourceHash
