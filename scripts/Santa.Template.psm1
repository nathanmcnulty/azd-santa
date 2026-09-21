Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-RepositoryRoot {
    return (Split-Path -Parent $PSScriptRoot)
}

function Get-SantaLock {
    $path = Join-Path (Get-RepositoryRoot) 'package/santa.lock.json'
    return Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
}

function Get-ProfileManifest {
    $path = Join-Path (Get-RepositoryRoot) 'profiles/manifests/baseline.json'
    return Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
}

function ConvertTo-OrganizationId {
    param([Parameter(Mandatory)][string] $Organization)
    $value = ($Organization.ToLowerInvariant() -replace '[^a-z0-9.-]', '-') -replace '-+', '-'
    $value = $value.Trim('.-')
    if ([string]::IsNullOrWhiteSpace($value)) { throw 'Organization must contain at least one letter or number.' }
    return $value
}

function New-SantaProfileSet {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string] $Organization = 'Contoso',
        [string] $OutputPath = (Join-Path (Get-RepositoryRoot) 'profiles/generated')
    )
    $manifest = Get-ProfileManifest
    $orgId = ConvertTo-OrganizationId -Organization $Organization
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    $outputs = @()
    foreach ($profileSpec in @($manifest.profiles | Sort-Object order)) {
        $source = Join-Path (Get-RepositoryRoot) ('profiles/templates/' + $profileSpec.template)
        $target = Join-Path $OutputPath ('{0:D2}-{1}.mobileconfig' -f [int]$profileSpec.order, $profileSpec.id)
        $content = (Get-Content -LiteralPath $source -Raw).Replace('{{ORGANIZATION}}', [System.Security.SecurityElement]::Escape($Organization)).Replace('{{ORG_ID}}', $orgId)
        if ($PSCmdlet.ShouldProcess($target, 'Generate Santa configuration profile')) {
            [System.IO.File]::WriteAllText($target, $content, [System.Text.UTF8Encoding]::new($false))
        }
        $outputs += $target
    }
    return $outputs
}

function Test-SantaProfileSet {
    [CmdletBinding()]
    param([string] $ProfilePath = (Join-Path (Get-RepositoryRoot) 'profiles/generated'))
    $manifest = Get-ProfileManifest
    $lock = Get-SantaLock
    $expected = @($manifest.profiles | Sort-Object order | ForEach-Object { '{0:D2}-{1}.mobileconfig' -f [int]$_.order, $_.id })
    $actual = @(Get-ChildItem -LiteralPath $ProfilePath -Filter '*.mobileconfig' -File | Sort-Object Name | Select-Object -ExpandProperty Name)
    if (($expected -join '|') -ne ($actual -join '|')) { throw "Generated profile set or order is invalid. Expected: $($expected -join ', '). Actual: $($actual -join ', ')." }
    foreach ($name in $actual) {
        $raw = Get-Content -LiteralPath (Join-Path $ProfilePath $name) -Raw
        try { [void][xml]$raw } catch { throw "Profile '$name' is not valid XML: $($_.Exception.Message)" }
        if ($raw -match '\{\{[^}]+\}\}') { throw "Profile '$name' contains an unresolved token." }
        if ($name -ne '50-notifications.mobileconfig' -and $raw -notmatch [regex]::Escape($lock.identity.teamId)) { throw "Profile '$name' does not bind the pinned Team ID." }
        if ($raw -match 'com\.northpolesec\.santa\.netd') { throw "Baseline profile '$name' unexpectedly enables the Workshop-only network extension." }
    }
    $config = Get-Content -LiteralPath (Join-Path $ProfilePath '40-configuration.mobileconfig') -Raw
    if ($config -notmatch '<key>ClientMode</key><integer>1</integer>') { throw 'Baseline configuration is not pinned to MONITOR mode (ClientMode 1).' }
    if ($config -match '<string>TEAMID</string>') { throw 'Baseline static rules must use narrow signing IDs, not a broad Team ID rule.' }
    return [pscustomobject]@{ valid = $true; profiles = $actual; release = $lock.release.tag; mode = 'MONITOR' }
}

function Test-SantaPackageHash {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Path)
    $lock = Get-SantaLock
    $item = Get-Item -LiteralPath $Path
    if ($item.Length -ne [long]$lock.package.size) { throw "Package size mismatch. Expected $($lock.package.size), found $($item.Length)." }
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $lock.package.sha256) { throw "Package SHA-256 mismatch. Expected $($lock.package.sha256), found $actual." }
    return $true
}

function Test-SantaPackageVerificationReceipt {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $Path,
        [string] $PackagePath
    )
    $root = Get-RepositoryRoot
    $schemaPath = Join-Path $root 'schemas/package-verification.schema.json'
    $raw = Get-Content -LiteralPath $Path -Raw
    if (-not ($raw | Test-Json -SchemaFile $schemaPath -ErrorAction Stop)) {
        throw 'Package verification receipt does not satisfy its schema.'
    }
    $receipt = $raw | ConvertFrom-Json
    $lock = Get-SantaLock
    $expected = [ordered]@{
        releaseTag = [string] $lock.release.tag
        assetName = [string] $lock.package.assetName
        size = [long] $lock.package.size
        sha256 = [string] $lock.package.sha256
        identifier = [string] $lock.package.packageIdentifier
        version = [string] $lock.package.packageVersion
        teamId = [string] $lock.identity.teamId
        installerCertificateCommonName = [string] $lock.identity.expectedInstallerCertificateCommonName
    }
    $actual = [ordered]@{
        releaseTag = [string] $receipt.releaseTag
        assetName = [string] $receipt.package.assetName
        size = [long] $receipt.package.size
        sha256 = [string] $receipt.package.sha256
        identifier = [string] $receipt.package.identifier
        version = [string] $receipt.package.version
        teamId = [string] $receipt.identity.teamId
        installerCertificateCommonName = [string] $receipt.identity.installerCertificateCommonName
    }
    foreach ($key in $expected.Keys) {
        if ($actual[$key] -cne $expected[$key]) {
            throw "Package verification receipt $key does not match the release lock."
        }
    }
    if ($PackagePath) { Test-SantaPackageHash -Path $PackagePath | Out-Null }
    return $true
}

function Get-SantaProfileCleanupPlan {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $ReceiptPath)
    $root = Get-RepositoryRoot
    $schemaPath = Join-Path $root 'schemas/intune-profile-receipt.schema.json'
    $raw = Get-Content -LiteralPath $ReceiptPath -Raw
    if (-not ($raw | Test-Json -SchemaFile $schemaPath -ErrorAction Stop)) {
        throw 'Intune profile receipt does not satisfy its schema.'
    }
    $receipt = $raw | ConvertFrom-Json
    $lock = Get-SantaLock
    if ([string] $receipt.release -ne [string] $lock.release.tag) {
        throw 'Intune profile receipt release does not match the release lock.'
    }
    if ([string] $receipt.package.status -ne 'not-uploaded') {
        throw 'Package cleanup and endpoint removal evidence are required before profile cleanup can be planned.'
    }
    $expectedIds = @((Get-ProfileManifest).profiles | Sort-Object order | ForEach-Object { [string] $_.id })
    $actualIds = @($receipt.profiles | ForEach-Object { [string] $_.id })
    $expectedIdSet = (($expectedIds | Sort-Object) -join '|')
    $actualIdSet = (($actualIds | Sort-Object) -join '|')
    if ($expectedIdSet -cne $actualIdSet) {
        throw 'Intune profile receipt does not contain the exact expected profile IDs.'
    }
    $pilotGroupId = [string] $receipt.pilotGroup.id
    foreach ($profile in @($receipt.profiles)) {
        if ([string] $profile.assignmentGroupId -ne $pilotGroupId) {
            throw "Profile '$($profile.id)' is scoped outside the recorded pilot group."
        }
    }
    $operations = @(
        $receipt.profiles |
            Sort-Object { [array]::IndexOf($expectedIds, [string] $_.id) } -Descending |
            ForEach-Object {
                [ordered]@{
                    action = 'delete-template-owned-profile'
                    profileId = [string] $_.id
                    objectId = [string] $_.objectId
                    expectedDisplayName = [string] $_.displayName
                    assignmentGroupId = $pilotGroupId
                    guard = 'exact receipt object ID and ownership marker must match at apply time'
                }
            }
    )
    return [pscustomobject] [ordered]@{
        schemaVersion = '1.0'
        mode = 'what-if'
        performsMutation = $false
        tenantId = [string] $receipt.tenantId
        pilotGroupId = $pilotGroupId
        release = [string] $receipt.release
        packageStatus = [string] $receipt.package.status
        operations = $operations
    }
}

function Test-EndpointState {
    [CmdletBinding()]
    param([Parameter(Mandatory)][psobject] $State)
    $lock = Get-SantaLock
    $failures = [System.Collections.Generic.List[string]]::new()
    foreach ($required in 'system-extension','tcc','service-management','configuration') {
        $entry = @($State.profiles | Where-Object id -eq $required)
        if ($entry.Count -ne 1 -or $entry[0].state -ne 'succeeded') { $failures.Add("profile:$required") }
    }
    if ($State.package.state -ne 'installed') { $failures.Add('package:installed') }
    if ($State.package.version -ne $lock.package.bundleShortVersion) { $failures.Add('package:version') }
    if ($State.santa.mode -ne 'MONITOR') { $failures.Add('santa:monitor') }
    if (-not $State.santa.doctorHealthy) { $failures.Add('santa:doctor') }
    if ($State.systemExtension.bundleId -ne 'com.northpolesec.santa.daemon' -or $State.systemExtension.state -ne 'activated enabled') { $failures.Add('system-extension:active') }
    if ($State.santa.syncConfigured -and -not $State.santa.lastSyncSucceeded) { $failures.Add('sync:success') }
    if ($State.lastCheckAgeMinutes -gt 1440) { $failures.Add('evidence:stale') }
    return [pscustomobject]@{ ready = ($failures.Count -eq 0); failures = @($failures) }
}

function Get-RulePrecedence {
    param([Parameter(Mandatory)][string] $RuleType)
    $order = @{ CDHASH = 1; BINARY = 2; SIGNINGID = 3; CERTIFICATE = 4; TEAMID = 5; SCOPE = 6; CLIENTMODE = 7; TRANSITIVE = 8 }
    $key = $RuleType.ToUpperInvariant()
    if (-not $order.ContainsKey($key)) { throw "Unsupported Santa rule type '$RuleType'." }
    return $order[$key]
}

function ConvertFrom-SantactlStatus {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Text)
    $values = @{}
    foreach ($line in ($Text -split "`r?`n")) {
        if ($line -match '^\s*(?<key>[^|]+?)\s*\|\s*(?<value>.*?)\s*$') {
            $values[$Matches.key.Trim()] = $Matches.value.Trim()
        }
    }
    if (-not $values.ContainsKey('Mode')) { throw 'santactl status output did not contain a Mode field.' }
    return [pscustomobject]@{
        mode = $values['Mode'].ToUpperInvariant()
        syncConfigured = $values.ContainsKey('Sync Server') -and -not [string]::IsNullOrWhiteSpace($values['Sync Server'])
        lastSuccessfulFullSync = if ($values.ContainsKey('Last Successful Full Sync')) { $values['Last Successful Full Sync'] } else { $null }
        values = $values
    }
}

function Invoke-SyncFixture {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Path)
    $fixture = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    if ($fixture.protocol -ne 'santa.sync.v1') { throw "Unsupported sync protocol '$($fixture.protocol)'." }
    $expectedStages = @('preflight','eventUpload','ruleDownload','postflight')
    if ((@($fixture.stages.name) -join '|') -ne ($expectedStages -join '|')) { throw 'Sync stages are missing or out of order.' }
    foreach ($stage in $fixture.stages) { if ([int]$stage.status -ne 200) { throw "Sync stage '$($stage.name)' failed with HTTP $($stage.status)." } }
    $eventIds = @($fixture.events | ForEach-Object event_id)
    $uniqueEventIds = @($eventIds | Sort-Object -Unique)
    $seen = [System.Collections.Generic.HashSet[string]]::new()
    $rules = @()
    foreach ($page in $fixture.rulePages) {
        if (-not $seen.Add([string]$page.cursor)) { throw "Rule cursor cycle detected at '$($page.cursor)'." }
        $rules += @($page.rules)
    }
    if ($fixture.rulePages[-1].nextCursor) { throw 'Final rule page must have an empty next cursor.' }
    return [pscustomobject]@{
        protocol = $fixture.protocol
        cleanSync = [bool]$fixture.cleanSync
        uploadedEventCount = $uniqueEventIds.Count
        duplicateEventCount = $eventIds.Count - $uniqueEventIds.Count
        appliedRuleCount = $rules.Count
        postflight = 'succeeded'
    }
}

Export-ModuleMember -Function Get-SantaLock, Get-ProfileManifest, New-SantaProfileSet, Test-SantaProfileSet, Test-SantaPackageHash, Test-SantaPackageVerificationReceipt, Get-SantaProfileCleanupPlan, Test-EndpointState, Get-RulePrecedence, ConvertFrom-SantactlStatus, Invoke-SyncFixture
