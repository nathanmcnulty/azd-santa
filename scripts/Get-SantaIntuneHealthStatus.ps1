#requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $TenantId,
    [Parameter(Mandatory)][string] $ExpectedAccount,
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$')][string] $EnvironmentName = 'default',
    [string] $PublicationReceiptPath,
    [string] $OutputPath
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (-not $PublicationReceiptPath) { $PublicationReceiptPath = Join-Path $root ".azure/$EnvironmentName/azd-santa-intune-health-script-state.json" }
if (-not $OutputPath) { $OutputPath = Join-Path $root ".azure/$EnvironmentName/santa-intune-health-result.json" }
if ($TenantId -notmatch '^[0-9a-fA-F-]{36}$') { throw 'TenantId must be a tenant GUID.' }
if ($ExpectedAccount -notmatch '^[^@\s]+@[^@\s]+$') { throw 'ExpectedAccount must be the intended Intune reader UPN.' }
if (-not (Test-Path -LiteralPath $PublicationReceiptPath -PathType Leaf)) { throw "Intune publication receipt not found: $PublicationReceiptPath" }

$publication = Get-Content -LiteralPath $PublicationReceiptPath -Raw | ConvertFrom-Json
if ($publication.template -ne 'azd-santa' -or $publication.objectType -ne 'intune-device-shell-script' -or
    $publication.tenantId -ne $TenantId -or $publication.environmentName -ne $EnvironmentName -or
    $publication.scriptId -notmatch '^[0-9a-fA-F-]{36}$' -or
    $publication.assignmentGroupId -notmatch '^[0-9a-fA-F-]{36}$' -or
    $publication.sha256 -notmatch '^[0-9a-f]{64}$') {
    throw 'Intune publication receipt does not match this environment, tenant, or object type.'
}
$scriptPath = Join-Path $PSScriptRoot 'live-response/Get-SantaHealth.sh'
$localHash = (Get-FileHash -LiteralPath $scriptPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($publication.sha256 -cne $localHash) { throw 'Published health script hash differs from the current repository artifact.' }

$scopes = @('DeviceManagementScripts.Read.All','DeviceManagementManagedDevices.Read.All','Group.Read.All','Device.Read.All')
Connect-MgGraph -TenantId $TenantId -Scopes $scopes -ContextScope Process -NoWelcome
$context = Get-MgContext
if ($context.TenantId -ne $TenantId -or $context.Account -ne $ExpectedAccount) { throw 'Microsoft Graph is connected to a different tenant or account.' }
foreach ($scope in $scopes) { if ($scope -notin $context.Scopes) { throw "Missing delegated scope '$scope'." } }

function Get-GraphObject {
    param([Parameter(Mandatory)][string] $Uri)
    Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType PSObject
}

$groupId = [string] $publication.assignmentGroupId
$scriptId = [string] $publication.scriptId
$deviceName = [string] $publication.expectedDeviceName
$group = Get-GraphObject "https://graph.microsoft.com/v1.0/groups/$groupId`?`$select=id,displayName,securityEnabled,mailEnabled"
if ($group.displayName -ne $publication.assignmentGroupName -or -not $group.securityEnabled -or $group.mailEnabled) { throw 'Pilot group identity or type changed.' }
$members = Get-GraphObject "https://graph.microsoft.com/v1.0/groups/$groupId/members`?`$select=id,displayName,deviceId,operatingSystem&`$top=100"
if (@($members.value).Count -ne 1 -or $members.value[0].'@odata.type' -ne '#microsoft.graph.device' -or
    $members.value[0].displayName -ne $deviceName -or $members.value[0].operatingSystem -notmatch '^Mac') {
    throw 'Pilot group is no longer the exact one-device macOS target.'
}
$entraDeviceId = [string] $members.value[0].deviceId
$managed = Get-GraphObject "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=azureADDeviceId eq '$entraDeviceId'&`$top=100"
if (@($managed.value).Count -ne 1 -or $managed.value[0].deviceName -ne $deviceName -or $managed.value[0].operatingSystem -ne 'macOS') {
    throw 'The pilot Entra device does not bind to exactly one matching Intune Mac.'
}
$managedDeviceId = [string] $managed.value[0].id

$remote = Get-GraphObject "https://graph.microsoft.com/beta/deviceManagement/deviceShellScripts/$scriptId`?`$expand=groupAssignments,assignments"
if ($remote.id -ne $scriptId -or $remote.displayName -ne $publication.displayName -or
    $remote.description -ne $publication.description -or $remote.runAsAccount -ne 'system') {
    throw 'Published Intune script identity or execution context changed.'
}
$remoteHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Convert]::FromBase64String([string] $remote.scriptContent))).ToLowerInvariant()
if ($remoteHash -cne $localHash) { throw 'Published Intune script content differs from the repository artifact.' }
$legacy = @($remote.groupAssignments)
$modern = @($remote.assignments)
if ($legacy.Count -gt 1 -or $modern.Count -gt 1) { throw 'Intune health script has duplicate pilot assignments.' }
if (@($legacy | Where-Object targetGroupId -ne $groupId).Count -gt 0 -or
    @($modern | Where-Object {
        $_.target.'@odata.type' -ne '#microsoft.graph.groupAssignmentTarget' -or
        $_.target.groupId -ne $groupId -or
        ($_.target.deviceAndAppManagementAssignmentFilterType -and $_.target.deviceAndAppManagementAssignmentFilterType -ne 'none')
    }).Count -gt 0) { throw 'Intune health script has a foreign or filtered assignment.' }
$assignmentTargets = @(@($legacy | ForEach-Object targetGroupId) + @($modern | ForEach-Object { $_.target.groupId }) | Sort-Object -Unique)
if ($assignmentTargets.Count -ne 1 -or $assignmentTargets[0] -ne $groupId) { throw 'Intune health script is not assigned only to the pilot group.' }

$states = Get-GraphObject "https://graph.microsoft.com/beta/deviceManagement/deviceShellScripts/$scriptId/deviceRunStates?`$expand=managedDevice"
$allStates = @($states.value)
if (@($allStates | Where-Object { $_.managedDevice.id -ne $managedDeviceId }).Count -gt 0 -or $allStates.Count -gt 1) {
    throw 'Intune returned a health-script run state outside the one-device pilot.'
}
$run = if ($allStates.Count -eq 1) { $allStates[0] } else { $null }
$resultText = if ($run) { [string] $run.resultMessage } else { '' }
$captured = [regex]::Match($resultText, '(?m)^capturedAtUtc=([^\r\n]+)$').Groups[1].Value
$reportedName = [regex]::Match($resultText, '(?m)^computerName=([^\r\n]+)$').Groups[1].Value
$expectedVersion = (Get-Content -LiteralPath (Join-Path $root 'package/santa.lock.json') -Raw | ConvertFrom-Json).release.tag
$versionReported = [regex]::Match($resultText, '(?m)^expectedSantaVersion=([^\r\n]+)$').Groups[1].Value
$runTime = if ($run) { [DateTimeOffset] $run.lastStateUpdateDateTime } else { $null }
$scriptTime = [DateTimeOffset] $remote.lastModifiedDateTime
$capturedTime = [DateTimeOffset]::MinValue
$hasCapturedTime = [DateTimeOffset]::TryParse($captured, [ref] $capturedTime)
$passed = $run -and $run.runState -eq 'success' -and [int]$run.errorCode -eq 0 -and
    $runTime -ge $scriptTime -and $hasCapturedTime -and $capturedTime -ge $scriptTime -and
    $reportedName -eq $deviceName -and $versionReported -eq $expectedVersion -and
    $resultText -match '(?m)^result=passed$'
$status = if ($passed) { 'passed' } elseif (-not $run -or $run.runState -in @('unknown','pending') -or ($runTime -lt $scriptTime)) { 'pending' } else { 'failed' }

New-Item -ItemType Directory -Path (Split-Path -Parent $OutputPath) -Force | Out-Null
[ordered]@{
    schemaVersion = '1.0'; template = 'azd-santa'; performsMutation = $false
    collectedUtc = [DateTimeOffset]::UtcNow.ToString('o'); status = $status
    tenantId = $TenantId; account = $ExpectedAccount; environmentName = $EnvironmentName
    script = [ordered]@{ id = $scriptId; sha256 = $remoteHash; lastModifiedUtc = $scriptTime.ToUniversalTime().ToString('o') }
    pilot = [ordered]@{ groupId = $groupId; entraDeviceId = $entraDeviceId; managedDeviceId = $managedDeviceId; deviceName = $deviceName }
    run = if ($run) { [ordered]@{
        id = [string] $run.id; state = [string] $run.runState; lastStateUpdateUtc = $runTime.ToUniversalTime().ToString('o')
        capturedUtc = $captured; errorCode = [int] $run.errorCode; errorDescription = [string] $run.errorDescription
        resultMessage = $resultText
    } } else { $null }
} | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
Write-Host "Intune Santa health on $deviceName`: $status. Result: $OutputPath"
