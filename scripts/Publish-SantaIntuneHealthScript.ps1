#requires -Version 7.0
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)][string] $TenantId,
    [Parameter(Mandatory)][string] $PilotGroupId,
    [Parameter(Mandatory)][string] $ExpectedGroupDisplayName,
    [Parameter(Mandatory)][string] $ExpectedDeviceName,
    [Parameter(Mandatory)][string] $ExpectedAccount,
    [string] $ScriptPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts/live-response/Get-SantaHealth.sh'),
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$')][string] $EnvironmentName = 'default',
    [string] $ReceiptPath,
    [switch] $Apply
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $PSScriptRoot 'Santa.Template.psm1') -Force
$lock = Get-SantaLock
if (-not $ReceiptPath) { $ReceiptPath = Join-Path $root ".azure/$EnvironmentName/azd-santa-intune-health-script-state.json" }
if (-not (Test-Path -LiteralPath $ScriptPath -PathType Leaf)) { throw "Intune health script not found: $ScriptPath" }
if ($TenantId -notmatch '^[0-9a-fA-F-]{36}$' -or $PilotGroupId -notmatch '^[0-9a-fA-F-]{36}$') { throw 'TenantId and PilotGroupId must be GUIDs.' }
if ($ExpectedAccount -notmatch '^[^@\s]+@[^@\s]+$') { throw 'ExpectedAccount must be the intended Intune administrator UPN.' }

$fileName = [IO.Path]::GetFileName($ScriptPath)
$bytes = [IO.File]::ReadAllBytes($ScriptPath)
$sha256 = (Get-FileHash -LiteralPath $ScriptPath -Algorithm SHA256).Hash.ToLowerInvariant()
$displayName = "Santa $($lock.release.tag) health verification (azd-santa)"
$description = "[azd-santa:health:$($lock.release.tag):$sha256] Template-owned macOS verification script."
if (-not $Apply) {
    [pscustomobject]@{ mode = 'what-if'; displayName = $displayName; fileName = $fileName; sha256 = $sha256; tenantId = $TenantId; pilotGroupId = $PilotGroupId; expectedDeviceName = $ExpectedDeviceName } | ConvertTo-Json
    return
}
if (-not $PSCmdlet.ShouldProcess("$ExpectedDeviceName via $ExpectedGroupDisplayName", "Publish and assign Intune macOS health script $displayName")) { return }

$scopes = @('DeviceManagementScripts.ReadWrite.All','DeviceManagementConfiguration.ReadWrite.All','DeviceManagementManagedDevices.ReadWrite.All','Group.Read.All','Device.Read.All')
Connect-MgGraph -TenantId $TenantId -Scopes $scopes -ContextScope Process -NoWelcome
$context = Get-MgContext
if ($context.TenantId -ne $TenantId -or $context.Account -ne $ExpectedAccount) { throw "Microsoft Graph context does not match the authorized tenant/account: $($context.Account) / $($context.TenantId)" }
foreach ($scope in $scopes) { if ($scope -notin $context.Scopes) { throw "Missing required delegated scope '$scope'." } }

function Invoke-GraphJson {
    param([Parameter(Mandatory)][ValidateSet('GET','POST','PATCH')][string] $Method, [Parameter(Mandatory)][string] $Uri, [object] $Body)
    $parameters = @{ Method = $Method; Uri = $Uri; OutputType = 'PSObject' }
    if ($null -ne $Body) { $parameters.Body = $Body | ConvertTo-Json -Depth 20 -Compress; $parameters.ContentType = 'application/json' }
    Invoke-MgGraphRequest @parameters
}

function Get-PilotAssignmentTargets {
    param([Parameter(Mandatory)] $Script, [Parameter(Mandatory)][string] $GroupId)
    $legacy = @($Script.groupAssignments)
    $modern = @($Script.assignments)
    if ($legacy.Count -gt 1 -or $modern.Count -gt 1) { throw 'Intune health script has duplicate pilot assignments.' }
    $foreignLegacy = @($legacy | Where-Object targetGroupId -ne $GroupId)
    $foreignModern = @($modern | Where-Object {
        $_.target.'@odata.type' -ne '#microsoft.graph.groupAssignmentTarget' -or
        $_.target.groupId -ne $GroupId -or
        ($_.target.deviceAndAppManagementAssignmentFilterType -and $_.target.deviceAndAppManagementAssignmentFilterType -ne 'none')
    })
    if ($foreignLegacy.Count -gt 0 -or $foreignModern.Count -gt 0) { throw 'Intune health script has an assignment outside the authorized unfiltered pilot group.' }
    @(@($legacy | ForEach-Object targetGroupId) + @($modern | ForEach-Object { $_.target.groupId }) | Sort-Object -Unique)
}

$group = Invoke-GraphJson -Method GET -Uri "https://graph.microsoft.com/v1.0/groups/$PilotGroupId`?`$select=id,displayName,securityEnabled,mailEnabled" -Body $null
if ($group.displayName -ne $ExpectedGroupDisplayName -or -not $group.securityEnabled -or $group.mailEnabled) { throw 'Pilot group identity or type did not match the authorized target.' }
$members = Invoke-GraphJson -Method GET -Uri "https://graph.microsoft.com/v1.0/groups/$PilotGroupId/members`?`$select=id,displayName,deviceId,operatingSystem&`$top=100" -Body $null
if (@($members.value).Count -ne 1 -or [string]$members.value[0].displayName -ne $ExpectedDeviceName -or [string]$members.value[0].operatingSystem -notmatch '^Mac') {
    throw 'Pilot group is not the exact one-device macOS target.'
}

$scripts = Invoke-GraphJson -Method GET -Uri 'https://graph.microsoft.com/beta/deviceManagement/deviceShellScripts?$select=id,displayName,description,fileName,runAsAccount,lastModifiedDateTime' -Body $null
$sameName = @($scripts.value | Where-Object displayName -eq $displayName)
$owned = @($sameName | Where-Object description -match '^\[azd-santa:health:')
if ($sameName.Count -ne $owned.Count) { throw "An unowned Intune shell script already uses '$displayName'." }
if ($owned.Count -gt 1) { throw "Multiple template-owned Intune shell scripts use '$displayName'." }
$body = [ordered]@{
    '@odata.type' = '#microsoft.graph.deviceShellScript'; displayName = $displayName; description = $description
    scriptContent = [Convert]::ToBase64String($bytes); runAsAccount = 'system'; fileName = $fileName
    retryCount = 3; blockExecutionNotifications = $true; roleScopeTagIds = @('0')
}
if ($owned.Count -eq 0) {
    $remote = Invoke-GraphJson -Method POST -Uri 'https://graph.microsoft.com/beta/deviceManagement/deviceShellScripts' -Body $body
    $action = 'created'
} else {
    $remote = Invoke-GraphJson -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceShellScripts/$($owned[0].id)?`$expand=groupAssignments,assignments" -Body $null
    $existingTargets = @(Get-PilotAssignmentTargets -Script $remote -GroupId $PilotGroupId)
    if ($existingTargets.Count -gt 1) { throw 'Intune health script has duplicate pilot assignments.' }
    $remoteHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Convert]::FromBase64String([string] $remote.scriptContent))).ToLowerInvariant()
    if ([string]$remote.description -eq $description -and $remoteHash -eq $sha256 -and
        [string]$remote.fileName -eq $fileName -and [string]$remote.runAsAccount -eq 'system') {
        $action = 'verified'
    } else {
        Invoke-GraphJson -Method PATCH -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceShellScripts/$($remote.id)" -Body $body | Out-Null
        $action = 'updated'
    }
}

$assignmentState = Invoke-GraphJson -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceShellScripts/$($remote.id)?`$expand=groupAssignments,assignments" -Body $null
$exactTargets = @(Get-PilotAssignmentTargets -Script $assignmentState -GroupId $PilotGroupId)
if ($exactTargets.Count -eq 0) {
    $assignmentBody = [ordered]@{
        deviceManagementScriptGroupAssignments = @()
        deviceManagementScriptAssignments = @(
            [ordered]@{
                '@odata.type' = '#microsoft.graph.deviceManagementScriptAssignment'
                target = [ordered]@{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = $PilotGroupId }
            }
        )
    }
    Invoke-GraphJson -Method POST -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceShellScripts/$($remote.id)/assign" -Body $assignmentBody | Out-Null
} elseif ($exactTargets.Count -gt 1) { throw 'Intune health script has duplicate pilot assignments.' }
$readback = Invoke-GraphJson -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceShellScripts/$($remote.id)?`$expand=groupAssignments,assignments" -Body $null
$readbackTargets = @(Get-PilotAssignmentTargets -Script $readback -GroupId $PilotGroupId)
if ($readbackTargets.Count -ne 1 -or [string]$readbackTargets[0] -ne $PilotGroupId) { throw 'Intune health script assignment read-back failed.' }
$readbackHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Convert]::FromBase64String([string] $readback.scriptContent))).ToLowerInvariant()
if ($readbackHash -ne $sha256 -or [string]$readback.description -ne $description) { throw 'Intune health script content read-back failed.' }

New-Item -ItemType Directory -Path (Split-Path -Parent $ReceiptPath) -Force | Out-Null
[ordered]@{
    schemaVersion = '1.0'; template = 'azd-santa'; objectType = 'intune-device-shell-script'; status = 'assigned'
    tenantId = $TenantId; account = $ExpectedAccount; environmentName = $EnvironmentName; scriptId = $remote.id
    displayName = $displayName; description = $description; fileName = $fileName; sha256 = $sha256; action = $action
    assignmentGroupId = $PilotGroupId; assignmentGroupName = $ExpectedGroupDisplayName; expectedDeviceName = $ExpectedDeviceName
    recordedUtc = [DateTime]::UtcNow.ToString('o')
} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $ReceiptPath -Encoding UTF8
Write-Host "Published and assigned Intune health script '$displayName' to '$ExpectedGroupDisplayName'." -ForegroundColor Green
