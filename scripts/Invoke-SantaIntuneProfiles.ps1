[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)][string] $TenantId,
    [Parameter(Mandatory)][string] $PilotGroupId,
    [Parameter(Mandatory)][string] $ExpectedGroupDisplayName,
    [Parameter(Mandatory)][string] $ExpectedDeviceName,
    [Parameter(Mandatory)][string] $ExpectedAccount,
    [string] $Organization = 'Contoso',
    [switch] $AllowProfileUpdate,
    [switch] $Apply,
    [string] $ReceiptPath = (Join-Path (Split-Path -Parent $PSScriptRoot) '.azure/azd-santa/intune-profiles-receipt.json')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $PSScriptRoot 'Santa.Template.psm1') -Force

function Invoke-GraphJson {
    param(
        [Parameter(Mandatory)][ValidateSet('GET','POST','PATCH')][string] $Method,
        [Parameter(Mandatory)][string] $Uri,
        [object] $Body
    )
    $parameters = @{ Method = $Method; Uri = $Uri; OutputType = 'PSObject' }
    if ($null -ne $Body) {
        $parameters.Body = $Body | ConvertTo-Json -Depth 20 -Compress
        $parameters.ContentType = 'application/json'
    }
    return Invoke-MgGraphRequest @parameters
}
function Test-ExactPilotAssignment {
    param([Parameter(Mandatory)][object] $Assignment, [Parameter(Mandatory)][string] $GroupId)
    $target = $Assignment.target
    if (-not $target -or $target.'@odata.type' -ne '#microsoft.graph.groupAssignmentTarget' -or $target.groupId -ne $GroupId) { return $false }
    $filterId = $target.PSObject.Properties['deviceAndAppManagementAssignmentFilterId']
    $filterType = $target.PSObject.Properties['deviceAndAppManagementAssignmentFilterType']
    return (-not $filterId -or -not $filterId.Value) -and (-not $filterType -or $filterType.Value -in @($null, 'none'))
}
function Get-RemoteProperty {
    param([Parameter(Mandatory)][object] $Object, [Parameter(Mandatory)][string] $Name)
    $property = $Object.PSObject.Properties[$Name]
    if ($property) { return [string] $property.Value }
    return ''
}
function Test-EquivalentPayload {
    param([Parameter(Mandatory)][string] $Remote, [Parameter(Mandatory)][string] $Desired)
    try {
        $remoteText = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Remote))
        $desiredText = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Desired))
        return $remoteText.TrimEnd([char[]]@("`r", "`n")) -ceq $desiredText.TrimEnd([char[]]@("`r", "`n"))
    }
    catch { return $false }
}

$liveProfilePath = Join-Path $root 'out/intune-profiles'
$profilePaths = New-SantaProfileSet -Organization $Organization -OutputPath $liveProfilePath
Test-SantaProfileSet -ProfilePath $liveProfilePath | Out-Null
$lock = Get-SantaLock
$desired = @(
    foreach ($profilePath in $profilePaths) {
        $fileName = Split-Path -Leaf $profilePath
        $profileId = $fileName -replace '^\d+-','' -replace '\.mobileconfig$',''
        [pscustomobject]@{
            id = $profileId
            fileName = $fileName
            required = $profileId -ne 'notifications'
            displayName = "Santa $($lock.release.tag) - $profileId"
            description = "[azd-santa:$($lock.release.tag):$profileId] Template-owned Intune profile."
            payload = [Convert]::ToBase64String([IO.File]::ReadAllBytes($profilePath))
        }
    }
)

if (-not $Apply) {
    [pscustomobject]@{
        mode = 'what-if'
        tenantId = $TenantId
        pilotGroupId = $PilotGroupId
        expectedGroupDisplayName = $ExpectedGroupDisplayName
        expectedDeviceName = $ExpectedDeviceName
        expectedAccount = $ExpectedAccount
        allowProfileUpdate = [bool] $AllowProfileUpdate
        profiles = @($desired | Select-Object id,displayName,fileName,required)
        mutations = @('create-or-update five custom profiles','assign each profile only to the verified pilot group')
        packageUpload = 'blocked-pending-macOS-verification'
    } | ConvertTo-Json -Depth 10
    return
}

$requiredScopes = @('DeviceManagementConfiguration.ReadWrite.All','Group.Read.All')
$context = Get-MgContext -ErrorAction SilentlyContinue
if (-not $context -or $context.TenantId -ne $TenantId -or @($requiredScopes | Where-Object { $_ -notin $context.Scopes }).Count -gt 0) {
    Connect-MgGraph -TenantId $TenantId -Scopes $requiredScopes -ContextScope CurrentUser -NoWelcome
    $context = Get-MgContext
}
if ($context.TenantId -ne $TenantId) { throw "Authenticated tenant '$($context.TenantId)' does not match '$TenantId'." }
if ($context.Account -ne $ExpectedAccount) { throw "Authenticated account '$($context.Account)' does not match '$ExpectedAccount'." }
foreach ($scope in $requiredScopes) { if ($scope -notin $context.Scopes) { throw "Missing required delegated scope '$scope'." } }

$group = Invoke-GraphJson -Method GET -Uri "/v1.0/groups/${PilotGroupId}?`$select=id,displayName,securityEnabled,mailEnabled,groupTypes,membershipRule" -Body $null
if ($group.displayName -ne $ExpectedGroupDisplayName) { throw "Pilot group name drift: expected '$ExpectedGroupDisplayName', found '$($group.displayName)'." }
if (-not $group.securityEnabled -or $group.mailEnabled) { throw 'Pilot target must be a security-enabled, non-mail-enabled group.' }
if ('DynamicMembership' -in @($group.groupTypes) -or $group.membershipRule) { throw 'Pilot group must have static membership.' }
$members = Invoke-GraphJson -Method GET -Uri "/v1.0/groups/$PilotGroupId/members?`$select=id,displayName,deviceId,operatingSystem,operatingSystemVersion,userPrincipalName&`$top=100" -Body $null
if (@($members.value).Count -ne 1) { throw "Pilot group must contain exactly one member; found $(@($members.value).Count)." }
$pilotMember = @($members.value)[0]
if ($pilotMember.'@odata.type' -ne '#microsoft.graph.device' -or $pilotMember.displayName -cne $ExpectedDeviceName -or $pilotMember.operatingSystem -notmatch '^Mac') {
    throw "Pilot group member must be the exact macOS device '$ExpectedDeviceName'."
}

$allProfiles = Invoke-GraphJson -Method GET -Uri "/v1.0/deviceManagement/deviceConfigurations?`$select=id,displayName,description,lastModifiedDateTime&`$top=999" -Body $null
if (Get-RemoteProperty -Object $allProfiles -Name '@odata.nextLink') { throw 'Intune profile inventory is paginated; refusing an incomplete collision check.' }
$preflight = @(
    foreach ($profileSpec in $desired) {
        $sameName = @($allProfiles.value | Where-Object displayName -eq $profileSpec.displayName)
        $owned = @($sameName | Where-Object description -eq $profileSpec.description)
        if ($sameName.Count -ne $owned.Count) { throw "An unowned Intune profile already uses '$($profileSpec.displayName)'. Refusing to overwrite it." }
        if ($owned.Count -gt 1) { throw "Multiple template-owned profiles match '$($profileSpec.displayName)'. Resolve duplicates before continuing." }
        $remote = if ($owned.Count -eq 1) { $owned[0] } else { $null }
        $assignments = @()
        if ($remote) {
            $remote = Invoke-GraphJson -Method GET -Uri "/v1.0/deviceManagement/deviceConfigurations/$($remote.id)" -Body $null
            if ($remote.'@odata.type' -ne '#microsoft.graph.macOSCustomConfiguration' -or $remote.description -cne $profileSpec.description) {
                throw "Profile '$($remote.id)' is not the expected template-owned macOS custom configuration."
            }
            $assignmentResult = Invoke-GraphJson -Method GET -Uri "/v1.0/deviceManagement/deviceConfigurations/$($remote.id)/assignments" -Body $null
            if (Get-RemoteProperty -Object $assignmentResult -Name '@odata.nextLink') { throw "Assignment inventory for profile '$($remote.id)' is incomplete." }
            $assignments = @($assignmentResult.value)
            if ($assignments.Count -gt 1 -or @($assignments | Where-Object { -not (Test-ExactPilotAssignment -Assignment $_ -GroupId $PilotGroupId) }).Count -gt 0) {
                throw "Profile '$($remote.id)' has an assignment outside the authorized pilot group."
            }
        }
        $action = if (-not $remote) { 'create' }
            elseif ((Test-EquivalentPayload -Remote (Get-RemoteProperty -Object $remote -Name 'payload') -Desired $profileSpec.payload) -and
                (Get-RemoteProperty -Object $remote -Name 'payloadName') -ceq $profileSpec.fileName -and
                (Get-RemoteProperty -Object $remote -Name 'payloadFileName') -ceq $profileSpec.fileName) { 'verify' }
            else { 'update' }
        [pscustomobject]@{ spec = $profileSpec; remote = $remote; assigned = $assignments.Count -eq 1; action = $action }
    }
)
$updates = @($preflight | Where-Object action -eq 'update')
if ($updates.Count -gt 0 -and -not $AllowProfileUpdate) {
    throw "Existing profile payload drift requires -AllowProfileUpdate after review: $($updates.spec.id -join ', '). No Intune changes were made."
}
$receipt = [ordered]@{
    schemaVersion = '1.0'
    tenantId = $TenantId
    account = $context.Account
    release = $lock.release.tag
    pilotGroup = [ordered]@{ id = $group.id; displayName = $group.displayName; memberId = $pilotMember.id; memberDisplayName = $pilotMember.displayName; operatingSystem = $pilotMember.operatingSystem; operatingSystemVersion = $pilotMember.operatingSystemVersion }
    appliedAt = [DateTimeOffset]::UtcNow.ToString('o')
    profiles = @()
    package = [ordered]@{ status = 'unknown'; reason = 'Profile apply does not prove package absence; inspect package separately before cleanup.' }
}

New-Item -ItemType Directory -Path (Split-Path -Parent $ReceiptPath) -Force | Out-Null
foreach ($item in $preflight) {
    $profileSpec = $item.spec
    $body = [ordered]@{
        '@odata.type' = '#microsoft.graph.macOSCustomConfiguration'
        displayName = $profileSpec.displayName
        description = $profileSpec.description
        payloadName = $profileSpec.fileName
        payloadFileName = $profileSpec.fileName
        payload = $profileSpec.payload
    }
    $action = $item.action
    if (-not $PSCmdlet.ShouldProcess("$($profileSpec.displayName) -> $($group.displayName)", "$action and assign Intune profile")) { continue }
    if ($action -eq 'create') {
        $remote = Invoke-GraphJson -Method POST -Uri '/v1.0/deviceManagement/deviceConfigurations' -Body $body
    } elseif ($action -eq 'update') {
        $remote = $item.remote
        Invoke-GraphJson -Method PATCH -Uri "/v1.0/deviceManagement/deviceConfigurations/$($remote.id)" -Body $body | Out-Null
    } else {
        $remote = $item.remote
    }
    if (-not $item.assigned -or $action -eq 'update') {
        $assignmentBody = @{ assignments = @(@{ '@odata.type' = '#microsoft.graph.deviceConfigurationAssignment'; target = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = $PilotGroupId } }) }
        Invoke-GraphJson -Method POST -Uri "/v1.0/deviceManagement/deviceConfigurations/$($remote.id)/assign" -Body $assignmentBody | Out-Null
    }
    $verifiedAssignments = Invoke-GraphJson -Method GET -Uri "/v1.0/deviceManagement/deviceConfigurations/$($remote.id)/assignments" -Body $null
    $verified = @($verifiedAssignments.value)
    if ($verified.Count -ne 1 -or -not (Test-ExactPilotAssignment -Assignment $verified[0] -GroupId $PilotGroupId)) {
        throw "Assignment verification failed for '$($remote.id)'."
    }
    $receipt.profiles += [ordered]@{ id = $profileSpec.id; objectId = $remote.id; displayName = $profileSpec.displayName; action = $action; assignmentGroupId = $PilotGroupId }
    [IO.File]::WriteAllText($ReceiptPath, (($receipt | ConvertTo-Json -Depth 20) + [Environment]::NewLine), [Text.UTF8Encoding]::new($false))
}

if ($receipt.profiles.Count -ne $desired.Count) { throw "Only $($receipt.profiles.Count) of $($desired.Count) profiles were applied." }
$receipt | ConvertTo-Json -Depth 20
