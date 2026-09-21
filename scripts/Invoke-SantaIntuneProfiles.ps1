[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)][string] $TenantId,
    [Parameter(Mandatory)][string] $PilotGroupId,
    [Parameter(Mandatory)][string] $ExpectedGroupDisplayName,
    [Parameter(Mandatory)][string] $ExpectedAccount,
    [string] $Organization = 'Contoso',
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
        expectedAccount = $ExpectedAccount
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
$members = Invoke-GraphJson -Method GET -Uri "/v1.0/groups/$PilotGroupId/members?`$select=id,displayName,deviceId,operatingSystem,operatingSystemVersion,userPrincipalName&`$top=100" -Body $null
if (@($members.value).Count -ne 1) { throw "Pilot group must contain exactly one member; found $(@($members.value).Count)." }
$pilotMember = @($members.value)[0]
if ($pilotMember.operatingSystem -notmatch '^Mac') { throw "Pilot group member '$($pilotMember.displayName)' is not reported as macOS." }

$allProfiles = Invoke-GraphJson -Method GET -Uri "/v1.0/deviceManagement/deviceConfigurations?`$select=id,displayName,description,lastModifiedDateTime&`$top=999" -Body $null
$receipt = [ordered]@{
    schemaVersion = '1.0'
    tenantId = $TenantId
    account = $context.Account
    release = $lock.release.tag
    pilotGroup = [ordered]@{ id = $group.id; displayName = $group.displayName; memberId = $pilotMember.id; memberDisplayName = $pilotMember.displayName; operatingSystem = $pilotMember.operatingSystem; operatingSystemVersion = $pilotMember.operatingSystemVersion }
    appliedAt = [DateTimeOffset]::UtcNow.ToString('o')
    profiles = @()
    package = [ordered]@{ status = 'not-uploaded'; reason = 'macOS signature and notarization verification required' }
}

New-Item -ItemType Directory -Path (Split-Path -Parent $ReceiptPath) -Force | Out-Null
foreach ($profileSpec in $desired) {
    $sameName = @($allProfiles.value | Where-Object displayName -eq $profileSpec.displayName)
    $owned = @($sameName | Where-Object description -eq $profileSpec.description)
    if ($sameName.Count -ne $owned.Count) { throw "An unowned Intune profile already uses '$($profileSpec.displayName)'. Refusing to overwrite it." }
    if ($owned.Count -gt 1) { throw "Multiple template-owned profiles match '$($profileSpec.displayName)'. Resolve duplicates before continuing." }
    $body = [ordered]@{
        '@odata.type' = '#microsoft.graph.macOSCustomConfiguration'
        displayName = $profileSpec.displayName
        description = $profileSpec.description
        payloadName = $profileSpec.fileName
        payloadFileName = $profileSpec.fileName
        payload = $profileSpec.payload
    }
    $action = if ($owned.Count -eq 1) { 'update' } else { 'create' }
    if (-not $PSCmdlet.ShouldProcess("$($profileSpec.displayName) -> $($group.displayName)", "$action and assign Intune profile")) { continue }
    if ($action -eq 'create') {
        $remote = Invoke-GraphJson -Method POST -Uri '/v1.0/deviceManagement/deviceConfigurations' -Body $body
    } else {
        $remote = $owned[0]
        Invoke-GraphJson -Method PATCH -Uri "/v1.0/deviceManagement/deviceConfigurations/$($remote.id)" -Body $body | Out-Null
    }
    $existingAssignments = Invoke-GraphJson -Method GET -Uri "/v1.0/deviceManagement/deviceConfigurations/$($remote.id)/assignments" -Body $null
    $foreignAssignments = @($existingAssignments.value | Where-Object { $_.target.groupId -and $_.target.groupId -ne $PilotGroupId })
    if ($foreignAssignments.Count -gt 0) { throw "Profile '$($remote.id)' has an assignment outside the authorized pilot group." }
    $assignmentBody = @{ assignments = @(@{ '@odata.type' = '#microsoft.graph.deviceConfigurationAssignment'; target = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = $PilotGroupId } }) }
    Invoke-GraphJson -Method POST -Uri "/v1.0/deviceManagement/deviceConfigurations/$($remote.id)/assign" -Body $assignmentBody | Out-Null
    $verifiedAssignments = Invoke-GraphJson -Method GET -Uri "/v1.0/deviceManagement/deviceConfigurations/$($remote.id)/assignments" -Body $null
    $targetIds = @($verifiedAssignments.value | ForEach-Object { $_.target.groupId } | Where-Object { $_ } | Sort-Object -Unique)
    if ($targetIds.Count -ne 1 -or $targetIds[0] -ne $PilotGroupId) { throw "Assignment verification failed for '$($remote.id)'." }
    $receipt.profiles += [ordered]@{ id = $profileSpec.id; objectId = $remote.id; displayName = $profileSpec.displayName; action = $action; assignmentGroupId = $PilotGroupId }
    [IO.File]::WriteAllText($ReceiptPath, (($receipt | ConvertTo-Json -Depth 20) + [Environment]::NewLine), [Text.UTF8Encoding]::new($false))
}

if ($receipt.profiles.Count -ne $desired.Count) { throw "Only $($receipt.profiles.Count) of $($desired.Count) profiles were applied." }
$receipt | ConvertTo-Json -Depth 20
