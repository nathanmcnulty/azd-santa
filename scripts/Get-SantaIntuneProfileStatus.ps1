[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $TenantId,
    [Parameter(Mandatory)][string] $ExpectedAccount,
    [Parameter(Mandatory)][string] $ExpectedDeviceName,
    [string] $ReceiptPath = (Join-Path (Split-Path -Parent $PSScriptRoot) '.azure/azd-santa/intune-profiles-receipt.json'),
    [string] $OutputPath = (Join-Path (Split-Path -Parent $PSScriptRoot) '.azure/azd-santa/intune-profile-status.json')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $PSScriptRoot 'Santa.Template.psm1') -Force

function Invoke-GraphRead {
    param([Parameter(Mandatory)][string] $Uri)
    return Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType PSObject
}

$receiptSchema = Join-Path $root 'schemas/intune-profile-receipt.schema.json'
$receiptRaw = Get-Content -LiteralPath $ReceiptPath -Raw
if (-not ($receiptRaw | Test-Json -SchemaFile $receiptSchema -ErrorAction Stop)) {
    throw 'Intune profile receipt does not satisfy its schema.'
}
$receipt = $receiptRaw | ConvertFrom-Json
$lock = Get-SantaLock
$manifest = Get-ProfileManifest
if ([string] $receipt.tenantId -cne $TenantId) { throw 'Receipt tenant does not match the requested tenant.' }
if ([string] $receipt.release -cne [string] $lock.release.tag) { throw 'Receipt release does not match the release lock.' }
$expectedIds = @($manifest.profiles | Sort-Object order | ForEach-Object { [string] $_.id })
$receiptIds = @($receipt.profiles | ForEach-Object { [string] $_.id })
if ((($expectedIds | Sort-Object) -join '|') -cne (($receiptIds | Sort-Object) -join '|') -or @($receiptIds | Sort-Object -Unique).Count -ne $expectedIds.Count) {
    throw 'Receipt does not contain the exact unique profile set.'
}
foreach ($receiptProfile in @($receipt.profiles)) {
    if ([string] $receiptProfile.assignmentGroupId -cne [string] $receipt.pilotGroup.id) {
        throw "Receipt profile '$($receiptProfile.id)' is scoped outside the recorded pilot group."
    }
}
if ([string]::IsNullOrWhiteSpace([string] $receipt.pilotGroup.memberId)) {
    throw 'Receipt does not identify the exact Entra pilot device member.'
}

$requiredScopes = @('DeviceManagementConfiguration.Read.All','DeviceManagementManagedDevices.Read.All','Device.Read.All','Group.Read.All')
$context = Get-MgContext -ErrorAction SilentlyContinue
if (-not $context -or $context.TenantId -ne $TenantId -or @($requiredScopes | Where-Object { $_ -notin $context.Scopes }).Count -gt 0) {
    Connect-MgGraph -TenantId $TenantId -Scopes $requiredScopes -ContextScope CurrentUser -NoWelcome
    $context = Get-MgContext
}
if ($context.TenantId -ne $TenantId) { throw "Authenticated tenant '$($context.TenantId)' does not match '$TenantId'." }
if ($context.Account -ine $ExpectedAccount) { throw "Authenticated account '$($context.Account)' does not match '$ExpectedAccount'." }
foreach ($requiredScope in $requiredScopes) {
    if ($requiredScope -notin $context.Scopes) { throw "Missing required delegated scope '$requiredScope'." }
}

$group = Invoke-GraphRead -Uri "/v1.0/groups/$($receipt.pilotGroup.id)?`$select=id,displayName"
if ([string] $group.id -cne [string] $receipt.pilotGroup.id -or [string] $group.displayName -cne [string] $receipt.pilotGroup.displayName) {
    throw 'Pilot group no longer matches its receipt identity.'
}
$members = Invoke-GraphRead -Uri "/v1.0/groups/$($receipt.pilotGroup.id)/members?`$select=id,displayName,deviceId,operatingSystem,operatingSystemVersion&`$top=100"
if (@($members.value).Count -ne 1) { throw "Pilot group must still contain exactly one member; found $(@($members.value).Count)." }
$groupMember = @($members.value)[0]
if ([string] $groupMember.id -cne [string] $receipt.pilotGroup.memberId -or [string] $groupMember.'@odata.type' -cne '#microsoft.graph.device') {
    throw 'Pilot group member no longer matches the recorded Entra device.'
}
$entraDevice = Invoke-GraphRead -Uri "/v1.0/devices/$($groupMember.id)?`$select=id,deviceId,displayName,operatingSystem,operatingSystemVersion,accountEnabled"
if (-not [bool] $entraDevice.accountEnabled -or [string] $entraDevice.displayName -cne $ExpectedDeviceName) {
    throw "Entra pilot device does not match enabled device '$ExpectedDeviceName'."
}
$managedDevices = Invoke-GraphRead -Uri "/beta/deviceManagement/managedDevices?`$filter=azureADDeviceId eq '$($entraDevice.deviceId)'&`$top=100"
if (@($managedDevices.value).Count -ne 1) { throw "Expected one Intune managed-device match for the pilot; found $(@($managedDevices.value).Count)." }
$managedDevice = @($managedDevices.value)[0]
if ([string] $managedDevice.deviceName -cne $ExpectedDeviceName -or [string] $managedDevice.operatingSystem -ine 'macOS') {
    throw "Intune pilot device does not match macOS device '$ExpectedDeviceName'."
}
$deviceConfigurationStates = Invoke-GraphRead -Uri "/beta/deviceManagement/managedDevices/$($managedDevice.id)/deviceConfigurationStates?`$top=200"

$report = [ordered]@{
    schemaVersion = '1.1'
    collectedAt = [DateTimeOffset]::UtcNow.ToString('o')
    performsMutation = $false
    tenantId = $TenantId
    account = [string] $context.Account
    release = [string] $receipt.release
    pilotGroup = [ordered]@{ id = [string] $receipt.pilotGroup.id; displayName = [string] $receipt.pilotGroup.displayName; memberId = [string] $groupMember.id }
    pilotDevice = [ordered]@{
        entraObjectId = [string] $entraDevice.id
        aadDeviceId = [string] $entraDevice.deviceId
        managedDeviceId = [string] $managedDevice.id
        deviceName = [string] $managedDevice.deviceName
        serialNumber = [string] $managedDevice.serialNumber
        operatingSystem = [string] $managedDevice.operatingSystem
        osVersion = [string] $managedDevice.osVersion
        complianceState = [string] $managedDevice.complianceState
        lastSyncDateTime = ([DateTimeOffset] $managedDevice.lastSyncDateTime).ToString('o')
        configurationStates = @($deviceConfigurationStates.value | ForEach-Object {
            [ordered]@{
                id = [string] $_.id
                displayName = [string] $_.displayName
                state = [string] $_.state
                version = [int] $_.version
            }
        })
    }
    profiles = @()
}
foreach ($spec in @($manifest.profiles | Sort-Object order)) {
    $record = @($receipt.profiles | Where-Object id -eq $spec.id)[0]
    $objectId = [string] $record.objectId
    $remote = Invoke-GraphRead -Uri "/v1.0/deviceManagement/deviceConfigurations/${objectId}?`$select=id,displayName,description,lastModifiedDateTime"
    if ([string] $remote.id -cne $objectId -or [string] $remote.displayName -cne [string] $record.displayName) {
        throw "Intune profile '$($spec.id)' no longer matches its receipt identity."
    }
    $assignments = Invoke-GraphRead -Uri "/v1.0/deviceManagement/deviceConfigurations/${objectId}/assignments?`$top=999"
    $groupIds = @($assignments.value | ForEach-Object { $_.target.groupId } | Where-Object { $_ } | Sort-Object -Unique)
    $overview = Invoke-GraphRead -Uri "/v1.0/deviceManagement/deviceConfigurations/${objectId}/deviceStatusOverview"
    $statuses = Invoke-GraphRead -Uri "/v1.0/deviceManagement/deviceConfigurations/${objectId}/deviceStatuses?`$top=100"
    $report.profiles += [ordered]@{
        id = [string] $spec.id
        required = [bool] $spec.required
        objectId = $objectId
        displayName = [string] $remote.displayName
        description = [string] $remote.description
        assignment = [ordered]@{
            groupIds = $groupIds
            exactPilotOnly = (@($assignments.value).Count -eq 1 -and $groupIds.Count -eq 1 -and [string] $groupIds[0] -ceq [string] $receipt.pilotGroup.id)
        }
        overview = [ordered]@{
            successCount = [int] $overview.successCount
            errorCount = [int] $overview.errorCount
            failedCount = [int] $overview.failedCount
            pendingCount = [int] $overview.pendingCount
            notApplicableCount = [int] $overview.notApplicableCount
        }
        deviceStatuses = @($statuses.value | ForEach-Object {
            [ordered]@{
                id = [string] $_.id
                deviceDisplayName = [string] $_.deviceDisplayName
                userName = [string] $_.userName
                status = [string] $_.status
                lastReportedDateTime = [string] $_.lastReportedDateTime
            }
        })
    }
}
$report.summary = Test-SantaIntuneProfileReport -State ([pscustomobject] $report)
$json = ([pscustomobject] $report) | ConvertTo-Json -Depth 20
if (-not ($json | Test-Json -SchemaFile (Join-Path $root 'schemas/intune-profile-status.schema.json') -ErrorAction Stop)) {
    throw 'Generated Intune profile status report does not satisfy its schema.'
}
New-Item -ItemType Directory -Path (Split-Path -Parent $OutputPath) -Force | Out-Null
[IO.File]::WriteAllText($OutputPath, ($json + [Environment]::NewLine), [Text.UTF8Encoding]::new($false))
[pscustomobject] $report
