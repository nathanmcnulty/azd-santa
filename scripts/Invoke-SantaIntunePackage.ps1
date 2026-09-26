[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)][string] $PackagePath,
    [Parameter(Mandatory)][string] $PackageVerificationReceiptPath,
    [Parameter(Mandatory)][string] $ProfileStatusPath,
    [Parameter(Mandatory)][string] $TenantId,
    [Parameter(Mandatory)][string] $PilotGroupId,
    [Parameter(Mandatory)][string] $ExpectedPilotGroupName,
    [Parameter(Mandatory)][string] $ExpectedDeviceName,
    [Parameter(Mandatory)][string] $ExpectedAccount,
    [string] $ReceiptPath = (Join-Path (Split-Path -Parent $PSScriptRoot) '.azure/azd-santa/intune-package-receipt.json'),
    [switch] $Apply
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Santa.Template.psm1') -Force
$lock = Get-SantaLock
$displayName = "Santa $($lock.release.tag) (azd-santa pilot)"
$ownershipMarker = "azd-santa; release=$($lock.release.tag); sha256=$($lock.package.sha256)"

function Invoke-GraphJson {
    param([Parameter(Mandatory)][ValidateSet('GET','POST','PATCH')][string] $Method, [Parameter(Mandatory)][string] $Uri, [object] $Body)
    $parameters = @{ Method = $Method; Uri = $Uri; OutputType = 'PSObject' }
    if ($null -ne $Body) {
        $parameters.Body = ($Body | ConvertTo-Json -Depth 30 -Compress)
        $parameters.ContentType = 'application/json'
    }
    Invoke-MgGraphRequest @parameters
}
function Test-ExactRequiredAssignment {
    param([Parameter(Mandatory)][object] $Assignment, [Parameter(Mandatory)][string] $GroupId)
    $target = $Assignment.target
    if ($Assignment.intent -ne 'required' -or -not $target -or $target.'@odata.type' -ne '#microsoft.graph.groupAssignmentTarget' -or $target.groupId -ne $GroupId) { return $false }
    $filterId = $target.PSObject.Properties['deviceAndAppManagementAssignmentFilterId']
    $filterType = $target.PSObject.Properties['deviceAndAppManagementAssignmentFilterType']
    return (-not $filterId -or -not $filterId.Value) -and (-not $filterType -or $filterType.Value -in @($null, 'none'))
}
function Write-PackageReceipt {
    param([Parameter(Mandatory)][object] $App, [Parameter(Mandatory)][object] $File, [Parameter(Mandatory)][object] $Assignment, [Parameter(Mandatory)][string] $Action)
    $receipt = [ordered]@{
        schemaVersion = '1.0'
        appliedAt = [DateTimeOffset]::UtcNow.ToString('o')
        tenantId = $TenantId
        account = $context.Account
        action = $Action
        app = [ordered]@{ id = $App.id; displayName = $App.displayName; publishingState = $App.publishingState; committedContentVersion = $App.committedContentVersion; contentFileId = $File.id; uploadState = $File.uploadState }
        package = [ordered]@{ sha256 = [string]$lock.package.sha256; verificationReceipt = $PackageVerificationReceiptPath }
        assignment = [ordered]@{ id = $Assignment.id; intent = $Assignment.intent; groupId = $PilotGroupId; groupDisplayName = $group.displayName; memberId = $members.value[0].id; memberDisplayName = $members.value[0].displayName }
    }
    New-Item -ItemType Directory -Path (Split-Path -Parent $ReceiptPath) -Force | Out-Null
    [IO.File]::WriteAllText($ReceiptPath, (($receipt | ConvertTo-Json -Depth 20) + [Environment]::NewLine), [Text.UTF8Encoding]::new($false))
    return $receipt
}

function Wait-ContentFileState {
    param([Parameter(Mandatory)][string] $Uri, [Parameter(Mandatory)][string] $Stage)
    for ($attempt = 0; $attempt -lt 12; $attempt++) {
        $file = Invoke-GraphJson -Method GET -Uri $Uri
        if ($file.uploadState -eq "${Stage}Success") { return $file }
        if ($file.uploadState -notin @("${Stage}Pending", 'success')) { throw "Intune content stage '$Stage' failed: $($file.uploadState)" }
        Start-Sleep -Seconds ([Math]::Min(30, [Math]::Pow(2, $attempt)))
    }
    throw "Timed out waiting for Intune content stage '$Stage'."
}

function Protect-IntuneContent {
    param([Parameter(Mandatory)][string] $Path)
    $source = $target = $crypto = $encryptor = $aes = $hmac = $keyGenerator = $null
    try {
        $aes = [Security.Cryptography.Aes]::Create()
        $initializationVector = $aes.IV
        $keyGenerator = [Security.Cryptography.AesCryptoServiceProvider]::new()
        $keyGenerator.GenerateKey()
        $macKey = $keyGenerator.Key
        $hmac = [Security.Cryptography.HMACSHA256]::new($macKey)
        $hmacLength = $hmac.HashSize / 8
        $keyGenerator.GenerateKey()
        $encryptionKey = $keyGenerator.Key
        $target = [IO.MemoryStream]::new()
        $target.Write([byte[]]::new($hmacLength + $initializationVector.Length), 0, $hmacLength + $initializationVector.Length)
        $encryptor = $aes.CreateEncryptor($encryptionKey, $initializationVector)
        $source = [IO.File]::OpenRead($Path)
        $crypto = [Security.Cryptography.CryptoStream]::new($target, $encryptor, [Security.Cryptography.CryptoStreamMode]::Write, $true)
        $source.CopyTo($crypto)
        $crypto.FlushFinalBlock()
        $target.Position = $hmacLength
        $target.Write($initializationVector, 0, $initializationVector.Length)
        $target.Position = $hmacLength
        $mac = $hmac.ComputeHash($target)
        $target.Position = 0
        $target.Write($mac, 0, $mac.Length)
        $digest = [Security.Cryptography.SHA256]::HashData([IO.File]::ReadAllBytes($Path))
        [pscustomobject]@{
            Bytes = $target.ToArray()
            Info = [ordered]@{
                '@odata.type' = 'microsoft.graph.fileEncryptionInfo'
                encryptionKey = [Convert]::ToBase64String($encryptionKey)
                initializationVector = [Convert]::ToBase64String($initializationVector)
                mac = [Convert]::ToBase64String($mac)
                macKey = [Convert]::ToBase64String($macKey)
                profileIdentifier = 'ProfileVersion1'
                fileDigest = [Convert]::ToBase64String($digest)
                fileDigestAlgorithm = 'SHA256'
            }
        }
    }
    finally {
        if ($crypto) { $crypto.Dispose() }
        if ($source) { $source.Dispose() }
        if ($encryptor) { $encryptor.Dispose() }
        if ($target) { $target.Dispose() }
        if ($hmac) { $hmac.Dispose() }
        if ($keyGenerator) { $keyGenerator.Dispose() }
        if ($aes) { $aes.Dispose() }
    }
}

function Send-BlockBlob {
    param([Parameter(Mandatory)][string] $SasUri, [Parameter(Mandatory)][byte[]] $Bytes)
    $blockSize = 4MB
    $blockIds = [Collections.Generic.List[string]]::new()
    for ($offset = 0; $offset -lt $Bytes.Length; $offset += $blockSize) {
        $length = [Math]::Min($blockSize, $Bytes.Length - $offset)
        $block = [byte[]]::new($length)
        [Array]::Copy($Bytes, $offset, $block, 0, $length)
        $blockId = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(('{0:d6}' -f ($offset / $blockSize))))
        $blockIds.Add($blockId)
        Invoke-WebRequest -Method PUT -Uri "$SasUri&comp=block&blockid=$([Uri]::EscapeDataString($blockId))" -Headers @{ 'x-ms-blob-type' = 'BlockBlob' } -Body $block -ContentType 'application/octet-stream' | Out-Null
        Write-Progress -Activity 'Uploading Santa package to Intune storage' -PercentComplete ((($offset + $length) / $Bytes.Length) * 100)
    }
    $xml = '<?xml version="1.0" encoding="utf-8"?><BlockList>' + (($blockIds | ForEach-Object { "<Latest>$_</Latest>" }) -join '') + '</BlockList>'
    Invoke-WebRequest -Method PUT -Uri "$SasUri&comp=blocklist" -Body $xml -ContentType 'application/xml' | Out-Null
    Write-Progress -Activity 'Uploading Santa package to Intune storage' -Completed
}

Test-SantaPackageVerificationReceipt -Path $PackageVerificationReceiptPath -PackagePath $PackagePath | Out-Null
$profileStatusRaw = Get-Content -LiteralPath $ProfileStatusPath -Raw
if (-not ($profileStatusRaw | Test-Json -SchemaFile (Join-Path (Split-Path -Parent $PSScriptRoot) 'schemas/intune-profile-status.schema.json') -ErrorAction Stop)) {
    throw 'Intune profile status report does not satisfy its schema.'
}
$profileStatus = $profileStatusRaw | ConvertFrom-Json
$statusAge = [DateTimeOffset]::UtcNow - [DateTimeOffset]$profileStatus.collectedAt
if ($statusAge.TotalMinutes -lt -5 -or $statusAge.TotalMinutes -gt 30) { throw 'Intune profile status report must have been collected within the last 30 minutes.' }
if ($profileStatus.tenantId -ne $TenantId -or $profileStatus.account -ne $ExpectedAccount -or
    $profileStatus.pilotGroup.id -ne $PilotGroupId -or $profileStatus.pilotGroup.displayName -ne $ExpectedPilotGroupName -or
    $profileStatus.pilotDevice.deviceName -ne $ExpectedDeviceName) {
    throw 'Intune profile status report does not match the selected tenant, account, group, and device.'
}
$verifiedProfileStatus = Test-SantaIntuneProfileReport -State $profileStatus
if (-not $profileStatus.summary.deliveryReadiness -or -not $verifiedProfileStatus.deliveryReadiness) { throw 'Exact-device prerequisite profile readiness is not proven.' }

if (-not $Apply) {
    Write-Information "WHAT-IF: would upload '$displayName' and assign it as Required only to '$ExpectedPilotGroupName' ($PilotGroupId)." -InformationAction Continue
    return
}
if (-not $PSCmdlet.ShouldProcess("Intune tenant $TenantId, group $PilotGroupId", "Upload and require $displayName")) { return }

Connect-MgGraph -TenantId $TenantId -Scopes @('DeviceManagementApps.ReadWrite.All','Group.Read.All','DeviceManagementManagedDevices.Read.All','Device.Read.All') -ContextScope Process -NoWelcome
$context = Get-MgContext
if ($context.TenantId -ne $TenantId -or $context.Account -ne $ExpectedAccount) { throw "Authenticated context does not match the authorized tenant/account: $($context.Account) / $($context.TenantId)" }

$group = Invoke-GraphJson -Method GET -Uri "https://graph.microsoft.com/v1.0/groups/${PilotGroupId}?`$select=id,displayName,securityEnabled,mailEnabled,groupTypes,membershipRule"
if ($group.displayName -ne $ExpectedPilotGroupName) { throw "Pilot group display name mismatch: $($group.displayName)" }
if (-not $group.securityEnabled -or $group.mailEnabled -or 'DynamicMembership' -in @($group.groupTypes) -or $group.membershipRule) { throw 'Pilot group must be a static security group.' }
$members = Invoke-GraphJson -Method GET -Uri "https://graph.microsoft.com/v1.0/groups/$PilotGroupId/members?`$select=id,displayName,deviceId,operatingSystem"
if (@($members.value).Count -ne 1 -or $members.value[0].'@odata.type' -ne '#microsoft.graph.device' -or $members.value[0].displayName -ne $ExpectedDeviceName -or $members.value[0].operatingSystem -notin @('macOS', 'MacMDM')) { throw 'Pilot group is not the exact one-device macOS target.' }

$escapedName = $displayName.Replace("'", "''")
$existing = Invoke-GraphJson -Method GET -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?`$filter=displayName eq '$escapedName'"

$appBody = [ordered]@{
    '@odata.type' = '#microsoft.graph.macOSPkgApp'
    displayName = $displayName
    description = 'Santa endpoint security in MONITOR mode. Owned by the azd-santa one-device pilot.'
    publisher = 'North Pole Security, Inc.'
    fileName = [IO.Path]::GetFileName($PackagePath)
    primaryBundleId = [string]$lock.package.bundleIdentifier
    primaryBundleVersion = [string]$lock.package.bundleShortVersion
    includedApps = @([ordered]@{ '@odata.type' = 'microsoft.graph.macOSIncludedApp'; bundleId = [string]$lock.package.bundleIdentifier; bundleVersion = [string]$lock.package.bundleShortVersion })
    ignoreVersionDetection = $false
    minimumSupportedOperatingSystem = [ordered]@{ '@odata.type' = 'microsoft.graph.macOSMinimumOperatingSystem'; v14_0 = $true }
    informationUrl = [string]$lock.release.releaseUrl
    developer = 'North Pole Security, Inc.'
    owner = 'azd-santa'
    notes = $ownershipMarker
    isFeatured = $false
    roleScopeTagIds = @('0')
}
$existingApps = @($existing.value)
if ($existingApps.Count -gt 1) {
    throw "An app named '$displayName' already exists and is not an uncommitted template-owned object; refusing to overwrite or duplicate it."
}
if ($existingApps.Count -eq 1) {
    $app = Invoke-GraphJson -Method GET -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$($existingApps[0].id)"
    if ($app.'@odata.type' -ne '#microsoft.graph.macOSPkgApp' -or $app.displayName -ne $displayName -or
        $app.notes -ne $ownershipMarker -or $app.owner -ne 'azd-santa' -or
        $app.primaryBundleId -ne $lock.package.bundleIdentifier -or $app.primaryBundleVersion -ne $lock.package.bundleShortVersion) {
        throw "Existing app '$($app.id)' does not match the locked template-owned package."
    }
    $readback = Invoke-GraphJson -Method GET -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$($app.id)/assignments"
    if ($app.committedContentVersion) {
        if ($app.publishingState -ne 'published' -or @($readback.value).Count -ne 1 -or
            -not (Test-ExactRequiredAssignment -Assignment $readback.value[0] -GroupId $PilotGroupId)) {
            throw "Published app '$($app.id)' is not in the exact required pilot state."
        }
        $contentFiles = Invoke-GraphJson -Method GET -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$($app.id)/microsoft.graph.macOSPkgApp/contentVersions/$($app.committedContentVersion)/files"
        if (@($contentFiles.value).Count -ne 1 -or $contentFiles.value[0].name -ne $lock.package.assetName -or
            [long]$contentFiles.value[0].size -ne [long]$lock.package.size -or $contentFiles.value[0].uploadState -ne 'commitFileSuccess') {
            throw "Published app '$($app.id)' does not have the expected committed package file."
        }
        Write-PackageReceipt -App $app -File $contentFiles.value[0] -Assignment $readback.value[0] -Action 'verified-existing' | ConvertTo-Json -Depth 20
        return
    }
    if (@($readback.value).Count -ne 0 -or $app.isAssigned) { throw "Uncommitted app '$($app.id)' already has assignments." }
}
else {
    $app = Invoke-GraphJson -Method POST -Uri 'https://graph.microsoft.com/beta/deviceAppManagement/mobileApps' -Body $appBody
}
$base = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$($app.id)/microsoft.graph.macOSPkgApp/contentVersions"
$existingContent = Invoke-GraphJson -Method GET -Uri $base
if (@($existingContent.value).Count -eq 0) {
    $content = Invoke-GraphJson -Method POST -Uri $base -Body @{ '@odata.type' = '#microsoft.graph.mobileAppContent' }
}
elseif (@($existingContent.value).Count -eq 1) {
    $content = $existingContent.value[0]
    $existingFiles = Invoke-GraphJson -Method GET -Uri "$base/$($content.id)/files"
    if (@($existingFiles.value).Count -ne 0) { throw 'The uncommitted template-owned app already has a content file; refusing an ambiguous retry.' }
}
else {
    throw 'The uncommitted template-owned app has multiple content versions; refusing an ambiguous retry.'
}
$protected = Protect-IntuneContent -Path $PackagePath
$fileBody = [ordered]@{
    '@odata.type' = '#microsoft.graph.mobileAppContentFile'
    name = [IO.Path]::GetFileName($PackagePath)
    size = [IO.FileInfo]::new($PackagePath).Length
    sizeEncrypted = $protected.Bytes.Length
    isFrameworkFile = $false
    isDependency = $false
}
$file = Invoke-GraphJson -Method POST -Uri "$base/$($content.id)/files" -Body $fileBody
$fileUri = "$base/$($content.id)/files/$($file.id)"
$file = Wait-ContentFileState -Uri $fileUri -Stage 'azureStorageUriRequest'
Send-BlockBlob -SasUri $file.azureStorageUri -Bytes $protected.Bytes
Invoke-GraphJson -Method POST -Uri "$fileUri/commit" -Body @{ fileEncryptionInfo = $protected.Info } | Out-Null
$file = Wait-ContentFileState -Uri $fileUri -Stage 'commitFile'
Invoke-GraphJson -Method PATCH -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$($app.id)" -Body @{ '@odata.type' = '#microsoft.graph.macOSPkgApp'; committedContentVersion = [string]$content.id } | Out-Null

for ($attempt = 0; $attempt -lt 18; $attempt++) {
    $app = Invoke-GraphJson -Method GET -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$($app.id)"
    if ($app.publishingState -eq 'published') { break }
    if ($app.publishingState -eq 'notPublished' -and $attempt -gt 2) { throw 'Intune did not publish the committed app.' }
    Start-Sleep -Seconds 10
}
if ($app.publishingState -ne 'published') { throw 'Timed out waiting for Intune to publish the app.' }

$assignment = Invoke-GraphJson -Method POST -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$($app.id)/assignments" -Body ([ordered]@{
    '@odata.type' = '#microsoft.graph.mobileAppAssignment'
    intent = 'required'
    target = [ordered]@{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = $PilotGroupId }
})
$readback = Invoke-GraphJson -Method GET -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$($app.id)/assignments"
if (@($readback.value).Count -ne 1 -or -not (Test-ExactRequiredAssignment -Assignment $readback.value[0] -GroupId $PilotGroupId)) { throw 'Assignment read-back did not match the exact required pilot target.' }
Write-PackageReceipt -App $app -File $file -Assignment $readback.value[0] -Action 'uploaded' | ConvertTo-Json -Depth 20
