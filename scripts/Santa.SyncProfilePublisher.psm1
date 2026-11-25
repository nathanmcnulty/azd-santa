#Requires -Version 7.6
# Original Unlicense. One existing configuration object; never create or assign.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$script:provider=Import-Module (Join-Path $PSScriptRoot 'Santa.ProviderPlan.psm1') -PassThru -Force

function Assert-Sync([bool]$Condition) { if(-not $Condition){throw 'SantaSync.BoundaryRejected'} }
function Sync-Hash([byte[]]$Bytes) { [Convert]::ToHexStringLower([Security.Cryptography.SHA256]::HashData($Bytes)) }
function Sync-Json($Value) {
    $canonical=& $script:provider {param($v) ConvertTo-SantaPlanCanonicalValue $v} $Value
    ConvertTo-Json -InputObject $canonical -Depth 40 -Compress
}
function Sync-Input([string]$Path) { & $script:provider {param($p) Read-SantaPlanInput $p} $Path }
function Sync-Parse([string]$Text) { & $script:provider {param($t) ConvertFrom-SantaPlanPlist $t} $Text }
function Sync-Payload($Profile) { & $script:provider {param($p) Get-SantaPlanPayload $p} $Profile }
function Assert-SyncContext($Target) {
    try { $context=Get-MgContext -ErrorAction Stop -Verbose:$false -Debug:$false }
    catch { throw 'SantaSync.CachedContextUnavailable' }
    Assert-Sync ($null -ne $context -and $context.TenantId -ieq $Target.tenant -and $context.Account -ieq $Target.account -and
        $context.AuthType -ceq 'Delegated' -and $context.Environment -ceq 'Global')
    $credential=$context.PSObject.Properties['TokenCredentialType']
    Assert-Sync ($credential -and [string]$credential.Value -notmatch 'DeviceCode' -and [string]$credential.Value -ne '')
    foreach($scope in @('DeviceManagementConfiguration.ReadWrite.All','Group.Read.All','Device.Read.All')) { Assert-Sync ($scope -cin $context.Scopes) }
}
function Invoke-SyncGraph([ValidateSet('GET','PATCH')][string]$Method,[string]$Uri,$Body,$Headers) {
    try {
        Assert-Sync ($Uri -match '^/v1\.0/' -and $Uri -notmatch '[\r\n]')
        $arguments=@{Method=$Method;Uri=$Uri;OutputType='PSObject';ErrorAction='Stop';Verbose=$false;Debug=$false
            WarningAction='SilentlyContinue';InformationAction='SilentlyContinue'}
        if($null -ne $Body){$arguments.Body=Sync-Json $Body;$arguments.ContentType='application/json'}
        if($null -ne $Headers -and $Headers.Count){$arguments.Headers=$Headers}
        $result=Invoke-MgGraphRequest @arguments
        if($null -eq $result){return $null}
        $json=ConvertTo-Json -InputObject $result -Depth 40 -Compress
        Assert-Sync ([Text.Encoding]::UTF8.GetByteCount($json) -le 2MB)
        ConvertFrom-Json -InputObject $json -AsHashtable -Depth 40 -DateKind String -NoEnumerate
    } catch { throw 'SantaSync.GraphFailedOrUnknown' }
}
function Read-SyncReceipt([string]$Path,$Target) {
    $inputFile=Sync-Input $Path
    $schema=Join-Path (Split-Path $PSScriptRoot -Parent) 'schemas/intune-profile-receipt.schema.json'
    Assert-Sync (Test-Json -Json $inputFile.text -SchemaFile $schema -ErrorAction SilentlyContinue)
    $receipt=ConvertFrom-Json $inputFile.text -AsHashtable -DateKind String
    $release=(Get-Content (Join-Path (Split-Path $PSScriptRoot -Parent) 'package/santa.lock.json') -Raw|ConvertFrom-Json).release.tag
    Assert-Sync ($receipt.tenantId -ieq $Target.tenant -and $receipt.account -ieq $Target.account -and $receipt.release -ceq $release -and
        $receipt.pilotGroup.id -ieq $Target.group -and $receipt.pilotGroup.displayName -ceq $Target.groupName -and
        $receipt.pilotGroup.memberId -ieq $Target.deviceObject -and $receipt.pilotGroup.memberDisplayName -ceq $Target.deviceName)
    $ids=@($receipt.profiles.id|Sort-Object -Unique)
    Assert-Sync ($ids.Count -eq 5 -and @($ids|Where-Object{$_ -cnotin @('system-extension','tcc','service-management','configuration','notifications')}).Count -eq 0)
    $objects=@(foreach($item in $receipt.profiles){Assert-Sync ($item.assignmentGroupId -ieq $Target.group);([guid]$item.objectId).ToString()})
    Assert-Sync (@($objects|Sort-Object -Unique).Count -eq 5)
    $owned=@($receipt.profiles|Where-Object id -CEQ 'configuration')
    Assert-Sync ($owned.Count -eq 1 -and $owned[0].objectId -ieq $Target.configuration)
    [pscustomobject]@{receipt=$receipt;sha256=$inputFile.sha256;name=$owned[0].displayName
        description="[azd-santa:$release`:configuration] Template-owned Intune profile."}
}
function Read-SyncSnapshot($Target,$Owned) {
    Assert-SyncContext $Target
    $group=Invoke-SyncGraph GET "/v1.0/groups/$($Target.group)?`$select=id,displayName,securityEnabled,mailEnabled,groupTypes,membershipRule" $null $null
    Assert-Sync ($group.id -ieq $Target.group -and $group.displayName -ceq $Target.groupName -and $group.securityEnabled -eq $true -and
        $group.mailEnabled -eq $false -and @($group.groupTypes).Count -eq 0 -and -not $group.membershipRule)
    $members=Invoke-SyncGraph GET "/v1.0/groups/$($Target.group)/members?`$select=id,displayName,deviceId,operatingSystem&`$top=2" $null $null
    Assert-Sync (-not $members.Contains('@odata.nextLink') -and @($members.value).Count -eq 1)
    $member=@($members.value)[0]
    Assert-Sync ($member['@odata.type'] -ceq '#microsoft.graph.device' -and $member.id -ieq $Target.deviceObject -and
        $member.deviceId -ieq $Target.device -and $member.displayName -ceq $Target.deviceName -and $member.operatingSystem -match '^Mac')
    $device=Invoke-SyncGraph GET "/v1.0/devices/$($Target.deviceObject)?`$select=id,deviceId,displayName,operatingSystem" $null $null
    Assert-Sync ($device.id -ieq $Target.deviceObject -and $device.deviceId -ieq $Target.device -and
        $device.displayName -ceq $Target.deviceName -and $device.operatingSystem -match '^Mac')
    $inventory=Invoke-SyncGraph GET '/v1.0/deviceManagement/deviceConfigurations?$select=id,displayName,description&$top=999' $null $null
    Assert-Sync (-not $inventory.Contains('@odata.nextLink'))
    $same=@($inventory.value|Where-Object{ $_.displayName -ceq $Owned.name -or $_.description -ceq $Owned.description })
    Assert-Sync ($same.Count -eq 1 -and $same[0].id -ieq $Target.configuration)
    $profile=Invoke-SyncGraph GET "/v1.0/deviceManagement/deviceConfigurations/$($Target.configuration)" $null $null
    Assert-Sync ($profile.id -ieq $Target.configuration -and $profile['@odata.type'] -ceq '#microsoft.graph.macOSCustomConfiguration' -and
        $profile.displayName -ceq $Owned.name -and $profile.description -ceq $Owned.description -and $profile.payloadName -ceq '40-configuration.mobileconfig')
    $bytes=[Convert]::FromBase64String($profile.payload);Assert-Sync ($bytes.Length -le 1MB)
    $assignments=Invoke-SyncGraph GET "/v1.0/deviceManagement/deviceConfigurations/$($Target.configuration)/assignments" $null $null
    Assert-Sync (-not $assignments.Contains('@odata.nextLink') -and @($assignments.value).Count -eq 1)
    $assignment=@($assignments.value)[0].target
    Assert-Sync ($assignment['@odata.type'] -ceq '#microsoft.graph.groupAssignmentTarget' -and $assignment.groupId -ieq $Target.group)
    foreach($key in $assignment.Keys) {Assert-Sync ($key -cin @('@odata.type','groupId','deviceAndAppManagementAssignmentFilterId','deviceAndAppManagementAssignmentFilterType'))}
    Assert-Sync ((-not $assignment.Contains('deviceAndAppManagementAssignmentFilterId') -or -not $assignment.deviceAndAppManagementAssignmentFilterId) -and
        (-not $assignment.Contains('deviceAndAppManagementAssignmentFilterType') -or $assignment.deviceAndAppManagementAssignmentFilterType -in @($null,'none')))
    Assert-SyncContext $Target
    [pscustomobject]@{profile=$profile;bytes=$bytes;hash=(Sync-Hash $bytes)
        scopeHash=(Sync-Hash ([Text.Encoding]::UTF8.GetBytes((Sync-Json @{group=$group;member=$member;device=$device;assignment=$assignment}))))}
}
function Merge-SyncProfile($Current,$Material,[string]$ExpectedOrigin) {
    $provider=$Material.payload;$contract=$Material.qualification
    $pin=Get-Content (Join-Path (Split-Path $PSScriptRoot -Parent) 'experiments/server/zentral-source.lock.json') -Raw|ConvertFrom-Json
    Assert-Sync ($contract.evidenceKind -ceq 'offline-source-review' -and $contract.providerRevision -ceq $pin.commit -and
        $contract.authHeaderName -ceq 'Zentral-Authorization')
    $origin=[uri]$ExpectedOrigin;$url=[uri]$provider['SyncBaseURL']
    Assert-Sync ($origin.IsAbsoluteUri -and $origin.Scheme -ceq 'https' -and -not $origin.UserInfo -and -not $origin.Query -and -not $origin.Fragment -and
        $origin.AbsolutePath -ceq '/' -and $url.GetLeftPart([UriPartial]::Authority) -ceq $origin.GetLeftPart([UriPartial]::Authority) -and
        $url.AbsolutePath -ceq '/public/santa/sync/' -and $url.AbsoluteUri -ceq ($origin.GetLeftPart([UriPartial]::Authority)+'/public/santa/sync/'))
    Assert-Sync ($provider['SyncExtraHeaders']['Zentral-Authorization'] -cmatch '\ABearer [A-Za-z0-9]{64}\z')
    $baseline=Sync-Parse $Material.baseline;$baseSettings=Sync-Payload $baseline
    $text=[Text.UTF8Encoding]::new($false,$true).GetString($Current.bytes)
    $remote=Sync-Parse $text;$settings=Sync-Payload $remote
    $metadata=@('PayloadType','PayloadVersion','PayloadUUID','PayloadIdentifier','PayloadDisplayName','PayloadDescription','PayloadOrganization','PayloadEnabled')
    foreach($key in $baseSettings.Keys){if($key -cnotin $metadata){Assert-Sync ($settings.ContainsKey($key) -and (Sync-Json $settings[$key]) -ceq (Sync-Json $baseSettings[$key]))}}
    foreach($key in $settings.Keys){Assert-Sync ($key -cin (@($baseSettings.Keys)+@($metadata)+@('SyncBaseURL','SyncExtraHeaders')))}
    foreach($key in $baseline.Keys){if($key -cnotin (@('PayloadContent')+$metadata)){Assert-Sync ($remote.ContainsKey($key) -and (Sync-Json $remote[$key]) -ceq (Sync-Json $baseline[$key]))}}
    foreach($key in $remote.Keys){Assert-Sync ($key -cin $baseline.Keys)}
    foreach($item in @($remote,$settings)) {
        foreach($key in $metadata){
            if($item.ContainsKey($key) -and $key -cnotin @('PayloadEnabled','PayloadVersion')){Assert-Sync ($item[$key] -is [string])}
        }
        Assert-Sync ($item.ContainsKey('PayloadVersion') -and $item['PayloadVersion'] -is [long] -and $item['PayloadVersion'] -eq 1)
        $id=[guid]::Empty
        Assert-Sync ($item.ContainsKey('PayloadUUID') -and [guid]::TryParse($item['PayloadUUID'],[ref]$id) -and $id -ne [guid]::Empty -and
            $item.ContainsKey('PayloadIdentifier') -and $item['PayloadIdentifier'] -is [string] -and $item['PayloadIdentifier'] -cmatch '^[A-Za-z0-9.-]{1,255}$')
    }
    $readerSettings=[Xml.XmlReaderSettings]::new();$readerSettings.DtdProcessing=[Xml.DtdProcessing]::Ignore;$readerSettings.XmlResolver=$null
    $readerSettings.MaxCharactersInDocument=1MB;$reader=[Xml.XmlReader]::Create([IO.StringReader]::new($text),$readerSettings)
    $document=[Xml.XmlDocument]::new();$document.XmlResolver=$null;$document.PreserveWhitespace=$true
    try{$document.Load($reader)}finally{$reader.Dispose()}
    $payloadArray=$document.SelectSingleNode('/plist/dict/key[text()="PayloadContent"]/following-sibling::*[1]')
    Assert-Sync ($null -ne $payloadArray -and $payloadArray.Name -ceq 'array')
    $dict=$payloadArray.SelectSingleNode('dict')
    $elements=@($dict.ChildNodes|Where-Object NodeType -EQ ([Xml.XmlNodeType]::Element))
    for($i=0;$i -lt $elements.Count;$i+=2){if($elements[$i].InnerText -cin @('SyncBaseURL','SyncExtraHeaders')){$null=$dict.RemoveChild($elements[$i]);$null=$dict.RemoveChild($elements[$i+1])}}
    foreach($key in @('SyncBaseURL','SyncExtraHeaders')) {
        $node=$document.CreateElement('key');$node.InnerText=$key;$null=$dict.AppendChild($node)
        if($key -ceq 'SyncBaseURL'){$node=$document.CreateElement('string');$node.InnerText=$provider[$key]}
        else{$node=$document.CreateElement('dict');$k=$document.CreateElement('key');$k.InnerText='Zentral-Authorization';$null=$node.AppendChild($k)
            $v=$document.CreateElement('string');$v.InnerText=$provider[$key]['Zentral-Authorization'];$null=$node.AppendChild($v)}
        $null=$dict.AppendChild($node)
    }
    # Compare the complete reparsed profile against precisely the intended edit,
    # including the actual PayloadContent Santa dictionary and all metadata.
    $settings['SyncBaseURL']=$provider['SyncBaseURL']
    $settings['SyncExtraHeaders']=$provider['SyncExtraHeaders']
    $merged=Sync-Parse $document.OuterXml
    Assert-Sync ((Sync-Json $merged) -ceq (Sync-Json $remote))
    $bytes=[Text.Encoding]::UTF8.GetBytes($document.OuterXml)
    [pscustomobject]@{payload=[Convert]::ToBase64String($bytes);hash=(Sync-Hash $bytes)}
}
function Write-SyncRecord([string]$Path,$Value) {
    Assert-Sync ([IO.Path]::IsPathFullyQualified($Path) -and [IO.Directory]::Exists([IO.Path]::GetDirectoryName($Path)))
    Assert-Sync (-not $Path.StartsWith('\\') -and -not $Path.StartsWith('//'))
    if($IsWindows){Assert-Sync ($Path -cmatch '^[A-Za-z]:[\\/]' -and $Path.Substring(2) -notmatch ':')}
    for($p=[IO.Path]::GetDirectoryName($Path);$p;$p=[IO.Path]::GetDirectoryName($p)){Assert-Sync (-not([IO.File]::GetAttributes($p)-band[IO.FileAttributes]::ReparsePoint))}
    $bytes=[Text.Encoding]::UTF8.GetBytes((Sync-Json $Value));Assert-Sync ($bytes.Length -le 32768)
    $options=[IO.FileStreamOptions]::new();$options.Mode=[IO.FileMode]::CreateNew;$options.Access=[IO.FileAccess]::Write;$options.Share=[IO.FileShare]::None
    if(-not $IsWindows){$options.UnixCreateMode=[IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite}
    $stream=[IO.FileStream]::new($Path,$options);try{$stream.Write($bytes);$stream.Flush($true)}finally{$stream.Dispose()}
}
function Invoke-SantaIntuneSyncProfile {
    [CmdletBinding()]
    param([ValidateSet('Disabled','Inspect','Apply','Observe')][string]$Action='Disabled',
        [string]$ExpectedTenantId,[string]$ExpectedAccount,[string]$ExpectedGroupId,[string]$ExpectedGroupDisplayName,
        [string]$ExpectedDeviceObjectId,[string]$ExpectedDeviceId,[string]$ExpectedDeviceName,[string]$ExpectedConfigurationObjectId,
        [string]$OwnedReceiptPath,[string]$ProviderProfilePath,[string]$QualificationPath,[string]$ReviewEvidencePath,
        [string]$ExpectedSyncOrigin,[string]$ExpectedCurrentProfileSha256,[string]$CheckpointPath)
    if($Action -ceq 'Disabled'){return [pscustomobject]@{state='disabled';cloudWrite=$false;additionalProfileAllowed=$false;assignmentsChanged=$false}}
    $saved=$null
    $stage='Input'; $submission='NoPatchSubmitted'
    try {
        foreach($value in @($ExpectedTenantId,$ExpectedGroupId,$ExpectedDeviceObjectId,$ExpectedDeviceId,$ExpectedConfigurationObjectId)){
            $parsed=[guid]::Empty;Assert-Sync ([guid]::TryParseExact($value,'D',[ref]$parsed) -and $parsed -ne [guid]::Empty)
        }
        Assert-Sync ($ExpectedAccount -match '^[^\s@]+@[^\s@]+$' -and $ExpectedGroupDisplayName -and $ExpectedDeviceName)
        $target=@{tenant=$ExpectedTenantId;account=$ExpectedAccount;group=$ExpectedGroupId;groupName=$ExpectedGroupDisplayName
            deviceObject=$ExpectedDeviceObjectId;device=$ExpectedDeviceId;deviceName=$ExpectedDeviceName;configuration=$ExpectedConfigurationObjectId}
        $owned=Read-SyncReceipt $OwnedReceiptPath $target
        $stage='CachedIdentity'
        Assert-SyncContext $target
        $stage='GraphRequestContext'
        $contextSettings=Get-MgRequestContext -ErrorAction Stop -Verbose:$false -Debug:$false
        $timeout=$contextSettings.ClientTimeout
        Assert-Sync ($timeout -is [TimeSpan] -and $timeout.Ticks -gt 0 -and
            $timeout.Ticks % [TimeSpan]::TicksPerSecond -eq 0 -and $timeout.TotalSeconds -le [int]::MaxValue)
        $saved=@{MaxRetry=[int]$contextSettings.MaxRetry;ClientTimeout=[int]$timeout.TotalSeconds}
        $null=Set-MgRequestContext -MaxRetry 0 -ClientTimeout 30 -ErrorAction Stop -Verbose:$false -Debug:$false -Confirm:$false
        $stage='TargetRead'
        $before=Read-SyncSnapshot $target $owned
        if($Action -ceq 'Inspect'){return [pscustomobject]@{state='read-only-inspection';target=$target;currentProfileSha256=$before.hash;cloudWrite=$false;nativeAcceptance=$false}}
        if($Action -ceq 'Observe') {
            $stage='ObserveCheckpoint'
            $intent=ConvertFrom-Json (Sync-Input $CheckpointPath).text -AsHashtable -DateKind String
            Assert-Sync ($intent.scope -ceq 'santa-owned-sync-profile-intent-v1' -and (Sync-Json $intent.target) -ceq (Sync-Json $target) -and
                $intent.ownershipReceiptSha256 -ceq $owned.sha256 -and $intent.scopeSha256 -ceq $before.scopeHash)
            $state=if($before.hash -ceq $intent.desiredProfileSha256){'payload-readback-verified'}elseif($before.hash -ceq $intent.previousProfileSha256){'previous-payload-observed-no-retry'}else{'payload-drift-no-retry'}
            return [pscustomobject]@{state=$state;currentProfileSha256=$before.hash;cloudWrite=$false;nativeAcceptance=$false;automaticReplay=$false}
        }
        Assert-Sync ($ExpectedCurrentProfileSha256 -cmatch '^[a-f0-9]{64}$' -and $before.hash -ceq $ExpectedCurrentProfileSha256)
        $stage='ProviderInput'
        $arguments=@{ProviderProfilePath=$ProviderProfilePath;QualificationPath=$QualificationPath;ReviewEvidencePath=$ReviewEvidencePath
            OwnedReceiptPath=$OwnedReceiptPath;ExpectedTenantId=$ExpectedTenantId;ExpectedGroupId=$ExpectedGroupId;ExpectedConfigurationObjectId=$ExpectedConfigurationObjectId}
        $material=& $script:provider {param($a) Read-SantaReviewedProviderMaterial $a} $arguments
        Assert-Sync ($material.plan.fingerprints.ownershipReceipt -ceq $owned.sha256)
        $desired=Merge-SyncProfile $before $material $ExpectedSyncOrigin
        $stage='TargetRecheck'
        $fresh=Read-SyncSnapshot $target $owned
        Assert-Sync ($fresh.hash -ceq $before.hash -and $fresh.scopeHash -ceq $before.scopeHash -and (Sync-Json $fresh.profile) -ceq (Sync-Json $before.profile))
        $stage='Intent'
        Assert-Sync (-not [IO.File]::Exists($CheckpointPath+'.result.json'))
        Write-SyncRecord $CheckpointPath @{scope='santa-owned-sync-profile-intent-v1';target=$target;ownershipReceiptSha256=$owned.sha256
            previousProfileSha256=$before.hash;desiredProfileSha256=$desired.hash;scopeSha256=$before.scopeHash
            providerRevision=$material.qualification.providerRevision;reviewSha256=$material.qualification.reviewEvidenceSha256
            qualificationSha256=$material.plan.fingerprints.qualification;nativeAcceptance=$false}
        $headers=@{}
        if($fresh.profile.Contains('@odata.etag')){
            Assert-Sync ($fresh.profile['@odata.etag'] -is [string] -and $fresh.profile['@odata.etag'] -cmatch '\A(?:W/)?"[\x21\x23-\x7e]{1,256}"\z')
            $headers['If-Match']=$fresh.profile['@odata.etag']
        }
        $stage='Patch'; $submission='PatchMayHaveStarted'
        $null=Invoke-SyncGraph PATCH "/v1.0/deviceManagement/deviceConfigurations/$ExpectedConfigurationObjectId" @{'@odata.type'='#microsoft.graph.macOSCustomConfiguration';payload=$desired.payload;payloadName=$fresh.profile.payloadName} $headers
        $stage='Readback'
        $after=Read-SyncSnapshot $target $owned
        Assert-Sync ($after.hash -ceq $desired.hash -and $after.scopeHash -ceq $before.scopeHash)
        $submission='PatchVerified'; $stage='ResultCheckpoint'
        $result=@{state='payload-readback-verified';configurationObjectId=$ExpectedConfigurationObjectId;profileSha256=$desired.hash
            assignmentsChanged=$false;additionalProfileAllowed=$false;nativeAcceptance=$false}
        Write-SyncRecord ($CheckpointPath+'.result.json') $result
        [pscustomobject]$result
    } catch {
        $guidance = if ($submission -eq 'NoPatchSubmitted') { 'Check the named stage. Preserve any existing checkpoint.' }
            else { 'Preserve the checkpoint and use Observe. Do not replay Apply.' }
        throw "SantaSync.${stage}.${submission}: $guidance"
    }
    finally {
        if($saved){try{$null=Set-MgRequestContext -MaxRetry $saved.MaxRetry -ClientTimeout $saved.ClientTimeout -ErrorAction Stop -Verbose:$false -Debug:$false -Confirm:$false}catch{throw "SantaSync.RequestContextRestoreFailed.${stage}.${submission}: Close this Graph session. If a PATCH may have started, preserve the checkpoint and use Observe."}}
    }
}
Export-ModuleMember -Function Invoke-SantaIntuneSyncProfile
