#Requires -Version 7.6
# Original Unlicense. One explicitly selected conditional subnet update.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$script:planner=Import-Module (Join-Path $PSScriptRoot 'PrivateStorageEndpoint.psm1') -PassThru -Force

function Endpoint-Canonical($Value) {
    if($Value -is [Collections.IDictionary]) {
        $map=[ordered]@{}
        foreach($key in @($Value.Keys | Sort-Object -CaseSensitive)) { $map[$key]=Endpoint-Canonical $Value[$key] }
        return $map
    }
    if($Value -is [pscustomobject]) {
        $map=[ordered]@{}
        foreach($key in @($Value.PSObject.Properties.Name | Sort-Object -CaseSensitive)) { $map[$key]=Endpoint-Canonical $Value.$key }
        return $map
    }
    if($Value -is [Collections.IEnumerable] -and $Value -isnot [string]) {
        $items=[Collections.Generic.List[object]]::new()
        foreach($item in $Value) { $items.Add((Endpoint-Canonical $item)) }
        return ,$items.ToArray()
    }
    return $Value
}
function Endpoint-Json($Value) { ConvertTo-Json -InputObject (Endpoint-Canonical $Value) -Depth 48 -Compress }
function Endpoint-Hash([string]$Value) { [Convert]::ToHexStringLower([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($Value))) }
function Assert-Endpoint([bool]$Value) { if(-not $Value) { throw 'Endpoint update invariant rejected.' } }
function Write-EndpointEvidence([string]$Directory,[string]$Name,$Value) {
    $bytes=[Text.Encoding]::UTF8.GetBytes((Endpoint-Json $Value));Assert-Endpoint ($bytes.Length -le 262144)
    $file=[IO.FileStream]::new((Join-Path $Directory $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $file.Write($bytes);$file.Flush($true) } finally { $file.Dispose() }
}
function Read-EndpointEvidence([string]$Directory,[string]$Name) {
    $path=Join-Path $Directory $Name;$info=Get-Item -LiteralPath $path
    Assert-Endpoint (-not $info.PSIsContainer -and -not ($info.Attributes -band [IO.FileAttributes]::ReparsePoint) -and $info.Length -le 262144)
    [IO.File]::ReadAllText($path) | ConvertFrom-Json -Depth 48 -AsHashtable
}
function Endpoint-Directory([string]$Path) {
    Assert-Endpoint ([IO.Path]::IsPathFullyQualified($Path))
    $full=[IO.Path]::GetFullPath($Path);$parent=[IO.Path]::GetDirectoryName($full)
    $item=Get-Item -LiteralPath $parent
    while($null -ne $item) {
        Assert-Endpoint ($item -is [IO.DirectoryInfo] -and -not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint))
        $item=$item.Parent
    }
    if(Test-Path -LiteralPath $full) {
        $existing=Get-Item -LiteralPath $full
        Assert-Endpoint ($existing.PSIsContainer -and -not ($existing.Attributes -band [IO.FileAttributes]::ReparsePoint))
    }
    return $full
}
function New-EndpointPlan([hashtable]$Target) {
    New-SantaPrivateStorageEndpointPlan @Target -EnableStorageEndpoint -ReadArm
}
function Get-EndpointToken([hashtable]$Target) {
    $value=& $script:planner {param($a) Read-Network -Arguments $a} @('account','get-access-token','--resource','https://management.azure.com/',
        '--subscription',$Target.SubscriptionId.ToString(),'--tenant',$Target.TenantId.ToString())
    Assert-Endpoint ($value.subscription -is [string] -and $value.tenant -is [string] -and $value.accessToken -is [string] -and
        $value.subscription -ieq $Target.SubscriptionId.ToString() -and $value.tenant -ieq $Target.TenantId.ToString() -and
        $value.tokenType -ceq 'Bearer' -and $value.accessToken -cmatch '^[A-Za-z0-9._~+/=-]{16,32768}$')
    return $value.accessToken
}
function New-EndpointHttpClient {
    $handler=[Net.Http.HttpClientHandler]::new();$handler.AllowAutoRedirect=$false;$handler.UseProxy=$false
    $client=[Net.Http.HttpClient]::new($handler);$client.Timeout=[Threading.Timeout]::InfiniteTimeSpan
    return $client
}
function Invoke-EndpointPut([string]$Url,$Body,[string]$Etag,[string]$Token,[int]$Seconds) {
    $uri=[uri]$Url
    Assert-Endpoint ($uri.Scheme -ceq 'https' -and $uri.Host -ceq 'management.azure.com' -and $uri.Port -eq 443 -and
        -not $uri.UserInfo -and -not $uri.Fragment -and $uri.Query -ceq '?api-version=2024-05-01')
    $client=New-EndpointHttpClient
    $cancel=[Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds($Seconds))
    $request=[Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Put,$uri);$response=$null
    try {
        $request.Headers.Authorization=[Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer',$Token)
        $null=$request.Headers.TryAddWithoutValidation('If-Match',$Etag)
        $request.Content=[Net.Http.StringContent]::new((Endpoint-Json $Body),[Text.Encoding]::UTF8,'application/json')
        $response=$client.SendAsync($request,[Net.Http.HttpCompletionOption]::ResponseHeadersRead,$cancel.Token).GetAwaiter().GetResult()
        # Discard bounded response bytes, including CloudError text. No error-body logging.
        $stream=$response.Content.ReadAsStreamAsync($cancel.Token).GetAwaiter().GetResult();$buffer=[byte[]]::new(8192);$total=0
        try {
            while(($read=$stream.ReadAsync($buffer,0,$buffer.Length,$cancel.Token).GetAwaiter().GetResult()) -gt 0) {
                $total+=$read;Assert-Endpoint ($total -le 262144)
            }
        } finally { $stream.Dispose() }
        return [int]$response.StatusCode
    } finally { if($null -ne $response){$response.Dispose()};$request.Dispose();$cancel.Dispose();$client.Dispose() }
}
function Test-EndpointReadback($Before,$After) {
    Assert-Endpoint ($After.scope -ceq 'private-storage-endpoint-proposal-v1' -and -not $After.changed -and
        $Before.subnetId -ieq $After.subnetId -and $Before.selectedVmId -ieq $After.selectedVmId -and
        $Before.selectedInstance -ieq $After.selectedInstance -and $Before.location -ceq $After.location)
    $old=$Before.observedSubnet.properties;$new=$After.observedSubnet.properties
    foreach($key in @('addressPrefix','defaultOutboundAccess','networkSecurityGroup','ipConfigurations','privateEndpointNetworkPolicies','privateLinkServiceNetworkPolicies')) {
        Assert-Endpoint ($old.ContainsKey($key) -eq $new.ContainsKey($key))
        if($old.ContainsKey($key)) { Assert-Endpoint ((Endpoint-Json $old[$key]) -ceq (Endpoint-Json $new[$key])) }
    }
    $expected=@($Before.existingHostServiceEndpoints);$actual=@($After.existingHostServiceEndpoints)
    $storage=@($actual | Where-Object {$_.service -ieq 'Microsoft.Storage'})
    # The regional provider can return its paired region as an additional location.
    Assert-Endpoint ($storage.Count -eq 1 -and @($storage[0].locations) -contains $Before.location)
    if(-not $Before.changed) {
        Assert-Endpoint ((Endpoint-Json $expected) -ceq (Endpoint-Json $actual))
        return
    }
    Assert-Endpoint ($actual.Count -eq $expected.Count+1)
    foreach($entry in $expected) {
        $matching=@($actual | Where-Object {$_.service -ceq $entry.service})
        Assert-Endpoint ($matching.Count -eq 1 -and (Endpoint-Json $matching[0]) -ceq (Endpoint-Json $entry))
    }
}
function Endpoint-Target([guid]$TenantId,[guid]$SubscriptionId,[string]$EnvironmentName,[guid]$VmInstanceId) {
    @{TenantId=$TenantId;SubscriptionId=$SubscriptionId;EnvironmentName=$EnvironmentName;VmInstanceId=$VmInstanceId}
}

function Set-SantaPrivateStorageEndpoint {
    [CmdletBinding()]
    param([Parameter(Mandatory)][guid]$TenantId,[Parameter(Mandatory)][guid]$SubscriptionId,
        [Parameter(Mandatory)][ValidatePattern('^[a-z0-9-]{2,32}$')][string]$EnvironmentName,
        [Parameter(Mandatory)][guid]$VmInstanceId,[string]$AttemptDirectory,
        [ValidateRange(1,120)][int]$Seconds=60,[switch]$Apply)
    $target=Endpoint-Target $TenantId $SubscriptionId $EnvironmentName $VmInstanceId
    if(-not $Apply) {
        return [pscustomobject]@{scope='private-storage-endpoint-update-plan-v1';cloudWrite=$false;requiresExplicitApply=$true
            requiresNewAttemptDirectory=$true;automaticReplay=$false;readPlan=(New-SantaPrivateStorageEndpointPlan @target -EnableStorageEndpoint)}
    }
    $reserved=$false;$submitted=$false;$status=$null;$token=$null
    try {
        $directory=Endpoint-Directory $AttemptDirectory
        Assert-Endpoint (-not (Test-Path -LiteralPath $directory))
        $null=[IO.Directory]::CreateDirectory($directory)
        Write-EndpointEvidence $directory 'reservation.json' @{scope='one-endpoint-update-reservation-v1';target=$target;automaticReplay=$false}
        $reserved=$true
        $plan=New-EndpointPlan $target
        Assert-Endpoint ($plan.scope -ceq 'private-storage-endpoint-proposal-v1' -and $plan.selectedInstance -ieq $VmInstanceId.ToString())
        Write-EndpointEvidence $directory 'plan.json' $plan
        if(-not $plan.changed) {
            Test-EndpointReadback $plan $plan
            $result=@{scope='private-storage-endpoint-update-v1';state='already-configured';cloudWriteAttempted=$false;httpStatus=$null;desiredStateObserved=$true;automaticReplay=$false
                multiResourceAtomic=$false;retentionProven=$false;restoreAccepted=$false}
            Write-EndpointEvidence $directory 'outcome.json' $result;return [pscustomobject]$result
        }
        $token=Get-EndpointToken $target
        $ready=New-EndpointPlan $target
        Assert-Endpoint ($ready.observationSha256 -ceq $plan.observationSha256 -and
            (Endpoint-Json $ready.proposedSubnetRequest) -ceq (Endpoint-Json $plan.proposedSubnetRequest))
        Assert-Endpoint ($ready.proposedSubnetRequest.method -ceq 'PUT' -and
            $ready.proposedSubnetRequest.url -ceq "https://management.azure.com$($ready.subnetId)?api-version=2024-05-01")
        $etag=$ready.expectedEtags[$ready.subnetId]
        Assert-Endpoint ($etag -ceq $ready.observedSubnet.etag -and $etag -cmatch '^(?:W/)?"[A-Za-z0-9-]{1,128}"$')
        Write-EndpointEvidence $directory 'submission-intent.json' @{scope='one-if-match-subnet-put-v1';subnetId=$ready.subnetId;etag=$etag
            requestSha256=(Endpoint-Hash (Endpoint-Json $ready.proposedSubnetRequest));automaticReplay=$false}
        $submitted=$true
        try {
            $status=Invoke-EndpointPut $ready.proposedSubnetRequest.url $ready.proposedSubnetRequest.body $etag $token $Seconds
            Assert-Endpoint ($status -is [int] -and $status -ge 100 -and $status -le 599)
        } catch { $status=$null }
        $observed=$false
        try { $after=New-EndpointPlan $target;Test-EndpointReadback $plan $after;Write-EndpointEvidence $directory 'readback.json' $after;$observed=$true } catch { $observed=$false }
        $state=if($status -eq 412){'precondition-rejected'}elseif($status -in @(200,201) -and $observed){'applied'}else{'unknown'}
        $result=@{scope='private-storage-endpoint-update-v1';state=$state;cloudWriteAttempted=$true;httpStatus=$status
            desiredStateObserved=$observed;automaticReplay=$false;multiResourceAtomic=$false;retentionProven=$false;restoreAccepted=$false}
        Write-EndpointEvidence $directory 'outcome.json' $result;return [pscustomobject]$result
    } catch {
        if($reserved -and -not (Test-Path -LiteralPath (Join-Path $directory 'outcome.json'))) {
            Write-EndpointEvidence $directory 'outcome.json' @{scope='private-storage-endpoint-update-v1';state='unknown';cloudWriteAttempted=$submitted
                httpStatus=$status;desiredStateObserved=$false;automaticReplay=$false;multiResourceAtomic=$false;retentionProven=$false;restoreAccepted=$false}
        }
        throw 'Storage endpoint update failed or is unknown; preserve this attempt and observe it. Never replay or replace its evidence.'
    } finally { $token=$null }
}

function Get-SantaPrivateStorageEndpointUpdate {
    [CmdletBinding()]
    param([Parameter(Mandatory)][guid]$TenantId,[Parameter(Mandatory)][guid]$SubscriptionId,
        [Parameter(Mandatory)][ValidatePattern('^[a-z0-9-]{2,32}$')][string]$EnvironmentName,
        [Parameter(Mandatory)][guid]$VmInstanceId,[Parameter(Mandatory)][string]$AttemptDirectory,[switch]$ReadArm)
    try {
        $directory=Endpoint-Directory $AttemptDirectory
        $reservation=Read-EndpointEvidence $directory 'reservation.json'
        $target=Endpoint-Target $TenantId $SubscriptionId $EnvironmentName $VmInstanceId
        Assert-Endpoint ($reservation.scope -ceq 'one-endpoint-update-reservation-v1' -and
            (Endpoint-Json $reservation.target) -ceq (Endpoint-Json $target))
        $outcome=if(Test-Path -LiteralPath (Join-Path $directory 'outcome.json')){Read-EndpointEvidence $directory 'outcome.json'}else{$null}
        if($null -ne $outcome) {
            Assert-Endpoint ($outcome.scope -ceq 'private-storage-endpoint-update-v1' -and
                $outcome.state -cin @('already-configured','applied','precondition-rejected','unknown') -and
                $outcome.automaticReplay -is [bool] -and -not $outcome.automaticReplay -and
                $outcome.cloudWriteAttempted -is [bool] -and $outcome.desiredStateObserved -is [bool])
            if($outcome.state -eq 'applied') {
                Assert-Endpoint ($outcome.cloudWriteAttempted -and $outcome.httpStatus -in @(200,201) -and
                    $outcome.desiredStateObserved -and (Test-Path -LiteralPath (Join-Path $directory 'submission-intent.json')))
            }
            if($outcome.state -eq 'precondition-rejected') { Assert-Endpoint ($outcome.httpStatus -eq 412) }
        }
        $observed=$false
        if($ReadArm) { $plan=Read-EndpointEvidence $directory 'plan.json';$after=New-EndpointPlan $target;Test-EndpointReadback $plan $after;$observed=$true }
        [pscustomobject]@{scope='private-storage-endpoint-update-observation-v1';state=if($null -eq $outcome){'unknown'}else{$outcome.state}
            cloudWrite=$false;desiredStateObserved=$observed;automaticReplay=$false;pastPutResultProven=$false;retentionProven=$false;restoreAccepted=$false}
    } catch { throw 'Storage endpoint observation failed or is unknown; retain the same attempt. No network write was attempted.' }
}

Export-ModuleMember -Function Set-SantaPrivateStorageEndpoint,Get-SantaPrivateStorageEndpointUpdate
