#Requires -Version 7.6
# Original Unlicense. Fresh independent store only; no automatic retry/adoption.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$script:reader=Import-Module (Join-Path $PSScriptRoot 'HttpsEndpoint.psm1') -PassThru -Force
$script:privateFiles=Import-Module (Join-Path $PSScriptRoot 'SealedSetup.psm1') -PassThru -Force
Import-Module (Join-Path $PSScriptRoot 'BackupStoreSelection.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '../vm/PrivateStorageEndpoint.psm1') -Force

function Assert-StoreDeployment([bool]$Condition) {
    if(-not $Condition) { throw 'Independent backup-store deployment boundary rejected; preserve local state and inspect prerequisites.' }
}
function Store-Normalize($Value) {
    if($Value -is [Collections.IDictionary]) {
        $result=[ordered]@{}
        foreach($key in @($Value.Keys | Sort-Object -CaseSensitive)) { $result[$key]=Store-Normalize $Value[$key] }
        return $result
    }
    if($Value -is [array]) { $items=@(foreach($item in $Value) { Store-Normalize $item });return ,$items }
    $Value
}
function Store-Json($Value) { ConvertTo-Json -InputObject (Store-Normalize $Value) -Depth 48 -Compress }
function Store-Hash([string]$Text) { [Convert]::ToHexStringLower([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($Text))) }
function Invoke-StoreAzure([string[]]$Arguments,[int]$TimeoutSeconds=30) {
    & $script:reader {param($a,$seconds) Invoke-SantaEndpointAzJson -Arguments $a -TimeoutSeconds $seconds} $Arguments $TimeoutSeconds
}
function Write-StoreRecord([string]$Path,$Value) {
    $bytes=[Text.Encoding]::UTF8.GetBytes((Store-Json $Value))
    Assert-StoreDeployment ($bytes.Length -le 262144)
    & $script:privateFiles {param($path,$bytes) Write-SantaPrivateBytes -Path $path -Bytes $bytes} $Path $bytes
}
function Read-StoreRecord([string]$Path) {
    Assert-StoreDeployment ([IO.File]::Exists($Path) -and -not ([IO.File]::GetAttributes($Path) -band [IO.FileAttributes]::ReparsePoint))
    $stream=[IO.FileStream]::new($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        Assert-StoreDeployment ($stream.Length -ge 2 -and $stream.Length -le 262144)
        $bytes=[byte[]]::new([int]$stream.Length);$stream.ReadExactly($bytes)
    } finally { $stream.Dispose() }
    ConvertFrom-Json -InputObject ([Text.UTF8Encoding]::new($false,$true).GetString($bytes)) -Depth 48 -AsHashtable -NoEnumerate
}
function Store-Sources {
    $result=[ordered]@{}
    foreach($relative in @('BackupStoreDeployment.psm1','Invoke-SantaBackupStoreDeployment.ps1','BackupStoreSelection.psm1','backup_store_selection.py','blob_retention.py',
        'HttpsEndpoint.psm1','SealedSetup.psm1','../vm/PrivateStorageEndpoint.psm1','../backup-store/main.bicep','../backup-store/store.bicep')) {
        $result[$relative]=(Get-FileHash (Join-Path $PSScriptRoot $relative) -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    $result
}
function Compile-StoreTemplate {
    $command=@(Get-Command bicep -CommandType Application -ErrorAction SilentlyContinue)
    $compiler=if($env:SANTA_BICEP_EXE){$env:SANTA_BICEP_EXE}elseif($command.Count){$command[0].Source}else{
        $config=if($env:AZURE_CONFIG_DIR){$env:AZURE_CONFIG_DIR}else{Join-Path ([Environment]::GetFolderPath('UserProfile')) '.azure'}
        Join-Path $config ('bin/bicep'+$(if($IsWindows){'.exe'}else{''}))
    }
    Assert-StoreDeployment ([IO.File]::Exists($compiler))
    $source=Join-Path $PSScriptRoot '../backup-store/main.bicep'
    $raw=& $script:reader {param($file,$source) Invoke-SantaEndpointProcess -FileName $file -Arguments @('build',$source,'--stdout') -TimeoutSeconds 30} $compiler $source
    ConvertFrom-Json -InputObject $raw -Depth 48 -AsHashtable -NoEnumerate -ErrorAction Stop
}
function New-SantaBackupStoreDeploymentPlan {
    [CmdletBinding()]
    param([Parameter(Mandatory)][guid]$TenantId,[Parameter(Mandatory)][guid]$SubscriptionId,
        [Parameter(Mandatory)][ValidatePattern('^[a-z0-9]{2,32}$')][string]$Location,
        [Parameter(Mandatory)][ValidatePattern('^[a-z0-9-]{2,32}$')][string]$SourceEnvironment,
        [Parameter(Mandatory)][guid]$SourceVmInstanceId,
        [ValidatePattern('^[a-z0-9-]{2,32}$')][string]$VerifierEnvironment,[guid]$VerifierVmInstanceId)
    Assert-StoreDeployment ($TenantId -ne [guid]::Empty -and $SubscriptionId -ne [guid]::Empty -and $SourceVmInstanceId -ne [guid]::Empty)
    Assert-StoreDeployment ([bool]$VerifierEnvironment -eq $PSBoundParameters.ContainsKey('VerifierVmInstanceId'))
    $owner=[guid]::NewGuid();$suffix=$owner.ToString('N')
    $selection=[ordered]@{TenantId=$TenantId.ToString();SubscriptionId=$SubscriptionId.ToString();Location=$Location
        BackupResourceGroupName="rg-santa-backup-$suffix";BackupStoreName=('stsb'+$suffix.Substring(0,20))
        OwnershipId=$owner.ToString();SourceEnvironment=$SourceEnvironment;SourceVmInstanceId=$SourceVmInstanceId.ToString()}
    if($VerifierEnvironment) {
        Assert-StoreDeployment ($VerifierEnvironment -cne $SourceEnvironment -and $VerifierVmInstanceId -ne [guid]::Empty)
        $selection.VerifierEnvironment=$VerifierEnvironment;$selection.VerifierVmInstanceId=$VerifierVmInstanceId.ToString()
    }
    [ordered]@{scope='independent-backup-store-deployment-plan-v1';selection=$selection
        deploymentName="santa-backup-$suffix";sourceHashes=(Store-Sources)
        cloudWrite=$false;retentionProven=$false;restoreAccepted=$false}
}
function Assert-StorePlan($Plan,[string]$Python='python') {
    Assert-StoreDeployment ($Plan.scope -ceq 'independent-backup-store-deployment-plan-v1' -and
        (Store-Json $Plan.sourceHashes) -ceq (Store-Json (Store-Sources)))
    $s=$Plan.selection;$owner=[guid]$s.OwnershipId;$suffix=$owner.ToString('N')
    Assert-StoreDeployment ($s.BackupResourceGroupName -ceq "rg-santa-backup-$suffix" -and
        $s.BackupStoreName -ceq ('stsb'+$suffix.Substring(0,20)) -and $Plan.deploymentName -ceq "santa-backup-$suffix")
    # Reuse the maintained intent/schema validator, never accept caller ARM facts.
    $null=Get-SantaBackupStoreSelection @s -Python $Python
}
function Get-StoreCreationPreflight($Plan,[string]$Python='python') {
    Assert-StorePlan $Plan $Python
    $s=$Plan.selection;$sub=$s.SubscriptionId
    $context=Invoke-StoreAzure @('account','show','--subscription',$sub)
    Assert-StoreDeployment ($context.id -ieq $sub -and $context.tenantId -ieq $s.TenantId -and
        $context.state -ceq 'Enabled' -and $context.environmentName -ceq 'AzureCloud')
    $exists=Invoke-StoreAzure @('group','exists','--subscription',$sub,'--name',$s.BackupResourceGroupName)
    Assert-StoreDeployment ($exists -is [bool] -and -not $exists)
    $available=Invoke-StoreAzure @('storage','account','check-name','--subscription',$sub,'--name',$s.BackupStoreName)
    Assert-StoreDeployment ($available.nameAvailable -is [bool] -and $available.nameAvailable)
    $deployments=Invoke-StoreAzure @('deployment','sub','list','--subscription',$sub,'--query',"[?name=='$($Plan.deploymentName)'].name")
    Assert-StoreDeployment ($deployments -is [array] -and $deployments.Count -eq 0)
    foreach($namespace in @('Microsoft.Resources','Microsoft.Network','Microsoft.Storage')) {
        # Provider catalogs can be large. Capture only the required facts, not
        # an entire Network/Storage API-version catalog.
        $query=if($namespace -eq 'Microsoft.Storage'){
            "{namespace:namespace,registrationState:registrationState,resourceTypes:resourceTypes[?resourceType=='storageAccounts'].{resourceType:resourceType,locations:locations,apiVersions:apiVersions}}"
        }else{'{namespace:namespace,registrationState:registrationState}'}
        $provider=Invoke-StoreAzure @('provider','show','--subscription',$sub,'--namespace',$namespace,'--query',$query)
        Assert-StoreDeployment ($provider.namespace -ceq $namespace -and $provider.registrationState -ceq 'Registered')
        if($namespace -eq 'Microsoft.Storage') {
            $types=@($provider.resourceTypes | Where-Object resourceType -CEQ 'storageAccounts')
            Assert-StoreDeployment ($types.Count -eq 1 -and '2025-06-01' -cin $types[0].apiVersions -and
                $s.Location -cin @($types[0].locations | ForEach-Object { $_.Replace(' ','').ToLowerInvariant() }))
        }
    }
    $subnets=@();$observations=@()
    foreach($prefix in @('Source','Verifier')) {
        if(-not $s.Contains($prefix+'Environment')) { continue }
        $network=New-SantaPrivateStorageEndpointPlan -TenantId $s.TenantId -SubscriptionId $sub `
            -EnvironmentName $s[$prefix+'Environment'] -VmInstanceId $s[$prefix+'VmInstanceId'] -ReadArm
        Assert-StoreDeployment ($network.scope -ceq 'private-storage-endpoint-proposal-v1' -and -not $network.changed -and
            $network.location -ceq $s.Location -and $network.selectedInstance -ieq $s[$prefix+'VmInstanceId'])
        $storage=@($network.observedSubnet.properties.serviceEndpoints | Where-Object service -IEQ 'Microsoft.Storage')
        Assert-StoreDeployment ($storage.Count -eq 1 -and $storage[0].provisioningState -ceq 'Succeeded')
        $locations=@($storage[0].locations)
        Assert-StoreDeployment ($locations.Count -ge 1 -and $locations.Count -le 16)
        $regions=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach($location in $locations) {
            Assert-StoreDeployment ($location -is [string] -and $location.ToLowerInvariant() -cmatch '^[a-z0-9]{2,32}$')
            Assert-StoreDeployment ($regions.Add($location.ToLowerInvariant()))
        }
        # Regional Storage can include its paired region; preserve the provider
        # set while requiring the selected store region, not one exact entry.
        Assert-StoreDeployment ($regions.Contains($s.Location))
        $subnets+= $network.subnetId;$observations+=$network.observationSha256
    }
    Assert-StoreDeployment ($subnets.Count -in @(1,2))
    $after=Invoke-StoreAzure @('account','show','--subscription',$sub)
    Assert-StoreDeployment ((Store-Json $after) -ceq (Store-Json $context))
    [ordered]@{contextSha256=(Store-Hash (Store-Json $context));subnets=$subnets;networkObservations=$observations}
}
function Assert-StoreWhatIf($Result,$Plan) {
    Assert-StoreDeployment ($Result.status -ceq 'Succeeded' -and -not ($Result.Contains('error') -and $null -ne $Result.error))
    $group="/subscriptions/$($Plan.selection.SubscriptionId)/resourceGroups/$($Plan.selection.BackupResourceGroupName)"
    $account="$group/providers/Microsoft.Storage/storageAccounts/$($Plan.selection.BackupStoreName)"
    $required=@($group,$account,"$account/blobServices/default","$account/blobServices/default/containers/native-captures")
    $allowed=@($required)+@("$group/providers/Microsoft.Resources/deployments/santa-independent-backup-store")
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach($change in @($Result.changes)) {
        Assert-StoreDeployment ($change.changeType -ceq 'Create' -and $change.resourceId -iin $allowed -and $seen.Add($change.resourceId))
    }
    foreach($id in $required) { Assert-StoreDeployment ($seen.Contains($id)) }
}
function Get-StoreSubmissionToken($Plan,[string]$ContextSha256) {
    $s=$Plan.selection
    $before=Invoke-StoreAzure @('account','show','--subscription',$s.SubscriptionId)
    Assert-StoreDeployment ((Store-Hash (Store-Json $before)) -ceq $ContextSha256)
    # CLI forbids combining subscription and tenant selectors here. Verify the
    # returned tenant/subscription instead; never request interactive login.
    $response=Invoke-StoreAzure @('account','get-access-token','--subscription',$s.SubscriptionId,'--resource','https://management.azure.com/')
    $expiry=0L
    Assert-StoreDeployment ($response.tenant -ieq $s.TenantId -and $response.subscription -ieq $s.SubscriptionId -and
        $response.tokenType -ceq 'Bearer' -and $response.accessToken -is [string] -and
        $response.accessToken -cmatch '^[A-Za-z0-9._~+/=-]{40,16384}$' -and
        [long]::TryParse([string]$response.expires_on,[ref]$expiry) -and $expiry -gt [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()+180)
    $after=Invoke-StoreAzure @('account','show','--subscription',$s.SubscriptionId)
    Assert-StoreDeployment ((Store-Json $before) -ceq (Store-Json $after))
    $response.accessToken
}
function New-StoreHttpHandler {
    $handler=[Net.Http.HttpClientHandler]::new();$handler.UseProxy=$false;$handler.AllowAutoRedirect=$false;$handler.UseCookies=$false
    $handler.MaxResponseHeadersLength=16
    $handler
}
function Send-StoreDeployment($Plan,$Template,$Parameters,[string]$AccessToken,[Net.Http.HttpMessageHandler]$Handler) {
    $subscription=[guid]::Empty
    Assert-StoreDeployment ([guid]::TryParseExact($Plan.selection.SubscriptionId,'D',[ref]$subscription) -and
        $Plan.deploymentName -cmatch '^santa-backup-[a-f0-9]{32}$' -and $AccessToken -cmatch '^[A-Za-z0-9._~+/=-]{40,16384}$')
    $uri="https://management.azure.com/subscriptions/$($subscription.ToString())/providers/Microsoft.Resources/deployments/$($Plan.deploymentName)?api-version=2025-04-01"
    $body=Store-Json @{location=$Plan.selection.Location;properties=@{mode='Incremental';template=$Template;parameters=$Parameters.parameters}}
    Assert-StoreDeployment ([Text.Encoding]::UTF8.GetByteCount($body) -le 262144)
    if($null -eq $Handler) { $Handler=New-StoreHttpHandler }
    $client=[Net.Http.HttpClient]::new($Handler,$true);$client.Timeout=[Threading.Timeout]::InfiniteTimeSpan
    $cancel=[Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds(60))
    $request=[Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Put,$uri);$response=$null
    try {
        $request.Version=[Version]::new(1,1);$request.VersionPolicy=[Net.Http.HttpVersionPolicy]::RequestVersionExact
        $request.Headers.Authorization=[Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer',$AccessToken)
        $request.Content=[Net.Http.StringContent]::new($body,[Text.Encoding]::UTF8,'application/json')
        # One application send. No retry, redirect, proxy, response URL or body
        # consumption. A timeout/cancel does not cancel accepted ARM work.
        $response=$client.SendAsync($request,[Net.Http.HttpCompletionOption]::ResponseHeadersRead,$cancel.Token).GetAwaiter().GetResult()
        [int]$response.StatusCode
    } catch { throw 'Deployment submission failed or is unknown; preserve intent and Observe the exact named deployment. Never retry PUT.' }
    finally {
        if($response){$response.Dispose()};$request.Dispose();$cancel.Dispose();$client.Dispose();$AccessToken=$null
    }
}
function Observe-StoreDeployment($Plan,[string]$Directory,[string]$Python='python') {
    Assert-StorePlan $Plan $Python
    $intent=Read-StoreRecord (Join-Path $Directory 'intent.json')
    Assert-StoreDeployment ($intent.scope -ceq 'independent-backup-store-submission-intent-v1' -and
        $intent.planSha256 -ceq (Store-Hash (Store-Json $Plan)) -and $intent.deploymentName -ceq $Plan.deploymentName)
    $parameters=Read-StoreRecord (Join-Path $Directory 'parameters.json')
    $template=Read-StoreRecord (Join-Path $Directory 'template.json')
    foreach($pair in @(@('parameters','parametersSha256'),@('template','templateSha256'))) {
        Assert-StoreDeployment ((Get-FileHash (Join-Path $Directory ($pair[0]+'.json')) -Algorithm SHA256).Hash.ToLowerInvariant() -ceq $intent[$pair[1]])
    }
    $s=$Plan.selection;$context=Invoke-StoreAzure @('account','show','--subscription',$s.SubscriptionId)
    Assert-StoreDeployment ($context.id -ieq $s.SubscriptionId -and $context.tenantId -ieq $s.TenantId -and
        $context.state -ceq 'Enabled' -and $context.environmentName -ceq 'AzureCloud')
    $deployment=Invoke-StoreAzure @('deployment','sub','show','--subscription',$s.SubscriptionId,'--name',$Plan.deploymentName)
    $id="/subscriptions/$($s.SubscriptionId)/providers/Microsoft.Resources/deployments/$($Plan.deploymentName)"
    Assert-StoreDeployment ($deployment.id -ieq $id -and $deployment.name -ceq $Plan.deploymentName)
    Assert-StoreDeployment ($deployment.properties.parameters.Count -eq $parameters.parameters.Count)
    foreach($key in $parameters.parameters.Keys) {
        $actual=$deployment.properties.parameters[$key]
        Assert-StoreDeployment ($null -ne $actual -and @($actual.Keys | Where-Object {$_ -cnotin @('type','value')}).Count -eq 0 -and
            (Store-Json $actual.value) -ceq (Store-Json $parameters.parameters[$key].value))
        if($actual.Contains('type')) { Assert-StoreDeployment ($actual.type -ieq $template.parameters[$key].type) }
    }
    $status=$deployment.properties.provisioningState
    Assert-StoreDeployment ($status -cin @('Accepted','Running','Succeeded','Failed','Canceled'))
    $selection=$null
    if($status -ceq 'Succeeded') {
        Assert-StoreDeployment ($deployment.properties.templateHash -ceq $template.metadata._generator.templateHash)
        $selection=Get-SantaBackupStoreSelection @s -ReadArm -Python $Python
    }
    $after=Invoke-StoreAzure @('account','show','--subscription',$s.SubscriptionId)
    Assert-StoreDeployment ((Store-Json $after) -ceq (Store-Json $context))
    $result=[ordered]@{scope='independent-backup-store-deployment-observation-v1';deploymentId=$id;state=$status
        selection=$selection;cloudWrite=$false;capabilityMinted=$false;retentionProven=$false;restoreAccepted=$false}
    Write-StoreRecord (Join-Path $Directory ('observation-'+[guid]::NewGuid().ToString('N')+'.json')) $result
    $result
}
function Invoke-SantaBackupStoreDeployment {
    [CmdletBinding()]
    param([ValidateSet('Plan','Apply','Observe')][string]$Action='Plan',
        [guid]$TenantId,[guid]$SubscriptionId,[string]$Location,[string]$SourceEnvironment,[guid]$SourceVmInstanceId,
        [string]$VerifierEnvironment,[guid]$VerifierVmInstanceId,[string]$StateDirectory,
        [string]$Python=$(if($env:SANTA_CRYPTO_PYTHON){$env:SANTA_CRYPTO_PYTHON}else{'python'}))
    if($Action -ceq 'Observe') {
        try {
            Assert-StoreDeployment ([bool]$StateDirectory)
            $StateDirectory=[IO.Path]::GetFullPath($StateDirectory)
            & $script:privateFiles {param($p) Assert-SantaPrivateDestination $p} (Join-Path $StateDirectory ('check-'+[guid]::NewGuid().ToString('N')))
            return Observe-StoreDeployment (Read-StoreRecord (Join-Path $StateDirectory 'plan.json')) $StateDirectory $Python
        } catch { throw 'Backup-store Observe failed or is unknown; preserve the same state directory and inspect that exact deployment. No submission was attempted.' }
    }
    $arguments=@{TenantId=$TenantId;SubscriptionId=$SubscriptionId;Location=$Location;SourceEnvironment=$SourceEnvironment;SourceVmInstanceId=$SourceVmInstanceId}
    if($VerifierEnvironment -or $PSBoundParameters.ContainsKey('VerifierVmInstanceId')) {
        $arguments.VerifierEnvironment=$VerifierEnvironment;$arguments.VerifierVmInstanceId=$VerifierVmInstanceId
    }
    $plan=New-SantaBackupStoreDeploymentPlan @arguments
    if($Action -ceq 'Plan') { return $plan }
    if(-not $StateDirectory) {
        $parent=Join-Path ([IO.Path]::GetFullPath((Get-Location).Path)) 'out'
        if(-not [IO.Directory]::Exists($parent)) { $null=New-Item -ItemType Directory -Path $parent }
        $StateDirectory=Join-Path $parent ('santa-backup-store-'+$plan.selection.OwnershipId)
    }
    $StateDirectory=[IO.Path]::GetFullPath($StateDirectory)
    & $script:privateFiles {param($p) Assert-SantaPrivateDestination $p} $StateDirectory
    $null=New-Item -ItemType Directory -Path $StateDirectory
    if(-not $IsWindows) { [IO.File]::SetUnixFileMode($StateDirectory,([IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite -bor [IO.UnixFileMode]::UserExecute)) }
    Write-StoreRecord (Join-Path $StateDirectory 'plan.json') $plan
    try {
        $before=Get-StoreCreationPreflight $plan $Python
        $parameters=@{parameters=@{location=@{value=$Location};backupResourceGroupName=@{value=$plan.selection.BackupResourceGroupName}
            backupStoreName=@{value=$plan.selection.BackupStoreName};ownershipId=@{value=$plan.selection.OwnershipId};ownedSubnetResourceIds=@{value=$before.subnets}}}
        Write-StoreRecord (Join-Path $StateDirectory 'parameters.json') $parameters
        $compiled=Compile-StoreTemplate
        Write-StoreRecord (Join-Path $StateDirectory 'template.json') $compiled
        $command=@('--subscription',$SubscriptionId.ToString(),'--location',$Location,'--name',($plan.deploymentName+'-check'),
            '--template-file',(Join-Path $StateDirectory 'template.json'),'--parameters',('@'+(Join-Path $StateDirectory 'parameters.json')))
        $validation=Invoke-StoreAzure (@('deployment','sub','validate')+$command+@('--validation-level','Provider')) 180
        Assert-StoreDeployment ($validation.properties.provisioningState -ceq 'Succeeded')
        $whatif=Invoke-StoreAzure (@('deployment','sub','what-if')+$command+@('--no-pretty-print','--validation-level','Provider')) 180
        Assert-StoreWhatIf $whatif $plan
        $fresh=Get-StoreCreationPreflight $plan $Python
        Assert-StoreDeployment ((Store-Json $fresh) -ceq (Store-Json $before))
        $token=Get-StoreSubmissionToken $plan $fresh.contextSha256
        Write-StoreRecord (Join-Path $StateDirectory 'intent.json') ([ordered]@{scope='independent-backup-store-submission-intent-v1'
            planSha256=(Store-Hash (Store-Json $plan));deploymentName=$plan.deploymentName;preflight=$fresh
            templateSha256=(Get-FileHash (Join-Path $StateDirectory 'template.json') -Algorithm SHA256).Hash.ToLowerInvariant()
            parametersSha256=(Get-FileHash (Join-Path $StateDirectory 'parameters.json') -Algorithm SHA256).Hash.ToLowerInvariant()})
        try { $status=Send-StoreDeployment $plan $compiled $parameters $token } finally { $token=$null }
        Write-StoreRecord (Join-Path $StateDirectory 'submission.json') @{statusCode=$status}
        Assert-StoreDeployment ($status -in @(200,201,202))
        $observed=Observe-StoreDeployment $plan $StateDirectory $Python
        [ordered]@{scope='independent-backup-store-apply-result-v1';stateDirectory=$StateDirectory
            deploymentId=$observed.deploymentId;state=$observed.state;selection=$observed.selection
            cloudWriteAttempted=$true;retentionProven=$false;restoreAccepted=$false}
    } catch { throw "Independent backup-store Apply failed or is unknown. Preserve '$StateDirectory'; never replay Apply. Observe that exact state directory; missing deployment or policy/provider gaps require inspection, not reinitialization." }
}
Export-ModuleMember -Function New-SantaBackupStoreDeploymentPlan,Invoke-SantaBackupStoreDeployment
