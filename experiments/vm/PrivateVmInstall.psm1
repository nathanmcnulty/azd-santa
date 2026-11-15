#Requires -Version 7.6
# Original Unlicense. Optional private template lifecycle; no root Intune hooks.
Set-StrictMode -Version Latest
$server = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../server'))
Import-Module (Join-Path $server 'SetupTransport.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'HostSubnetStorageEndpoint.psm1') -Force
$files = @('private_install.py', 'private_install_transport.py', 'bootstrap-host.sh', 'prepare_source.py',
    'prepare_core_build.py', 'prepare_operator_mfa.py', 'operator_mfa.py', 'prepare_operator_recovery.py',
    'operator_recovery.py', 'sealed_setup.py', 'prepare_request_limits.py', 'santa_request_limits.py',
    'prepare_database_roles.py', 'database_roles.py', 'prepare_zentral_eval.py', 'stage_runtime.py',
    'runtime_service.py', 'santa_admission.py', 'cold_backup.py', 'native_snapshot.py',
    'worker_lifecycle.py', 'prepare_worker_lifecycle.py', 'test_live_zentral.py',
    'zentral-source.lock.json', 'dependency-images.lock.json')

function Invoke-PrivateAzd {
    param([string[]]$Arguments, [switch]$Json)
    $value = & azd --cwd $PSScriptRoot @Arguments 2>$null
    if ($LASTEXITCODE) { throw 'Selected azd environment operation failed.' }
    if ($Json) { try { ($value -join "`n") | ConvertFrom-Json -AsHashtable } catch { throw 'Selected azd response was not complete JSON.' } }
}

function Invoke-PrivateAzure {
    param([string[]]$Arguments)
    $value = & az @Arguments --only-show-errors -o json 2>$null
    if ($LASTEXITCODE) { throw 'Selected Azure operation did not return a confirmed result.' }
    try { ($value -join "`n") | ConvertFrom-Json -AsHashtable } catch { throw 'Selected Azure response was not complete JSON; inspect same operation.' }
}

function New-ProvisioningPublicKey {
    $key = [Security.Cryptography.RSA]::Create(3072)
    try {
        $parameters = $key.ExportParameters($false)
        $buffer = [Collections.Generic.List[byte]]::new()
        foreach ($item in @([Text.Encoding]::ASCII.GetBytes('ssh-rsa'), $parameters.Exponent, $parameters.Modulus)) {
            [byte[]]$bytes = $item
            if ($bytes[0] -band 128) { $bytes = [byte[]](@(0) + $bytes) }
            $size = [BitConverter]::GetBytes([uint32]$bytes.Length)
            if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($size) }
            $buffer.AddRange($size); $buffer.AddRange($bytes)
        }
        'ssh-rsa ' + [Convert]::ToBase64String($buffer.ToArray()) + ' azd-private-provisioning-only'
    } finally { $key.Dispose() } # Throwaway key: private material is never exported.
}

function Get-PrivateEnvironmentDirectory([string]$Name) {
    Join-Path $PSScriptRoot ".azure/$Name"
}

function Get-PrivateHostNetworkObservation {
    param([string] $SubscriptionId, [string] $EnvironmentName)
    $resourceGroup = "rg-azd-santa-vm-$EnvironmentName"
    $exists = Invoke-PrivateAzure @('group', 'exists', '--subscription', $SubscriptionId, '--name', $resourceGroup)
    if ($exists -isnot [bool]) { throw 'Azure resource group existence read was not a Boolean result.' }
    if (-not $exists) { return $null }
    return [ordered]@{
        resourceGroup = Invoke-PrivateAzure @('group', 'show', '--subscription', $SubscriptionId, '--name', $resourceGroup)
        vnet = Invoke-PrivateAzure @('network', 'vnet', 'show', '--subscription', $SubscriptionId, '--resource-group', $resourceGroup, '--name', 'vnet-santa-lab')
        nsg = Invoke-PrivateAzure @('network', 'nsg', 'show', '--subscription', $SubscriptionId, '--resource-group', $resourceGroup, '--name', 'nsg-santa-lab')
        nic = Invoke-PrivateAzure @('network', 'nic', 'show', '--subscription', $SubscriptionId, '--resource-group', $resourceGroup, '--name', 'nic-santa-lab')
        publicIp = Invoke-PrivateAzure @('network', 'public-ip', 'show', '--subscription', $SubscriptionId, '--resource-group', $resourceGroup, '--name', 'pip-santa-lab-egress')
        vm = Invoke-PrivateAzure @('vm', 'show', '--subscription', $SubscriptionId, '--resource-group', $resourceGroup, '--name', 'vm-santa-lab')
    }
}

function Set-PrivateAzdEnvironmentValue {
    param([string] $EnvironmentName, [string] $Name, [string] $Value)
    Invoke-PrivateAzd @('env', 'set', $Name, $Value, '--environment', $EnvironmentName, '--no-prompt')
}

function Write-PrivateJsonReceipt {
    param([string] $Path, [object] $Value)
    $json = ConvertTo-Json -InputObject $Value -Depth 16
    $temporary = "$Path.$([guid]::NewGuid().ToString('N')).tmp"
    $stream = [IO.FileStream]::new($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json + [Environment]::NewLine)
        $stream.Write($bytes); $stream.Flush($true)
    } finally { $stream.Dispose() }
    try { [IO.File]::Move($temporary, $Path) }
    catch { if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) }; throw }
}

function Prepare-PrivateHostSubnetStorageEndpoint {
    param([hashtable] $EnvironmentValues, [string] $EnvironmentName)
    $subscriptionId = [string]$EnvironmentValues.AZURE_SUBSCRIPTION_ID
    $location = [string]$EnvironmentValues.AZURE_LOCATION
    if ($subscriptionId -notmatch '^[0-9a-fA-F-]{36}$' -or $location -notmatch '^[A-Za-z0-9 -]{2,64}$') {
        throw 'Selected azd subscription and location are required for the host-network ownership read.'
    }
    $account = Invoke-PrivateAzure @('account', 'show', '--subscription', $subscriptionId)
    $expectedTenantId = if ($EnvironmentValues.ContainsKey('AZURE_TENANT_ID')) { [string]$EnvironmentValues['AZURE_TENANT_ID'] } else { '' }
    if ([string]$account.id -ine $subscriptionId -or [string]$account.environmentName -cne 'AzureCloud' -or
        ($expectedTenantId -and [string]$account.tenantId -ine $expectedTenantId)) {
        throw 'Cached Azure context does not match the selected azd tenant, subscription and AzureCloud.'
    }
    $settingValue = if ($EnvironmentValues.ContainsKey('SANTA_VM_ENABLE_STORAGE_SERVICE_ENDPOINT')) { [string]$EnvironmentValues['SANTA_VM_ENABLE_STORAGE_SERVICE_ENDPOINT'] } else { '' }
    $enable = Get-SantaBooleanSetting -Value $settingValue -Name 'SANTA_VM_ENABLE_STORAGE_SERVICE_ENDPOINT'
    $observation = Get-PrivateHostNetworkObservation -SubscriptionId $subscriptionId -EnvironmentName $EnvironmentName
    $validated = $null
    if ($null -ne $observation) {
        $expectedVmResourceId = "/subscriptions/$subscriptionId/resourceGroups/rg-azd-santa-vm-$EnvironmentName/providers/Microsoft.Compute/virtualMachines/vm-santa-lab"
        if (-not $EnvironmentValues.ContainsKey('SANTA_VM_RESOURCE_ID') -or [string]$EnvironmentValues.SANTA_VM_RESOURCE_ID -ine $expectedVmResourceId -or
            -not $EnvironmentValues.ContainsKey('SANTA_VM_INSTANCE_ID') -or [string]$EnvironmentValues.SANTA_VM_INSTANCE_ID -notmatch '^[0-9a-fA-F-]{36}$') {
            throw 'Existing host requires matching prior azd VM resource and immutable instance outputs; tags alone cannot authorize adoption.'
        }
        $validated = Assert-SantaOwnedHostNetwork -SubscriptionId $subscriptionId -EnvironmentName $EnvironmentName -Location $location `
            -ResourceGroupName "rg-azd-santa-vm-$EnvironmentName" -ExpectedVmInstanceId ([guid]$EnvironmentValues.SANTA_VM_INSTANCE_ID) -Observation $observation
    }
    $repositoryRoot = (& git -C $PSScriptRoot rev-parse --show-toplevel 2>$null | Select-Object -Last 1)
    if ($LASTEXITCODE -ne 0 -or -not [IO.Directory]::Exists($repositoryRoot)) { throw 'Current Santa repository root is unavailable for the network plan.' }
    $revision = (& git -C $repositoryRoot rev-parse HEAD 2>$null | Select-Object -Last 1)
    if ($LASTEXITCODE -ne 0 -or $revision -cnotmatch '^[0-9a-f]{40}$') { throw 'Current Santa source revision is unavailable for the network plan.' }
    $sourcePaths = @('experiments/vm/azure.yaml', 'experiments/vm/Install-PrivateBackend.ps1',
        'experiments/vm/PrivateVmInstall.psm1', 'experiments/vm/HostSubnetStorageEndpoint.psm1',
        'experiments/vm/infra/main.bicep', 'experiments/vm/infra/host.bicep', 'experiments/vm/infra/main.parameters.json')
    $sourceManifest = foreach ($sourcePath in $sourcePaths) {
        $fullPath = Join-Path $repositoryRoot $sourcePath
        if (-not [IO.File]::Exists($fullPath)) { throw 'A network-plan source file is missing.' }
        [ordered]@{ path = $sourcePath; sha256 = (Get-FileHash -LiteralPath $fullPath -Algorithm SHA256).Hash.ToLowerInvariant() }
    }
    $sourceCanonical = ConvertTo-Json -InputObject @($sourceManifest) -Depth 4 -Compress
    $sourceSha256 = [Convert]::ToHexStringLower([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($sourceCanonical)))
    $plan = New-SantaHostSubnetEndpointPlan -SubscriptionId $subscriptionId -EnvironmentName $EnvironmentName `
        -Location $location -SourceRevision $revision -SourceSha256 $sourceSha256 -PlanId ([guid]::NewGuid()) `
        -EnableStorageEndpoint $enable -ValidatedNetwork $validated
    $directory = Get-PrivateEnvironmentDirectory $EnvironmentName
    $stamp = [DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssZ')
    $planPath = Join-Path $directory "host-subnet-storage-endpoint-plan-$stamp-$($plan.Plan.plan.planId).json"
    Write-PrivateJsonReceipt -Path $planPath -Value ([ordered]@{ observedAtUtc = [DateTimeOffset]::UtcNow.ToString('o'); readOnly = $true; plan = $plan.Plan })
    if ($plan.Plan.requiresConfirmation) {
        $approval = [string]$EnvironmentValues.SANTA_VM_HOST_SUBNET_UPDATE_PLAN_SHA256
        $consumedPath = Join-Path $directory "host-subnet-storage-endpoint-consumed-$($plan.Plan.planSha256).json"
        if ($approval -cne $plan.Plan.planSha256 -or [IO.File]::Exists($consumedPath)) {
            Write-Host "A current live-read subnet plan requires review: $planPath" -ForegroundColor Yellow
            Write-Host "After reviewing its exact IDs and before/after serviceEndpoints, set SANTA_VM_HOST_SUBNET_UPDATE_PLAN_SHA256 to $($plan.Plan.planSha256), then rerun azd provision." -ForegroundColor Yellow
            throw 'Existing host subnet change is held until its fresh plan hash is explicitly selected.'
        }
        Write-PrivateJsonReceipt -Path $consumedPath -Value ([ordered]@{
            consumedAtUtc = [DateTimeOffset]::UtcNow.ToString('o')
            planSha256 = $plan.Plan.planSha256
            planPath = [IO.Path]::GetFileName($planPath)
            sourceRevision = $revision
            note = 'Local one-time confirmation consumed before provisioning; a retry requires a fresh live read and a new plan hash.'
        })
        Invoke-PrivateAzd @('env', 'unset', 'SANTA_VM_HOST_SUBNET_UPDATE_PLAN_SHA256', '--environment', $EnvironmentName, '--no-prompt', '--force')
    }
    elseif ($EnvironmentValues.ContainsKey('SANTA_VM_HOST_SUBNET_UPDATE_PLAN_SHA256') -and
        -not [string]::IsNullOrWhiteSpace([string]$EnvironmentValues.SANTA_VM_HOST_SUBNET_UPDATE_PLAN_SHA256)) {
        Invoke-PrivateAzd @('env', 'unset', 'SANTA_VM_HOST_SUBNET_UPDATE_PLAN_SHA256', '--environment', $EnvironmentName, '--no-prompt', '--force')
    }

    Set-PrivateAzdEnvironmentValue -EnvironmentName $EnvironmentName -Name 'SANTA_VM_ENABLE_STORAGE_SERVICE_ENDPOINT' -Value $plan.EndpointBoolean
    Set-PrivateAzdEnvironmentValue -EnvironmentName $EnvironmentName -Name 'SANTA_VM_HOST_SUBNET_SERVICE_ENDPOINTS_JSON' -Value $plan.ExistingServiceEndpointsJson
    Set-PrivateAzdEnvironmentValue -EnvironmentName $EnvironmentName -Name 'SANTA_VM_STORAGE_SERVICE_ENDPOINT_JSON' -Value $plan.StorageServiceEndpointJson
    Set-PrivateAzdEnvironmentValue -EnvironmentName $EnvironmentName -Name 'SANTA_VM_PRIVATE_ENDPOINT_NETWORK_POLICIES' -Value $plan.PrivateEndpointNetworkPolicies
    Set-PrivateAzdEnvironmentValue -EnvironmentName $EnvironmentName -Name 'SANTA_VM_PRIVATE_LINK_SERVICE_NETWORK_POLICIES' -Value $plan.PrivateLinkServiceNetworkPolicies
    Write-Host "Host subnet endpoint plan: $($plan.Plan.planSha256) ($($plan.Plan.plan.ownership)); incremental endpoint cost $($plan.Plan.plan.endpointIncrementalMonthlyCost)/month." -ForegroundColor DarkGray
}

function Confirm-PrivateHostSubnetStorageEndpoint {
    param([hashtable] $EnvironmentValues, [string] $EnvironmentName)
    $subscriptionId = [string]$EnvironmentValues.AZURE_SUBSCRIPTION_ID
    $location = [string]$EnvironmentValues.AZURE_LOCATION
    $settingValue = if ($EnvironmentValues.ContainsKey('SANTA_VM_ENABLE_STORAGE_SERVICE_ENDPOINT')) { [string]$EnvironmentValues['SANTA_VM_ENABLE_STORAGE_SERVICE_ENDPOINT'] } else { '' }
    $enable = Get-SantaBooleanSetting -Value $settingValue -Name 'SANTA_VM_ENABLE_STORAGE_SERVICE_ENDPOINT'
    $observation = Get-PrivateHostNetworkObservation -SubscriptionId $subscriptionId -EnvironmentName $EnvironmentName
    if ($null -eq $observation) { throw 'Provisioning completed without the selected host resource group.' }
    if (-not $EnvironmentValues.ContainsKey('SANTA_VM_INSTANCE_ID') -or [string]$EnvironmentValues.SANTA_VM_INSTANCE_ID -notmatch '^[0-9a-fA-F-]{36}$') {
        throw 'Current VM instance output is missing; no network readback can bind to this azd environment.'
    }
    $validated = Assert-SantaOwnedHostNetwork -SubscriptionId $subscriptionId -EnvironmentName $EnvironmentName -Location $location `
        -ResourceGroupName "rg-azd-santa-vm-$EnvironmentName" -ExpectedVmInstanceId ([guid]$EnvironmentValues.SANTA_VM_INSTANCE_ID) -Observation $observation
    $storageEndpoints = @($validated.endpointList | Where-Object { [string]$_.service -ieq 'Microsoft.Storage' })
    if ($enable -and $storageEndpoints.Count -ne 1) { throw 'Storage endpoint readback does not match the selected opt-in; preserve the deployment result and inspect the same environment.' }
    $receipt = [ordered]@{
        observedAtUtc = [DateTimeOffset]::UtcNow.ToString('o')
        sourceRevision = (& git -C $PSScriptRoot rev-parse HEAD 2>$null | Select-Object -Last 1)
        subscriptionId = $subscriptionId
        environmentName = $EnvironmentName
        subnetId = $validated.subnetId
        enableStorageServiceEndpoint = $enable
        serviceEndpoints = @($validated.endpointList)
        ownership = 'current-resource-identity-and-linkage-verified'
        storageAccountProvisioned = $false
        liveNetworkAndStorageDataPathVerified = $false
    }
    $directory = Get-PrivateEnvironmentDirectory $EnvironmentName
    $path = Join-Path $directory ('host-subnet-storage-endpoint-readback-' + [DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssZ') + '.json')
    Write-PrivateJsonReceipt -Path $path -Value $receipt
}

function New-PrivateSourceBundle {
    $entries = [ordered]@{}
    foreach ($name in $files) {
        $bytes = [IO.File]::ReadAllBytes((Join-Path $server $name))
        if ($bytes.Length -gt 262144) { throw 'Installer source file exceeded bound.' }
        $entries[$name] = [ordered]@{ sha256 = [Convert]::ToHexStringLower([Security.Cryptography.SHA256]::HashData($bytes)); base64 = [Convert]::ToBase64String($bytes) }
    }
    $raw = [Text.Encoding]::UTF8.GetBytes(([ordered]@{ scope = 'private-azd-source-v1'; files = $entries } | ConvertTo-Json -Depth 6 -Compress))
    if ($raw.Length -gt 2097152) { throw 'Installer bundle exceeded bound.' }
    $memory = [IO.MemoryStream]::new()
    try {
        $zip = [IO.Compression.GZipStream]::new($memory, [IO.Compression.CompressionLevel]::Optimal, $true)
        try { $zip.Write($raw) } finally { $zip.Dispose() }
        if ($memory.Length -gt 1048576) { throw 'Compressed installer bundle exceeded bound.' }
        $compressed = $memory.ToArray()
        $archiveHash = [Convert]::ToHexStringLower([Security.Cryptography.SHA256]::HashData($compressed))
        $encoded = [Convert]::ToBase64String($compressed)
    } finally { $memory.Dispose() }
    $chunks = @(); for ($index = 0; $index -lt $encoded.Length; $index += 24576) { $chunks += $encoded.Substring($index, [Math]::Min(24576, $encoded.Length - $index)) }
    if ($chunks.Count -gt 64) { throw 'Too many bounded installer chunks.' }
    [pscustomobject]@{ Sha256 = [Convert]::ToHexStringLower([Security.Cryptography.SHA256]::HashData($raw)); ArchiveSha256 = $archiveHash; Chunks = $chunks }
}

function Send-PrivateInstallCommand {
    param([hashtable]$Target, [hashtable]$Command)
    $body = [IO.File]::ReadAllText((Join-Path $server 'private_install_transport.py'), [Text.UTF8Encoding]::new($false, $true))
    $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($Command | ConvertTo-Json -Depth 6 -Compress)))
    $nonce = [guid]::NewGuid().ToString('N')
    $script = "set -eu`nexport AZD_PRIVATE_INSTALL_COMMAND='$encoded'`npython3 -I - <<'PRIVATE_INSTALL_PY'`n$body`nPRIVATE_INSTALL_PY`nprintf '%s\n' 'SANTA_PRIVATE_TRANSPORT_DONE:$nonce'`n"
    if ([Text.Encoding]::UTF8.GetByteCount($script) -gt 65536) { throw 'Installer transport command exceeded 64KiB.' }
    $temporary = Join-Path ([IO.Path]::GetTempPath()) ('santa-private-' + [guid]::NewGuid() + '.sh')
    try {
        $file = [IO.FileStream]::new($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $file.Write([Text.Encoding]::UTF8.GetBytes($script)) } finally { $file.Dispose() }
        $result = Invoke-PrivateAzure @('vm', 'run-command', 'invoke', '--subscription', $Target.SubscriptionId,
            '--resource-group', $Target.ResourceGroup, '--name', $Target.VmName, '--command-id', 'RunShellScript', '--scripts', "@$temporary")
        if (-not $result.value -or @($result.value).Count -gt 4 -or @($result.value | Where-Object { $_.code -cnotmatch '/succeeded$' }).Count) { throw 'Nonterminal installer transport result.' }
        $lines = ($result.value.message -join "`n") -split '\r?\n'
        $data = @($lines | Where-Object { $_.StartsWith('SANTA_PRIVATE_INSTALL_JSON:', [StringComparison]::Ordinal) })
        $done = @($lines | Where-Object { $_.StartsWith('SANTA_PRIVATE_TRANSPORT_DONE:', [StringComparison]::Ordinal) })
        if ($data.Count -ne 1 -or $done.Count -ne 1 -or $done[0] -cne "SANTA_PRIVATE_TRANSPORT_DONE:$nonce" -or
            [Array]::IndexOf($lines, $done[0]) -lt [Array]::IndexOf($lines, $data[0]) -or $data[0].Length -gt 4096) { throw 'Installer transport receipt absent/truncated; observe same job.' }
        $value = $data[0].Substring('SANTA_PRIVATE_INSTALL_JSON:'.Length) | ConvertFrom-Json -AsHashtable
        if ($value.bundle_sha256 -cne $Command.bundle_sha256) { throw 'Installer bundle observation mismatch.' }
        $value
    } finally { if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) } }
}

function Invoke-PrivateVmAzdHook {
    [CmdletBinding()]
    param([Parameter(Mandatory)][ValidateSet('preprovision', 'postprovision')][string]$Phase)
    $environment = $env:AZURE_ENV_NAME
    if ($environment -cnotmatch '^[a-z0-9-]{2,32}$') { throw 'Selected private azd environment required.' }
    $values = Invoke-PrivateAzd @('env', 'get-values', '--environment', $environment, '--output', 'json') -Json
    if ($values.AZURE_ENV_NAME -cne $environment) { throw 'Selected azd environment changed.' }
    $directory = Get-PrivateEnvironmentDirectory $environment
    if (-not [IO.Directory]::Exists($directory)) { throw 'Selected local azd environment directory missing.' }
    if ($Phase -eq 'preprovision') {
        Prepare-PrivateHostSubnetStorageEndpoint -EnvironmentValues $values -EnvironmentName $environment
        if ($values.ContainsKey('SANTA_VM_SSH_PUBLIC_KEY') -and -not [string]::IsNullOrWhiteSpace($values.SANTA_VM_SSH_PUBLIC_KEY)) { return }
        $path = Join-Path $directory 'provisioning-only.pub'
        if ([IO.File]::Exists($path)) { $public = [IO.File]::ReadAllText($path).Trim() }
        else {
            $public = New-ProvisioningPublicKey
            $stream = [IO.FileStream]::new($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
            try { $stream.Write([Text.Encoding]::ASCII.GetBytes($public)); $stream.Flush($true) } finally { $stream.Dispose() }
        }
        if ($public -cnotmatch '^ssh-rsa [A-Za-z0-9+/=]+ azd-private-provisioning-only$') { throw 'Generated provisioning artifact changed.' }
        Invoke-PrivateAzd @('env', 'set', 'SANTA_VM_SSH_PUBLIC_KEY', $public, '--environment', $environment, '--no-prompt')
        return
    }
    $installBackend = $false
    if ($values.ContainsKey('SANTA_PRIVATE_BACKEND_INSTALL')) {
        if ($values.SANTA_PRIVATE_BACKEND_INSTALL -ceq 'true') { $installBackend = $true }
        elseif ($values.SANTA_PRIVATE_BACKEND_INSTALL -cne 'false') { throw 'SANTA_PRIVATE_BACKEND_INSTALL must be true or false.' }
    }
    $target = Get-SantaPrivateVmDeploymentTarget -SubscriptionId $values.AZURE_SUBSCRIPTION_ID -EnvironmentName $environment
    foreach ($pair in @(@('AZURE_RESOURCE_GROUP', 'ResourceGroup'), @('SANTA_VM_NAME', 'VmName'), @('SANTA_VM_RESOURCE_ID', 'VmId'), @('SANTA_VM_INSTANCE_ID', 'VmInstanceId'))) {
        if (-not $values.ContainsKey($pair[0]) -or $values[$pair[0]] -ine $target[$pair[1]]) { throw 'Authoritative provisioned VM outputs missing/mismatched.' }
    }
    $subscription = [regex]::Escape($target.SubscriptionId); $group = [regex]::Escape($target.ResourceGroup)
    if (-not $values.ContainsKey('SANTA_VM_DEPLOYMENT_ID') -or $values.SANTA_VM_DEPLOYMENT_ID -cnotmatch
        "^/subscriptions/$subscription/(?:resourceGroups/$group/)?providers/Microsoft\.Resources/deployments/[A-Za-z0-9_.()-]{1,64}$") {
        throw 'Selected canonical deployment output missing/mismatched; no installation submitted.'
    }
    $endpointSetting = if ($values.ContainsKey('SANTA_VM_ENABLE_STORAGE_SERVICE_ENDPOINT')) { [string]$values['SANTA_VM_ENABLE_STORAGE_SERVICE_ENDPOINT'] } else { '' }
    if (Get-SantaBooleanSetting -Value $endpointSetting -Name 'SANTA_VM_ENABLE_STORAGE_SERVICE_ENDPOINT') {
        Confirm-PrivateHostSubnetStorageEndpoint -EnvironmentValues $values -EnvironmentName $environment
    }
    $shutdown = [DateTimeOffset]::UtcNow.AddHours(2).ToString('HHmm')
    $null = Invoke-PrivateAzure @('vm', 'auto-shutdown', '--subscription', $target.SubscriptionId, '--resource-group', $target.ResourceGroup, '--name', $target.VmName, '--time', $shutdown)
    if (-not $installBackend) { return }
    $bundle = New-PrivateSourceBundle
    $state = Send-PrivateInstallCommand $target @{ mode = 'observe'; bundle_sha256 = $bundle.Sha256 }
    if ($state.state -ceq 'not-installed') {
        for ($index = 0; $index -lt $bundle.Chunks.Count; $index++) {
            $receipt = Send-PrivateInstallCommand $target @{ mode = 'chunk'; bundle_sha256 = $bundle.Sha256; archive_sha256 = $bundle.ArchiveSha256; index = $index; count = $bundle.Chunks.Count; data = $bundle.Chunks[$index] }
            if ($receipt.scope -cne 'private-azd-install-chunk' -or $receipt.index -ne $index -or $receipt.count -ne $bundle.Chunks.Count) { throw 'Source chunk delivery not confirmed; initialization not submitted.' }
        }
        try { $state = Send-PrivateInstallCommand $target @{ mode = 'submit'; bundle_sha256 = $bundle.Sha256; archive_sha256 = $bundle.ArchiveSha256; count = $bundle.Chunks.Count; target = $target } }
        catch {
            # Submission outcome is unknown: inspect only; never submit/init again.
            $state = Send-PrivateInstallCommand $target @{ mode = 'observe'; bundle_sha256 = $bundle.Sha256 }
        }
    }
    $deadline = [DateTimeOffset]::UtcNow.AddMinutes(110)
    while (-not $state.completion) {
        if ($state.scope -cne 'private-azd-install-observation' -or $state.state -in @('failed', 'inactive', 'not-installed') -or [DateTimeOffset]::UtcNow -gt $deadline) { throw 'Private install did not complete; same unit/data retained. Rerun azd observes that job, never initialization.' }
        Write-Host "Private backend job: $($state.state)/$($state.substate); observing same unit."
        Start-Sleep -Seconds 15
        $state = Send-PrivateInstallCommand $target @{ mode = 'observe'; bundle_sha256 = $bundle.Sha256 }
    }
    if ($state.scope -cne 'private-azd-install-observation' -or $state.unit -cne ('azd-santa-install-' + $bundle.Sha256.Substring(0,16) + '.service') -or
        $state.completion.scope -cne 'private-azd-install-complete' -or $state.completion.bundle_sha256 -cne $bundle.Sha256) { throw 'Installer completion binding invalid.' }
    $outputs = $state.completion.outputs
    foreach ($key in $target.Keys) { if ($outputs[$key] -cne $target[$key]) { throw 'Installer completed on another target.' } }
    $suffix = [guid]::NewGuid().ToString('N')
    $binding = Complete-SantaBackendInstallation -InstallationOutputs $outputs -DeploymentId $values.SANTA_VM_DEPLOYMENT_ID `
        -InstallationReceiptPath (Join-Path $directory "installation-$suffix.json") -OperatorBindingPath (Join-Path $directory "operator-binding-$suffix.json")
    Invoke-PrivateAzd @('env', 'set', 'SANTA_OPERATOR_BINDING_PATH', $binding.Path, '--environment', $environment, '--no-prompt')
    Write-Host 'Private backend initialized and binding recorded. Native HTTPS/browser/MFA acceptance remains pending.'
}

Export-ModuleMember -Function Invoke-PrivateVmAzdHook
