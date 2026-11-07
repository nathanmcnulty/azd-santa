#Requires -Version 7.6
# Original Unlicense. Optional private template lifecycle; no root Intune hooks.
Set-StrictMode -Version Latest
$server = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../server'))
Import-Module (Join-Path $server 'SetupTransport.psm1') -Force
$files = @('private_install.py', 'private_install_transport.py', 'bootstrap-host.sh', 'prepare_source.py',
    'prepare_core_build.py', 'prepare_operator_mfa.py', 'operator_mfa.py', 'prepare_operator_recovery.py',
    'operator_recovery.py', 'sealed_setup.py', 'prepare_request_limits.py', 'santa_request_limits.py',
    'prepare_database_roles.py', 'database_roles.py', 'prepare_zentral_eval.py', 'stage_runtime.py',
    'runtime_service.py', 'test_live_zentral.py', 'zentral-source.lock.json', 'dependency-images.lock.json')

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
    if (-not $values.ContainsKey('SANTA_PRIVATE_BACKEND_INSTALL') -or $values.SANTA_PRIVATE_BACKEND_INSTALL -eq 'false') { return }
    if ($values.SANTA_PRIVATE_BACKEND_INSTALL -cne 'true') { throw 'SANTA_PRIVATE_BACKEND_INSTALL must be true or false.' }
    $target = Get-SantaPrivateVmDeploymentTarget -SubscriptionId $values.AZURE_SUBSCRIPTION_ID -EnvironmentName $environment
    foreach ($pair in @(@('AZURE_RESOURCE_GROUP', 'ResourceGroup'), @('SANTA_VM_NAME', 'VmName'), @('SANTA_VM_RESOURCE_ID', 'VmId'), @('SANTA_VM_INSTANCE_ID', 'VmInstanceId'))) {
        if (-not $values.ContainsKey($pair[0]) -or $values[$pair[0]] -ine $target[$pair[1]]) { throw 'Authoritative provisioned VM outputs missing/mismatched.' }
    }
    $subscription = [regex]::Escape($target.SubscriptionId); $group = [regex]::Escape($target.ResourceGroup)
    if (-not $values.ContainsKey('SANTA_VM_DEPLOYMENT_ID') -or $values.SANTA_VM_DEPLOYMENT_ID -cnotmatch
        "^/subscriptions/$subscription/(?:resourceGroups/$group/)?providers/Microsoft\.Resources/deployments/[A-Za-z0-9_.()-]{1,64}$") {
        throw 'Selected canonical deployment output missing/mismatched; no installation submitted.'
    }
    $shutdown = [DateTimeOffset]::UtcNow.AddHours(2).ToString('HHmm')
    $null = Invoke-PrivateAzure @('vm', 'auto-shutdown', '--subscription', $target.SubscriptionId, '--resource-group', $target.ResourceGroup, '--name', $target.VmName, '--time', $shutdown)
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
