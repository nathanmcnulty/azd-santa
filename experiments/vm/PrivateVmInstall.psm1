#Requires -Version 7.6
# Original Unlicense. Optional private template lifecycle; no root Intune hooks.
Set-StrictMode -Version Latest
$server = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../server'))
Import-Module (Join-Path $server 'SetupTransport.psm1') -Force
Import-Module (Join-Path $server 'SealedSetup.psm1') -Force
Import-Module (Join-Path $server 'HttpsEndpoint.psm1') -Force
$files = @('private_install.py', 'private_install_transport.py', 'bootstrap-host.sh', 'prepare_source.py',
    'prepare_core_build.py', 'prepare_operator_mfa.py', 'operator_mfa.py', 'prepare_operator_recovery.py',
    'operator_recovery.py', 'sealed_setup.py', 'prepare_request_limits.py', 'santa_request_limits.py',
    'prepare_database_roles.py', 'database_roles.py', 'prepare_zentral_eval.py', 'stage_runtime.py',
    'runtime_service.py', 'santa_admission.py', 'cold_backup.py', 'native_snapshot.py',
    'worker_lifecycle.py', 'prepare_worker_lifecycle.py', 'test_live_zentral.py',
    'zentral-source.lock.json', 'dependency-images.lock.json', 'prepare_held_https.py',
    'https_edge.py', 'prepare_https_proxy.py', 'caddy.lock.json')

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

function Assert-PrivateProvisionedVmOutputs {
    param([hashtable]$Values, [hashtable]$Target)
    foreach ($pair in @(@('AZURE_SUBSCRIPTION_ID', 'SubscriptionId'), @('AZURE_RESOURCE_GROUP', 'ResourceGroup'),
            @('SANTA_VM_NAME', 'VmName'), @('SANTA_VM_RESOURCE_ID', 'VmId'), @('SANTA_VM_INSTANCE_ID', 'VmInstanceId'))) {
        if ($Values[$pair[0]] -isnot [string] -or $Values[$pair[0]] -ine $Target[$pair[1]]) {
            throw 'Authoritative provisioned VM outputs missing/mismatched.'
        }
    }
}

function Assert-PrivateOperatorHttps {
    param([uri]$Origin)
    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $handler.UseCookies = $false
    $client = [Net.Http.HttpClient]::new($handler)
    $client.Timeout = [TimeSpan]::FromSeconds(8)
    try {
        $login = [uri]::new($Origin, '/accounts/login/')
        try {
            $response = $client.GetAsync($login, [Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
        } catch {
            throw 'Santa login is unreachable over trusted HTTPS from this workstation. Check VM power and the HTTPS route, then retry. No setup attempt was reserved.'
        }
        try {
            if ($response.StatusCode -ne [Net.HttpStatusCode]::OK) {
                throw "Santa login returned HTTP $([int]$response.StatusCode). Check the HTTPS route, then retry. No setup attempt was reserved."
            }
        } finally { $response.Dispose() }
    } finally { $client.Dispose() }
}

function Get-PrivateHeldHttpsSelection([string]$EnvironmentName) {
    $values = Invoke-PrivateAzd @('env', 'get-values', '--environment', $EnvironmentName, '--output', 'json') -Json
    if ($values['AZURE_ENV_NAME'] -cne $EnvironmentName -or $values['SANTA_PRIVATE_BACKEND_INSTALL'] -cne 'true' -or
        $values['SANTA_PRIVATE_HTTPS_ORIGIN'] -cne 'true') { throw 'Select the azd environment with the fresh HTTPS service staged.' }
    $target = Get-SantaPrivateVmDeploymentTarget -SubscriptionId $values['AZURE_SUBSCRIPTION_ID'] -EnvironmentName $EnvironmentName
    Assert-PrivateProvisionedVmOutputs $values $target
    $facts = Get-SantaHttpsEndpointFacts -TenantId $target.TenantId -SubscriptionId $target.SubscriptionId `
        -VmInstanceId $target.VmInstanceId -EnvironmentName $EnvironmentName
    @{ Target = $target; Facts = $facts }
}

function Get-PrivateVmHeldHttpsReadiness {
    [CmdletBinding()]
    param([Parameter(Mandatory)][ValidatePattern('^[a-z0-9-]{2,32}$')][string]$EnvironmentName)
    $selection = Get-PrivateHeldHttpsSelection $EnvironmentName
    $target = $selection.Target
    $facts = $selection.Facts

    $renderer = Join-Path $server 'held_https_readiness.py'
    $rendered = ($facts | ConvertTo-Json -Compress) | & python -I -B $renderer render
    if ($LASTEXITCODE -or -not $rendered) { throw 'Could not render the held HTTPS readiness check.' }
    $marker = 'SANTA_HELD_READY:'
    $nonce = 'SANTA_HELD_READBACK_DONE:' + [guid]::NewGuid().ToString('N')
    $body = ($rendered -join "`n") + "`nprintf '%s\n' '$nonce'`n"
    if ([Text.Encoding]::UTF8.GetByteCount($body) -gt 49152) { throw 'HTTPS readiness check exceeded transport bound.' }
    $path = Join-Path ([IO.Path]::GetTempPath()) ('santa-held-readback-' + [guid]::NewGuid() + '.sh')
    try {
        $file = [IO.FileStream]::new($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $file.Write([Text.Encoding]::UTF8.GetBytes($body)) } finally { $file.Dispose() }
        $result = Invoke-PrivateAzure @('vm', 'run-command', 'invoke', '--subscription', $target.SubscriptionId,
            '--resource-group', $target.ResourceGroup, '--name', $target.VmName, '--command-id', 'RunShellScript', '--scripts', "@$path")
    } finally {
        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force }
    }
    if (-not $result['value'] -or @($result['value'] | Where-Object { $_.code -cnotmatch '/succeeded$' }).Count) {
        throw 'Guest readiness did not reach a successful terminal transport result.'
    }
    $lines = ($result['value'].message -join "`n") -split '\r?\n'
    $proof = @($lines | Where-Object { $_.StartsWith($marker, [StringComparison]::Ordinal) })
    $done = @($lines | Where-Object { $_ -ceq $nonce })
    if ($proof.Count -ne 1 -or $done.Count -ne 1 -or $proof[0].Length -gt 4096 -or
        [array]::IndexOf($lines, $done[0]) -le [array]::IndexOf($lines, $proof[0])) {
        throw 'Guest readiness proof is missing or incomplete. Inspect the selected VM and staged HTTPS files.'
    }
    $receipt = $proof[0].Substring($marker.Length) | ConvertFrom-Json -AsHashtable
    if ($receipt['scope'] -cne 'santa-held-https-readiness-v1' -or $receipt['vm_instance_id'] -cne $target.VmInstanceId -or
        $receipt['fqdn'] -cne $facts.Fqdn -or $receipt['tcp443'] -cne 'unbound' -or $receipt['held_unit'] -cne 'disabled' -or
        $receipt['binary_sha256'] -cnotmatch '^[a-f0-9]{64}$' -or $receipt['acme_empty'] -isnot [bool]) {
        throw 'Guest readiness proof does not match the selected VM and staged service.'
    }
    [pscustomobject]$receipt
}

function Invoke-PrivateVmHeldCertificateTrial {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([Parameter(Mandatory)][ValidatePattern('^[a-z0-9-]{2,32}$')][string]$EnvironmentName,
        [ValidateSet('Issue', 'Renew')][string]$Mode = 'Issue')
    $selection = Get-PrivateHeldHttpsSelection $EnvironmentName
    if (-not $PSCmdlet.ShouldProcess($selection.Facts.Fqdn, "Temporarily allow TCP443 for one held HTTPS certificate $Mode trial")) { return }
    $directory = Join-Path (Get-PrivateEnvironmentDirectory $EnvironmentName) ('certificate-' + [guid]::NewGuid().ToString('N'))
    Assert-SantaPrivateDestination $directory
    $null = [IO.Directory]::CreateDirectory($directory)
    $PSNativeCommandUseErrorActionPreference = $false
    $output = ($selection.Facts | ConvertTo-Json -Compress) | & python -I -B (Join-Path $server 'run_held_certificate_trial.py') $directory $Mode.ToLowerInvariant()
    if ($LASTEXITCODE -or -not $output) { throw "Certificate trial did not complete. Inspect the selected NSG and '$directory' before another action." }
    [pscustomobject]@{ AttemptDirectory = $directory; Certificate = ($output -join "`n") | ConvertFrom-Json }
}

function Invoke-PrivateVmOperatorSetup {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][ValidatePattern('^[a-z0-9-]{2,32}$')][string]$EnvironmentName,
        [Parameter(Mandatory)][ValidateSet('bootstrap', 'recover')][string]$Mode,
        [Parameter(Mandatory)][string]$Username,
        [Parameter(Mandatory)][string]$Email,
        [Parameter(Mandatory)][string]$Reason,
        [ValidatePattern('^[a-z0-9][a-z0-9-]{0,31}$')][string]$RecoveryAttempt
    )
    $Mode = $Mode.ToLowerInvariant()
    if (($Mode -eq 'recover') -ne [bool]$RecoveryAttempt) {
        throw 'Supply a recovery attempt label for recover only.'
    }
    if ($EnvironmentName -cnotmatch '^[a-z0-9-]{2,32}$' -or
        ($RecoveryAttempt -and $RecoveryAttempt -cnotmatch '^[a-z0-9][a-z0-9-]{0,31}$')) {
        throw 'Use lowercase environment and recovery attempt names.'
    }
    if ($Username.Length -gt 150 -or -not $Username.Trim() -or $Username -cne $Username.Trim() -or
        $Email.Length -gt 254 -or -not $Email.Trim() -or $Email -cne $Email.Trim() -or
        -not $Reason.Trim() -or $Reason.Length -gt 256 -or $Reason -match '[\x00-\x1f]') {
        throw 'Bounded exact operator identity and reason required.'
    }
    $values = Invoke-PrivateAzd @('env', 'get-values', '--environment', $EnvironmentName, '--output', 'json') -Json
    if ($values['AZURE_ENV_NAME'] -cne $EnvironmentName -or $values['SANTA_PRIVATE_BACKEND_INSTALL'] -cne 'true') {
        throw 'Select an azd environment with the private backend installed.'
    }
    $directory = Get-PrivateEnvironmentDirectory $EnvironmentName
    $bindingPath = $values['SANTA_OPERATOR_BINDING_PATH']
    if ($bindingPath -isnot [string] -or -not [IO.Path]::IsPathFullyQualified($bindingPath) -or
        [IO.Path]::GetFullPath($bindingPath) -cne $bindingPath -or
        [IO.Path]::GetDirectoryName($bindingPath) -cne $directory -or
        [IO.Path]::GetFileName($bindingPath) -cnotmatch '^operator-binding-[a-f0-9]{32}\.json$') {
        throw 'The selected azd environment requires its machine-produced operator binding. Complete the private VM install first.'
    }
    $instance = $values['SANTA_VM_INSTANCE_ID']
    if ($instance -isnot [string] -or $instance -cnotmatch '^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$') {
        throw 'The selected azd environment has no canonical VM instance.'
    }
    $attempt = if ($Mode -eq 'bootstrap') { 'bootstrap' } else { "recover-$RecoveryAttempt" }
    $checkpoints = Join-Path $directory "operator-$instance-$attempt"
    $intent = "$checkpoints.intent"
    if ((Test-Path -LiteralPath $intent) -or (Test-Path -LiteralPath $checkpoints)) {
        throw "This setup attempt is already reserved. Inspect '$checkpoints' before a deliberate recovery."
    }
    Assert-SantaPrivateDestination $intent
    $file = Get-Item -LiteralPath $bindingPath
    if ($file -isnot [IO.FileInfo] -or $file.Length -gt 4096 -or
        ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'The selected operator binding is not a bounded local file.'
    }
    $binding = Get-Content -LiteralPath $bindingPath -Raw | ConvertFrom-Json -AsHashtable
    Assert-SantaSetupBinding $binding
    if ($binding['EnvironmentName'] -cne $EnvironmentName) { throw 'The operator binding belongs to a different azd environment.' }
    Assert-PrivateProvisionedVmOutputs $values $binding
    if (-not $PSCmdlet.ShouldProcess($EnvironmentName, "Request Santa administrator $attempt and open the local browser")) { return }

    Assert-PrivateOperatorHttps $binding.Origin
    $stream = [IO.FileStream]::new($intent, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Flush($true) } finally { $stream.Dispose() }
    $null = [IO.Directory]::CreateDirectory($checkpoints)
    Assert-SantaPrivateDestination (Join-Path $checkpoints 'local-check')
    & (Join-Path $server 'Invoke-SantaOperatorSetup.ps1') -DeploymentBindingPath $bindingPath -Mode $Mode `
        -Username $Username -Email $Email -Reason $Reason -CheckpointDirectory $checkpoints -OpenBrowser -ReadbackOnUnknown
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
    $installBackend = $false
    if ($values.ContainsKey('SANTA_PRIVATE_BACKEND_INSTALL')) {
        if ($values.SANTA_PRIVATE_BACKEND_INSTALL -ceq 'true') { $installBackend = $true }
        elseif ($values.SANTA_PRIVATE_BACKEND_INSTALL -cne 'false') { throw 'SANTA_PRIVATE_BACKEND_INSTALL must be true or false.' }
    }
    $target = Get-SantaPrivateVmDeploymentTarget -SubscriptionId $values.AZURE_SUBSCRIPTION_ID -EnvironmentName $environment
    Assert-PrivateProvisionedVmOutputs $values $target
    $subscription = [regex]::Escape($target.SubscriptionId); $group = [regex]::Escape($target.ResourceGroup)
    if (-not $values.ContainsKey('SANTA_VM_DEPLOYMENT_ID') -or $values.SANTA_VM_DEPLOYMENT_ID -cnotmatch
        "^/subscriptions/$subscription/(?:resourceGroups/$group/)?providers/Microsoft\.Resources/deployments/[A-Za-z0-9_.()-]{1,64}$") {
        throw 'Selected canonical deployment output missing/mismatched; no installation submitted.'
    }
    $origin = 'https://localhost:8000'
    if ($values.ContainsKey('SANTA_PRIVATE_HTTPS_ORIGIN')) {
        if ($values.SANTA_PRIVATE_HTTPS_ORIGIN -isnot [string]) { throw 'SANTA_PRIVATE_HTTPS_ORIGIN must be true or false.' }
        if ($values.SANTA_PRIVATE_HTTPS_ORIGIN -ceq 'true') {
            if (-not $installBackend) { throw 'Fresh HTTPS origin requires SANTA_PRIVATE_BACKEND_INSTALL=true.' }
            $endpoint = Get-SantaHttpsEndpointFacts -TenantId $target.TenantId -SubscriptionId $target.SubscriptionId `
                -VmInstanceId $target.VmInstanceId -EnvironmentName $environment -WaitForProvisioning
            $origin = 'https://' + $endpoint.Fqdn
        } elseif ($values.SANTA_PRIVATE_HTTPS_ORIGIN -cne 'false') { throw 'SANTA_PRIVATE_HTTPS_ORIGIN must be true or false.' }
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
        try {
            $submission = @{ mode = 'submit'; bundle_sha256 = $bundle.Sha256; archive_sha256 = $bundle.ArchiveSha256; count = $bundle.Chunks.Count; target = $target }
            if ($origin -cne 'https://localhost:8000') {
                $submission.https_origin = $origin
                $submission.https_endpoint = $endpoint
            }
            $state = Send-PrivateInstallCommand $target $submission
        }
        catch {
            # Submission outcome is unknown: inspect only; never submit/init again.
            $state = Send-PrivateInstallCommand $target @{ mode = 'observe'; bundle_sha256 = $bundle.Sha256 }
        }
    }
    $deadline = [DateTimeOffset]::UtcNow.AddMinutes(110)
    while (-not $state.completion -or $state['state'] -ceq 'failed') {
        if ($state.scope -ceq 'private-azd-install-observation' -and $state.state -ceq 'failed' -and
            $state['bundle_sha256'] -ceq $bundle.Sha256 -and
            $state['unit'] -ceq ('azd-santa-install-' + $bundle.Sha256.Substring(0,16) + '.service')) {
            $guidance = @{
                'source-verification' = 'Check the pinned installer bundle and context for this deployment.'
                'vm-identity' = 'Check the selected VM instance, ownership tags, and configured hostname.'
                'fresh-state' = 'Check for an existing Santa runtime or service on the selected VM.'
                'docker-prerequisites' = 'Check the pinned Docker and Compose prerequisite evidence.'
                'source-build' = 'Check the retained source build and dependency image evidence.'
                'runtime-initialization' = 'Check the retained runtime initialization evidence.'
                'held-https-staging' = 'Check the pinned Caddy download and retained HTTPS staging evidence.'
            }
            $failureCode = $state['failure_code']
            if ($failureCode -is [string] -and $guidance.ContainsKey($failureCode)) {
                throw "SantaInstall.${failureCode}: $($guidance[$failureCode]) Preserve the same job and data for inspection."
            }
        }
        if ($state.scope -cne 'private-azd-install-observation' -or $state.state -in @('failed', 'inactive', 'not-installed') -or [DateTimeOffset]::UtcNow -gt $deadline) { throw 'Private install did not complete; same unit/data retained. Rerun azd observes that job, never initialization.' }
        Write-Host "Private backend job: $($state.state)/$($state.substate); observing same unit."
        Start-Sleep -Seconds 15
        $state = Send-PrivateInstallCommand $target @{ mode = 'observe'; bundle_sha256 = $bundle.Sha256 }
    }
    if ($state.scope -cne 'private-azd-install-observation' -or $state.unit -cne ('azd-santa-install-' + $bundle.Sha256.Substring(0,16) + '.service') -or
        $state.completion.scope -cne 'private-azd-install-complete' -or $state.completion.bundle_sha256 -cne $bundle.Sha256) { throw 'Installer completion binding invalid.' }
    $outputs = $state.completion.outputs
    if ($outputs.Origin -cne $origin) { throw 'Installer origin differs from selected fresh profile.' }
    foreach ($key in $target.Keys) { if ($outputs[$key] -cne $target[$key]) { throw 'Installer completed on another target.' } }
    $suffix = [guid]::NewGuid().ToString('N')
    $binding = Complete-SantaBackendInstallation -InstallationOutputs $outputs -DeploymentId $values.SANTA_VM_DEPLOYMENT_ID `
        -InstallationReceiptPath (Join-Path $directory "installation-$suffix.json") -OperatorBindingPath (Join-Path $directory "operator-binding-$suffix.json")
    Invoke-PrivateAzd @('env', 'set', 'SANTA_OPERATOR_BINDING_PATH', $binding.Path, '--environment', $environment, '--no-prompt')
    Write-Host 'Private backend initialized and binding recorded. Native HTTPS/browser/MFA acceptance remains pending.'
}

Export-ModuleMember -Function Invoke-PrivateVmAzdHook, Invoke-PrivateVmOperatorSetup, Get-PrivateVmHeldHttpsReadiness, Invoke-PrivateVmHeldCertificateTrial
