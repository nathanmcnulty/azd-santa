#Requires -Version 7.6
# Original Unlicense. Transport primitives; not an azd hook or remote attestor.
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'SealedSetup.psm1') -Force

function Get-SantaTransportHash([string]$Value) {
    [Convert]::ToHexStringLower([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($Value)))
}

function Assert-SantaSetupBinding {
    param([hashtable]$Binding, [switch]$SourceBinding)
    $names = @('TenantId', 'SubscriptionId', 'EnvironmentName', 'ResourceGroup', 'VmName', 'VmId',
        'VmInstanceId', 'ImageId', 'ComposePath', 'ComposeSha256', 'Origin')
    if ($SourceBinding) { $names += @('SourceCommit', 'RecoverySha256', 'SealedSha256', 'RemoteProgramSha256') }
    if ($Binding.Count -ne $names.Count -or @($names | Where-Object { -not $Binding.ContainsKey($_) }).Count) { throw 'Exact setup binding fields required.' }
    if (@($Binding.Keys | Where-Object { $_ -cnotin $names -or $Binding[$_] -isnot [string] }).Count) { throw 'Exact case-sensitive string binding fields required.' }
    foreach ($name in @('TenantId', 'SubscriptionId', 'VmInstanceId')) {
        if ($Binding[$name] -cnotmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') { throw 'Canonical selected tenant/subscription required.' }
    }
    if ($Binding.EnvironmentName -cnotmatch '^[a-z0-9-]{2,32}$' -or
        $Binding.ResourceGroup -cne "rg-azd-santa-vm-$($Binding.EnvironmentName)" -or $Binding.VmName -cne 'vm-santa-lab' -or
        $Binding.VmId -cne "/subscriptions/$($Binding.SubscriptionId)/resourceGroups/$($Binding.ResourceGroup)/providers/Microsoft.Compute/virtualMachines/vm-santa-lab") { throw 'Exact selected private pilot VM binding required.' }
    $hashNames = @('ComposeSha256')
    if ($SourceBinding) { $hashNames += @('RecoverySha256', 'SealedSha256', 'RemoteProgramSha256') }
    foreach ($name in $hashNames) {
        if ($Binding[$name] -cnotmatch '^[a-f0-9]{64}$') { throw 'Exact source hashes required.' }
    }
    if ($Binding.ImageId -cnotmatch '^sha256:[a-f0-9]{64}$' -or ($SourceBinding -and $Binding.SourceCommit -cnotmatch '^[a-f0-9]{40}$') -or
        $Binding.ComposePath.Length -gt 512 -or $Binding.ComposePath -cnotmatch '^/(?:[A-Za-z0-9_-]+/)+[A-Za-z0-9_-]+\.json$') { throw 'Exact runtime binding required.' }
    $origin = [uri]$Binding.Origin
    if ($origin.Scheme -cne 'https' -or $origin.UserInfo -or $origin.Query -or $origin.Fragment -or
        $origin.AbsolutePath -ne '/' -or $Binding.Origin.Length -gt 256 -or $Binding.Origin -match '[^\x21-\x7e]') { throw 'Explicit HTTPS origin required.' }
}

function New-SantaSetupTransportRequest {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Binding,
        [Parameter(Mandatory)][ValidateSet('bootstrap', 'recover')][string]$Mode,
        [Parameter(Mandatory)][string]$Username, [Parameter(Mandatory)][string]$Email,
        [Parameter(Mandatory)][string]$Reason)
    Assert-SantaSetupBinding $Binding -SourceBinding
    $names = @($Binding.Keys)
    if (-not $Username -or $Username.Length -gt 150 -or $Username -cne $Username.Trim() -or
        -not $Email -or $Email.Length -gt 254 -or $Email -cne $Email.Trim() -or
        -not $Reason.Trim() -or $Reason.Length -gt 256 -or $Reason -match '[\x00-\x1f]') { throw 'Bounded exact operator identity and reason required.' }
    $recipient = New-SantaSetupRecipient
    try {
        $nonce = [Convert]::ToHexStringLower([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
        $target = Get-SantaSetupTargetDigest -Username $Username -Email $Email
        $ordered = [ordered]@{}
        foreach ($name in ($names | Sort-Object -CaseSensitive)) { $ordered[$name] = $Binding[$name] }
        $record = [ordered]@{ scope = 'azd-santa-setup-request-v1'; nonce = $nonce; binding = $ordered
            mode = $Mode; target_sha256 = $target; recipient_sha256 = $recipient.KeyId }
        $context = Get-SantaTransportHash ($record | ConvertTo-Json -Depth 6 -Compress)
        $payload = [ordered]@{ context = $record; context_sha256 = $context; recipient_public_key = $recipient.PublicKeyBase64
            username = $Username; email = $Email; reason = $Reason }
        [pscustomobject]@{ Recipient = $recipient; Context = $context; Binding = $ordered; Mode = $Mode
            TargetDigest = $target; RequestId = $nonce
            PayloadBase64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($payload | ConvertTo-Json -Depth 8 -Compress))) }
    } catch { $recipient.Key.Dispose(); throw 'Setup transport request preparation failed.' }
}

function Invoke-SantaSetupAzJson {
    param([string[]]$Arguments)
    # Reuse cached CLI credentials. Never log in, change active account or grant.
    $output = & az @Arguments --only-show-errors -o json 2>$null
    if ($LASTEXITCODE) { throw 'Selected Azure operation failed; inspect state before any retry.' }
    try { ($output -join "`n") | ConvertFrom-Json -Depth 32 -ErrorAction Stop }
    catch { throw 'Azure response was not complete JSON; outcome requires inspection.' }
}

function Assert-SantaSetupAzureTarget {
    param([object]$Request)
    $b = $Request.Binding
    $account = Invoke-SantaSetupAzJson @('account', 'show', '--subscription', $b.SubscriptionId)
    if ($account.id -ine $b.SubscriptionId -or $account.tenantId -ine $b.TenantId -or $account.state -cne 'Enabled') { throw 'Cached account does not match selected enabled subscription/tenant.' }
    $group = Invoke-SantaSetupAzJson @('group', 'show', '--subscription', $b.SubscriptionId, '--name', $b.ResourceGroup)
    if ($group.id -ine "/subscriptions/$($b.SubscriptionId)/resourceGroups/$($b.ResourceGroup)" -or
        $group.tags.'azd-solution' -cne 'azd-santa' -or $group.tags.purpose -cne 'synthetic-vm-lab' -or
        $group.tags.'azd-env-name' -cne $b.EnvironmentName) { throw 'Selected group is not the tagged private pilot.' }
    $vm = Invoke-SantaSetupAzJson @('vm', 'show', '--subscription', $b.SubscriptionId, '--resource-group', $b.ResourceGroup, '--name', $b.VmName)
    if ($vm.id -ine $b.VmId -or $vm.vmId -ine $b.VmInstanceId -or $vm.provisioningState -cne 'Succeeded' -or
        $vm.tags.'azd-solution' -cne 'azd-santa' -or $vm.tags.purpose -cne 'synthetic-vm-lab' -or
        $vm.tags.'azd-env-name' -cne $b.EnvironmentName) { throw 'Selected VM identity/tags/provisioning binding failed.' }
}

function Assert-SantaReceiptFields {
    param([Text.Json.JsonElement]$Element, [string[]]$Names)
    if ($Element.ValueKind -ne [Text.Json.JsonValueKind]::Object) { throw 'Receipt object required.' }
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($property in $Element.EnumerateObject()) {
        if ($property.Name -cnotin $Names -or -not $seen.Add($property.Name)) { throw 'Unexpected or duplicate receipt field.' }
    }
    if ($seen.Count -ne $Names.Count) { throw 'Incomplete installation receipt.' }
}

function New-SantaOperatorDeploymentBinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$InstallationReceiptPath,
        [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedReceiptSha256,
        [Parameter(Mandatory)][guid]$TenantId,
        [Parameter(Mandatory)][guid]$SubscriptionId,
        [Parameter(Mandatory)][ValidatePattern('^[a-z0-9-]{2,32}$')][string]$EnvironmentName,
        [Parameter(Mandatory)][string]$DeploymentId,
        [Parameter(Mandatory)][string]$OutputPath
    )
    # Called by a future selected installer/hook with its pinned local receipt.
    # Current host-only azd outputs are intentionally insufficient for setup.
    $document = $null; $phase = 'source'
    try {
        Assert-SantaPrivateDestination $OutputPath
        if ([IO.Path]::GetFullPath($OutputPath) -cne $OutputPath -or
            -not [IO.Path]::IsPathFullyQualified($InstallationReceiptPath)) { throw 'Canonical local paths required.' }
        $directory = [IO.Path]::GetDirectoryName($OutputPath)
        $name = [IO.Path]::GetFileName($InstallationReceiptPath)
        $comparer = if ($IsWindows) { [StringComparer]::OrdinalIgnoreCase } else { [StringComparer]::Ordinal }
        if ($name -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,120}\.json$' -or
            -not $comparer.Equals([IO.Path]::Combine($directory, $name), $InstallationReceiptPath) -or
            -not [IO.File]::Exists($InstallationReceiptPath) -or
            ([IO.File]::GetAttributes($InstallationReceiptPath) -band [IO.FileAttributes]::ReparsePoint)) { throw 'Selected local installation receipt unavailable.' }
        $stream = [IO.FileStream]::new($InstallationReceiptPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        try {
            if ($stream.Length -lt 1 -or $stream.Length -gt 16384) { throw 'Installation receipt size invalid.' }
            $bytes = [byte[]]::new([int]$stream.Length); $stream.ReadExactly($bytes)
        } finally { $stream.Dispose() }
        if ([Convert]::ToHexStringLower([Security.Cryptography.SHA256]::HashData($bytes)) -cne $ExpectedReceiptSha256) { throw 'Installation receipt changed.' }
        $document = [Text.Json.JsonDocument]::Parse([Text.UTF8Encoding]::new($false, $true).GetString($bytes))
        $receipt = $document.RootElement
        Assert-SantaReceiptFields $receipt @('schemaVersion', 'scope', 'state', 'deploymentId', 'outputs')
        if ($receipt.GetProperty('schemaVersion').GetInt32() -ne 1 -or
            $receipt.GetProperty('scope').GetString() -cne 'azd-santa-backend-installation' -or
            $receipt.GetProperty('state').GetString() -cne 'installed' -or
            $receipt.GetProperty('deploymentId').GetString() -cne $DeploymentId) { throw 'Selected installation is not ready.' }
        $fields = @('TenantId', 'SubscriptionId', 'EnvironmentName', 'ResourceGroup', 'VmName', 'VmId',
            'VmInstanceId', 'ImageId', 'ComposePath', 'ComposeSha256', 'Origin')
        $outputs = $receipt.GetProperty('outputs'); Assert-SantaReceiptFields $outputs $fields
        $binding = [ordered]@{}
        foreach ($field in $fields) { $binding[$field] = $outputs.GetProperty($field).GetString() }
        Assert-SantaSetupBinding $binding
        if ($binding.TenantId -cne $TenantId.ToString() -or $binding.SubscriptionId -cne $SubscriptionId.ToString() -or
            $binding.EnvironmentName -cne $EnvironmentName -or
            -not $binding.ComposePath.StartsWith('/var/lib/azd-santa-qualification/', [StringComparison]::Ordinal)) { throw 'Installation output selection mismatch.' }
        $group = [regex]::Escape($binding.ResourceGroup)
        $sub = [regex]::Escape($binding.SubscriptionId)
        if ($DeploymentId -cnotmatch "^/subscriptions/$sub/(?:resourceGroups/$group/)?providers/Microsoft\.Resources/deployments/[A-Za-z0-9_.()-]{1,64}$") { throw 'Selected deployment identity mismatch.' }
        $phase = 'preflight'
        Assert-SantaSetupAzureTarget ([pscustomobject]@{ Binding = $binding })
        $phase = 'write'
        # Reuse the exact exclusive/flushed JSON writer. These eleven fields
        # contain deployment facts only, never credentials or a setup link.
        Write-SantaSetupCheckpoint $OutputPath $binding
        $outputHash = (Get-FileHash -LiteralPath $OutputPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($outputHash -cne (Get-SantaTransportHash ($binding | ConvertTo-Json -Depth 8 -Compress))) { throw 'Written binding differs from selected installation facts.' }
        [pscustomobject]@{ Scope = 'local-operator-deployment-binding'; Path = $OutputPath
            Sha256 = $outputHash
            InstallationReceiptSha256 = $ExpectedReceiptSha256
            ControlPlane = 'selected-account-group-vm-verified'; RuntimeAcceptance = 'not-performed' }
    } catch {
        if ($phase -eq 'write') { throw 'Binding generation did not complete; output may be partial. Preserve it for inspection; no setup action was submitted.' }
        throw 'Deployment is not ready for operator setup: selected installation outputs or cached ARM preflight are missing or mismatched. No binding was written; no setup action was submitted.'
    } finally { if ($document) { $document.Dispose() } }
}

function Read-SantaRunCommandPayload {
    param([object]$Result, [string]$Context, [string]$Marker, [string]$DoneMarker, [int]$MaximumBytes)
    if ($Context -cnotmatch '^[a-f0-9]{64}$' -or -not $Result.value -or @($Result.value).Count -gt 4) { throw 'Incomplete terminal Run Command result.' }
    foreach ($entry in $Result.value) {
        if ($entry.code -cnotmatch '/succeeded$' -or $entry.level -eq 'Error') { throw 'Run Command did not report terminal success.' }
    }
    $message = @($Result.value | ForEach-Object { $_.message }) -join "`n"
    if ($message.Length -gt 16384) { throw 'Unexpected Run Command output bound.' }
    $lines = $message -split '\r?\n'
    $envelopes = @($lines | Where-Object { $_.StartsWith($Marker, [StringComparison]::Ordinal) })
    $done = @($lines | Where-Object { $_.StartsWith($DoneMarker, [StringComparison]::Ordinal) })
    if ($envelopes.Count -ne 1 -or $done.Count -ne 1 -or $done[0] -cne ($DoneMarker + $Context)) { throw 'Complete unique transport markers absent; inspect outcome without retry.' }
    $envelope = $envelopes[0].Substring($Marker.Length)
    if ([Text.Encoding]::UTF8.GetByteCount($envelope) -gt $MaximumBytes -or
        [Array]::IndexOf($lines, $done[0]) -le [Array]::IndexOf($lines, $envelopes[0])) { throw 'Truncated or out-of-order sealed result.' }
    $envelope
}

function ConvertFrom-SantaSetupRunCommandResult {
    param([object]$Result, [string]$Context, [string]$RecipientDigest, [string]$TargetDigest, [string]$Mode)
    $envelope = Read-SantaRunCommandPayload $Result $Context 'SANTA_SEALED_SETUP_JSON:' 'SANTA_SETUP_TRANSPORT_DONE:' 2600
    # Reject cleartext/fake marker payloads before returning even an opaque
    # object. Decryption/AAD/expiry/origin checks remain the recipient's gate.
    $document = $null
    try {
        $document = [Text.Json.JsonDocument]::Parse($envelope)
        $root = $document.RootElement
        if ($root.ValueKind -ne [Text.Json.JsonValueKind]::Object) { throw 'Envelope object required.' }
        $names = @('scope', 'version', 'algorithm', 'mode', 'kid_sha256', 'context_sha256', 'target_sha256', 'wrapped_key_base64', 'nonce_base64', 'ciphertext_base64')
        $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($property in $root.EnumerateObject()) {
            if ($property.Name -cnotin $names -or -not $seen.Add($property.Name)) { throw 'Unexpected/duplicate sealed field.' }
        }
        if ($seen.Count -ne 10 -or $root.GetProperty('scope').GetString() -cne 'azd-santa-sealed-setup' -or
            $root.GetProperty('version').GetInt32() -ne 1 -or $root.GetProperty('algorithm').GetString() -cne 'RSA-OAEP-256+A256GCM' -or
            $root.GetProperty('context_sha256').GetString() -cne $Context -or
            $root.GetProperty('kid_sha256').GetString() -cne $RecipientDigest -or
            $root.GetProperty('target_sha256').GetString() -cne $TargetDigest -or $root.GetProperty('mode').GetString() -cne $Mode) { throw 'Sealed envelope binding mismatch.' }
        foreach ($field in @('wrapped_key_base64', 'nonce_base64', 'ciphertext_base64')) {
            $value = $root.GetProperty($field).GetString()
            $bytes = [Convert]::FromBase64String($value)
            if ([Convert]::ToBase64String($bytes) -cne $value -or
                ($field -ceq 'wrapped_key_base64' -and $bytes.Length -ne 384) -or
                ($field -ceq 'nonce_base64' -and $bytes.Length -ne 12) -or
                ($field -ceq 'ciphertext_base64' -and ($bytes.Length -lt 17 -or $bytes.Length -gt 1600))) { throw 'Invalid sealed encoding.' }
        }
    } catch { throw 'Run Command did not return a bounded opaque sealed envelope.' }
    finally { if ($document) { $document.Dispose() } }
    $envelope
}

function New-SantaInstallationProgram {
    param([string]$DeploymentId)
    $attestor = [IO.File]::ReadAllBytes((Join-Path $PSScriptRoot 'operator_setup_host.py'))
    $producer = [IO.File]::ReadAllBytes((Join-Path $PSScriptRoot 'installation_readback.py'))
    if ($attestor.Length -gt 24576 -or $producer.Length -gt 8192) { throw 'Pinned installation source exceeded its bound.' }
    $attestorHash = [Convert]::ToHexStringLower([Security.Cryptography.SHA256]::HashData($attestor))
    $producerHash = [Convert]::ToHexStringLower([Security.Cryptography.SHA256]::HashData($producer))
    $memory = [IO.MemoryStream]::new()
    try {
        $zip = [IO.Compression.GZipStream]::new($memory, [IO.Compression.CompressionLevel]::Optimal, $true)
        try { $zip.Write($attestor) } finally { $zip.Dispose() }
        $compressed = [Convert]::ToBase64String($memory.ToArray())
    } finally { $memory.Dispose() }
    $deployment = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($DeploymentId))
    $program = "import base64,gzip,hashlib,types`n" + [Text.UTF8Encoding]::new($false, $true).GetString($producer) + @"

try:
    source=gzip.decompress(base64.b64decode('$compressed',validate=True))
    if len(source)>24576 or hashlib.sha256(source).hexdigest()!='$attestorHash': raise ValueError('Pinned host source changed')
    host=types.ModuleType('azd_santa_installer_attestor')
    exec(compile(source,'<pinned-installer-attestor>','exec'),host.__dict__)
    produce_installation(host,base64.b64decode('$deployment',validate=True).decode('utf-8'),'$attestorHash','$producerHash')
except BaseException:
    raise SystemExit('Deployment is not ready: initialization readback failed; no setup action was submitted.') from None
"@
    if ([Text.Encoding]::UTF8.GetByteCount($program) -gt 24576 -or $program -match '(?m)^AZD_SANTA_INSTALL_PY\r?$') { throw 'Composite installation program exceeded its bound.' }
    [pscustomobject]@{ Program = $program; Sha256 = Get-SantaTransportHash $program
        AttestorSha256 = $attestorHash; ProducerSha256 = $producerHash }
}

function Complete-SantaBackendInstallation {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$InstallationOutputs,
        [Parameter(Mandatory)][string]$DeploymentId,
        [Parameter(Mandatory)][string]$InstallationReceiptPath,
        [Parameter(Mandatory)][string]$OperatorBindingPath)
    $request = $null; $temporary = $null; $document = $null
    try {
        Assert-SantaSetupBinding $InstallationOutputs
        Assert-SantaPrivateDestination $InstallationReceiptPath
        Assert-SantaPrivateDestination $OperatorBindingPath
        if ([IO.Path]::GetFullPath($InstallationReceiptPath) -cne $InstallationReceiptPath -or
            [IO.Path]::GetFullPath($OperatorBindingPath) -cne $OperatorBindingPath -or
            [IO.Path]::GetDirectoryName($InstallationReceiptPath) -cne [IO.Path]::GetDirectoryName($OperatorBindingPath) -or
            $InstallationReceiptPath -eq $OperatorBindingPath -or
            [IO.Path]::GetFileName($InstallationReceiptPath) -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,120}\.json$') { throw 'Selected local environment paths required.' }
        $sub = [regex]::Escape($InstallationOutputs.SubscriptionId); $group = [regex]::Escape($InstallationOutputs.ResourceGroup)
        if ($DeploymentId -cnotmatch "^/subscriptions/$sub/(?:resourceGroups/$group/)?providers/Microsoft\.Resources/deployments/[A-Za-z0-9_.()-]{1,64}$") { throw 'Selected installation deployment mismatch.' }
        $source = New-SantaInstallationProgram $DeploymentId
        $binding = @{}; foreach ($key in $InstallationOutputs.Keys) { $binding[$key] = $InstallationOutputs[$key] }
        $binding.SourceCommit = (Get-Content (Join-Path $PSScriptRoot 'zentral-source.lock.json') -Raw | ConvertFrom-Json).commit
        foreach ($pair in @(@('RecoverySha256', 'operator_recovery.py'), @('SealedSha256', 'sealed_setup.py'))) {
            $text = [IO.File]::ReadAllText((Join-Path $PSScriptRoot $pair[1]), [Text.UTF8Encoding]::new($false, $true)).Replace("`r`n", "`n")
            $binding[$pair[0]] = Get-SantaTransportHash $text
        }
        $binding.RemoteProgramSha256 = $source.Sha256
        # A structural crypto probe only: these fixed identifiers are never
        # created as users and the producer never calls the setup mutation path.
        $request = New-SantaSetupTransportRequest $binding bootstrap 'azd-installation-probe' 'azd-installation-probe@example.invalid' 'Read-only installation readiness'
        if ($request.PayloadBase64.Length -gt 8192) { throw 'Installation request exceeded its bound.' }
        Assert-SantaSetupPreparedRequest $request
        Assert-SantaSetupAzureTarget $request
        $script = "set -eu`nexport AZD_SANTA_SETUP_REQUEST_B64='$($request.PayloadBase64)'`npython3 -I - <<'AZD_SANTA_INSTALL_PY'`n" +
            $source.Program + "`nAZD_SANTA_INSTALL_PY`nprintf '%s\n' 'SANTA_INSTALLATION_TRANSPORT_DONE:$($request.Context)'`n"
        if ([Text.Encoding]::UTF8.GetByteCount($script) -gt 45056) { throw 'Installation transport exceeded 44KiB.' }
        $temporary = Join-Path ([IO.Path]::GetTempPath()) ('santa-install-' + [guid]::NewGuid() + '.sh')
        $stream = [IO.FileStream]::new($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $stream.Write([Text.Encoding]::UTF8.GetBytes($script)) } finally { $stream.Dispose() }
        $b = $request.Binding
        $result = Invoke-SantaSetupAzJson @('vm', 'run-command', 'invoke', '--subscription', $b.SubscriptionId,
            '--resource-group', $b.ResourceGroup, '--name', $b.VmName, '--command-id', 'RunShellScript', '--scripts', "@$temporary")
        $payload = Read-SantaRunCommandPayload $result $request.Context 'SANTA_INSTALLATION_JSON:' 'SANTA_INSTALLATION_TRANSPORT_DONE:' 3200
        $document = [Text.Json.JsonDocument]::Parse($payload); $root = $document.RootElement
        Assert-SantaReceiptFields $root @('scope', 'context_sha256', 'attestor_sha256', 'producer_sha256', 'readiness', 'installation')
        if ($root.GetProperty('scope').GetString() -cne 'azd-santa-installation-readback' -or
            $root.GetProperty('context_sha256').GetString() -cne $request.Context -or
            $root.GetProperty('attestor_sha256').GetString() -cne $source.AttestorSha256 -or
            $root.GetProperty('producer_sha256').GetString() -cne $source.ProducerSha256) { throw 'Installation readback source/selection mismatch.' }
        $ready = $root.GetProperty('readiness'); $gates = @('database_authority', 'migrations', 'store', 'security_store', 'event_consumers', 'search')
        Assert-SantaReceiptFields $ready $gates
        foreach ($gate in $gates) { if (-not $ready.GetProperty($gate).GetBoolean()) { throw 'Runtime initialization is not complete.' } }
        $receipt = $root.GetProperty('installation')
        Assert-SantaReceiptFields $receipt @('schemaVersion', 'scope', 'state', 'deploymentId', 'outputs')
        if ($receipt.GetProperty('schemaVersion').GetInt32() -ne 1 -or $receipt.GetProperty('scope').GetString() -cne 'azd-santa-backend-installation' -or
            $receipt.GetProperty('state').GetString() -cne 'installed' -or $receipt.GetProperty('deploymentId').GetString() -cne $DeploymentId) { throw 'Selected installation receipt mismatch.' }
        $outputs = $receipt.GetProperty('outputs'); Assert-SantaReceiptFields $outputs @($InstallationOutputs.Keys)
        foreach ($key in $InstallationOutputs.Keys) { if ($outputs.GetProperty($key).GetString() -cne $InstallationOutputs[$key]) { throw 'Installed runtime differs from selected installer outputs.' } }
        # Machine-produced bytes, pinned immediately before passing to the local
        # consumer. No admin JSON construction or setup-mutation result is used.
        $receiptBytes = [Text.Encoding]::UTF8.GetBytes($receipt.GetRawText())
        $file = [IO.FileStream]::new($InstallationReceiptPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $file.Write($receiptBytes); $file.Flush($true) } finally { $file.Dispose() }
        $completed = New-SantaOperatorDeploymentBinding -InstallationReceiptPath $InstallationReceiptPath `
            -ExpectedReceiptSha256 ([Convert]::ToHexStringLower([Security.Cryptography.SHA256]::HashData($receiptBytes))) `
            -TenantId $InstallationOutputs.TenantId -SubscriptionId $InstallationOutputs.SubscriptionId `
            -EnvironmentName $InstallationOutputs.EnvironmentName -DeploymentId $DeploymentId -OutputPath $OperatorBindingPath
        $completed | Add-Member -NotePropertyMembers @{
            InitializationContextSha256 = $request.Context; AttestorSha256 = $source.AttestorSha256
            ProducerSha256 = $source.ProducerSha256; ProgramSha256 = $source.Sha256
            SourceCommit = $binding.SourceCommit; RecoverySha256 = $binding.RecoverySha256; SealedSha256 = $binding.SealedSha256
            InitializationReadback = 'migrations-store-security-consumers-search'
        } -PassThru
    } catch { throw 'Deployment is not ready for operator setup: initialization/source/selection readback or local finalization failed. Preserve any local artifacts; no setup action was submitted.' }
    finally {
        if ($request) { $request.Recipient.Key.Dispose() }
        if ($document) { $document.Dispose() }
        if ($temporary -and [IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) }
    }
}

function Write-SantaSetupCheckpoint {
    param([string]$Path, [object]$Value)
    $bytes = [Text.Encoding]::UTF8.GetBytes(($Value | ConvertTo-Json -Depth 8 -Compress))
    $stream = [IO.FileStream]::new($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($bytes); $stream.Flush($true) } finally { $stream.Dispose() }
}

function Assert-SantaSetupPreparedRequest {
    param([object]$Request)
    $raw = [Convert]::FromBase64String($Request.PayloadBase64)
    if ([Convert]::ToBase64String($raw) -cne $Request.PayloadBase64) { throw 'Noncanonical prepared request.' }
    $payload = [Text.UTF8Encoding]::new($false, $true).GetString($raw) | ConvertFrom-Json -AsHashtable -Depth 12
    # Bind the identity actually delivered to the remote command, rather than
    # trusting the digest fields copied from the original preparation.
    if ($payload.username -isnot [string] -or -not $payload.username -or $payload.username.Length -gt 150 -or
        $payload.username -cne $payload.username.Trim() -or $payload.email -isnot [string] -or -not $payload.email -or
        $payload.email.Length -gt 254 -or $payload.email -cne $payload.email.Trim() -or
        $payload.reason -isnot [string] -or -not $payload.reason.Trim() -or $payload.reason.Length -gt 256 -or
        $payload.reason -match '[\x00-\x1f]') { throw 'Prepared identity/reason failed validation.' }
    $actualTarget = Get-SantaSetupTargetDigest -Username $payload.username -Email $payload.email
    if ((Get-SantaTransportHash ($payload.context | ConvertTo-Json -Depth 6 -Compress)) -cne $Request.Context -or
        $payload.context_sha256 -cne $Request.Context -or $payload.context.nonce -cne $Request.RequestId -or
        $payload.context.mode -cne $Request.Mode -or $payload.context.target_sha256 -cne $Request.TargetDigest -or
        $actualTarget -cne $Request.TargetDigest -or $actualTarget -cne $payload.context.target_sha256 -or
        $payload.context.recipient_sha256 -cne $Request.Recipient.KeyId -or
        $payload.recipient_public_key -cne [Convert]::ToBase64String($Request.Recipient.Key.ExportSubjectPublicKeyInfo()) -or
        ($payload.context.binding | ConvertTo-Json -Compress) -cne ($Request.Binding | ConvertTo-Json -Compress)) {
        throw 'Prepared request binding changed; do not submit.'
    }
}

function Send-SantaSetupRunCommand {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Request,
        [Parameter(Mandatory)][string]$RemoteProgramPath,
        [Parameter(Mandatory)][string]$CheckpointDirectory,
        [Parameter(Mandatory)][ValidateSet('create', 'readback')][string]$Operation)
    # The reviewed stdlib Python host program performs actual runtime checks
    # before mutation and ciphertext-only readback; no customer-local upload.
    $rawProgram = [IO.File]::ReadAllBytes($RemoteProgramPath)
    $program = [Text.UTF8Encoding]::new($false, $true).GetString($rawProgram)
    if ($rawProgram.Length -gt 24576 -or [Convert]::ToHexStringLower([Security.Cryptography.SHA256]::HashData($rawProgram)) -cne $Request.Binding.RemoteProgramSha256 -or
        $program.Contains([char]0) -or $program.StartsWith([char]0xfeff) -or $program -match '(?m)^AZD_SANTA_SETUP_PY\r?$') { throw 'Reviewed UTF8 remote program hash/size mismatch.' }
    if (-not [IO.Path]::IsPathFullyQualified($CheckpointDirectory) -or -not [IO.Directory]::Exists($CheckpointDirectory)) { throw 'Existing absolute checkpoint directory required.' }
    if ($Request.Context -cnotmatch '^[a-f0-9]{64}$' -or $Request.RequestId -cnotmatch '^[a-f0-9]{64}$' -or
        $Request.PayloadBase64.Length -gt 16384 -or $Request.PayloadBase64 -cnotmatch '^[A-Za-z0-9+/]+={0,2}$') { throw 'Invalid prepared request.' }
    Assert-SantaSetupPreparedRequest $Request
    Assert-SantaSetupAzureTarget $Request
    $stem = Join-Path $CheckpointDirectory ($Request.RequestId + '-' + $Operation)
    $checkpoint = [ordered]@{ scope = 'setup-transport-checkpoint-only'; request_id = $Request.RequestId
        context_sha256 = $Request.Context; operation = $Operation; binding = $Request.Binding
        state = 'submission-may-have-started'; limitation = 'No source/runtime attestation or operator delivery proof' }
    # Durable exclusive reservation BEFORE mutation. Any invocation failure,
    # timeout or caller termination retains this and never permits silent replay.
    Write-SantaSetupCheckpoint ($stem + '.submitted.json') $checkpoint
    $temporary = Join-Path ([IO.Path]::GetTempPath()) ('santa-setup-' + [guid]::NewGuid() + '.sh')
    try {
        $script = "set -eu`nexport AZD_SANTA_SETUP_REQUEST_B64='$($Request.PayloadBase64)'`nexport AZD_SANTA_SETUP_OPERATION='$Operation'`n" +
            "python3 - <<'AZD_SANTA_SETUP_PY'`n" + $program + "`nAZD_SANTA_SETUP_PY`nprintf '%s\n' 'SANTA_SETUP_TRANSPORT_DONE:$($Request.Context)'`n"
        if ([Text.Encoding]::UTF8.GetByteCount($script) -gt 45056) { throw 'Bounded transport script exceeded 44KiB.' }
        $file = [IO.FileStream]::new($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $file.Write([Text.Encoding]::UTF8.GetBytes($script)) } finally { $file.Dispose() }
        $b = $Request.Binding
        $result = Invoke-SantaSetupAzJson @('vm', 'run-command', 'invoke', '--subscription', $b.SubscriptionId,
            '--resource-group', $b.ResourceGroup, '--name', $b.VmName, '--command-id', 'RunShellScript', '--scripts', "@$temporary")
        $envelope = ConvertFrom-SantaSetupRunCommandResult $result $Request.Context $Request.Recipient.KeyId $Request.TargetDigest $Request.Mode
        $checkpoint.state = 'terminal-ciphertext-returned'
        Write-SantaSetupCheckpoint ($stem + '.terminal.json') $checkpoint
        # Ciphertext only. Caller retains Recipient in memory and explicitly
        # decrypts/delivers via SealedSetup. No browser/auth action is automatic.
        $envelope
    } catch { throw 'Setup transport outcome requires inspection; no automatic retry or plaintext fallback. Preserve checkpoint and in-memory recipient.' }
    finally { if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) } }
}

Export-ModuleMember -Function New-SantaSetupTransportRequest, Send-SantaSetupRunCommand, New-SantaOperatorDeploymentBinding, Complete-SantaBackendInstallation
