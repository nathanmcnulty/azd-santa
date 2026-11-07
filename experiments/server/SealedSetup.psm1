#Requires -Version 7.6
# Original Unlicense local recipient/delivery primitives. No Azure/auth calls.
Set-StrictMode -Version Latest

function New-SantaSetupRecipient {
    [CmdletBinding()]
    param()
    $key = [Security.Cryptography.RSA]::Create(3072)
    $public = $key.ExportSubjectPublicKeyInfo()
    [pscustomobject]@{
        Key = $key
        PublicKeyBase64 = [Convert]::ToBase64String($public)
        KeyId = [Convert]::ToHexStringLower([Security.Cryptography.SHA256]::HashData($public))
    }
}

function Get-SantaSetupTargetDigest {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Username, [Parameter(Mandatory)][string]$Email)
    $buffer = [Collections.Generic.List[byte]]::new()
    foreach ($value in @($Username, $Email)) {
        $bytes = [Text.Encoding]::UTF8.GetBytes($value)
        if ($bytes.Length -gt 2048) { throw 'Setup identity exceeds its bound.' }
        $length = [BitConverter]::GetBytes([uint32]$bytes.Length)
        if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($length) }
        $buffer.AddRange($length)
        $buffer.AddRange($bytes)
    }
    [Convert]::ToHexStringLower([Security.Cryptography.SHA256]::HashData($buffer.ToArray()))
}

function Assert-SantaJsonFields {
    param([Text.Json.JsonElement]$Element, [string[]]$Names)
    if ($Element.ValueKind -ne [Text.Json.JsonValueKind]::Object) { throw 'Invalid envelope.' }
    $allowed = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($name in $Names) { $null = $allowed.Add($name) }
    $found = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($property in $Element.EnumerateObject()) {
        if (-not $allowed.Contains($property.Name) -or -not $found.Add($property.Name)) { throw 'Invalid envelope fields.' }
    }
    if ($found.Count -ne $allowed.Count) { throw 'Incomplete envelope fields.' }
}

function ConvertFrom-SantaBase64 {
    param([string]$Value)
    $bytes = [Convert]::FromBase64String($Value)
    if ([Convert]::ToBase64String($bytes) -cne $Value) { throw 'Noncanonical envelope encoding.' }
    # Prevent PowerShell from unrolling byte arrays, including a one-byte value.
    return ,$bytes
}

function Write-SantaPrivateBytes {
    param([string]$Path, [byte[]]$Bytes)
    if (-not [IO.Path]::IsPathFullyQualified($Path)) { throw 'An absolute private output path is required.' }
    $stream = $null
    try {
        if ($IsWindows) {
            $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
            $acl = [Security.AccessControl.FileSecurity]::new()
            $acl.SetOwner($sid)
            $acl.SetAccessRuleProtection($true, $false)
            $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, [Security.AccessControl.FileSystemRights]::FullControl, [Security.AccessControl.AccessControlType]::Allow))
            $stream = [IO.FileSystemAclExtensions]::Create([IO.FileInfo]::new($Path), [IO.FileMode]::CreateNew,
                [Security.AccessControl.FileSystemRights]::Write, [IO.FileShare]::None, 4096, [IO.FileOptions]::None, $acl)
        } else {
            $options = [IO.FileStreamOptions]::new()
            $options.Mode = [IO.FileMode]::CreateNew
            $options.Access = [IO.FileAccess]::Write
            $options.Share = [IO.FileShare]::None
            $options.UnixCreateMode = [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite
            $stream = [IO.FileStream]::new($Path, $options)
        }
        $stream.Write($Bytes, 0, $Bytes.Length)
        $stream.Flush($true)
    } finally {
        if ($stream) { $stream.Dispose() }
    }
}

function Receive-SantaSetupEnvelope {
    [CmdletBinding(DefaultParameterSetName = 'File')]
    param(
        [Parameter(Mandatory)][psobject]$Recipient,
        [Parameter(Mandatory)][string]$EnvelopeJson,
        [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedContext,
        [Parameter(Mandatory)][ValidateSet('bootstrap', 'recover')][string]$ExpectedMode,
        [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedTargetDigest,
        [Parameter(Mandatory)][uri]$ExpectedOrigin,
        [Parameter(Mandatory, ParameterSetName = 'File')][string]$PrivateOutputPath,
        [Parameter(Mandatory, ParameterSetName = 'Browser')][switch]$OpenBrowser
    )
    $keyBytes = $null; $clear = $null; $aes = $null; $document = $null; $payloadDocument = $null
    try {
        if ($EnvelopeJson.Length -gt 2600 -or [Text.Encoding]::UTF8.GetByteCount($EnvelopeJson) -gt 2600) { throw 'Envelope too large.' }
        if ($ExpectedOrigin.Scheme -cne 'https' -or $ExpectedOrigin.UserInfo -or $ExpectedOrigin.Query -or
            $ExpectedOrigin.Fragment -or $ExpectedOrigin.AbsolutePath -ne '/') { throw 'Expected HTTPS origin required.' }
        if ($PSCmdlet.ParameterSetName -eq 'Browser' -and -not $OpenBrowser) { throw 'Explicit delivery is required.' }
        $document = [Text.Json.JsonDocument]::Parse($EnvelopeJson)
        $envelope = $document.RootElement
        Assert-SantaJsonFields $envelope @('scope', 'version', 'algorithm', 'mode', 'kid_sha256', 'context_sha256', 'target_sha256', 'wrapped_key_base64', 'nonce_base64', 'ciphertext_base64')
        $kid = [Convert]::ToHexStringLower([Security.Cryptography.SHA256]::HashData($Recipient.Key.ExportSubjectPublicKeyInfo()))
        if ($envelope.GetProperty('scope').GetString() -cne 'azd-santa-sealed-setup' -or
            $envelope.GetProperty('version').GetInt32() -ne 1 -or
            $envelope.GetProperty('algorithm').GetString() -cne 'RSA-OAEP-256+A256GCM' -or
            $envelope.GetProperty('kid_sha256').GetString() -cne $kid -or
            $envelope.GetProperty('mode').GetString() -cne $ExpectedMode -or
            $envelope.GetProperty('context_sha256').GetString() -cne $ExpectedContext -or
            $envelope.GetProperty('target_sha256').GetString() -cne $ExpectedTargetDigest) { throw 'Envelope binding mismatch.' }
        $wrapped = ConvertFrom-SantaBase64 $envelope.GetProperty('wrapped_key_base64').GetString()
        $nonce = ConvertFrom-SantaBase64 $envelope.GetProperty('nonce_base64').GetString()
        $cipher = ConvertFrom-SantaBase64 $envelope.GetProperty('ciphertext_base64').GetString()
        if ($wrapped.Length -ne 384 -or $nonce.Length -ne 12 -or $cipher.Length -lt 17 -or $cipher.Length -gt 1600) { throw 'Invalid envelope size.' }
        $keyBytes = $Recipient.Key.Decrypt($wrapped, [Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
        if ($keyBytes.Length -ne 32) { throw 'Invalid envelope key.' }
        $associated = [Text.Encoding]::ASCII.GetBytes("azd-santa-operator-setup/v1|RSA-OAEP-256+A256GCM|$ExpectedMode|$kid|$ExpectedContext|$ExpectedTargetDigest")
        $content = [byte[]]::new($cipher.Length - 16)
        [Array]::Copy($cipher, 0, $content, 0, $content.Length)
        $tag = [byte[]]::new(16)
        [Array]::Copy($cipher, $content.Length, $tag, 0, 16)
        $clear = [byte[]]::new($content.Length)
        $aes = [Security.Cryptography.AesGcm]::new($keyBytes, 16)
        $aes.Decrypt($nonce, $content, $tag, $clear, $associated)
        $payloadDocument = [Text.Json.JsonDocument]::Parse([Text.UTF8Encoding]::new($false, $true).GetString($clear))
        $payload = $payloadDocument.RootElement
        Assert-SantaJsonFields $payload @('setup_url', 'expires_at_unix', 'target_pk')
        $expires = $payload.GetProperty('expires_at_unix').GetDouble()
        $pk = $payload.GetProperty('target_pk').GetInt64()
        $now = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() / 1000.0
        if (-not [double]::IsFinite($expires) -or $expires -le $now -or $expires -gt $now + 660 -or $pk -le 0) { throw 'Expired or invalid setup payload.' }
        $url = [uri]$payload.GetProperty('setup_url').GetString()
        if ($url.Scheme -cne 'https' -or $url.UserInfo -or $url.Query -or $url.Fragment -or
            $url.GetLeftPart([UriPartial]::Authority) -ine $ExpectedOrigin.GetLeftPart([UriPartial]::Authority) -or
            $url.AbsolutePath -cnotmatch '^/accounts/reset/(?<uid>[A-Za-z0-9_-]{1,32})/[0-9a-z]{1,16}-[0-9a-f]{32}/$') { throw 'Setup origin/path mismatch.' }
        $uid = $Matches.uid.Replace('-', '+').Replace('_', '/')
        $uid = $uid.PadRight($uid.Length + ((4 - $uid.Length % 4) % 4), '=')
        if ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($uid)) -cne $pk.ToString([Globalization.CultureInfo]::InvariantCulture)) { throw 'Setup target mismatch.' }
        if ($PSCmdlet.ParameterSetName -eq 'Browser') {
            # The local user requested normal browser navigation, not an auth
            # automation or proof that a browser opened or login completed.
            Start-Process -FilePath $url.AbsoluteUri -ErrorAction Stop | Out-Null
            $delivery = 'browser-open-requested'
        } else {
            Write-SantaPrivateBytes -Path $PrivateOutputPath -Bytes $clear
            $delivery = 'private-file-written'
        }
        [pscustomobject]@{ Scope = 'local-sealed-setup-delivery'; Delivery = $delivery }
    } catch {
        throw 'Sealed setup delivery failed; no plaintext fallback. Inspect the selected operation state before creating another recovery.'
    } finally {
        if ($aes) { $aes.Dispose() }
        if ($keyBytes) { [Array]::Clear($keyBytes, 0, $keyBytes.Length) }
        if ($clear) { [Array]::Clear($clear, 0, $clear.Length) }
        if ($document) { $document.Dispose() }
        if ($payloadDocument) { $payloadDocument.Dispose() }
        $Recipient.Key.Dispose()
    }
}

Export-ModuleMember -Function New-SantaSetupRecipient, Get-SantaSetupTargetDigest, Receive-SantaSetupEnvelope
