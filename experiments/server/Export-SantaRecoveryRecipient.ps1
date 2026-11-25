#Requires -Version 7.6
<#
.SYNOPSIS
Exports a Windows pilot recipient key as an encrypted PKCS#8 recovery key.
.DESCRIPTION
Run under the Windows account that protected the original key. Obtain the
expected public fingerprint from the original capture receipt independently.
Keep the passphrase and encrypted key in separate recovery storage.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$ProtectedKeyPath,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ProtectionPurpose,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$RecipientSha256,
    [Parameter(Mandatory)][string]$OutputPath,
    [Security.SecureString]$Passphrase
)

$ErrorActionPreference = 'Stop'
if (-not $IsWindows) { throw 'This export requires the original Windows user profile.' }
if (-not [IO.Path]::IsPathFullyQualified($ProtectedKeyPath) -or -not [IO.Path]::IsPathFullyQualified($OutputPath)) {
    throw 'Use absolute filesystem paths for the protected input and encrypted output.'
}
$destination = [IO.Path]::GetFullPath($OutputPath)
$parent = [IO.Path]::GetDirectoryName($destination)
if (-not [IO.Directory]::Exists($parent) -or [IO.File]::Exists($destination)) {
    throw 'Choose a new output file in an existing recovery directory.'
}
if (-not $PSCmdlet.ShouldProcess($destination, 'Export encrypted Santa recovery key')) { return }

function Copy-Password([Security.SecureString]$Password) {
    if ($Password.Length -lt 16 -or $Password.Length -gt 512) {
        throw 'Use a passphrase of 16 to 512 UTF-8 bytes.'
    }
    $marshal = [Runtime.InteropServices.Marshal]
    $pointer = $marshal::SecureStringToGlobalAllocUnicode($Password)
    try {
        $chars = [char[]]::new($Password.Length)
        $marshal::Copy($pointer, $chars, 0, $chars.Length)
        return ,$chars
    } finally {
        $marshal::ZeroFreeGlobalAllocUnicode($pointer)
    }
}

$sha = [Security.Cryptography.SHA256]
$key = [Security.Cryptography.RSA]::Create()
$check = [Security.Cryptography.RSA]::Create()
$pendingPath = Join-Path $parent ('.santa-recipient-' + [guid]::NewGuid().ToString('N'))
$pendingCreated = $false
$privateKey = $password = $confirmation = $prompted = $repeat = $null
try {
    $source = [IO.File]::Open($ProtectedKeyPath, 'Open', 'Read', 'Read')
    try {
        if ($source.Length -lt 1 -or $source.Length -gt 8192) { throw 'Invalid protected key length.' }
        $wrapped = [byte[]]::new([int]$source.Length)
        $source.ReadExactly($wrapped)
    } finally { $source.Dispose() }
    $entropy = [Text.Encoding]::UTF8.GetBytes($ProtectionPurpose)
    $privateKey = [Security.Cryptography.ProtectedData]::Unprotect($wrapped, $entropy, 'CurrentUser')
    $read = 0
    $key.ImportPkcs8PrivateKey($privateKey, [ref]$read)
    $fingerprint = [Convert]::ToHexString($sha::HashData($key.ExportSubjectPublicKeyInfo())).ToLowerInvariant()
    $rsaPublic = $key.ExportParameters($false)
    if ($read -ne $privateKey.Length -or $key.KeySize -ne 3072 -or
        -not [Linq.Enumerable]::SequenceEqual[byte]($rsaPublic.Exponent, [byte[]](1, 0, 1)) -or
        $fingerprint -cne $RecipientSha256.ToLowerInvariant()) {
        throw 'The protected key does not match the capture recipient.'
    }
    [Array]::Clear($privateKey)

    if ($null -eq $Passphrase) {
        $prompted = Read-Host 'Recovery key passphrase' -AsSecureString
        $repeat = Read-Host 'Confirm recovery key passphrase' -AsSecureString
        $password = Copy-Password $prompted
        $confirmation = Copy-Password $repeat
        if (-not [Linq.Enumerable]::SequenceEqual[char]($password, $confirmation)) {
            throw 'The recovery key passphrases differ.'
        }
    } else {
        $password = Copy-Password $Passphrase
    }
    if ([Text.Encoding]::UTF8.GetByteCount($password) -gt 512 -or
        $password -contains [char]0 -or $password -contains [char]10 -or $password -contains [char]13) {
        throw 'Use a passphrase of 16 to 512 UTF-8 bytes without line breaks or NUL.'
    }

    $parameters = [Security.Cryptography.PbeParameters]::new(
        'Aes256Cbc', [Security.Cryptography.HashAlgorithmName]::SHA256, 600000)
    $encrypted = $key.ExportEncryptedPkcs8PrivateKey($password, $parameters)
    $read = 0
    $check.ImportEncryptedPkcs8PrivateKey($password, $encrypted, [ref]$read)
    $checkedFingerprint = [Convert]::ToHexString($sha::HashData($check.ExportSubjectPublicKeyInfo())).ToLowerInvariant()
    if ($read -ne $encrypted.Length -or $checkedFingerprint -cne $fingerprint) {
        throw 'Encrypted recovery key did not pass readback.'
    }
    $output = [IO.File]::Open($pendingPath, 'CreateNew', 'Write', 'None')
    $pendingCreated = $true
    try {
        $output.Write($encrypted)
        $output.Flush($true)
    } finally { $output.Dispose() }
    [IO.File]::Move($pendingPath, $destination)
    $pendingCreated = $false
    [pscustomobject]@{
        scope = 'azd-santa-portable-recipient-key-v1'
        recipient_sha256 = $fingerprint
        encrypted_key_sha256 = [Convert]::ToHexString($sha::HashData($encrypted)).ToLowerInvariant()
    }
} finally {
    if ($null -ne $privateKey) { [Array]::Clear($privateKey) }
    if ($null -ne $password) { [Array]::Clear($password) }
    if ($null -ne $confirmation) { [Array]::Clear($confirmation) }
    if ($null -ne $prompted) { $prompted.Dispose() }
    if ($null -ne $repeat) { $repeat.Dispose() }
    $key.Dispose()
    $check.Dispose()
    if ($pendingCreated) { [IO.File]::Delete($pendingPath) }
}
