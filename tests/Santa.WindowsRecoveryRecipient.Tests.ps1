#Requires -Version 7.6
Describe 'Windows Santa recovery recipient export' -Skip:(-not $IsWindows) {
    BeforeAll {
        $export = Join-Path $PSScriptRoot '../experiments/server/Export-SantaRecoveryRecipient.ps1'
        $key = [Security.Cryptography.RSA]::Create(3072)
        $purpose = 'Santa Windows recovery key test'
        $phrase = 'synthetic recovery fixture passphrase é'
        $passphrase = ConvertTo-SecureString $phrase -AsPlainText -Force
        $protectedPath = Join-Path $TestDrive 'recipient.dpapi'
        $privateKey = $key.ExportPkcs8PrivateKey()
        try {
            $protected = [Security.Cryptography.ProtectedData]::Protect(
                $privateKey, [Text.Encoding]::UTF8.GetBytes($purpose), 'CurrentUser')
            [IO.File]::WriteAllBytes($protectedPath, $protected)
            $fingerprint = [Convert]::ToHexString(
                [Security.Cryptography.SHA256]::HashData($key.ExportSubjectPublicKeyInfo())).ToLowerInvariant()
        } finally {
            [Array]::Clear($privateKey)
            $key.Dispose()
        }
        $parameters = @{
            ProtectedKeyPath = $protectedPath
            ProtectionPurpose = $purpose
            RecipientSha256 = $fingerprint
            Passphrase = $passphrase
        }
    }

    AfterAll {
        if ($null -ne $passphrase) { $passphrase.Dispose() }
    }

    It 'authenticates sealed backup bytes with the Windows export in the existing Python crypto path' {
        $destination = Join-Path $TestDrive 'recovery.pkcs8'
        $receipt = & $export @parameters -OutputPath $destination
        $receipt.scope | Should -Be 'azd-santa-portable-recipient-key-v1'
        $receipt.recipient_sha256 | Should -BeExactly $fingerprint
        (Get-FileHash -LiteralPath $destination).Hash.ToLowerInvariant() | Should -BeExactly $receipt.encrypted_key_sha256
        $code = @'
import sys
from pathlib import Path
from cryptography.hazmat.primitives import serialization
sys.path.insert(0, sys.argv[1])
import test_restore_cipher as fixture
case = fixture.Authentication()
encrypted = Path(sys.argv[2]).read_bytes()
try:
    serialization.load_der_private_key(encrypted, password=None)
except TypeError:
    pass
else:
    raise AssertionError('Expected an encrypted private key')
case.key = serialization.load_der_private_key(encrypted, password=sys.argv[3].encode())
case.public = case.key.public_key().public_bytes(
    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
result = case.verify(case.sealed())
assert result['recipient_sha256'] == sys.argv[4]
assert result['plaintext_released'] is False
'@
        $result = & python -c $code $PSScriptRoot $destination $phrase $fingerprint 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($result -join "`n")
        $original = (Get-FileHash -LiteralPath $destination).Hash
        { & $export @parameters -OutputPath $destination } | Should -Throw '*new output file*'
        (Get-FileHash -LiteralPath $destination).Hash | Should -BeExactly $original
    }

    It 'leaves protected keys and output paths untouched in WhatIf and on a fingerprint mismatch' {
        $destination = Join-Path $TestDrive 'rejected.pkcs8'
        $original = (Get-FileHash -LiteralPath $protectedPath).Hash
        & $export @parameters -OutputPath $destination -WhatIf
        $bad = $parameters.Clone()
        $bad.RecipientSha256 = '0' * 64
        { & $export @bad -OutputPath $destination } | Should -Throw '*does not match*'
        Test-Path -LiteralPath $destination | Should -BeFalse
        (Get-FileHash -LiteralPath $protectedPath).Hash | Should -BeExactly $original
        @(Get-ChildItem -LiteralPath $TestDrive -Force -Filter '.santa-recipient-*').Count | Should -Be 0
    }
}
