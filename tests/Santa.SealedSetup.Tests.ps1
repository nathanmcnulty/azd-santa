#Requires -Version 7.6
Describe 'Private setup transport local crypto boundaries' {
    BeforeAll {
        $root = Split-Path $PSScriptRoot -Parent
        Import-Module (Join-Path $root 'experiments/server/SealedSetup.psm1') -Force
        $cryptoPython = if ($env:SANTA_CRYPTO_PYTHON) { $env:SANTA_CRYPTO_PYTHON } else { 'python' }
        $vector = Join-Path $root 'tests/test_sealed_setup.py'
        function New-TestEnvelope($Recipient, $Context = ('c' * 64), $Expires = ([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() + 600)) {
            $data = @{
                public_key_base64 = $Recipient.PublicKeyBase64
                context_sha256 = $Context
                origin = 'https://santa.example.invalid'
                artifact = @{
                    mode = 'recover'
                    target = @{ pk = 7; username = 'synthetic-é'; email = 'synthetic@example.invalid' }
                    setup_url = ('https://santa.example.invalid/accounts/reset/Nw/abcdef-' + ('a' * 32) + '/')
                    expires_at_unix = $Expires
                }
            } | ConvertTo-Json -Depth 5 -Compress
            $result = $data | & $cryptoPython $vector --seal-json
            if ($LASTEXITCODE) { throw 'Local Python crypto vector failed.' }
            return ($result -join "`n")
        }
        $targetDigest = Get-SantaSetupTargetDigest -Username 'synthetic-é' -Email 'synthetic@example.invalid'
    }
    It 'passes actual Python cryptographic vectors without a service or tenant' {
        $output = & $cryptoPython $vector 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($output -join "`n")
    }
    It 'decrypts real Python crypto in .NET and writes an exclusive owner-private artifact' {
        $recipient = New-SantaSetupRecipient
        $envelope = New-TestEnvelope $recipient
        $path = Join-Path $TestDrive 'setup.json'
        $receipt = Receive-SantaSetupEnvelope -Recipient $recipient -EnvelopeJson $envelope -ExpectedContext ('c' * 64) -ExpectedMode recover -ExpectedTargetDigest $targetDigest -ExpectedOrigin 'https://santa.example.invalid' -PrivateOutputPath $path
        $receipt.Delivery | Should -Be 'private-file-written'
        ($receipt | ConvertTo-Json) | Should -Not -Match 'setup_url|accounts/reset'
        $data = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        $data.target_pk | Should -Be 7
        if ($IsWindows) {
            $acl = Get-Acl -LiteralPath $path
            $acl.AreAccessRulesProtected | Should -BeTrue
            @($acl.Access | Where-Object { $_.IsInherited }).Count | Should -Be 0
        } else {
            [int][IO.File]::GetUnixFileMode($path) | Should -Be 384 # 0600
        }
        { $recipient.Key.ExportSubjectPublicKeyInfo() } | Should -Throw
    }
    It 'rejects tampering or wrong request binding without creating plaintext output' {
        foreach ($change in @('context', 'ciphertext')) {
            $recipient = New-SantaSetupRecipient
            $envelope = New-TestEnvelope $recipient
            if ($change -eq 'ciphertext') {
                $json = $envelope | ConvertFrom-Json
                $bytes = [Convert]::FromBase64String($json.ciphertext_base64)
                $bytes[-1] = $bytes[-1] -bxor 1
                $json.ciphertext_base64 = [Convert]::ToBase64String($bytes)
                $envelope = $json | ConvertTo-Json -Compress
            }
            $expected = if ($change -eq 'context') { 'd' * 64 } else { 'c' * 64 }
            $path = Join-Path $TestDrive ($change + '.json')
            { Receive-SantaSetupEnvelope -Recipient $recipient -EnvelopeJson $envelope -ExpectedContext $expected -ExpectedMode recover -ExpectedTargetDigest $targetDigest -ExpectedOrigin 'https://santa.example.invalid' -PrivateOutputPath $path } | Should -Throw
            Test-Path -LiteralPath $path | Should -BeFalse
        }
    }
    It 'does not replace existing local output or print a plaintext fallback' {
        $recipient = New-SantaSetupRecipient
        $envelope = New-TestEnvelope $recipient
        $path = Join-Path $TestDrive 'existing.json'
        Set-Content -LiteralPath $path -Value 'preserve'
        { Receive-SantaSetupEnvelope -Recipient $recipient -EnvelopeJson $envelope -ExpectedContext ('c' * 64) -ExpectedMode recover -ExpectedTargetDigest $targetDigest -ExpectedOrigin 'https://santa.example.invalid' -PrivateOutputPath $path } | Should -Throw
        (Get-Content -LiteralPath $path -Raw).Trim() | Should -Be 'preserve'
    }
    It 'rejects expired links and unexpected origins without requesting a browser' {
        foreach ($case in @('expired', 'origin')) {
            $recipient = New-SantaSetupRecipient
            $expires = if ($case -eq 'expired') { [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - 1 } else { [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() + 600 }
            $envelope = New-TestEnvelope $recipient ('c' * 64) $expires
            $origin = if ($case -eq 'origin') { 'https://outside.example.invalid' } else { 'https://santa.example.invalid' }
            $path = Join-Path $TestDrive ($case + '.json')
            { Receive-SantaSetupEnvelope -Recipient $recipient -EnvelopeJson $envelope -ExpectedContext ('c' * 64) -ExpectedMode recover -ExpectedTargetDigest $targetDigest -ExpectedOrigin $origin -PrivateOutputPath $path } | Should -Throw
            Test-Path -LiteralPath $path | Should -BeFalse
        }
    }
}
