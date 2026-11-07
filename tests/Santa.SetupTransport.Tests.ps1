#Requires -Version 7.6
BeforeDiscovery {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'experiments/server/SetupTransport.psm1') -Force
}
Describe 'Offline setup transport boundaries' {
    InModuleScope SetupTransport {
        BeforeAll {
            function New-TestRequest {
                $sub = '11111111-1111-4111-8111-111111111111'
                New-SantaSetupTransportRequest -Binding @{
                    TenantId = '22222222-2222-4222-8222-222222222222'; SubscriptionId = $sub
                    EnvironmentName = 'synthetic'; ResourceGroup = 'rg-azd-santa-vm-synthetic'; VmName = 'vm-santa-lab'
                    VmId = "/subscriptions/$sub/resourceGroups/rg-azd-santa-vm-synthetic/providers/Microsoft.Compute/virtualMachines/vm-santa-lab"
                    ImageId = 'sha256:' + ('a' * 64); ComposePath = '/var/lib/synthetic/compose.json'
                    ComposeSha256 = 'b' * 64; SourceCommit = 'c' * 40; RecoverySha256 = 'd' * 64
                    Origin = 'https://santa.example.invalid'; RemoteProgramSha256 = Get-SantaTransportHash "exit 0`n"
                } -Mode recover -Username 'synthetic-é' -Email 'synthetic@example.invalid' -Reason 'Synthetic transport qualification'
            }
            function New-TestResult($Context, $Envelope = '', $Kid = ('a' * 64), $Target = ('b' * 64)) {
                if (-not $Envelope) {
                    $Envelope = @{ scope = 'azd-santa-sealed-setup'; version = 1; algorithm = 'RSA-OAEP-256+A256GCM'
                        mode = 'recover'; context_sha256 = $Context; kid_sha256 = $Kid; target_sha256 = $Target
                        wrapped_key_base64 = [Convert]::ToBase64String([byte[]]::new(384))
                        nonce_base64 = [Convert]::ToBase64String([byte[]]::new(12))
                        ciphertext_base64 = [Convert]::ToBase64String([byte[]]::new(17)) } | ConvertTo-Json -Compress
                }
                @{ value = @(@{ code = 'ProvisioningState/succeeded'; level = 'Info'
                    message = "[stdout]`nSANTA_SEALED_SETUP_JSON:$Envelope`nSANTA_SETUP_TRANSPORT_DONE:$Context`n[stderr]`n" }) }
            }
            function Read-TestResult($Result, $Context) {
                ConvertFrom-SantaSetupRunCommandResult $Result $Context ('a' * 64) ('b' * 64) recover
            }
        }
        BeforeEach { Mock Invoke-SantaSetupAzJson { throw 'Unexpected external invocation.' } }
        It 'creates fresh nonce/context and exports only a public key in UTF8 structured arguments' {
            $one = New-TestRequest; $two = New-TestRequest
            try {
                $one.Context | Should -Not -Be $two.Context
                $one.RequestId | Should -Not -Be $two.RequestId
                $payload = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($one.PayloadBase64)) | ConvertFrom-Json
                $payload.username | Should -BeExactly 'synthetic-é'
                $payload.context_sha256 | Should -Be $one.Context
                $payload.context.recipient_sha256 | Should -Be $one.Recipient.KeyId
                ($payload | ConvertTo-Json -Depth 9) | Should -Not -Match 'PRIVATE KEY|setup_url|password'
                Should -Invoke Invoke-SantaSetupAzJson -Times 0
            } finally { $one.Recipient.Key.Dispose(); $two.Recipient.Key.Dispose() }
        }
        It 'rejects wrong tenant or group tags before VM submission' {
            $request = New-TestRequest
            try {
                Mock Invoke-SantaSetupAzJson { @{ id = 'wrong'; tenantId = 'wrong'; state = 'Enabled' } }
                { Assert-SantaSetupAzureTarget $request } | Should -Throw
                Should -Invoke Invoke-SantaSetupAzJson -Times 1 -Exactly
            } finally { $request.Recipient.Key.Dispose() }
        }
        It 'checks group and VM tags and exact identifiers under the selected subscription' {
            $request = New-TestRequest
            try {
                Mock Invoke-SantaSetupAzJson { param($Arguments)
                    $Arguments | Should -Contain '--subscription'
                    if ($Arguments[0] -eq 'account') { return @{ id = $request.Binding.SubscriptionId; tenantId = $request.Binding.TenantId; state = 'Enabled' } }
                    $tags = @{ 'azd-solution' = 'azd-santa'; purpose = 'synthetic-vm-lab'; 'azd-env-name' = 'synthetic' }
                    if ($Arguments[0] -eq 'group') { return @{ id = "/subscriptions/$($request.Binding.SubscriptionId)/resourceGroups/rg-azd-santa-vm-synthetic"; tags = $tags } }
                    return @{ id = $request.Binding.VmId; provisioningState = 'Succeeded'; tags = $tags }
                }
                { Assert-SantaSetupAzureTarget $request } | Should -Not -Throw
                Should -Invoke Invoke-SantaSetupAzJson -Times 3 -Exactly
                Mock Invoke-SantaSetupAzJson -ParameterFilter { $Arguments[0] -eq 'vm' } {
                    @{ id = $request.Binding.VmId; provisioningState = 'Succeeded'; tags = @{ purpose = 'unrelated' } }
                }
                { Assert-SantaSetupAzureTarget $request } | Should -Throw
            } finally { $request.Recipient.Key.Dispose() }
        }
        It 'rejects changed prepared context or runtime selection before any Azure operation' {
            $request = New-TestRequest
            try {
                Assert-SantaSetupPreparedRequest $request
                $request.Binding.ComposeSha256 = 'f' * 64
                { Assert-SantaSetupPreparedRequest $request } | Should -Throw
                Should -Invoke Invoke-SantaSetupAzJson -Times 0
            } finally { $request.Recipient.Key.Dispose() }
        }
        It 'rejects independently mutated encoded username, email and invalid reason before Azure calls' {
            foreach ($field in @('username', 'email', 'reason')) {
                $request = New-TestRequest
                try {
                    $payload = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($request.PayloadBase64)) | ConvertFrom-Json -AsHashtable
                    $payload[$field] = switch ($field) { username { 'different-user' } email { 'different@example.invalid' } reason { "invalid`nreason" } }
                    $request.PayloadBase64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($payload | ConvertTo-Json -Depth 8 -Compress)))
                    $path = Join-Path $TestDrive ($field + '.sh'); [IO.File]::WriteAllText($path, "exit 0`n")
                    { Send-SantaSetupRunCommand $request $path $TestDrive create } | Should -Throw
                    Should -Invoke Invoke-SantaSetupAzJson -Times 0
                    Test-Path (Join-Path $TestDrive ($request.RequestId + '-create.submitted.json')) | Should -BeFalse
                } finally { $request.Recipient.Key.Dispose() }
            }
        }
        It 'requires complete unique ciphertext and terminal markers after successful result codes' {
            $context = 'e' * 64
            (Read-TestResult (New-TestResult $context) $context | ConvertFrom-Json).scope | Should -Be 'azd-santa-sealed-setup'
            foreach ($kind in @('duplicate', 'missing', 'wrong', 'failed', 'order', 'plaintext', 'duplicatefield', 'wrongkey')) {
                $result = New-TestResult $context
                if ($kind -eq 'duplicate') { $result.value[0].message += "`nSANTA_SEALED_SETUP_JSON:{}" }
                if ($kind -eq 'missing') { $result.value[0].message = 'SANTA_SEALED_SETUP_JSON:{}' }
                if ($kind -eq 'wrong') { $result = New-TestResult ('f' * 64) }
                if ($kind -eq 'failed') { $result.value[0].code = 'ProvisioningState/failed' }
                if ($kind -eq 'order') { $result.value[0].message = "SANTA_SETUP_TRANSPORT_DONE:$context`nSANTA_SEALED_SETUP_JSON:{}" }
                if ($kind -eq 'plaintext') { $result = New-TestResult $context '{"setup_url":"https://synthetic.invalid/accounts/reset/secret"}' }
                if ($kind -eq 'duplicatefield') { $result.value[0].message = $result.value[0].message.Replace('"version":1', '"version":1,"version":1') }
                if ($kind -eq 'wrongkey') { $result = New-TestResult $context '' ('f' * 64) }
                { Read-TestResult $result $context } | Should -Throw
            }
        }
        It 'does not submit when the reviewed remote program hash differs' {
            $request = New-TestRequest
            try {
                $path = Join-Path $TestDrive 'unreviewed.sh'; Set-Content $path 'changed'
                { Send-SantaSetupRunCommand $request $path $TestDrive create } | Should -Throw
                Should -Invoke Invoke-SantaSetupAzJson -Times 0
            } finally { $request.Recipient.Key.Dispose() }
        }
        It 'retains unknown-outcome checkpoint and refuses a second create without invoking Azure again' {
            $request = New-TestRequest
            try {
                $path = Join-Path $TestDrive 'program.sh'; [IO.File]::WriteAllText($path, "exit 0`n")
                Mock Assert-SantaSetupAzureTarget {}
                Mock Invoke-SantaSetupAzJson { throw 'Synthetic timeout.' }
                { Send-SantaSetupRunCommand $request $path $TestDrive create } | Should -Throw
                $checkpoint = Join-Path $TestDrive ($request.RequestId + '-create.submitted.json')
                Test-Path $checkpoint | Should -BeTrue
                (Get-Content $checkpoint -Raw) | Should -Not -Match 'Recipient|PayloadBase64|username|setup_url|password'
                { Send-SantaSetupRunCommand $request $path $TestDrive create } | Should -Throw
                Should -Invoke Invoke-SantaSetupAzJson -Times 1 -Exactly
            } finally { $request.Recipient.Key.Dispose() }
        }
        It 'returns ciphertext only and keeps readback as an explicit separate invocation' {
            $request = New-TestRequest
            try {
                $path = Join-Path $TestDrive 'success.sh'; [IO.File]::WriteAllText($path, "exit 0`n")
                Mock Assert-SantaSetupAzureTarget {}
                Mock Invoke-SantaSetupAzJson { param($Arguments)
                    $Arguments[0..2] -join ' ' | Should -Be 'vm run-command invoke'
                    $script = [IO.File]::ReadAllText(($Arguments[-1]).Substring(1))
                    $script | Should -Match 'AZD_SANTA_SETUP_REQUEST_B64=' # base64 only interpolation
                    $script | Should -Not -Match 'synthetic-é|PRIVATE KEY'
                    New-TestResult $request.Context '' $request.Recipient.KeyId $request.TargetDigest
                }
                (Send-SantaSetupRunCommand $request $path $TestDrive readback | ConvertFrom-Json).scope | Should -Be 'azd-santa-sealed-setup'
                Test-Path (Join-Path $TestDrive ($request.RequestId + '-readback.terminal.json')) | Should -BeTrue
                Should -Invoke Invoke-SantaSetupAzJson -Times 1 -Exactly
            } finally { $request.Recipient.Key.Dispose() }
        }
    }
}
