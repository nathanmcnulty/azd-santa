#Requires -Version 7.6
BeforeDiscovery {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'experiments/server/SetupTransport.psm1') -Force
}
Describe 'Installation output to local operator binding' {
    InModuleScope SetupTransport {
        BeforeAll {
            function New-InstallationFixture {
                $sub = '11111111-1111-4111-8111-111111111111'
                $binding = [ordered]@{
                    TenantId = '22222222-2222-4222-8222-222222222222'; SubscriptionId = $sub
                    EnvironmentName = 'synthetic'; ResourceGroup = 'rg-azd-santa-vm-synthetic'; VmName = 'vm-santa-lab'
                    VmId = "/subscriptions/$sub/resourceGroups/rg-azd-santa-vm-synthetic/providers/Microsoft.Compute/virtualMachines/vm-santa-lab"
                    VmInstanceId = '33333333-3333-4333-8333-333333333333'; ImageId = 'sha256:' + ('a' * 64)
                    ComposePath = '/var/lib/azd-santa-qualification/synthetic/compose.json'; ComposeSha256 = 'b' * 64
                    Origin = 'https://santa.example.invalid'
                }
                $id = "/subscriptions/$sub/providers/Microsoft.Resources/deployments/azd-synthetic"
                $receipt = [ordered]@{ schemaVersion = 1; scope = 'azd-santa-backend-installation'; state = 'installed'
                    deploymentId = $id; outputs = $binding }
                $source = Join-Path $TestDrive ('installation-' + [guid]::NewGuid() + '.json')
                [IO.File]::WriteAllText($source, ($receipt | ConvertTo-Json -Depth 8 -Compress), [Text.UTF8Encoding]::new($false))
                @{ InstallationReceiptPath = $source; ExpectedReceiptSha256 = (Get-FileHash $source).Hash.ToLowerInvariant()
                    TenantId = $binding.TenantId; SubscriptionId = $sub; EnvironmentName = 'synthetic'; DeploymentId = $id
                    OutputPath = (Join-Path $TestDrive ('binding-' + [guid]::NewGuid() + '.json')) }
            }
            function Read-Fixture($Arguments) {
                Get-Content -LiteralPath $Arguments.InstallationReceiptPath -Raw | ConvertFrom-Json -AsHashtable
            }
            function Update-Fixture($Arguments, $Receipt) {
                [IO.File]::WriteAllText($Arguments.InstallationReceiptPath, ($Receipt | ConvertTo-Json -Depth 8 -Compress), [Text.UTF8Encoding]::new($false))
                $Arguments.ExpectedReceiptSha256 = (Get-FileHash $Arguments.InstallationReceiptPath).Hash.ToLowerInvariant()
            }
        }
        BeforeEach {
            Mock Invoke-SantaSetupAzJson { throw 'Unexpected Azure call.' }
        }
        It 'uses three selected read-only checks and writes only exact deployment facts' {
            $arguments = New-InstallationFixture; $receipt = Read-Fixture $arguments
            $script:expectedInstallation = $receipt
            Mock Invoke-SantaSetupAzJson { param($Arguments)
                $Arguments | Should -Contain '--subscription'
                if ($Arguments[0] -eq 'account') { return @{ id = $script:expectedInstallation.outputs.SubscriptionId; tenantId = $script:expectedInstallation.outputs.TenantId; state = 'Enabled' } }
                $tags = @{ 'azd-solution' = 'azd-santa'; purpose = 'synthetic-vm-lab'; 'azd-env-name' = 'synthetic' }
                if ($Arguments[0] -eq 'group') { return @{ id = "/subscriptions/$($script:expectedInstallation.outputs.SubscriptionId)/resourceGroups/rg-azd-santa-vm-synthetic"; tags = $tags } }
                @{ id = $script:expectedInstallation.outputs.VmId; vmId = $script:expectedInstallation.outputs.VmInstanceId; provisioningState = 'Succeeded'; tags = $tags }
            }
            $result = New-SantaOperatorDeploymentBinding @arguments
            $result.RuntimeAcceptance | Should -Be 'not-performed'
            $result.InstallationReceiptSha256 | Should -Be $arguments.ExpectedReceiptSha256
            $result.Sha256 | Should -Be (Get-FileHash $arguments.OutputPath).Hash.ToLowerInvariant()
            $binding = Get-Content $arguments.OutputPath -Raw | ConvertFrom-Json -AsHashtable
            $binding.Count | Should -Be 11
            foreach ($key in $receipt.outputs.Keys) { $binding[$key] | Should -BeExactly $receipt.outputs[$key] }
            (Get-Content $arguments.OutputPath -Raw) | Should -Not -Match 'password|recipient|setup_url|secret|token'
            Should -Invoke Invoke-SantaSetupAzJson -Times 3 -Exactly
        }
        It 'reports missing source and changed bytes as deployment not ready before Azure or output' {
            foreach ($case in @('absent', 'tampered')) {
                $arguments = New-InstallationFixture
                if ($case -eq 'absent') { Remove-Item -LiteralPath $arguments.InstallationReceiptPath }
                else { Add-Content -LiteralPath $arguments.InstallationReceiptPath -Value 'changed' }
                { New-SantaOperatorDeploymentBinding @arguments } | Should -Throw '*Deployment is not ready*'
                Test-Path $arguments.OutputPath | Should -BeFalse
            }
            Should -Invoke Invoke-SantaSetupAzJson -Times 0
        }
        It 'rejects incomplete installer outputs, pending state, secrets and credential URLs' {
            foreach ($case in @('missing', 'pending', 'secret', 'url', 'duplicate', 'mutationreceipt')) {
                $arguments = New-InstallationFixture; $receipt = Read-Fixture $arguments
                switch ($case) {
                    missing { $receipt.outputs.Remove('ImageId') }
                    pending { $receipt.state = 'provisioned' }
                    mutationreceipt { $receipt.scope = 'azd-santa-operator-setup' }
                    secret { $receipt.outputs.access_token = 'synthetic-do-not-persist' }
                    url { $receipt.outputs.Origin = 'https://santa.example.invalid/accounts/reset/credential?token=synthetic' }
                }
                Update-Fixture $arguments $receipt
                if ($case -eq 'duplicate') {
                    $raw = [IO.File]::ReadAllText($arguments.InstallationReceiptPath).Replace('"schemaVersion":1', '"schemaVersion":1,"schemaVersion":1')
                    [IO.File]::WriteAllText($arguments.InstallationReceiptPath, $raw)
                    $arguments.ExpectedReceiptSha256 = (Get-FileHash $arguments.InstallationReceiptPath).Hash.ToLowerInvariant()
                }
                { New-SantaOperatorDeploymentBinding @arguments } | Should -Throw '*Deployment is not ready*'
                Test-Path $arguments.OutputPath | Should -BeFalse
            }
            Should -Invoke Invoke-SantaSetupAzJson -Times 0
        }
        It 'rejects a different explicitly selected tenant, subscription, environment or deployment' {
            foreach ($field in @('TenantId', 'SubscriptionId', 'EnvironmentName', 'DeploymentId')) {
                $arguments = New-InstallationFixture
                $arguments[$field] = switch ($field) {
                    TenantId { '44444444-4444-4444-8444-444444444444' }
                    SubscriptionId { '55555555-5555-4555-8555-555555555555' }
                    EnvironmentName { 'different' }
                    DeploymentId { $arguments.DeploymentId + '-different' }
                }
                { New-SantaOperatorDeploymentBinding @arguments } | Should -Throw '*Deployment is not ready*'
                Test-Path $arguments.OutputPath | Should -BeFalse
            }
            Should -Invoke Invoke-SantaSetupAzJson -Times 0
        }
        It 'preserves a collision before reading Azure or writing replacement metadata' {
            $arguments = New-InstallationFixture
            [IO.File]::WriteAllText($arguments.OutputPath, 'preserve')
            { New-SantaOperatorDeploymentBinding @arguments } | Should -Throw '*Deployment is not ready*'
            [IO.File]::ReadAllText($arguments.OutputPath) | Should -Be 'preserve'
            Should -Invoke Invoke-SantaSetupAzJson -Times 0
        }
        It 'rejects receipt substitution outside the selected local environment without lookup or Azure calls' {
            foreach ($source in @('\\server\share\installation.json', 'C:\private\installation.json:stream', (Join-Path ([IO.Path]::GetTempPath()) 'other-environment.json'))) {
                $arguments = New-InstallationFixture; $arguments.InstallationReceiptPath = $source
                { New-SantaOperatorDeploymentBinding @arguments } | Should -Throw '*Deployment is not ready*'
                Test-Path $arguments.OutputPath | Should -BeFalse
            }
            Should -Invoke Invoke-SantaSetupAzJson -Times 0
        }
        It 'does not produce a binding when selected immutable VM identity mismatches' {
            $arguments = New-InstallationFixture; $receipt = Read-Fixture $arguments
            $script:expectedInstallation = $receipt
            Mock Invoke-SantaSetupAzJson { param($Arguments)
                if ($Arguments[0] -eq 'account') { return @{ id = $script:expectedInstallation.outputs.SubscriptionId; tenantId = $script:expectedInstallation.outputs.TenantId; state = 'Enabled' } }
                $tags = @{ 'azd-solution' = 'azd-santa'; purpose = 'synthetic-vm-lab'; 'azd-env-name' = 'synthetic' }
                if ($Arguments[0] -eq 'group') { return @{ id = "/subscriptions/$($script:expectedInstallation.outputs.SubscriptionId)/resourceGroups/rg-azd-santa-vm-synthetic"; tags = $tags } }
                @{ id = $script:expectedInstallation.outputs.VmId; vmId = '44444444-4444-4444-8444-444444444444'; provisioningState = 'Succeeded'; tags = $tags }
            }
            { New-SantaOperatorDeploymentBinding @arguments } | Should -Throw '*Deployment is not ready*'
            Test-Path $arguments.OutputPath | Should -BeFalse
            Should -Invoke Invoke-SantaSetupAzJson -Times 3 -Exactly
        }
        It 'reports partial local output truthfully and never submits a setup mutation' {
            $arguments = New-InstallationFixture
            Mock Assert-SantaSetupAzureTarget {}
            Mock Write-SantaSetupCheckpoint { param($Path, $Value)
                [IO.File]::WriteAllText($Path, 'partial'); throw 'Synthetic local write failure.'
            }
            { New-SantaOperatorDeploymentBinding @arguments } | Should -Throw '*output may be partial*'
            [IO.File]::ReadAllText($arguments.OutputPath) | Should -Be 'partial'
            { New-SantaOperatorDeploymentBinding @arguments } | Should -Throw '*Deployment is not ready*'
            Should -Invoke Invoke-SantaSetupAzJson -Times 0
        }
        It 'refuses a ready receipt when written binding bytes were substituted' {
            $arguments = New-InstallationFixture
            Mock Assert-SantaSetupAzureTarget {}
            Mock Write-SantaSetupCheckpoint { param($Path, $Value) [IO.File]::WriteAllText($Path, '{"wrong":"synthetic"}') }
            { New-SantaOperatorDeploymentBinding @arguments } | Should -Throw '*output may be partial*'
            [IO.File]::ReadAllText($arguments.OutputPath) | Should -Be '{"wrong":"synthetic"}'
            Should -Invoke Invoke-SantaSetupAzJson -Times 0
        }
    }
}
