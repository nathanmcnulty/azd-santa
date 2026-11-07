#Requires -Version 7.6
BeforeDiscovery {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'experiments/server/SetupTransport.psm1') -Force
}
Describe 'Machine-produced installation readiness and binding' {
    InModuleScope SetupTransport {
        BeforeAll {
            $script:producerSourceDirectory = Split-Path (Get-Module SetupTransport).Path -Parent
            $script:producerRepository = Split-Path (Split-Path $script:producerSourceDirectory -Parent) -Parent
            function New-InstallerOutputs {
                $sub = '11111111-1111-4111-8111-111111111111'
                @{
                    TenantId = '22222222-2222-4222-8222-222222222222'; SubscriptionId = $sub
                    EnvironmentName = 'synthetic'; ResourceGroup = 'rg-azd-santa-vm-synthetic'; VmName = 'vm-santa-lab'
                    VmId = "/subscriptions/$sub/resourceGroups/rg-azd-santa-vm-synthetic/providers/Microsoft.Compute/virtualMachines/vm-santa-lab"
                    VmInstanceId = '33333333-3333-4333-8333-333333333333'; ImageId = 'sha256:' + ('a' * 64)
                    ComposePath = '/var/lib/azd-santa-qualification/synthetic/compose.json'; ComposeSha256 = 'b' * 64
                    Origin = 'https://santa.example.invalid'
                }
            }
            function Set-ReadyAzureMock {
                Mock Invoke-SantaSetupAzJson { param($Arguments)
                    $Arguments | Should -Contain '--subscription'
                    $facts = $script:installerFacts
                    if ($Arguments[0] -eq 'account') { return @{ id = $facts.SubscriptionId; tenantId = $facts.TenantId; state = 'Enabled' } }
                    $tags = @{ 'azd-solution' = 'azd-santa'; purpose = 'synthetic-vm-lab'; 'azd-env-name' = 'synthetic' }
                    if ($Arguments[0] -eq 'group') { return @{ id = "/subscriptions/$($facts.SubscriptionId)/resourceGroups/rg-azd-santa-vm-synthetic"; tags = $tags } }
                    if ($Arguments[1] -eq 'show') { return @{ id = $facts.VmId; vmId = $facts.VmInstanceId; provisioningState = 'Succeeded'; tags = $tags } }
                    ($Arguments[0..2] -join ' ') | Should -Be 'vm run-command invoke'
                    $text = [IO.File]::ReadAllText($Arguments[-1].Substring(1))
                    $text | Should -Match 'python3 -I -'
                    $text | Should -Not -Match 'operator_access'
                    [Text.Encoding]::UTF8.GetByteCount($text) | Should -BeLessOrEqual 45056
                    $text -match "(?m)^export AZD_SANTA_SETUP_REQUEST_B64='(?<payload>[A-Za-z0-9+/=]+)'$" | Should -BeTrue
                    $requestData = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Matches.payload)) | ConvertFrom-Json -AsHashtable
                    $ready = @{ migrations = $true; store = $true; security_store = $true; event_consumers = $true; search = $true }
                    $result = @{
                        scope = 'azd-santa-installation-readback'; context_sha256 = $requestData.context_sha256
                        attestor_sha256 = (Get-FileHash (Join-Path $script:producerSourceDirectory 'operator_setup_host.py')).Hash.ToLowerInvariant()
                        producer_sha256 = (Get-FileHash (Join-Path $script:producerSourceDirectory 'installation_readback.py')).Hash.ToLowerInvariant()
                        readiness = $ready
                        installation = @{ schemaVersion = 1; scope = 'azd-santa-backend-installation'; state = 'installed'
                            deploymentId = $script:deployment; outputs = $facts.Clone() }
                    }
                    switch ($script:tamper) {
                        context { $result.context_sha256 = 'f' * 64 }
                        source { $result.attestor_sha256 = 'f' * 64 }
                        runtime { $result.installation.outputs.ImageId = 'sha256:' + ('f' * 64) }
                        uninitialized { $ready.event_consumers = $false }
                    }
                    $payload = $result | ConvertTo-Json -Depth 8 -Compress
                    @{ value = @(@{ code = 'ProvisioningState/succeeded'; level = 'Info'
                        message = "SANTA_INSTALLATION_JSON:$payload`nSANTA_INSTALLATION_TRANSPORT_DONE:$($requestData.context_sha256)" }) }
                }
            }
        }
        BeforeEach {
            $script:installerFacts = New-InstallerOutputs
            $script:deployment = "/subscriptions/$($script:installerFacts.SubscriptionId)/providers/Microsoft.Resources/deployments/azd-synthetic"
            $script:tamper = ''
            $arguments = @{ InstallationOutputs = $script:installerFacts; DeploymentId = $script:deployment
                InstallationReceiptPath = (Join-Path $TestDrive ('installation-' + [guid]::NewGuid() + '.json'))
                OperatorBindingPath = (Join-Path $TestDrive ('binding-' + [guid]::NewGuid() + '.json')) }
            Mock Invoke-SantaSetupAzJson { throw 'Unexpected Azure invocation.' }
        }
        It 'passes offline producer readiness and no-mutation guards' {
            $output = & python -m unittest discover -s (Join-Path $script:producerRepository 'tests') -p test_installation_readback.py 2>&1
            $LASTEXITCODE | Should -Be 0 -Because ($output -join "`n")
        }
        It 'builds a source-pinned bounded inline program that compiles without executing it' {
            $source = New-SantaInstallationProgram $script:deployment
            $source.Program | Should -Match 'hashlib.sha256\(source\).hexdigest\(\)'
            $source.Program | Should -Match "types.ModuleType\('azd_santa_installer_attestor'\)"
            [Text.Encoding]::UTF8.GetByteCount($source.Program) | Should -BeLessOrEqual 24576
            $path = Join-Path $TestDrive 'composite.py'
            [IO.File]::WriteAllText($path, $source.Program, [Text.UTF8Encoding]::new($false))
            & python -m py_compile $path
            $LASTEXITCODE | Should -Be 0
            Should -Invoke Invoke-SantaSetupAzJson -Times 0
        }
        It 'produces a pinned receipt and exact binding from selected machine readback without admin JSON' {
            Set-ReadyAzureMock
            $result = Complete-SantaBackendInstallation @arguments
            $result.RuntimeAcceptance | Should -Be 'not-performed'
            $result.InstallationReceiptSha256 | Should -Be (Get-FileHash $arguments.InstallationReceiptPath).Hash.ToLowerInvariant()
            $receipt = Get-Content $arguments.InstallationReceiptPath -Raw | ConvertFrom-Json -AsHashtable
            $receipt.scope | Should -Be 'azd-santa-backend-installation'
            $binding = Get-Content $arguments.OperatorBindingPath -Raw | ConvertFrom-Json -AsHashtable
            $binding.Count | Should -Be 11
            foreach ($key in $script:installerFacts.Keys) { $binding[$key] | Should -BeExactly $script:installerFacts[$key] }
            (Get-Content $arguments.InstallationReceiptPath -Raw) | Should -Not -Match 'recipient|username|password|setup_url|private_key'
            Should -Invoke Invoke-SantaSetupAzJson -Times 7 -Exactly # preflight + read-only command + fresh binding preflight
        }
        It 'fails closed before persistence when source context runtime or readiness do not match' {
            Set-ReadyAzureMock
            foreach ($case in @('context', 'source', 'runtime', 'uninitialized')) {
                $script:tamper = $case
                { Complete-SantaBackendInstallation @arguments } | Should -Throw '*Deployment is not ready*'
                Test-Path $arguments.InstallationReceiptPath | Should -BeFalse
                Test-Path $arguments.OperatorBindingPath | Should -BeFalse
            }
            Should -Invoke Invoke-SantaSetupAzJson -Times 16 -Exactly
        }
        It 'does not observe a VM when deployment runtime facts are missing or output collides' {
            $arguments.InstallationOutputs = @{ ResourceGroup = 'rg-azd-santa-vm-synthetic'; VmName = 'vm-santa-lab' }
            { Complete-SantaBackendInstallation @arguments } | Should -Throw '*Deployment is not ready*'
            $arguments.InstallationOutputs = $script:installerFacts
            [IO.File]::WriteAllText($arguments.InstallationReceiptPath, 'preserve')
            { Complete-SantaBackendInstallation @arguments } | Should -Throw '*Deployment is not ready*'
            [IO.File]::ReadAllText($arguments.InstallationReceiptPath) | Should -Be 'preserve'
            Should -Invoke Invoke-SantaSetupAzJson -Times 0
        }
    }
}
