#Requires -Version 7.6
BeforeDiscovery {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'experiments/vm/PrivateVmInstall.psm1') -Force
}

Describe 'Private VM administrator setup from a selected azd environment' {
    InModuleScope PrivateVmInstall {
        BeforeAll {
            $savedServer = $script:server
            $script:server = Join-Path $TestDrive 'operator-setup-fixture'
            $null = [IO.Directory]::CreateDirectory($script:server)
            @'
param($DeploymentBindingPath, $Mode, $Username, $Email, $Reason, $CheckpointDirectory,
      [switch]$OpenBrowser, [switch]$ReadbackOnUnknown)
if (-not $OpenBrowser -or -not $ReadbackOnUnknown -or -not (Test-Path -LiteralPath "$CheckpointDirectory.intent")) {
    throw 'Expected sealed browser delivery, same-request readback and a prior reservation.'
}
if ($Reason -eq 'simulated unknown') { throw 'Synthetic unknown outcome.' }
[pscustomobject]@{ Binding = $DeploymentBindingPath; Mode = $Mode; Username = $Username
    Email = $Email; Reason = $Reason; Directory = $CheckpointDirectory }
'@ | Set-Content (Join-Path $script:server 'Invoke-SantaOperatorSetup.ps1')
        }
        AfterAll { $script:server = $savedServer }
        BeforeEach {
            $script:directory = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
            $null = [IO.Directory]::CreateDirectory($script:directory)
            $script:bindingPath = Join-Path $script:directory ('operator-binding-' + ('a' * 32) + '.json')
            $subscription = '11111111-1111-4111-8111-111111111111'
            $group = 'rg-azd-santa-vm-synthetic'
            $vm = "/subscriptions/$subscription/resourceGroups/$group/providers/Microsoft.Compute/virtualMachines/vm-santa-lab"
            $script:instance = '33333333-3333-4333-8333-333333333333'
            $script:binding = @{
                TenantId = '22222222-2222-4222-8222-222222222222'; SubscriptionId = $subscription
                EnvironmentName = 'synthetic'; ResourceGroup = $group; VmName = 'vm-santa-lab'; VmId = $vm
                VmInstanceId = $script:instance; ImageId = 'sha256:' + ('b' * 64)
                ComposePath = '/private/setup/compose.json'; ComposeSha256 = 'c' * 64; Origin = 'https://localhost:8000'
            }
            $script:binding | ConvertTo-Json | Set-Content -LiteralPath $script:bindingPath
            $script:values = @{
                AZURE_ENV_NAME = 'synthetic'; SANTA_PRIVATE_BACKEND_INSTALL = 'true'; AZURE_SUBSCRIPTION_ID = $subscription
                AZURE_RESOURCE_GROUP = $group; SANTA_VM_NAME = 'vm-santa-lab'; SANTA_VM_RESOURCE_ID = $vm
                SANTA_VM_INSTANCE_ID = $script:instance; SANTA_OPERATOR_BINDING_PATH = $script:bindingPath
            }
            $script:arguments = @{ EnvironmentName = 'synthetic'; Mode = 'bootstrap'
                Username = 'admin'; Email = 'admin@example.invalid'; Reason = 'Initial setup' }
            Mock Get-PrivateEnvironmentDirectory { $script:directory }
            Mock Invoke-PrivateAzd { $script:values }
            Mock Invoke-PrivateAzure { throw 'Unexpected external operation.' }
            Mock Assert-PrivateOperatorHttps {}
        }

        It 'uses the selected binding and reserves bootstrap once per immutable VM' {
            $result = Invoke-PrivateVmOperatorSetup @arguments
            $result.Binding | Should -BeExactly $bindingPath
            $result.Mode | Should -BeExactly 'bootstrap'
            $result.Username | Should -BeExactly 'admin'
            $result.Email | Should -BeExactly 'admin@example.invalid'
            $result.Directory | Should -BeExactly (Join-Path $directory "operator-$instance-bootstrap")
            Should -Invoke Assert-PrivateOperatorHttps -Times 1 -Exactly -ParameterFilter { $Origin.AbsoluteUri -ceq 'https://localhost:8000/' }
            Should -Invoke Invoke-PrivateAzd -Times 1 -Exactly -ParameterFilter {
                ($Arguments -join ' ') -ceq 'env get-values --environment synthetic --output json' -and $Json
            }
            # Install finalization may publish a new filename for the same VM.
            $other = Join-Path $directory ('operator-binding-' + ('d' * 32) + '.json')
            Copy-Item -LiteralPath $bindingPath -Destination $other
            $values.SANTA_OPERATOR_BINDING_PATH = $other
            { Invoke-PrivateVmOperatorSetup @arguments } | Should -Throw '*already reserved*'
        }

        It 'retains an unknown recovery attempt and only accepts a separately named deliberate recovery' {
            $arguments.Mode = 'recover'
            { Invoke-PrivateVmOperatorSetup @arguments } | Should -Throw '*recovery attempt label*'
            $arguments.RecoveryAttempt = 'first'
            $arguments.Reason = 'simulated unknown'
            { Invoke-PrivateVmOperatorSetup @arguments } | Should -Throw '*Synthetic unknown outcome*'
            { Invoke-PrivateVmOperatorSetup @arguments } | Should -Throw '*already reserved*'
            $arguments.RecoveryAttempt = 'reviewedsecond'
            $arguments.Reason = 'Verified loss of second factor'
            $result = Invoke-PrivateVmOperatorSetup @arguments
            $result.Mode | Should -BeExactly 'recover'
            $result.Directory | Should -BeExactly (Join-Path $directory "operator-$instance-recover-reviewedsecond")
        }

        It 'checks selection without reserving a setup operation in WhatIf' {
            Invoke-PrivateVmOperatorSetup @arguments -WhatIf | Should -BeNullOrEmpty
            @(Get-ChildItem -LiteralPath $directory).Count | Should -Be 1
            Should -Invoke Invoke-PrivateAzure -Times 0
            Should -Invoke Assert-PrivateOperatorHttps -Times 0
        }

        It 'leaves the same attempt available if the login page is unreachable' {
            Mock Assert-PrivateOperatorHttps { throw 'Synthetic login unavailable.' }
            { Invoke-PrivateVmOperatorSetup @arguments } | Should -Throw '*Synthetic login unavailable*'
            @(Get-ChildItem -LiteralPath $directory).Count | Should -Be 1
            Mock Assert-PrivateOperatorHttps {}
            (Invoke-PrivateVmOperatorSetup @arguments).Mode | Should -BeExactly 'bootstrap'
        }

        It 'rejects a foreign binding path, disabled backend, or stale instance before reserving an attempt' {
            $values.SANTA_OPERATOR_BINDING_PATH = Join-Path $TestDrive ([IO.Path]::GetFileName($bindingPath))
            { Invoke-PrivateVmOperatorSetup @arguments } | Should -Throw '*machine-produced operator binding*'
            $values.SANTA_OPERATOR_BINDING_PATH = $bindingPath
            $values.SANTA_PRIVATE_BACKEND_INSTALL = 'false'
            { Invoke-PrivateVmOperatorSetup @arguments } | Should -Throw '*private backend installed*'
            $values.SANTA_PRIVATE_BACKEND_INSTALL = 'true'
            $values.SANTA_VM_INSTANCE_ID = '44444444-4444-4444-8444-444444444444'
            { Invoke-PrivateVmOperatorSetup @arguments } | Should -Throw '*provisioned VM outputs missing/mismatched*'
            @(Get-ChildItem -LiteralPath $directory).Count | Should -Be 1
        }
    }
}
