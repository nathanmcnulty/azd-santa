#Requires -Version 7.6
Describe 'Offline operator setup host and entrypoint' {
    BeforeAll {
        $root = Split-Path $PSScriptRoot -Parent
        $entrypoint = Join-Path $root 'experiments/server/Invoke-SantaOperatorSetup.ps1'
        Import-Module (Join-Path $root 'experiments/server/SetupTransport.psm1') -Force
        Import-Module (Join-Path $root 'experiments/server/SealedSetup.psm1') -Force
        function New-DeploymentFixture($Path) {
            $sub = '11111111-1111-4111-8111-111111111111'
            @{
                TenantId = '22222222-2222-4222-8222-222222222222'; SubscriptionId = $sub
                EnvironmentName = 'synthetic'; ResourceGroup = 'rg-azd-santa-vm-synthetic'; VmName = 'vm-santa-lab'
                VmId = "/subscriptions/$sub/resourceGroups/rg-azd-santa-vm-synthetic/providers/Microsoft.Compute/virtualMachines/vm-santa-lab"
                VmInstanceId = '33333333-3333-4333-8333-333333333333'; ImageId = 'sha256:' + ('a' * 64)
                ComposePath = '/var/lib/azd-santa-qualification/synthetic/compose.json'; ComposeSha256 = 'b' * 64
                Origin = 'https://santa.example.invalid'
            } | ConvertTo-Json | Set-Content -LiteralPath $Path
        }
    }
    It 'passes the stdlib host security/state tests without Azure or Docker calls' {
        $result = & python -m unittest discover -s (Join-Path $root 'tests') -p test_operator_setup_host.py 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($result -join "`n")
    }
    Context 'One-command orchestration with transport and delivery mocked' {
        BeforeEach {
            Mock Import-Module {}
            Mock Send-SantaSetupRunCommand { throw 'Synthetic unknown outcome.' }
            Mock Receive-SantaSetupEnvelope { [pscustomobject]@{ Delivery = 'synthetic-private-file-receipt' } }
            $path = Join-Path $TestDrive 'binding.json'; New-DeploymentFixture $path
            $arguments = @{ DeploymentBindingPath = $path; Mode = 'recover'; Username = 'synthetic'; Email = 'synthetic@example.invalid'
                Reason = 'Synthetic qualification'; CheckpointDirectory = $TestDrive; PrivateOutputPath = (Join-Path $TestDrive ([guid]::NewGuid().ToString() + '.json')) }
        }
        It 'stops after unknown create and disposes recipient without implicit readback or delivery' {
            Mock Send-SantaSetupRunCommand { $script:observedKey = $Request.Recipient.Key; throw 'Synthetic unknown outcome.' }
            { & $entrypoint @arguments } | Should -Throw '*outcome requires inspection*'
            { $script:observedKey.ExportSubjectPublicKeyInfo() } | Should -Throw
            Should -Invoke Send-SantaSetupRunCommand -Times 1 -ParameterFilter { $Operation -eq 'create' }
            Should -Invoke Send-SantaSetupRunCommand -Times 0 -ParameterFilter { $Operation -eq 'readback' }
            Should -Invoke Receive-SantaSetupEnvelope -Times 0
        }
        It 'rejects an existing private output before any remote reset' {
            [IO.File]::WriteAllText($arguments.PrivateOutputPath, 'preserve')
            { & $entrypoint @arguments } | Should -Throw '*absent private output*'
            Should -Invoke Send-SantaSetupRunCommand -Times 0
            [IO.File]::ReadAllText($arguments.PrivateOutputPath) | Should -Be 'preserve'
        }
        It 'performs ciphertext readback only on explicit opt-in and then requests explicit private delivery' {
            Mock Send-SantaSetupRunCommand {
                if ($Operation -eq 'create') { throw 'Synthetic unknown outcome.' }
                'synthetic-opaque-envelope'
            }
            (& $entrypoint @arguments -ReadbackOnUnknown).Delivery | Should -Be 'synthetic-private-file-receipt'
            Should -Invoke Send-SantaSetupRunCommand -Times 1 -ParameterFilter { $Operation -eq 'create' }
            Should -Invoke Send-SantaSetupRunCommand -Times 1 -ParameterFilter { $Operation -eq 'readback' }
            Should -Invoke Receive-SantaSetupEnvelope -Times 1 -ParameterFilter { $PrivateOutputPath -eq $arguments.PrivateOutputPath -and -not $OpenBrowser }
        }
    }
}
