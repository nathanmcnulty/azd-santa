#Requires -Version 7.6
BeforeDiscovery {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'experiments/vm/PrivateHelperUpgrade.psm1') -Force
}
Describe 'Explicit one-helper maintenance' {
    It 'passes offline source transition, history, durable job and failure protocol tests' {
        $result = & python -m unittest discover -s $PSScriptRoot -p test_helper_upgrade.py 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($result -join "`n")
    }
    InModuleScope PrivateHelperUpgrade {
        BeforeEach {
            $script:target = @{ TenantId='22222222-2222-4222-8222-222222222222'; SubscriptionId='11111111-1111-4111-8111-111111111111'
                EnvironmentName='synthetic'; ResourceGroup='rg-azd-santa-vm-synthetic'; VmName='vm-santa-lab'; VmId='/selected/vm'
                VmInstanceId='33333333-3333-4333-8333-333333333333' }
            $script:calls = @()
            Mock New-UpgradeBundle { [pscustomobject]@{ Sha256='b'*64; ArchiveSha256='c'*64; Chunks=@('YWJj','ZGVm') } }
            Mock Get-UpgradeTarget { $script:target }
            Mock Invoke-UpgradeAzure { throw 'Unexpected Azure request.' }
            Mock Send-UpgradeCommand {
                param($Target,$Command)
                $script:calls += $Command
                if ($Command.mode -eq 'chunk') { return @{ scope='azd-santa-helper-upgrade-chunk-v1'; index=$Command.index; new_bundle_sha256=$Command.bundle_sha256 } }
                @{ scope='azd-santa-helper-upgrade-observation-v1'; state=if($Command.mode -eq 'observe'){'not-requested'}else{'in-progress'}; new_bundle_sha256=$Command.bundle_sha256 }
            }
        }
        It 'defaults to an offline plan without Azure discovery or transport' {
            $result = Invoke-SantaPrivateHelperUpgrade -SubscriptionId $script:target.SubscriptionId -EnvironmentName synthetic
            $result.performsMutation | Should -BeFalse
            Should -Invoke Get-UpgradeTarget -Times 0
            Should -Invoke Send-UpgradeCommand -Times 0
        }
        It 'requires a separate Observe or one explicit Apply' {
            { Invoke-SantaPrivateHelperUpgrade -SubscriptionId $script:target.SubscriptionId -EnvironmentName synthetic -Apply -Observe } | Should -Throw
            Invoke-SantaPrivateHelperUpgrade -SubscriptionId $script:target.SubscriptionId -EnvironmentName synthetic -Observe | Out-Null
            $script:calls.Count | Should -Be 1
            $script:calls[0].mode | Should -Be 'observe'
        }
        It 'uploads bounded chunks and submits maintenance exactly once' {
            $result = Invoke-SantaPrivateHelperUpgrade -SubscriptionId $script:target.SubscriptionId -EnvironmentName synthetic -Apply
            ($script:calls.mode -join ',') | Should -Be 'observe,chunk,chunk,request'
            $result.state | Should -Be 'in-progress'
            Should -Invoke Get-UpgradeTarget -Times 1
        }
        It 'observes a previous reservation without another upload or submission' {
            Mock Send-UpgradeCommand { @{ scope='azd-santa-helper-upgrade-observation-v1'; state='unknown'; new_bundle_sha256='b'*64 } }
            $result = Invoke-SantaPrivateHelperUpgrade -SubscriptionId $script:target.SubscriptionId -EnvironmentName synthetic -Apply
            $result.state | Should -Be 'unknown'
            Should -Invoke Send-UpgradeCommand -Times 1 -ParameterFilter { $Command.mode -eq 'observe' }
            Should -Invoke Send-UpgradeCommand -Times 0 -ParameterFilter { $Command.mode -eq 'request' }
        }
        It 'does not retry or resubmit after an unknown request response' {
            Mock Send-UpgradeCommand {
                param($Target,$Command)
                $script:calls += $Command
                if ($Command.mode -eq 'request') { throw 'Unknown submission; observe only.' }
                if ($Command.mode -eq 'chunk') { return @{ scope='azd-santa-helper-upgrade-chunk-v1'; index=$Command.index } }
                @{ scope='azd-santa-helper-upgrade-observation-v1'; state='not-requested' }
            }
            { Invoke-SantaPrivateHelperUpgrade -SubscriptionId $script:target.SubscriptionId -EnvironmentName synthetic -Apply } | Should -Throw
            @($script:calls | Where-Object mode -eq request).Count | Should -Be 1
        }
    }
}

Describe 'Helper upgrade transport envelopes' {
    InModuleScope PrivateHelperUpgrade {
        BeforeEach {
            $script:transportTarget = @{ SubscriptionId='11111111-1111-4111-8111-111111111111'; ResourceGroup='rg-selected'; VmName='vm-selected' }
            Mock Invoke-UpgradeAzure {
                param($Arguments)
                $Arguments[0..2] -join ',' | Should -Be 'vm,run-command,invoke'
                $Arguments[4] | Should -Be $script:transportTarget.SubscriptionId
                $Arguments[6] | Should -Be $script:transportTarget.ResourceGroup
                $Arguments[8] | Should -Be $script:transportTarget.VmName
                $script:sentTemporary = $Arguments[-1].Substring(1)
                $body = [IO.File]::ReadAllText($script:sentTemporary)
                [Text.Encoding]::UTF8.GetByteCount($body) | Should -BeLessThan 65537
                $nonce = [regex]::Match($body,'SANTA_HELPER_UPGRADE_DONE:([a-f0-9]{32})').Groups[1].Value
                $encoded = [regex]::Match($body,"export AZD_HELPER_UPGRADE_COMMAND='([^']+)'").Groups[1].Value
                $command = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encoded)) | ConvertFrom-Json -AsHashtable
                $command.mode | Should -Be 'chunk'
                $reply = @{ scope='azd-santa-helper-upgrade-chunk-v1'; index=0; new_bundle_sha256=$command.bundle_sha256 } | ConvertTo-Json -Compress
                @{ value=@(@{ code='ProvisioningState/succeeded'; message="SANTA_HELPER_UPGRADE_JSON:$reply`nSANTA_HELPER_UPGRADE_DONE:$nonce" }) }
            }
        }
        It 'bounds a maximum chunk and verifies selected target and nonce through the actual sender' {
            $reply = Send-UpgradeCommand $script:transportTarget @{ mode='chunk'; target=$script:transportTarget; bundle_sha256='b'*64
                archive_sha256='c'*64; index=0; count=1; data='a'*24576 }
            $reply.index | Should -Be 0
            [IO.File]::Exists($script:sentTemporary) | Should -BeFalse
            Should -Invoke Invoke-UpgradeAzure -Times 1
        }
        It 'rejects truncated or missing terminal receipts without retry' {
            Mock Invoke-UpgradeAzure { @{ value=@(@{ code='ProvisioningState/succeeded'; message='SANTA_HELPER_UPGRADE_JSON:{}' }) } }
            { Send-UpgradeCommand $script:transportTarget @{ mode='observe'; target=$script:transportTarget; bundle_sha256='b'*64 } } | Should -Throw
            Should -Invoke Invoke-UpgradeAzure -Times 1
        }
    }
}
