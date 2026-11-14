#Requires -Version 7.6
BeforeDiscovery {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'experiments/vm/PrivatePreSnapshotRecovery.psm1') -Force
}
Describe 'Explicit pre-snapshot failure recovery' {
    It 'passes offline preservation and terminal protocol tests' {
        $result = & python -m unittest discover -s $PSScriptRoot -p test_presnapshot_recovery.py 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($result -join "`n")
    }
    InModuleScope PrivatePreSnapshotRecovery {
        BeforeEach {
            $script:target = @{ SubscriptionId='11111111-1111-4111-8111-111111111111' }
            $script:calls = @()
            Mock New-RecoveryBundle { @{ Sha256='b'*64; ArchiveSha256='c'*64; Chunks=@('YWJj','ZGVm') } }
            Mock Get-RecoveryTarget { $script:target }
            Mock Send-RecoveryCommand {
                param($Target,$Command)
                $script:calls += $Command
                if ($Command.mode -eq 'chunk') { return @{ scope='exact-presnapshot-recovery-chunk-v1'; index=$Command.index } }
                @{ scope='exact-presnapshot-recovery-observation-v1'; state=if($Command.mode -eq 'observe'){'not-requested'}else{'in-progress'} }
            }
        }
        It 'defaults to a local plan without target or transport calls' {
            $result = Repair-SantaPrivatePreSnapshotFailure -SubscriptionId $script:target.SubscriptionId -EnvironmentName synthetic
            $result.performsMutation | Should -BeFalse
            $result.backupResume | Should -BeFalse
            $result.newBackupRequested | Should -BeFalse
            Should -Invoke Get-RecoveryTarget -Times 0
            Should -Invoke Send-RecoveryCommand -Times 0
        }
        It 'uploads chunks then requests exactly once' {
            $result = Repair-SantaPrivatePreSnapshotFailure -SubscriptionId $script:target.SubscriptionId -EnvironmentName synthetic -Apply
            ($script:calls.mode -join ',') | Should -Be 'observe,chunk,chunk,request'
            $result.state | Should -Be in-progress
        }
        It 'only observes in Observe mode' {
            Repair-SantaPrivatePreSnapshotFailure -SubscriptionId $script:target.SubscriptionId -EnvironmentName synthetic -Observe | Out-Null
            ($script:calls.mode -join ',') | Should -Be observe
        }
        It 'does not replay failed or unknown reservations' -ForEach @(@{State='failed'},@{State='unknown'},@{State='in-progress'},@{State='completed'}) {
            Mock Send-RecoveryCommand { @{ scope='exact-presnapshot-recovery-observation-v1'; state=$State } }
            $result = Repair-SantaPrivatePreSnapshotFailure -SubscriptionId $script:target.SubscriptionId -EnvironmentName synthetic -Apply
            $result.state | Should -Be $State
            Should -Invoke Send-RecoveryCommand -Times 1
        }
        It 'does not retry a request with unknown transport outcome' {
            Mock Send-RecoveryCommand {
                param($Target,$Command)
                $script:calls += $Command
                if ($Command.mode -eq 'request') { throw 'unknown' }
                if ($Command.mode -eq 'chunk') { return @{ scope='exact-presnapshot-recovery-chunk-v1'; index=$Command.index } }
                @{ scope='exact-presnapshot-recovery-observation-v1'; state='not-requested' }
            }
            { Repair-SantaPrivatePreSnapshotFailure -SubscriptionId $script:target.SubscriptionId -EnvironmentName synthetic -Apply } | Should -Throw
            @($script:calls | Where-Object mode -eq request).Count | Should -Be 1
        }
        It 'rejects conflicting action switches and invalid observation scope' {
            { Repair-SantaPrivatePreSnapshotFailure -SubscriptionId $script:target.SubscriptionId -EnvironmentName synthetic -Apply -Observe } | Should -Throw
            Mock Send-RecoveryCommand { @{scope='other';state='not-requested'} }
            { Repair-SantaPrivatePreSnapshotFailure -SubscriptionId $script:target.SubscriptionId -EnvironmentName synthetic -Apply } | Should -Throw
        }
    }
}
Describe 'Recovery transport envelope' {
    InModuleScope PrivateHelperUpgrade {
        It 'uses the fixed recovery source with a maximum chunk through the actual bounded sender' {
            Mock Invoke-UpgradeAzure {
                param($Arguments)
                $body = [IO.File]::ReadAllText($Arguments[-1].Substring(1))
                [Text.Encoding]::UTF8.GetByteCount($body) | Should -BeLessThan 65537
                $nonce = [regex]::Match($body,'SANTA_HELPER_UPGRADE_DONE:([a-f0-9]{32})').Groups[1].Value
                @{ value=@(@{code='ProvisioningState/succeeded';message="SANTA_HELPER_UPGRADE_JSON:{""new_bundle_sha256"":""bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb""}`nSANTA_HELPER_UPGRADE_DONE:$nonce"}) }
            }
            $program = Join-Path $PSScriptRoot '../experiments/server/presnapshot_recovery.py'
            Send-UpgradeCommand @{SubscriptionId='11111111-1111-4111-8111-111111111111';ResourceGroup='synthetic';VmName='synthetic'} @{mode='chunk';bundle_sha256='b'*64;data='a'*24576} -ProgramPath $program | Out-Null
            Should -Invoke Invoke-UpgradeAzure -Times 1
        }
    }
}
