#Requires -Version 7.6
BeforeDiscovery {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'experiments/server/BackupStoreSelection.psm1') -Force
}
Describe 'GET-only cached backup store selection producer' {
    InModuleScope BackupStoreSelection {
        BeforeAll {
            $script:python = if ($env:SANTA_CRYPTO_PYTHON) { $env:SANTA_CRYPTO_PYTHON } else { 'python' }
            $script:pythonResolved = @(Get-Command $script:python -CommandType Application)[0].Source
            $script:arguments = @{
                TenantId='55555555-5555-4555-8555-555555555555';SubscriptionId='11111111-1111-4111-8111-111111111111'
                Location='westus2';BackupResourceGroupName='independent-backups';BackupStoreName='santatestbackup'
                OwnershipId='22222222-2222-4222-8222-222222222222';SourceEnvironment='source'
                SourceVmInstanceId='33333333-3333-4333-8333-333333333333';VerifierEnvironment='restore'
                VerifierVmInstanceId='44444444-4444-4444-8444-444444444444';Python=$script:python
            }
            $code='import sys,json;sys.path.insert(0,sys.argv[1]);from test_backup_store_selection import fixture;print(json.dumps(fixture()))'
            $raw = & $script:python -c $code $PSScriptRoot
            if ($LASTEXITCODE) { throw 'Offline fixture generation failed.' }
            $script:fixtureJson = $raw -join "`n"
        }
        BeforeEach {
            $script:fixture=$script:fixtureJson | ConvertFrom-Json -Depth 48 -AsHashtable
            $script:reads=0
            Mock Invoke-SantaStoreCachedRead { param($Arguments)
                $Arguments | Should -Contain '--subscription'
                if ($Arguments[0] -eq 'account') { return $script:fixture.context_before }
                $Arguments[0] | Should -BeExactly 'rest'; $Arguments[2] | Should -BeExactly 'get'
                $script:reads++
                if (-not $script:fixture.before.ContainsKey($Arguments[4])) { throw 'Unplanned URL.' }
                $script:fixture.before[$Arguments[4]]
            }
        }
        It 'plans without invoking CLI or accepting caller-supplied ARM facts' {
            $result=Get-SantaBackupStoreSelection @script:arguments
            $result.scope | Should -BeExactly 'backup-store-selection-plan-v1'
            $result.urls.Count | Should -Be 15
            Should -Invoke Invoke-SantaStoreCachedRead -Times 0 -Exactly
            (Get-Command Get-SantaBackupStoreSelection).Parameters.Keys | Should -Not -Contain 'Facts'
        }
        It 'collects two complete exact GET readbacks and produces bounded machine evidence' {
            $result=Get-SantaBackupStoreSelection @script:arguments -ReadArm
            $result.status | Should -BeExactly 'selected'
            $result.cloud_write | Should -BeFalse
            $result.retention_proven | Should -BeFalse
            $script:reads | Should -Be 30
            Should -Invoke Invoke-SantaStoreCachedRead -Times 32 -Exactly
        }
        It 'starts the first Python PATH match when command discovery returns several' {
            Mock Get-Command { @(
                [pscustomobject]@{Source=$script:pythonResolved},
                [pscustomobject]@{Source='/never-used/second/python'}
            ) } -ParameterFilter { $CommandType -eq 'Application' }
            $result=Get-SantaBackupStoreSelection @script:arguments
            $result.scope | Should -BeExactly 'backup-store-selection-plan-v1'
            Should -Invoke Get-Command -Times 1 -Exactly
            Should -Invoke Invoke-SantaStoreCachedRead -Times 0 -Exactly
        }
        It 'rejects wrong cached context before resource reads' {
            $script:fixture.context_before.tenantId=$script:arguments.OwnershipId
            { Get-SantaBackupStoreSelection @script:arguments -ReadArm } | Should -Throw '*failed or is unknown*'
            $script:reads | Should -Be 0
        }
        It 'preserves failed or unknown state for missing, forbidden and timeout reads' -ForEach @(
            @{failure='404 missing'},@{failure='403 forbidden secret-sas'},@{failure='timeout unknown'}
        ) {
            Mock Invoke-SantaStoreCachedRead { throw $failure }
            { Get-SantaBackupStoreSelection @script:arguments -ReadArm } | Should -Throw '*No cloud write was attempted*'
            Should -Invoke Invoke-SantaStoreCachedRead -Times 1 -Exactly
        }
        It 'rejects observation drift rather than returning stale readiness' {
            Mock Invoke-SantaStoreCachedRead { param($Arguments)
                if ($Arguments[0] -eq 'account') { return $script:fixture.context_before }
                $script:reads++
                $row=$script:fixture.before[$Arguments[4]] | ConvertTo-Json -Depth 48 | ConvertFrom-Json -Depth 48 -AsHashtable
                if ($script:reads -gt 15) { $row.etag='changed' }
                $row
            }
            { Get-SantaBackupStoreSelection @script:arguments -ReadArm } | Should -Throw '*failed or is unknown*'
        }
        It 'does not adopt or update an unrelated preexisting backup resource group' {
            $url=$script:fixture.before.Keys | Where-Object { $_ -match '/resourceGroups/independent-backups\?' }
            $script:fixture.before[$url].tags['AZD-ENV-NAME']='foreign'
            { Get-SantaBackupStoreSelection @script:arguments -ReadArm } | Should -Throw '*failed or is unknown*'
            $script:reads | Should -Be 30
        }
        It 'runs the separate Python bridge validation and protocol negatives' {
            $result=& $script:python -m unittest discover -s $PSScriptRoot -p test_backup_store_selection.py 2>&1
            $LASTEXITCODE | Should -Be 0 -Because ($result -join "`n")
        }
    }
}
Describe 'Backup selector reuse of cached bounded CLI reader' {
    InModuleScope BackupStoreSelection {
        It 'passes only the selected argument array into the existing private reader' {
            Mock Invoke-SantaEndpointAzJson -ModuleName HttpsEndpoint { param($Arguments)
                $Arguments.Count | Should -Be 7
                $Arguments[0] | Should -BeExactly 'rest'
                $Arguments[2] | Should -BeExactly 'get'
                $Arguments[4] | Should -BeExactly 'https://management.azure.com/selected?api-version=2025-04-01'
                $Arguments[6] | Should -BeExactly '11111111-1111-4111-8111-111111111111'
                @{observed=$true}
            }
            # Explicit array binding preserves flags; the reader adds only output format/quiet flags.
            $result=Invoke-SantaStoreCachedRead @('rest','--method','get','--url',
                'https://management.azure.com/selected?api-version=2025-04-01','--subscription',
                '11111111-1111-4111-8111-111111111111')
            $result.observed | Should -BeTrue
            Should -Invoke Invoke-SantaEndpointAzJson -ModuleName HttpsEndpoint -Times 1 -Exactly
        }
    }
}
