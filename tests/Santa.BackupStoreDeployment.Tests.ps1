#Requires -Version 7.6
BeforeDiscovery { Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'experiments/server/BackupStoreDeployment.psm1') -Force }
Describe 'Fresh independent backup-store creation orchestration' {
    InModuleScope BackupStoreDeployment {
        BeforeAll {
            $script:selectionArgs=@{TenantId='55555555-5555-4555-8555-555555555555';SubscriptionId='11111111-1111-4111-8111-111111111111'
                Location='westus2';SourceEnvironment='source';SourceVmInstanceId='33333333-3333-4333-8333-333333333333'}
            function Test-DeploymentResponse($Arguments) {
                $plan=Read-StoreRecord (Join-Path $script:directory 'plan.json')
                $group="/subscriptions/$($plan.selection.SubscriptionId)/resourceGroups/$($plan.selection.BackupResourceGroupName)"
                $account="$group/providers/Microsoft.Storage/storageAccounts/$($plan.selection.BackupStoreName)"
                if($Arguments[0] -eq 'bicep') {
                    return @{metadata=@{_generator=@{templateHash='1234567890123456'}};parameters=@{
                        location=@{type='string'};backupResourceGroupName=@{type='string'};backupStoreName=@{type='string'}
                        ownershipId=@{type='string'};ownedSubnetResourceIds=@{type='array'}}}
                }
                if($Arguments[2] -eq 'validate') { return @{properties=@{provisioningState='Succeeded'}} }
                if($Arguments[2] -eq 'what-if') {
                    return @{status='Succeeded';changes=@($group,$account,"$account/blobServices/default","$account/blobServices/default/containers/native-captures")|
                        ForEach-Object { @{resourceId=$_;changeType='Create'} }}
                }
                if($Arguments[2] -eq 'create') {
                    Test-Path (Join-Path $script:directory 'intent.json') | Should -BeTrue
                    $Arguments | Should -Contain '--no-wait';return
                }
                if($Arguments[0] -eq 'account') {
                    return @{id=$script:selectionArgs.SubscriptionId;tenantId=$script:selectionArgs.TenantId;state='Enabled';environmentName='AzureCloud'}
                }
                if($Arguments[2] -eq 'show') {
                    return @{id="/subscriptions/$($plan.selection.SubscriptionId)/providers/Microsoft.Resources/deployments/$($plan.deploymentName)"
                        name=$plan.deploymentName;properties=@{provisioningState=$script:status;templateHash='1234567890123456'
                            parameters=(Read-StoreRecord (Join-Path $script:directory 'parameters.json')).parameters}}
                }
                throw 'Unexpected command'
            }
        }
        BeforeEach {
            $script:directory=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'));$script:status='Succeeded'
            $script:preflight=@{contextSha256='a'*64;subnets=@('/selected/subnet');networkObservations=@('b'*64)}
            Mock Get-SantaBackupStoreSelection { @{scope='cached-arm-backup-store-selection-v1';status='selected';retention_proven=$false;restore_accepted=$false} }
            Mock Compile-StoreTemplate { Test-DeploymentResponse @('bicep','build') }
            Mock Get-StoreSubmissionToken { 'x'*64 }
            Mock Send-StoreDeployment {
                Test-Path (Join-Path $script:directory 'intent.json') | Should -BeTrue
                202
            }
            Mock Get-StoreCreationPreflight { $script:preflight }
            Mock Invoke-StoreAzure { param($Arguments) Test-DeploymentResponse $Arguments }
        }
        It 'defaults to a no-cloud/no-file plan with independently generated exact identities' {
            $first=Invoke-SantaBackupStoreDeployment @script:selectionArgs
            $second=Invoke-SantaBackupStoreDeployment @script:selectionArgs
            $first.cloudWrite | Should -BeFalse
            $first.selection.OwnershipId | Should -Not -Be $second.selection.OwnershipId
            $first.selection.BackupStoreName.Length | Should -Be 24
            $first.selection.BackupResourceGroupName | Should -Match '^rg-santa-backup-[a-f0-9]{32}$'
            $first.deploymentName | Should -Match '^santa-backup-[a-f0-9]{32}$'
            Should -Invoke Invoke-StoreAzure -Times 0 -Exactly
            Should -Invoke Get-SantaBackupStoreSelection -Times 0 -Exactly
            Test-Path $script:directory | Should -BeFalse
        }
        It 'validates/what-ifs then repeats preflight before one durable async submission and maintained post-read' {
            $result=Invoke-SantaBackupStoreDeployment @script:selectionArgs -Action Apply -StateDirectory $script:directory
            $result.state | Should -BeExactly 'Succeeded';$result.cloudWriteAttempted | Should -BeTrue
            $result.retentionProven | Should -BeFalse
            Should -Invoke Get-StoreCreationPreflight -Times 2 -Exactly
            Should -Invoke Send-StoreDeployment -Times 1 -Exactly
            Should -Invoke Invoke-StoreAzure -Times 0 -Exactly -ParameterFilter {$Arguments[0] -eq 'deployment' -and $Arguments[2] -eq 'create'}
            Should -Invoke Invoke-StoreAzure -Times 1 -Exactly -ParameterFilter {$Arguments[2] -eq 'validate' -and $TimeoutSeconds -eq 180 -and $Arguments -contains 'Provider'}
            Should -Invoke Get-SantaBackupStoreSelection -Times 1 -Exactly -ParameterFilter {$ReadArm}
            $intent=Read-StoreRecord (Join-Path $script:directory 'intent.json')
            $intent.planSha256 | Should -Match '^[a-f0-9]{64}$'
        }
        It 'keeps unknown submission intent and never replays Apply; Observe only reads its exact deployment' {
            Mock Send-StoreDeployment { throw 'simulated submission uncertainty' }
            { Invoke-SantaBackupStoreDeployment @script:selectionArgs -Action Apply -StateDirectory $script:directory } | Should -Throw '*never replay Apply*'
            Test-Path (Join-Path $script:directory 'intent.json') | Should -BeTrue
            { Invoke-SantaBackupStoreDeployment @script:selectionArgs -Action Apply -StateDirectory $script:directory } | Should -Throw
            $result=Invoke-SantaBackupStoreDeployment -Action Observe -StateDirectory $script:directory
            $result.state | Should -BeExactly 'Succeeded';$result.cloudWrite | Should -BeFalse
            Should -Invoke Send-StoreDeployment -Times 1 -Exactly
        }
        It 'does not create when validation, what-if or final fresh facts fail' -ForEach @(@{fault='validate'},@{fault='what-if'},@{fault='fresh'}) {
            if($fault -eq 'fresh') {
                $script:preflights=0
                Mock Get-StoreCreationPreflight { $script:preflights++;if($script:preflights -eq 2){throw 'drift'};$script:preflight }
            } else { Mock Invoke-StoreAzure { throw 'policy or unsupported change' } -ParameterFilter {$Arguments[2] -eq $fault} }
            { Invoke-SantaBackupStoreDeployment @script:selectionArgs -Action Apply -StateDirectory $script:directory } | Should -Throw
            Test-Path (Join-Path $script:directory 'intent.json') | Should -BeFalse
            Should -Invoke Send-StoreDeployment -Times 0 -Exactly
        }
        It 'reports terminal failure without selecting or deleting storage' {
            $script:status='Failed'
            $result=Invoke-SantaBackupStoreDeployment @script:selectionArgs -Action Apply -StateDirectory $script:directory
            $result.state | Should -BeExactly 'Failed';$result.selection | Should -BeNullOrEmpty
            Should -Invoke Get-SantaBackupStoreSelection -Times 0 -Exactly -ParameterFilter {$ReadArm}
        }
        It 'rejects modified local parameters before Observe reads ARM' {
            $null=Invoke-SantaBackupStoreDeployment @script:selectionArgs -Action Apply -StateDirectory $script:directory
            Add-Content (Join-Path $script:directory 'parameters.json') ' '
            $script:afterReads=0
            Mock Invoke-StoreAzure { $script:afterReads++;throw 'Must reject before any read' }
            { Invoke-SantaBackupStoreDeployment -Action Observe -StateDirectory $script:directory } | Should -Throw '*No submission was attempted*'
            $script:afterReads | Should -Be 0
        }
        It 'rejects noncreate, foreign, duplicate and missing what-if changes' {
            $plan=New-SantaBackupStoreDeploymentPlan @script:selectionArgs
            foreach($row in @(@{resourceId='/foreign';changeType='Create'},@{resourceId='/foreign';changeType='Modify'})) {
                { Assert-StoreWhatIf @{status='Succeeded';changes=@($row)} $plan } | Should -Throw
            }
            { Assert-StoreWhatIf @{status='Succeeded';changes=@()} $plan } | Should -Throw
        }
    }
}
Describe 'Fresh creation authority and owned regional network prerequisites' {
    InModuleScope BackupStoreDeployment {
        BeforeEach {
            $script:selectionArgs=@{TenantId='55555555-5555-4555-8555-555555555555';SubscriptionId='11111111-1111-4111-8111-111111111111'
                Location='westus2';SourceEnvironment='source';SourceVmInstanceId='33333333-3333-4333-8333-333333333333'}
            $script:fault='';$script:contextReads=0
            Mock Get-SantaBackupStoreSelection { @{scope='backup-store-selection-plan-v1'} }
            Mock Invoke-StoreAzure { param($Arguments)
                if($Arguments[0] -eq 'account') {
                    $script:contextReads++
                    return @{id=$script:selectionArgs.SubscriptionId;tenantId=if($script:fault -eq 'tenant'){'wrong'}else{$script:selectionArgs.TenantId}
                        state='Enabled';environmentName='AzureCloud';principal=if($script:fault -eq 'drift' -and $script:contextReads -eq 2){'changed'}else{'selected'}}
                }
                if($Arguments[0] -eq 'group') { return ($script:fault -eq 'existing-group') }
                if($Arguments[0] -eq 'storage') { return @{nameAvailable=($script:fault -ne 'name-unavailable')} }
                if($Arguments[0] -eq 'deployment') { if($script:fault -eq 'existing-deployment'){return ,@('already-there')};return ,@() }
                if($Arguments[0] -eq 'provider') {
                    return @{namespace=$Arguments[5];registrationState=if($script:fault -eq 'provider'){'NotRegistered'}else{'Registered'}
                        resourceTypes=@(@{resourceType='storageAccounts';apiVersions=@('2025-06-01');locations=@('West US 2')})}
                }
                throw 'Unexpected Azure command'
            }
            Mock New-SantaPrivateStorageEndpointPlan {
                param($TenantId,$SubscriptionId,$EnvironmentName,$VmInstanceId,$ReadArm)
                $ReadArm | Should -BeTrue
                $region=if($script:fault -eq 'region'){'eastus'}else{'westus2'}
                $endpoint=@{service=if($script:fault -eq 'global'){'Microsoft.Storage.Global'}else{'Microsoft.Storage'}
                    locations=@('westus2');provisioningState=if($script:fault -eq 'pending'){'Updating'}else{'Succeeded'}}
                @{scope='private-storage-endpoint-proposal-v1';changed=$false;location=$region;selectedInstance=$VmInstanceId.ToString()
                    observedSubnet=@{properties=@{serviceEndpoints=if($script:fault -eq 'missing-endpoint'){@()}else{@($endpoint)}}}
                    subnetId="/subscriptions/$SubscriptionId/resourceGroups/rg-azd-santa-vm-$EnvironmentName/providers/Microsoft.Network/virtualNetworks/vnet-santa-lab/subnets/host"
                    observationSha256='a'*64}
            }
        }
        It 'reuses the owned network producer and requires a successful regional endpoint without changing it' {
            $plan=New-SantaBackupStoreDeploymentPlan @script:selectionArgs
            $result=Get-StoreCreationPreflight $plan
            $result.subnets.Count | Should -Be 1
            Should -Invoke New-SantaPrivateStorageEndpointPlan -Times 1 -Exactly -ParameterFilter {$ReadArm -and -not $EnableStorageEndpoint}
            Should -Invoke Invoke-StoreAzure -Times 2 -Exactly -ParameterFilter {$Arguments[0] -eq 'account'}
            Should -Invoke Invoke-StoreAzure -Times 3 -Exactly -ParameterFilter {$Arguments[0] -eq 'provider' -and $Arguments -contains '--query'}
        }
        It 'rejects existing ownership/name, provider and network gaps without remediation' -ForEach @(
            @{fault='tenant'},@{fault='existing-group'},@{fault='name-unavailable'},@{fault='existing-deployment'},@{fault='provider'},
            @{fault='region'},@{fault='global'},@{fault='pending'},@{fault='missing-endpoint'},@{fault='drift'}
        ) {
            $script:fault=$fault;$plan=New-SantaBackupStoreDeploymentPlan @script:selectionArgs
            { Get-StoreCreationPreflight $plan } | Should -Throw
            Should -Invoke Invoke-StoreAzure -Times 0 -Exactly -ParameterFilter {$Arguments -contains 'create' -or $Arguments -contains 'register'}
        }
    }
}
