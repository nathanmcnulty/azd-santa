#Requires -Version 7.6
BeforeDiscovery { Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'experiments/server/BackupStoreDeployment.psm1') -Force }
Describe 'Fresh independent backup-store creation orchestration' {
    InModuleScope BackupStoreDeployment {
        BeforeAll {
            $script:selectionArgs=@{TenantId='55555555-5555-4555-8555-555555555555';SubscriptionId='11111111-1111-4111-8111-111111111111'
                Location='westus2';SourceEnvironment='source';SourceVmInstanceId='33333333-3333-4333-8333-333333333333'}
            function New-StoreTemplateFixture {
                [ordered]@{
                    '$schema'='https://schema.management.azure.com/schemas/2018-05-01/subscriptionDeploymentTemplate.json#'
                    contentVersion='1.0.0.0'
                    metadata=[ordered]@{_generator=[ordered]@{name='bicep';version='0.42.1';templateHash='7648908632598025806'}}
                    parameters=[ordered]@{
                        location=[ordered]@{type='string';defaultValue='westus2'}
                        backupResourceGroupName=[ordered]@{type='string'}
                        backupStoreName=[ordered]@{type='string'}
                        ownershipId=[ordered]@{type='string'}
                        ownedSubnetResourceIds=[ordered]@{type='array'}
                    }
                    resources=@(
                        [ordered]@{type='Microsoft.Storage/storageAccounts';apiVersion='2025-06-01';name='[parameters(''backupStoreName'')]'
                            location='[parameters(''location'')]';kind='StorageV2';sku=[ordered]@{name='Standard_LRS'}
                            properties=[ordered]@{supportsHttpsTrafficOnly=$true;minimumTlsVersion='TLS1_2'
                                networkAcls=[ordered]@{defaultAction='Deny';bypass='None';virtualNetworkRules=@()}}}
                    )
                    outputs=[ordered]@{backupStoreId=[ordered]@{type='string';value='[resourceId(''Microsoft.Storage/storageAccounts'', parameters(''backupStoreName''))]'}}
                }
            }
            function Copy-StoreTemplateFixture($Value) {
                ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $Value -Depth 48 -Compress) -Depth 48 -AsHashtable -NoEnumerate
            }
            function New-StoreArmTemplateProjection($Template) {
                $copy=Copy-StoreTemplateFixture $Template
                $copy.metadata.Remove('_generator')
                if($copy.metadata.Count -eq 0) { $copy.Remove('metadata') }
                foreach($sectionName in @('parameters','outputs')) {
                    foreach($name in @($copy[$sectionName].Keys)) { $copy[$sectionName][$name].type=$copy[$sectionName][$name].type.ToUpperInvariant() }
                }
                $copy
            }
            function Test-DeploymentResponse($Arguments) {
                $plan=Read-StoreRecord (Join-Path $script:directory 'plan.json')
                $group="/subscriptions/$($plan.selection.SubscriptionId)/resourceGroups/$($plan.selection.BackupResourceGroupName)"
                $account="$group/providers/Microsoft.Storage/storageAccounts/$($plan.selection.BackupStoreName)"
                if($Arguments[0] -eq 'bicep') {
                    return $script:submittedTemplate
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
                if($Arguments[0] -eq 'deployment' -and $Arguments[1] -eq 'sub' -and $Arguments[2] -eq 'export') {
                    $Arguments[3] | Should -BeExactly '--subscription'
                    $Arguments[4] | Should -BeExactly $script:selectionArgs.SubscriptionId
                    $Arguments[5] | Should -BeExactly '--name'
                    $Arguments[6] | Should -BeExactly $plan.deploymentName
                    if($script:exportFault -ceq 'denied') { throw 'synthetic-raw-export-error-not-for-output' }
                    if($script:exportFault -ceq 'missing') { return $null }
                    if($script:exportFault -ceq 'rest-envelope') { return @{template=$script:exportTemplate} }
                    return $script:exportTemplate
                }
                if($Arguments[0] -eq 'deployment' -and $Arguments[1] -eq 'sub' -and $Arguments[2] -eq 'show') {
                    $observedParameters=(Read-StoreRecord (Join-Path $script:directory 'parameters.json')).parameters
                    if($script:parameterPayloadFault -ceq 'changed-value') { $observedParameters.backupStoreName.value='different-store-name' }
                    if($script:parameterPayloadFault -ceq 'extra-parameter') { $observedParameters.unexpected=@{value='unexpected'} }
                    if($script:parameterPayloadFault -ceq 'renamed-parameter') {
                        $entry=$observedParameters['backupStoreName']
                        $observedParameters.Remove('backupStoreName')
                        $observedParameters['BackupStoreName']=$entry
                    }
                    $properties=[ordered]@{provisioningState=$script:status;parameters=$observedParameters}
                    if($script:serverTemplateHashFault -cne 'missing') { $properties.templateHash=$script:serverTemplateHash }
                    return @{id="/subscriptions/$($plan.selection.SubscriptionId)/providers/Microsoft.Resources/deployments/$($plan.deploymentName)"
                        name=$plan.deploymentName;properties=$properties}
                }
                throw 'Unexpected command'
            }
        }
        BeforeEach {
            $script:directory=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'));$script:status='Succeeded'
            $script:submittedTemplate=New-StoreTemplateFixture
            $script:exportTemplate=New-StoreArmTemplateProjection $script:submittedTemplate
            $script:serverTemplateHash='15050816737742618192';$script:serverTemplateHashFault='';$script:parameterPayloadFault='';$script:exportFault='';$script:selectionReadCount=0
            $script:preflight=@{contextSha256='a'*64;subnets=@('/selected/subnet');networkObservations=@('b'*64)}
            Mock Get-SantaBackupStoreSelection {
                if($ReadArm) { $script:selectionReadCount++ }
                @{scope='cached-arm-backup-store-selection-v1';status='selected';retention_proven=$false;restore_accepted=$false}
            }
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
        It 'accepts only the recorded ARM export normalization after one durable async submission' {
            $script:submittedTemplate.metadata._generator.templateHash | Should -BeExactly '7648908632598025806'
            $script:serverTemplateHash | Should -BeExactly '15050816737742618192'
            $result=Invoke-SantaBackupStoreDeployment @script:selectionArgs -Action Apply -StateDirectory $script:directory
            $result.state | Should -BeExactly 'Succeeded';$result.cloudWriteAttempted | Should -BeTrue
            $result.retentionProven | Should -BeFalse
            Should -Invoke Get-StoreCreationPreflight -Times 2 -Exactly
            Should -Invoke Send-StoreDeployment -Times 1 -Exactly
            Should -Invoke Invoke-StoreAzure -Times 0 -Exactly -ParameterFilter {$Arguments[0] -eq 'deployment' -and $Arguments[2] -eq 'create'}
            Should -Invoke Invoke-StoreAzure -Times 1 -Exactly -ParameterFilter {$Arguments[2] -eq 'validate' -and $TimeoutSeconds -eq 180 -and $Arguments -contains 'Provider'}
            Should -Invoke Get-SantaBackupStoreSelection -Times 1 -Exactly -ParameterFilter {$ReadArm}
            Should -Invoke Invoke-StoreAzure -Times 1 -Exactly -ParameterFilter {$Arguments[0] -eq 'deployment' -and $Arguments[1] -eq 'sub' -and $Arguments[2] -eq 'export' -and $Arguments[3] -eq '--subscription' -and $Arguments[4] -eq $script:selectionArgs.SubscriptionId -and $Arguments[5] -eq '--name'}
            $intent=Read-StoreRecord (Join-Path $script:directory 'intent.json')
            $intent.planSha256 | Should -Match '^[a-f0-9]{64}$'
        }
        It 'rejects template drift and unsupported export shapes even when the service hash equals Bicep' -ForEach @(
            @{fault='firewall'},@{fault='parameter-default'},@{fault='extra-property'},@{fault='missing-property'},
            @{fault='extra-root-field'},@{fault='resource-type-case'},@{fault='generator-mismatch'},
            @{fault='unsupported-output-type'},@{fault='malformed-template'},@{fault='missing-template'},
            @{fault='parameter-value'},@{fault='extra-deployed-parameter'},@{fault='renamed-deployed-parameter'}
        ) {
            $null=Invoke-SantaBackupStoreDeployment @script:selectionArgs -Action Apply -StateDirectory $script:directory
            $script:serverTemplateHash='7648908632598025806'
            $script:exportTemplate=Copy-StoreTemplateFixture $script:exportTemplate
            switch($fault) {
                'firewall' { $script:exportTemplate.resources[0].properties.networkAcls.defaultAction='Allow' }
                'parameter-default' { $script:exportTemplate.parameters.location.defaultValue='eastus' }
                'extra-property' { $script:exportTemplate.resources[0].properties.allowBlobPublicAccess=$true }
                'missing-property' { $script:exportTemplate.resources[0].properties.Remove('supportsHttpsTrafficOnly') }
                'extra-root-field' { $script:exportTemplate.unreviewedField='must-not-be-ignored' }
                'resource-type-case' { $script:exportTemplate.resources[0].type='microsoft.storage/storageaccounts' }
                'generator-mismatch' {
                    $script:exportTemplate.metadata=[ordered]@{_generator=[ordered]@{name='bicep';version='0.42.1';templateHash='15050816737742618192'}}
                }
                'unsupported-output-type' { $script:exportTemplate.outputs.backupStoreId.type='secureString' }
                'malformed-template' { $script:exportTemplate=@('unsupported-template-shape') }
                'missing-template' { $script:exportTemplate=$null }
                'parameter-value' { $script:parameterPayloadFault='changed-value' }
                'extra-deployed-parameter' { $script:parameterPayloadFault='extra-parameter' }
                'renamed-deployed-parameter' { $script:parameterPayloadFault='renamed-parameter' }
            }
            { Invoke-SantaBackupStoreDeployment -Action Observe -StateDirectory $script:directory } | Should -Throw '*No submission was attempted*'
            $script:selectionReadCount | Should -Be 1
        }
        It 'rejects nested case-colliding template keys in either insertion order before normalization' {
            foreach($reverse in @($false,$true)) {
                $observed=Copy-StoreTemplateFixture $script:submittedTemplate
                $properties=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
                $keys=if($reverse){@('SupportsHttpsTrafficOnly','supportsHttpsTrafficOnly')}else{@('supportsHttpsTrafficOnly','SupportsHttpsTrafficOnly')}
                $values=if($reverse){@($false,$true)}else{@($true,$false)}
                $properties.Add($keys[0],$values[0]);$properties.Add($keys[1],$values[1])
                $observed.resources[0].properties=$properties
                { Assert-StoreTemplateMatches $script:submittedTemplate $observed } | Should -Throw
            }
        }
        It 'normalizes only exact canonical metadata and declaration type keys' {
            $metadataAlias=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
            foreach($key in $script:submittedTemplate.Keys) {
                $actualKey=if($key -ceq 'metadata'){'Metadata'}else{[string]$key}
                $metadataAlias.Add($actualKey,$script:submittedTemplate[$key])
            }
            { Assert-StoreTemplateMatches $script:submittedTemplate $metadataAlias } | Should -Throw

            $typeAlias=Copy-StoreTemplateFixture $script:submittedTemplate
            $typeDeclaration=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
            foreach($key in $typeAlias.parameters.location.Keys) {
                $actualKey=if($key -ceq 'type'){'Type'}else{[string]$key}
                $typeDeclaration.Add($actualKey,$typeAlias.parameters.location[$key])
            }
            $typeAlias.parameters.location=$typeDeclaration
            { Assert-StoreTemplateMatches $script:submittedTemplate $typeAlias } | Should -Throw
        }
        It 'accepts the exact reviewed prior source manifest only for Observe and keeps the persisted plan hash strict' {
            function New-TestHistoricalState([string]$Directory,[bool]$WrongPlanHash) {
                $null=New-Item -ItemType Directory -Path $Directory
                $plan=New-SantaBackupStoreDeploymentPlan @script:selectionArgs
                $plan.sourceHashes=Get-StoreReviewedPriorSourceHashes
                $planPath=Join-Path $Directory 'plan.json'
                Write-StoreRecord $planPath $plan
                $templatePath=Join-Path $Directory 'template.json'
                Write-StoreRecord $templatePath $script:submittedTemplate
                $parameters=[ordered]@{parameters=[ordered]@{
                    location=[ordered]@{value=$plan.selection.Location}
                    backupResourceGroupName=[ordered]@{value=$plan.selection.BackupResourceGroupName}
                    backupStoreName=[ordered]@{value=$plan.selection.BackupStoreName}
                    ownershipId=[ordered]@{value=$plan.selection.OwnershipId}
                    ownedSubnetResourceIds=[ordered]@{value=@('/selected/subnet')}
                }}
                $parametersPath=Join-Path $Directory 'parameters.json'
                Write-StoreRecord $parametersPath $parameters
                $planHash=Store-Hash (Store-Json $plan)
                if($WrongPlanHash) { $planHash='0'*64 }
                $intent=[ordered]@{
                    scope='independent-backup-store-submission-intent-v1'
                    planSha256=$planHash
                    deploymentName=$plan.deploymentName
                    templateSha256=(Get-FileHash $templatePath -Algorithm SHA256).Hash.ToLowerInvariant()
                    parametersSha256=(Get-FileHash $parametersPath -Algorithm SHA256).Hash.ToLowerInvariant()
                }
                Write-StoreRecord (Join-Path $Directory 'intent.json') $intent
            }
            $badDirectory=$script:directory
            New-TestHistoricalState $badDirectory $true
            $script:directory=$badDirectory
            $failure=$null
            try { $null=Invoke-SantaBackupStoreDeployment -Action Observe -StateDirectory $script:directory }
            catch { $failure=$_.Exception.Message }
            $failure | Should -BeOfType [string]
            $failure | Should -Match 'No submission was attempted'

            $goodDirectory=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
            New-TestHistoricalState $goodDirectory $false
            $script:directory=$goodDirectory
            $result=Invoke-SantaBackupStoreDeployment -Action Observe -StateDirectory $script:directory
            $result.state | Should -BeExactly 'Succeeded'
            $result.Contains('template') | Should -BeFalse
            Should -Invoke Send-StoreDeployment -Times 0 -Exactly
        }
        It 'rejects arbitrary historical source changes and keeps Apply on the current source manifest' {
            $plan=New-SantaBackupStoreDeploymentPlan @script:selectionArgs
            $plan.sourceHashes=Get-StoreReviewedPriorSourceHashes
            { Assert-StorePlan $plan } | Should -Throw
            $plan.sourceHashes['../backup-store/store.bicep']='0000000000000000000000000000000000000000000000000000000000000000'
            { Assert-StorePlan $plan -AllowReviewedPriorSources } | Should -Throw
        }
        It 'fails closed on unavailable, denied or REST-envelope template exports' -ForEach @(
            @{fault='denied'},@{fault='missing'},@{fault='rest-envelope'}
        ) {
            $null=Invoke-SantaBackupStoreDeployment @script:selectionArgs -Action Apply -StateDirectory $script:directory
            $script:exportFault=$fault
            $failure=$null
            try { $null=Invoke-SantaBackupStoreDeployment -Action Observe -StateDirectory $script:directory }
            catch { $failure=$_.Exception.Message }
            $failure | Should -BeOfType [string]
            $failure | Should -Match 'No submission was attempted'
            $failure | Should -Not -Match 'synthetic-raw-export-error-not-for-output'
        }
        It 'rejects missing, null, nonscalar and malformed service template hashes' -ForEach @(
            @{fault='missing'},@{fault='null'},@{fault='array'},@{fault='object'},@{fault='boolean'},@{fault='nondigit'}
        ) {
            $null=Invoke-SantaBackupStoreDeployment @script:selectionArgs -Action Apply -StateDirectory $script:directory
            switch($fault) {
                'missing' { $script:serverTemplateHashFault='missing' }
                'null' { $script:serverTemplateHash=$null }
                'array' { $script:serverTemplateHash=@('15050816737742618192') }
                'object' { $script:serverTemplateHash=@{value='15050816737742618192'} }
                'boolean' { $script:serverTemplateHash=$true }
                'nondigit' { $script:serverTemplateHash='15050816737742618192x' }
            }
            { Invoke-SantaBackupStoreDeployment -Action Observe -StateDirectory $script:directory } | Should -Throw '*No submission was attempted*'
            $script:selectionReadCount | Should -Be 1
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
            Should -Invoke Invoke-StoreAzure -Times 0 -Exactly -ParameterFilter {$Arguments[2] -eq 'export'}
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
                switch($script:fault) {
                    paired {$endpoint.locations=@('westus2','eastus2')}
                    no-selected {$endpoint.locations=@('eastus2')}
                    duplicate {$endpoint.locations=@('westus2','WESTUS2')}
                    unsupported {$endpoint.locations=@('westus2','*')}
                }
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
        It 'accepts the provider-expanded paired region while retaining the selected region' {
            $script:fault='paired';$plan=New-SantaBackupStoreDeploymentPlan @script:selectionArgs
            $result=Get-StoreCreationPreflight $plan
            $result.subnets.Count | Should -Be 1
            Should -Invoke New-SantaPrivateStorageEndpointPlan -Times 1 -Exactly -ParameterFilter {$ReadArm -and -not $EnableStorageEndpoint}
        }
        It 'rejects existing ownership/name, provider and network gaps without remediation' -ForEach @(
            @{fault='tenant'},@{fault='existing-group'},@{fault='name-unavailable'},@{fault='existing-deployment'},@{fault='provider'},
            @{fault='region'},@{fault='global'},@{fault='pending'},@{fault='missing-endpoint'},@{fault='drift'},
            @{fault='no-selected'},@{fault='duplicate'},@{fault='unsupported'}
        ) {
            $script:fault=$fault;$plan=New-SantaBackupStoreDeploymentPlan @script:selectionArgs
            { Get-StoreCreationPreflight $plan } | Should -Throw
            Should -Invoke Invoke-StoreAzure -Times 0 -Exactly -ParameterFilter {$Arguments -contains 'create' -or $Arguments -contains 'register'}
        }
    }
}
