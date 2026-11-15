#Requires -Version 7.6
BeforeDiscovery {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'experiments/vm/PrivateStorageEndpoint.psm1') -Force
}
Describe 'Private owned-subnet Storage endpoint plans' {
    InModuleScope PrivateStorageEndpoint {
        BeforeAll {
            function New-NetworkFixture {
                $sub='11111111-1111-4111-8111-111111111111';$group="/subscriptions/$sub/resourceGroups/rg-azd-santa-vm-synthetic";$base="$group/providers/"
                $vm=$base+'Microsoft.Compute/virtualMachines/vm-santa-lab';$nic=$base+'Microsoft.Network/networkInterfaces/nic-santa-lab'
                $vnet=$base+'Microsoft.Network/virtualNetworks/vnet-santa-lab';$subnet="$vnet/subnets/host";$nsg=$base+'Microsoft.Network/networkSecurityGroups/nsg-santa-lab'
                $tags=@{'azd-env-name'='synthetic';'azd-solution'='azd-santa';purpose='synthetic-vm-lab'};$rows=@{}
                foreach($id in @($group,$vm,$nic,$vnet,$subnet,$nsg)) {$rows[$id]=@{id=$id;etag='W/"11111111-2222-3333-4444-555555555555"';tags=$tags;location='westus2';properties=@{provisioningState='Succeeded'}}}
                $rows[$vm].properties+=@{vmId='33333333-3333-4333-8333-333333333333';networkProfile=@{networkInterfaces=@(@{id=$nic})}}
                $rows[$nic].properties+=@{virtualMachine=@{id=$vm};ipConfigurations=@(@{id="$nic/ipConfigurations/primary";properties=@{subnet=@{id=$subnet}}})}
                $rows[$subnet].properties+=@{addressPrefix='10.247.0.0/27';defaultOutboundAccess=$false;networkSecurityGroup=@{id=$nsg}
                    ipConfigurations=@(@{id="$nic/ipConfigurations/primary"});delegations=@();privateEndpointNetworkPolicies='Disabled';privateLinkServiceNetworkPolicies='Enabled'}
                $rows[$vnet].properties+=@{addressSpace=@{addressPrefixes=@('10.247.0.0/24')};subnets=@($rows[$subnet]);virtualNetworkPeerings=@();enableDdosProtection=$false;enableVmProtection=$false;dhcpOptions=@{dnsServers=@()}}
                $rows[$nsg].properties.securityRules=@(@{name='deny-all-inbound';properties=@{priority=100;direction='Inbound';access='Deny';protocol='*';sourcePortRange='*';destinationPortRange='*';sourceAddressPrefix='*';destinationAddressPrefix='*'}})
                @{rows=$rows;group=$group;vm=$vm;nic=$nic;vnet=$vnet;subnet=$subnet;nsg=$nsg;arguments=@{TenantId='22222222-2222-4222-8222-222222222222';SubscriptionId=$sub;EnvironmentName='synthetic';VmInstanceId='33333333-3333-4333-8333-333333333333'}}
            }
        }
        BeforeEach {
            $script:f=New-NetworkFixture;$script:arguments=$script:f.arguments;$script:reads=0
            Mock Read-Network { param($Arguments)
                $Arguments | Should -Contain '--subscription'
                if($Arguments[0] -eq 'account') {return @{id=$script:f.arguments.SubscriptionId;tenantId=$script:f.arguments.TenantId;state='Enabled';environmentName='AzureCloud'}}
                $Arguments[0] | Should -BeExactly 'rest';$Arguments[2] | Should -BeExactly 'get'
                $script:reads++;$uri=[uri]$Arguments[4];$uri.Host | Should -BeExactly 'management.azure.com'
                $script:f.rows[$uri.AbsolutePath]
            }
        }
        It 'defaults to a local disabled plan with no CLI or network write capability' {
            $p=New-SantaPrivateStorageEndpointPlan @script:arguments
            $p.enableStorageEndpoint | Should -BeFalse;$p.cloudWrite | Should -BeFalse;$p.mutationAuthorized | Should -BeFalse
            $p.urls.Count | Should -Be 6
            Should -Invoke Read-Network -Times 0
            (Get-Command New-SantaPrivateStorageEndpointPlan).Parameters.Keys | Should -Not -Contain 'Apply'
        }
        It 'plans the absent endpoint using actual observed subnet facts and machine-generated empty parameters' {
            $p=New-SantaPrivateStorageEndpointPlan @script:arguments -EnableStorageEndpoint -ReadArm
            $p.changed | Should -BeTrue;$p.existingHostServiceEndpoints | Should -HaveCount 0
            $p.suggestedParameters.existingHostServiceEndpointsJson | Should -BeExactly '[]'
            $p.desiredServiceEndpoints | Should -HaveCount 1
            $p.observedSubnet.id | Should -BeExactly $script:f.subnet
            $p.observedSubnet.etag | Should -BeExactly $script:f.rows[$script:f.subnet].etag
            $p.observedSubnet.properties.ContainsKey('ipConfigurations') | Should -BeTrue
            $p.proposedSubnetRequest.body.properties.ContainsKey('ipConfigurations') | Should -BeFalse
            $p.resourceIds.vnet | Should -BeExactly $script:f.vnet
        }
        It 'preserves all existing nonstorage endpoints and adds only regional Storage in a subnet-only proposal' {
            $script:f.rows[$script:f.subnet].properties.serviceEndpoints=@(@{service='Microsoft.Sql';locations=@('westus2');provisioningState='Succeeded'},@{service='Microsoft.KeyVault';locations=@('*');provisioningState='Succeeded'})
            $p=New-SantaPrivateStorageEndpointPlan @script:arguments -EnableStorageEndpoint -ReadArm
            $p.changed | Should -BeTrue;$p.mutationAuthorized | Should -BeFalse;$p.atomicPreconditionProven | Should -BeFalse
            $p.expectedEtags.Count | Should -Be 4;$p.vnetUpdatePlanned | Should -BeFalse
            $p.proposedSubnetRequest.url | Should -Match '/subnets/host\?'
            ($p.desiredServiceEndpoints.service -join ',') | Should -BeExactly 'Microsoft.Sql,Microsoft.KeyVault,Microsoft.Storage'
            ($p.desiredServiceEndpoints[1].locations -join ',') | Should -BeExactly '*'
            $p.proposedSubnetRequest.body.properties.privateEndpointNetworkPolicies | Should -BeExactly 'Disabled'
            $p.proposedSubnetRequest.body.properties.ContainsKey('ipConfigurations') | Should -BeFalse
            $p.proposedSubnetRequest.body.properties.serviceEndpoints[0].ContainsKey('provisioningState') | Should -BeFalse
            $p.suggestedParameters.existingHostServiceEndpointsJson | ConvertFrom-Json | Should -HaveCount 2
            Should -Invoke Read-Network -Times 14 -Exactly
        }
        It 'keeps an existing Storage endpoint idempotently and never removes endpoints when disabled' {
            $script:f.rows[$script:f.subnet].properties.serviceEndpoints=@(@{service='Microsoft.Storage';locations=@('westus2','westcentralus');provisioningState='Succeeded'})
            foreach($enable in @($true,$false)) {
                $p=New-SantaPrivateStorageEndpointPlan @script:arguments -EnableStorageEndpoint:$enable -ReadArm
                $p.changed | Should -BeFalse;$p.desiredServiceEndpoints | Should -HaveCount 1
                ($p.desiredServiceEndpoints[0].locations -join ',') | Should -BeExactly 'westus2,westcentralus'
            }
        }
        It 'rejects unknown or unrelated network shapes before returning a proposal' -ForEach @(
            @{change='vnet-property'},@{change='subnet-property'},@{change='second-subnet'},@{change='peer'},@{change='route'},@{change='dns'},@{change='endpoint-property'},@{change='global'},@{change='provisioning'},@{change='nsg'},@{change='identity'},@{change='tag'},@{change='etag'},@{change='nic-owner'},@{change='missing-membership'},@{change='shared-subnet'},@{change='typed-egress'},@{change='case-global'}
        ) {
            $f=$script:f
            switch($change) {
                vnet-property {$f.rows[$f.vnet].properties.flowTimeoutInMinutes=10}
                subnet-property {$f.rows[$f.subnet].properties.unknownProperty='preserve me'}
                second-subnet {$f.rows[$f.vnet].properties.subnets+=@{id='unrelated'}}
                peer {$f.rows[$f.vnet].properties.virtualNetworkPeerings=@(@{id='unrelated'})}
                route {$f.rows[$f.subnet].properties.routeTable=@{id='unrelated'}}
                dns {$f.rows[$f.vnet].properties.dhcpOptions.dnsServers=@('10.0.0.4')}
                endpoint-property {$f.rows[$f.subnet].properties.serviceEndpoints=@(@{service='Microsoft.Sql';locations=@('westus2');provisioningState='Succeeded';unknown='preserve me'})}
                global {$f.rows[$f.subnet].properties.serviceEndpoints=@(@{service='Microsoft.Storage.Global';locations=@('*');provisioningState='Succeeded'})}
                provisioning {$f.rows[$f.subnet].properties.provisioningState='Updating'}
                nsg {$f.rows[$f.nsg].properties.securityRules[0].properties.access='Allow'}
                identity {$f.rows[$f.vm].properties.vmId='44444444-4444-4444-8444-444444444444'}
                tag {$f.rows[$f.vnet].tags['azd-env-name']='foreign'}
                etag {$f.rows[$f.subnet].Remove('etag')}
                nic-owner {$f.rows[$f.nic].properties.virtualMachine.id='unrelated'}
                missing-membership {$f.rows[$f.subnet].properties.Remove('ipConfigurations')}
                shared-subnet {$f.rows[$f.subnet].properties.ipConfigurations+=@{id='unrelated'}}
                typed-egress {$f.rows[$f.subnet].properties.defaultOutboundAccess='false'}
                case-global {$f.rows[$f.subnet].properties.serviceEndpoints=@(@{service='Microsoft.storage.global';locations=@('*');provisioningState='Succeeded'})}
            }
            {New-SantaPrivateStorageEndpointPlan @script:arguments -EnableStorageEndpoint -ReadArm} | Should -Throw '*failed or is unknown*'
        }
        It 'treats Storage service aliases idempotently without editing retained entries' {
            $script:f.rows[$script:f.subnet].properties.serviceEndpoints=@(@{service='Microsoft.storage';locations=@('westus2');provisioningState='Succeeded'})
            $p=New-SantaPrivateStorageEndpointPlan @script:arguments -EnableStorageEndpoint -ReadArm
            $p.changed | Should -BeFalse;$p.desiredServiceEndpoints | Should -HaveCount 1
            $p.desiredServiceEndpoints[0].service | Should -BeExactly 'Microsoft.storage'
        }
        It 'rejects wrong cached context before any resource GET' {
            Mock Read-Network { @{id=$script:f.arguments.SubscriptionId;tenantId='44444444-4444-4444-8444-444444444444';state='Enabled';environmentName='AzureCloud'} }
            {New-SantaPrivateStorageEndpointPlan @script:arguments -ReadArm} | Should -Throw
            Should -Invoke Read-Network -Times 1 -Exactly
        }
        It 'rejects changed observations and ETags after the second complete readback' {
            Mock Read-Network { param($Arguments)
                if($Arguments[0] -eq 'account') {return @{id=$script:f.arguments.SubscriptionId;tenantId=$script:f.arguments.TenantId;state='Enabled';environmentName='AzureCloud'}}
                $script:reads++;$row=$script:f.rows[([uri]$Arguments[4]).AbsolutePath] | ConvertTo-Json -Depth 48 | ConvertFrom-Json -Depth 48 -AsHashtable
                if($script:reads -gt 6) {$row.etag='W/"changed"'}
                $row
            }
            {New-SantaPrivateStorageEndpointPlan @script:arguments -EnableStorageEndpoint -ReadArm} | Should -Throw '*failed or is unknown*'
        }
        It 'rejects missing forbidden and unknown reads without creation or retries' -ForEach @(@{failure='404 missing'},@{failure='403 forbidden raw secret'},@{failure='timeout'}) {
            Mock Read-Network {throw $failure}
            {New-SantaPrivateStorageEndpointPlan @script:arguments -EnableStorageEndpoint -ReadArm} | Should -Throw '*No network write was attempted*'
            Should -Invoke Read-Network -Times 1 -Exactly
        }
    }
}

Describe 'Storage endpoint transport and optional template boundary' {
    InModuleScope PrivateStorageEndpoint {
        It 'dispatches the exact selected read argument array into the existing bounded reader' {
            Mock Invoke-SantaEndpointAzJson -ModuleName HttpsEndpoint {param($Arguments)
                $Arguments | Should -HaveCount 7
                $Arguments[0] | Should -BeExactly 'rest';$Arguments[2] | Should -BeExactly 'get'
                @{observed=$true}
            }
            (Read-Network @('rest','--method','get','--url','https://management.azure.com/selected?api-version=2024-05-01','--subscription','11111111-1111-4111-8111-111111111111')).observed | Should -BeTrue
            Should -Invoke Invoke-SantaEndpointAzJson -ModuleName HttpsEndpoint -Times 1 -Exactly
        }
    }
    It 'wires optional empty/default inputs without altering root Intune or backend hooks' {
        $root=Split-Path $PSScriptRoot -Parent
        $input=Get-Content (Join-Path $root 'experiments/vm/infra/main.parameters.json') -Raw | ConvertFrom-Json
        $input.parameters.backupStorageEndpoint.value | Should -BeExactly '${SANTA_VM_STORAGE_ENDPOINT_ENABLED}'
        $input.parameters.existingHostServiceEndpointsJson.value | Should -BeExactly '${SANTA_VM_HOST_SERVICE_ENDPOINTS_JSON}'
        Get-Content (Join-Path $root 'infra/main.bicep') -Raw | Should -Not -Match 'Microsoft.Compute|backupStorageEndpoint'
        Get-Content (Join-Path $root 'experiments/vm/infra/main.bicep') -Raw | Should -Match "param backupStorageEndpoint string = ''"
        Get-Content (Join-Path $root 'experiments/vm/infra/host.bicep') -Raw | Should -Match 'param enableBackupStorageEndpoint bool = false'
        Get-Content (Join-Path $root 'experiments/vm/azure.yaml') -Raw | Should -Not -Match 'StorageEndpoint'
    }
}
Describe 'Compiled Storage endpoint parameter sets' {
    It 'compiles default and opted-in sets with the existing locally selected compiler' -Skip:([string]::IsNullOrEmpty($env:SANTA_BICEP_EXE)) {
        $root=Split-Path $PSScriptRoot -Parent
        $compiled=Join-Path $TestDrive 'main.json'
        & $env:SANTA_BICEP_EXE build (Join-Path $root 'experiments/vm/infra/main.bicep') --outfile $compiled
        $LASTEXITCODE | Should -Be 0
        $template=Get-Content $compiled -Raw | ConvertFrom-Json -AsHashtable
        $template.parameters.backupStorageEndpoint.defaultValue | Should -BeExactly ''
        $template.parameters.existingHostServiceEndpointsJson.defaultValue | Should -BeExactly ''
        $hostTemplate=$template.resources[1].properties.template
        $hostTemplate.parameters.enableBackupStorageEndpoint.defaultValue | Should -BeFalse
        $hostTemplate.parameters.existingHostServiceEndpoints.defaultValue | Should -HaveCount 0
        foreach($name in @('default','enabled')) {
            $params=Join-Path $TestDrive ($name+'.json')
            & $env:SANTA_BICEP_EXE build-params (Join-Path $root "tests/fixtures/storage-endpoint/$name.bicepparam") --outfile $params
            $LASTEXITCODE | Should -Be 0
            $values=Get-Content $params -Raw | ConvertFrom-Json -AsHashtable
            if($name -eq 'default') { $values.parameters.ContainsKey('backupStorageEndpoint') | Should -BeFalse }
            else {
                $values.parameters.backupStorageEndpoint.value | Should -BeExactly 'true'
                ($values.parameters.existingHostServiceEndpointsJson.value | ConvertFrom-Json).service | Should -BeExactly 'Microsoft.Sql'
            }
        }
    }
}
