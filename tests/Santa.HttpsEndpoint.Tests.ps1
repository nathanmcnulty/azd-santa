#Requires -Version 7.6
BeforeDiscovery {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'experiments/server/HttpsEndpoint.psm1') -Force
}
Describe 'Selected cached ARM endpoint producer' {
    InModuleScope HttpsEndpoint {
        BeforeAll {
            function New-EndpointFixture {
                $sub='11111111-1111-4111-8111-111111111111'; $group="/subscriptions/$sub/resourceGroups/rg-azd-santa-vm-synthetic"
                $base="$group/providers/"; $vm=$base+'Microsoft.Compute/virtualMachines/vm-santa-lab'
                $nic=$base+'Microsoft.Network/networkInterfaces/nic-santa-lab'; $ip="$nic/ipConfigurations/primary"
                $pip=$base+'Microsoft.Network/publicIPAddresses/pip-santa-lab-egress'
                $subnet=$base+'Microsoft.Network/virtualNetworks/vnet-santa-lab/subnets/host'
                $nsg=$base+'Microsoft.Network/networkSecurityGroups/nsg-santa-lab'
                $tags=@{'azd-solution'='azd-santa'; purpose='synthetic-vm-lab'; 'azd-env-name'='synthetic'}
                $rows=@{}
                foreach ($id in @($group,$vm,$nic,$pip,$subnet,$nsg)) {
                    $rows[$id]=@{id=$id; location='westus2'; tags=$tags; properties=@{provisioningState='Succeeded'}}
                }
                $rows[$vm].properties.vmId='33333333-3333-4333-8333-333333333333'
                $rows[$vm].properties.networkProfile=@{networkInterfaces=@(@{id=$nic;properties=@{primary=$true}})}
                $rows[$nic].properties.virtualMachine=@{id=$vm}
                $rows[$nic].properties.ipConfigurations=@(@{id=$ip;name='primary';properties=@{publicIPAddress=@{id=$pip};subnet=@{id=$subnet}}})
                $rows[$pip].sku=@{name='Standard'}
                $rows[$pip].properties += @{publicIPAllocationMethod='Static'; publicIPAddressVersion='IPv4';ipAddress='8.8.8.8';ipConfiguration=@{id=$ip}
                    dnsSettings=@{domainNameLabel='santa-1111111111114111-synthetic-vm';fqdn='santa-1111111111114111-synthetic-vm.westus2.cloudapp.azure.com'}}
                $rows[$subnet].properties += @{networkSecurityGroup=@{id=$nsg};defaultOutboundAccess=$false}
                $rows[$nsg].properties.securityRules=@(@{name='deny-all-inbound';properties=@{priority=100;direction='Inbound';access='Deny';protocol='*'
                    sourcePortRange='*';destinationPortRange='*';sourceAddressPrefix='*';destinationAddressPrefix='*'}})
                @{rows=$rows;vm=$vm;nic=$nic;pip=$pip;subnet=$subnet;nsg=$nsg;group=$group
                    arguments=@{TenantId='22222222-2222-4222-8222-222222222222';SubscriptionId=$sub
                        VmInstanceId='33333333-3333-4333-8333-333333333333';EnvironmentName='synthetic'}}
            }
        }
        BeforeEach {
            $script:fixture=New-EndpointFixture; $script:reads=0
            Mock Invoke-SantaEndpointAzJson { param($Arguments)
                $Arguments | Should -Contain '--subscription'
                if ($Arguments[0] -eq 'account') {
                    return @{id=$script:fixture.arguments.SubscriptionId;tenantId=$script:fixture.arguments.TenantId;state='Enabled';environmentName='AzureCloud'}
                }
                $Arguments[0] | Should -BeExactly 'rest'; $Arguments[2] | Should -BeExactly 'get'
                $script:reads++
                $uri=[uri]$Arguments[4]
                $uri.Host | Should -BeExactly 'management.azure.com'
                $script:fixture.rows[$uri.AbsolutePath]
            }
        }
        It 'produces the exact renderer schema after two complete linked readbacks' {
            $arguments=$script:fixture.arguments; $facts=Get-SantaHttpsEndpointFacts @arguments
            $facts.Count | Should -Be 11
            $facts.Fqdn | Should -BeExactly $script:fixture.rows[$script:fixture.pip].properties.dnsSettings.fqdn
            $script:reads | Should -Be 12
            $path=Join-Path $TestDrive 'facts.json'; $facts | ConvertTo-Json | Set-Content $path
            $renderer=Join-Path $PSScriptRoot '../experiments/server/prepare_https_proxy.py'
            & python -I $renderer --facts $path --expected-facts-sha256 (Get-FileHash $path).Hash.ToLowerInvariant() --destination (Join-Path $TestDrive 'candidate')
            $LASTEXITCODE | Should -Be 0
            $candidate=Get-Content (Join-Path $TestDrive 'candidate/candidate.json') -Raw | ConvertFrom-Json
            $candidate.admission | Should -BeExactly 'held-closed'
            ($candidate.gates.PSObject.Properties.Value | Select-Object -Unique) | Should -BeExactly 'not_run'
        }
        It 'rejects substituted links, incomplete identity and open ingress' -ForEach @(
            @{mutation='vmid'},@{mutation='multinic'},@{mutation='multiconfig'},@{mutation='nicowner'},@{mutation='pipbackref'},
            @{mutation='subnet'},@{mutation='nsg'},@{mutation='location'},@{mutation='tag'},@{mutation='dns'},
            @{mutation='label'},@{mutation='scope'},@{mutation='address'},@{mutation='allow'},@{mutation='extra_rule'}
        ) {
            $f=$script:fixture
            switch ($mutation) {
                vmid {$f.rows[$f.vm].properties.vmId='44444444-4444-4444-8444-444444444444'}
                multinic {$f.rows[$f.vm].properties.networkProfile.networkInterfaces += @{id=$f.nic;properties=@{primary=$true}}}
                multiconfig {$f.rows[$f.nic].properties.ipConfigurations += $f.rows[$f.nic].properties.ipConfigurations[0]}
                nicowner {$f.rows[$f.nic].properties.virtualMachine.id='/foreign'}
                pipbackref {$f.rows[$f.pip].properties.ipConfiguration.id='/foreign'}
                subnet {$f.rows[$f.nic].properties.ipConfigurations[0].properties.subnet.id='/foreign'}
                nsg {$f.rows[$f.subnet].properties.networkSecurityGroup.id='/foreign'}
                location {$f.rows[$f.pip].location='eastus'}
                tag {$f.rows[$f.pip].tags['azd-env-name']='other'}
                dns {$f.rows[$f.pip].properties.dnsSettings.Remove('fqdn')}
                label {$f.rows[$f.pip].properties.dnsSettings.domainNameLabel='other'}
                scope {$f.rows[$f.pip].properties.dnsSettings.domainNameLabelScope='ResourceGroupReuse'}
                address {$f.rows[$f.pip].properties.ipAddress='127.0.0.1'}
                allow {$f.rows[$f.nsg].properties.securityRules[0].properties.access='Allow'}
                extra_rule {$f.rows[$f.nsg].properties.securityRules += @{name='unexpected';properties=@{}}}
            }
            $arguments=$f.arguments
            { Get-SantaHttpsEndpointFacts @arguments } | Should -Throw
        }
        It 'rejects a change during the final complete linkage readback' {
            Mock Invoke-SantaEndpointAzJson { param($Arguments)
                if ($Arguments[0] -eq 'account') { return @{id=$script:fixture.arguments.SubscriptionId;tenantId=$script:fixture.arguments.TenantId;state='Enabled';environmentName='AzureCloud'} }
                $script:reads++; $row=$script:fixture.rows[([uri]$Arguments[4]).AbsolutePath]
                if ($script:reads -gt 6) { return @{id=$row.id;changed=$true} }
                $row
            }
            $arguments=$script:fixture.arguments
            { Get-SantaHttpsEndpointFacts @arguments } | Should -Throw
        }
        It 'rejects a different cached tenant before ARM resource reads' {
            Mock Invoke-SantaEndpointAzJson { @{id=$script:fixture.arguments.SubscriptionId;tenantId='44444444-4444-4444-8444-444444444444';state='Enabled';environmentName='AzureCloud'} }
            $arguments=$script:fixture.arguments
            { Get-SantaHttpsEndpointFacts @arguments } | Should -Throw
            $script:reads | Should -Be 0
        }
    }
}
