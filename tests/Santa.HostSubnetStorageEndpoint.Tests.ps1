#Requires -Version 7.6
Describe 'Optional owned-subnet Storage service endpoint' {
    BeforeAll {
        $script:root = Split-Path $PSScriptRoot -Parent
        $script:modulePath = Join-Path $script:root 'experiments/vm/HostSubnetStorageEndpoint.psm1'
        Import-Module $script:modulePath -Force
        $script:subscription = '11111111-1111-4111-8111-111111111111'
        $script:environment = 'offline'
        $script:location = 'westus2'
        $script:groupId = "/subscriptions/$script:subscription/resourceGroups/rg-azd-santa-vm-$script:environment"
        $script:vnetId = "$script:groupId/providers/Microsoft.Network/virtualNetworks/vnet-santa-lab"
        $script:nsgId = "$script:groupId/providers/Microsoft.Network/networkSecurityGroups/nsg-santa-lab"
        $script:nicId = "$script:groupId/providers/Microsoft.Network/networkInterfaces/nic-santa-lab"
        $script:pipId = "$script:groupId/providers/Microsoft.Network/publicIPAddresses/pip-santa-lab-egress"
        $script:vmId = "$script:groupId/providers/Microsoft.Compute/virtualMachines/vm-santa-lab"
        $script:subnetId = "$script:vnetId/subnets/host"
        $script:vmInstance = '22222222-2222-4222-8222-222222222222'
        $script:tags = @{ 'azd-env-name' = $script:environment; 'azd-solution' = 'azd-santa'; purpose = 'synthetic-vm-lab' }
        function New-SantaEndpointObservation {
            param([object[]] $ServiceEndpoints = @())
            $subnet = @{
                id = $script:subnetId; name = 'host'; properties = @{
                    addressPrefix = '10.247.0.0/27'; defaultOutboundAccess = $false
                    networkSecurityGroup = @{ id = $script:nsgId }; serviceEndpoints = @($ServiceEndpoints)
                    privateEndpointNetworkPolicies = 'Enabled'; privateLinkServiceNetworkPolicies = 'Enabled'
                    delegations = @(); serviceEndpointPolicies = @(); ipConfigurations = @(); ipAllocations = @()
                    ipamPoolPrefixAllocations = @(); applicationGatewayIPConfigurations = @()
                }
            }
            return @{
                resourceGroup = @{ id = $script:groupId; name = "rg-azd-santa-vm-$script:environment"; location = $script:location; tags = ($script:tags.Clone()) }
                vnet = @{ id = $script:vnetId; location = $script:location; tags = ($script:tags.Clone()); properties = @{
                    addressSpace = @{ addressPrefixes = @('10.247.0.0/24') }; subnets = @($subnet)
                } }
                nsg = @{ id = $script:nsgId; location = $script:location; tags = ($script:tags.Clone()); properties = @{ securityRules = @(@{
                    name = 'deny-all-inbound'; properties = @{
                        direction = 'Inbound'; access = 'Deny'; protocol = '*'; priority = 100
                        sourcePortRange = '*'; destinationPortRange = '*'; sourceAddressPrefix = '*'; destinationAddressPrefix = '*'
                    }
                }) } }
                nic = @{ id = $script:nicId; location = $script:location; tags = ($script:tags.Clone()); properties = @{ ipConfigurations = @(@{
                    name = 'primary'; properties = @{ privateIPAllocationMethod = 'Dynamic'; subnet = @{ id = $script:subnetId }; publicIPAddress = @{ id = $script:pipId } }
                }) } }
                publicIp = @{ id = $script:pipId; location = $script:location; tags = ($script:tags.Clone()); sku = @{ name = 'Standard' }; properties = @{
                    publicIPAllocationMethod = 'Static'; publicIPAddressVersion = 'IPv4'; dnsSettings = @{ domainNameLabel = 'santa-1111111111114111-offline-vm' }
                } }
                vm = @{ id = $script:vmId; location = $script:location; tags = ($script:tags.Clone()); properties = @{ vmId = $script:vmInstance; networkProfile = @{ networkInterfaces = @(@{ id = $script:nicId }) } } }
            }
        }
    }

    It 'defaults missing and false settings off and rejects ambiguous values' {
        (Get-SantaBooleanSetting -Value '') | Should -BeFalse
        (Get-SantaBooleanSetting -Value 'false') | Should -BeFalse
        (Get-SantaBooleanSetting -Value 'true') | Should -BeTrue
        { Get-SantaBooleanSetting -Value 'yes' } | Should -Throw '*exactly true or false*'
    }

    It 'keeps a fresh default deployment free of endpoint and storage resources' {
        $plan = New-SantaHostSubnetEndpointPlan -SubscriptionId $script:subscription -EnvironmentName $script:environment `
            -Location $script:location -SourceRevision ('a' * 40) -SourceSha256 ('b' * 64) -PlanId ([guid]::NewGuid()) -EnableStorageEndpoint $false -ValidatedNetwork $null
        $plan.EndpointBoolean | Should -Be 'false'
        $plan.DesiredServiceEndpoints | Should -BeNullOrEmpty
        $plan.Plan.plan.storageAccountProvisioned | Should -BeFalse
        $plan.Plan.plan.endpointIncrementalMonthlyCost | Should -Be 0
        $plan.Plan.requiresConfirmation | Should -BeFalse
    }

    It 'retains unrelated endpoints and subnet network policy in the default path' {
        $observation = New-SantaEndpointObservation -ServiceEndpoints @(@{ service = 'Microsoft.KeyVault'; locations = @('*') })
        $validated = Assert-SantaOwnedHostNetwork -SubscriptionId $script:subscription -EnvironmentName $script:environment `
            -Location $script:location -ResourceGroupName "rg-azd-santa-vm-$script:environment" -ExpectedVmInstanceId $script:vmInstance -Observation $observation
        $plan = New-SantaHostSubnetEndpointPlan -SubscriptionId $script:subscription -EnvironmentName $script:environment `
            -Location $script:location -SourceRevision ('a' * 40) -SourceSha256 ('b' * 64) -PlanId ([guid]::NewGuid()) -EnableStorageEndpoint $false -ValidatedNetwork $validated
        $plan.DesiredServiceEndpoints.Count | Should -Be 1
        $plan.DesiredServiceEndpoints[0].service | Should -Be 'Microsoft.KeyVault'
        $plan.PrivateEndpointNetworkPolicies | Should -Be 'Enabled'
        $plan.Plan.requiresConfirmation | Should -BeFalse
    }

    It 'adds only Microsoft.Storage, preserves unrelated endpoints, and requires a fresh existing-subnet review' {
        $observation = New-SantaEndpointObservation -ServiceEndpoints @(@{ service = 'Microsoft.KeyVault'; locations = @('*') })
        $validated = Assert-SantaOwnedHostNetwork -SubscriptionId $script:subscription -EnvironmentName $script:environment `
            -Location $script:location -ResourceGroupName "rg-azd-santa-vm-$script:environment" -ExpectedVmInstanceId $script:vmInstance -Observation $observation
        $plan = New-SantaHostSubnetEndpointPlan -SubscriptionId $script:subscription -EnvironmentName $script:environment `
            -Location $script:location -SourceRevision ('a' * 40) -SourceSha256 ('b' * 64) -PlanId ([guid]::NewGuid()) -EnableStorageEndpoint $true -ValidatedNetwork $validated
        $plan.DesiredServiceEndpoints.Count | Should -Be 2
        @($plan.DesiredServiceEndpoints.service) | Should -Contain 'Microsoft.KeyVault'
        @($plan.DesiredServiceEndpoints.service) | Should -Contain 'Microsoft.Storage'
        $plan.Plan.plan.subnetId | Should -Be $script:subnetId
        $plan.Plan.plan.vmInstanceId | Should -Be $script:vmInstance
        $plan.Plan.plan.ownershipChecks | Should -Contain 'prior azd VM resource and instance outputs'
        $plan.Plan.requiresConfirmation | Should -BeTrue
        $plan.Plan.plan.performsMutation | Should -BeFalse
        $plan.EndpointBoolean | Should -Be 'true'
    }

    It 'keeps existing Storage endpoint location scope unchanged and does not duplicate it' {
        $storage = @{ service = 'Microsoft.Storage'; locations = @('westus2') }
        $observation = New-SantaEndpointObservation -ServiceEndpoints @($storage, @{ service = 'Microsoft.KeyVault'; locations = @('*') })
        $validated = Assert-SantaOwnedHostNetwork -SubscriptionId $script:subscription -EnvironmentName $script:environment `
            -Location $script:location -ResourceGroupName "rg-azd-santa-vm-$script:environment" -ExpectedVmInstanceId $script:vmInstance -Observation $observation
        $plan = New-SantaHostSubnetEndpointPlan -SubscriptionId $script:subscription -EnvironmentName $script:environment `
            -Location $script:location -SourceRevision ('a' * 40) -SourceSha256 ('b' * 64) -PlanId ([guid]::NewGuid()) -EnableStorageEndpoint $true -ValidatedNetwork $validated
        $plan.DesiredServiceEndpoints.Count | Should -Be 2
        @($plan.DesiredServiceEndpoints | Where-Object service -EQ 'Microsoft.Storage')[0].locations | Should -Be @('westus2')
        $plan.Plan.requiresConfirmation | Should -BeFalse
    }

    It 'rejects identity and networking drift even when tags still look owned' {
        $wrongNic = New-SantaEndpointObservation
        $wrongNic.nic.properties.ipConfigurations[0].properties.subnet.id = "$script:vnetId/subnets/other"
        { Assert-SantaOwnedHostNetwork -SubscriptionId $script:subscription -EnvironmentName $script:environment `
            -Location $script:location -ResourceGroupName "rg-azd-santa-vm-$script:environment" -ExpectedVmInstanceId $script:vmInstance -Observation $wrongNic } | Should -Throw '*NIC does not link*'

        $recreatedVm = New-SantaEndpointObservation
        $recreatedVm.vm.properties.vmId = '33333333-3333-4333-8333-333333333333'
        { Assert-SantaOwnedHostNetwork -SubscriptionId $script:subscription -EnvironmentName $script:environment `
            -Location $script:location -ResourceGroupName "rg-azd-santa-vm-$script:environment" -ExpectedVmInstanceId $script:vmInstance -Observation $recreatedVm } | Should -Throw '*instance identity*'

        $extraSubnet = New-SantaEndpointObservation
        $extraSubnet.vnet.properties.subnets += @{ id = "$script:vnetId/subnets/other"; name = 'other'; properties = @{} }
        { Assert-SantaOwnedHostNetwork -SubscriptionId $script:subscription -EnvironmentName $script:environment `
            -Location $script:location -ResourceGroupName "rg-azd-santa-vm-$script:environment" -ExpectedVmInstanceId $script:vmInstance -Observation $extraSubnet } | Should -Throw '*additional subnets*'

        $foreignTag = New-SantaEndpointObservation
        $foreignTag.vnet.tags.owner = 'someone-else'
        { Assert-SantaOwnedHostNetwork -SubscriptionId $script:subscription -EnvironmentName $script:environment `
            -Location $script:location -ResourceGroupName "rg-azd-santa-vm-$script:environment" -ExpectedVmInstanceId $script:vmInstance -Observation $foreignTag } | Should -Throw '*unreviewed tags*'

        $standardEndpoint = New-SantaEndpointObservation -ServiceEndpoints @(@{ service = 'Microsoft.KeyVault'; locations = @('*'); networkIdentifier = @{ id = '/providers/Microsoft.Network/networkIdentifiers/example' } })
        { Assert-SantaOwnedHostNetwork -SubscriptionId $script:subscription -EnvironmentName $script:environment `
            -Location $script:location -ResourceGroupName "rg-azd-santa-vm-$script:environment" -ExpectedVmInstanceId $script:vmInstance -Observation $standardEndpoint } | Should -Throw '*network identifier*'
    }

    It 'binds a proposed change to a unique source-bound plan hash' {
        $validated = Assert-SantaOwnedHostNetwork -SubscriptionId $script:subscription -EnvironmentName $script:environment `
            -Location $script:location -ResourceGroupName "rg-azd-santa-vm-$script:environment" -ExpectedVmInstanceId $script:vmInstance -Observation (New-SantaEndpointObservation)
        $one = New-SantaHostSubnetEndpointPlan -SubscriptionId $script:subscription -EnvironmentName $script:environment `
            -Location $script:location -SourceRevision ('a' * 40) -SourceSha256 ('b' * 64) -PlanId ([guid]::NewGuid()) -EnableStorageEndpoint $true -ValidatedNetwork $validated
        $two = New-SantaHostSubnetEndpointPlan -SubscriptionId $script:subscription -EnvironmentName $script:environment `
            -Location $script:location -SourceRevision ('a' * 40) -SourceSha256 ('b' * 64) -PlanId ([guid]::NewGuid()) -EnableStorageEndpoint $true -ValidatedNetwork $validated
        $samePlanId = [guid]::Parse('44444444-4444-4444-8444-444444444444')
        $sourceOne = New-SantaHostSubnetEndpointPlan -SubscriptionId $script:subscription -EnvironmentName $script:environment `
            -Location $script:location -SourceRevision ('a' * 40) -SourceSha256 ('b' * 64) -PlanId $samePlanId -EnableStorageEndpoint $true -ValidatedNetwork $validated
        $sourceTwo = New-SantaHostSubnetEndpointPlan -SubscriptionId $script:subscription -EnvironmentName $script:environment `
            -Location $script:location -SourceRevision ('a' * 40) -SourceSha256 ('c' * 64) -PlanId $samePlanId -EnableStorageEndpoint $true -ValidatedNetwork $validated
        $one.Plan.planSha256 | Should -Not -Be $two.Plan.planSha256
        $sourceOne.Plan.planSha256 | Should -Not -Be $sourceTwo.Plan.planSha256
        $one.Plan.plan.sourceRevision | Should -Be ('a' * 40)
        $one.Plan.plan.sourceSha256 | Should -Be ('b' * 64)
    }

    It 'keeps the root project compute-free and binds endpoint source into permission evidence' {
        $main = Get-Content -Raw (Join-Path $script:root 'experiments/vm/infra/main.bicep')
        $hostTemplate = Get-Content -Raw (Join-Path $script:root 'experiments/vm/infra/host.bicep')
        $parameters = Get-Content -Raw (Join-Path $script:root 'experiments/vm/infra/main.parameters.json') | ConvertFrom-Json
        $main | Should -Match "param enableStorageServiceEndpoint string = 'false'"
        $main | Should -Match 'hostSubnetServiceEndpointsJson'
        $hostTemplate | Should -Match "service: 'Microsoft.Storage'"
        $hostTemplate | Should -Match 'serviceEndpoints: serviceEndpoints'
        $hostTemplate | Should -Match "access: 'Deny'"
        $parameters.parameters.enableStorageServiceEndpoint.value | Should -Be '${SANTA_VM_ENABLE_STORAGE_SERVICE_ENDPOINT}'
        Get-Content -Raw (Join-Path $script:root 'infra/main.bicep') | Should -Not -Match 'Microsoft.Compute/'

        $manifest = Get-Content -Raw (Join-Path $script:root 'azd-permissions.json') | ConvertFrom-Json
        $deploy = @($manifest.requirements | Where-Object { $_.feature -EQ 'synthetic-vm-lab' -and $_.phase -EQ 'deployment' })[0]
        $evidence = @($deploy.evidence | Where-Object { $_.path -in @(
            'experiments/vm/infra/main.bicep','experiments/vm/infra/host.bicep','experiments/vm/infra/main.parameters.json',
            'experiments/vm/PrivateVmInstall.psm1','experiments/vm/HostSubnetStorageEndpoint.psm1','tests/Santa.HostSubnetStorageEndpoint.Tests.ps1'
        ) })
        $evidence.Count | Should -Be 6
        foreach ($entry in $evidence) {
            $actualHash = (Get-FileHash (Join-Path $script:root $entry.path) -Algorithm SHA256).Hash.ToLowerInvariant()
            $actualHash | Should -Be $entry.sha256
        }
    }
}
