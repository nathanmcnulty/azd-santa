#Requires -Version 7.6
Set-StrictMode -Version Latest

function Get-SantaBooleanSetting {
    [CmdletBinding()]
    param([AllowNull()][string] $Value, [string] $Name = 'setting')

    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    if ($Value -ceq 'true') { return $true }
    if ($Value -ceq 'false') { return $false }
    throw "$Name must be exactly true or false."
}

function Get-SantaProperty {
    param([AllowNull()][object] $InputObject, [Parameter(Mandatory)][string] $Name)
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [System.Collections.IDictionary]) {
        foreach ($key in $InputObject.Keys) { if ([string]$key -ieq $Name) { return $InputObject[$key] } }
        return $null
    }
    $property = $InputObject.PSObject.Properties | Where-Object Name -IEQ $Name | Select-Object -First 1
    if ($property) { return $property.Value }
    return $null
}

function Assert-SantaResourceTags {
    param([object] $Resource, [string] $EnvironmentName, [string] $Purpose)
    $tags = Get-SantaProperty $Resource 'tags'
    if ($null -eq $tags) { throw 'Existing lab resource has no current ownership tags.' }
    $expected = [ordered]@{
        'azd-env-name' = $EnvironmentName
        'azd-solution' = 'azd-santa'
        purpose = 'synthetic-vm-lab'
    }
    foreach ($name in $expected.Keys) {
        $actual = Get-SantaProperty $tags $name
        if ([string]$actual -cne [string]$expected[$name]) { throw 'Existing lab resource ownership tags do not match the selected environment.' }
    }
    foreach ($key in $tags.Keys) {
        if ($key -notin $expected.Keys) { throw 'Existing lab resource has unreviewed tags that the template could replace.' }
    }
}

function Assert-SantaResourceId {
    param([object] $Resource, [string] $ExpectedId)
    $actual = [string](Get-SantaProperty $Resource 'id')
    if ([string]::IsNullOrWhiteSpace($actual) -or $actual -ine $ExpectedId) { throw 'Existing lab resource identity does not match the selected resource path.' }
}

function Assert-SantaEmptyCollection {
    param([object] $Object, [string] $PropertyName)
    $value = Get-SantaProperty $Object $PropertyName
    if ($null -ne $value -and @($value).Count -gt 0) { throw "Existing host subnet has unsupported '$PropertyName' configuration; refusing to overwrite it." }
}

function ConvertTo-SantaServiceEndpointList {
    param([AllowNull()][object] $Endpoints)
    $result = [Collections.Generic.List[object]]::new()
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    if ($null -eq $Endpoints) { return @() }
    foreach ($endpoint in @($Endpoints)) {
        $service = [string](Get-SantaProperty $endpoint 'service')
        if ($service -notmatch '^Microsoft\.[A-Za-z0-9.]+$' -or -not $seen.Add($service)) {
            throw 'Existing host subnet contains an invalid or duplicate service endpoint.'
        }
        foreach ($key in $endpoint.Keys) {
            if ($key -notin @('service', 'locations', 'provisioningState', 'networkIdentifier')) {
                throw 'Existing service endpoint has an unrecognized property; refusing to replace it.'
            }
        }
        if ($null -ne (Get-SantaProperty $endpoint 'networkIdentifier')) {
            throw 'Existing service endpoint has an unsupported network identifier; refusing to replace it.'
        }
        $locations = @((Get-SantaProperty $endpoint 'locations') | ForEach-Object { [string]$_ })
        if (@($locations | Where-Object { $_ -notmatch '^[A-Za-z0-9* -]{1,64}$' }).Count -gt 0) {
            throw 'Existing service endpoint location is invalid.'
        }
        $result.Add([ordered]@{ service = $service; locations = @($locations) })
    }
    return @($result | Sort-Object { $_.service.ToLowerInvariant() })
}

function Assert-SantaOwnedHostNetwork {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $SubscriptionId,
        [Parameter(Mandatory)][string] $EnvironmentName,
        [Parameter(Mandatory)][string] $Location,
        [Parameter(Mandatory)][string] $ResourceGroupName,
        [Parameter(Mandatory)][guid] $ExpectedVmInstanceId,
        [Parameter(Mandatory)][object] $Observation
    )

    $group = Get-SantaProperty $Observation 'resourceGroup'
    $vnet = Get-SantaProperty $Observation 'vnet'
    $nsg = Get-SantaProperty $Observation 'nsg'
    $nic = Get-SantaProperty $Observation 'nic'
    $pip = Get-SantaProperty $Observation 'publicIp'
    $vm = Get-SantaProperty $Observation 'vm'
    if (@($group, $vnet, $nsg, $nic, $pip, $vm | Where-Object { $null -ne $_ }).Count -ne 6) {
        throw 'Existing VM lab is partial; refusing to infer ownership or overwrite its network.'
    }

    $groupId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName"
    $vnetId = "$groupId/providers/Microsoft.Network/virtualNetworks/vnet-santa-lab"
    $nsgId = "$groupId/providers/Microsoft.Network/networkSecurityGroups/nsg-santa-lab"
    $nicId = "$groupId/providers/Microsoft.Network/networkInterfaces/nic-santa-lab"
    $pipId = "$groupId/providers/Microsoft.Network/publicIPAddresses/pip-santa-lab-egress"
    $vmId = "$groupId/providers/Microsoft.Compute/virtualMachines/vm-santa-lab"
    $subnetId = "$vnetId/subnets/host"

    foreach ($pair in @(@($group, $groupId), @($vnet, $vnetId), @($nsg, $nsgId), @($nic, $nicId), @($pip, $pipId), @($vm, $vmId))) {
        Assert-SantaResourceId -Resource $pair[0] -ExpectedId $pair[1]
        Assert-SantaResourceTags -Resource $pair[0] -EnvironmentName $EnvironmentName -Purpose 'synthetic-vm-lab'
        $resourceLocation = Get-SantaProperty $pair[0] 'location'
        if ($resourceLocation -and [string]$resourceLocation -ine $Location) { throw 'Existing lab resource location differs from the selected environment.' }
    }

    $groupTags = Get-SantaProperty $group 'tags'
    if ([string](Get-SantaProperty $groupTags 'azd-env-name') -cne $EnvironmentName) { throw 'Existing resource group environment identity mismatch.' }

    $vnetProperties = Get-SantaProperty $vnet 'properties'
    $addressPrefixes = @(Get-SantaProperty (Get-SantaProperty $vnetProperties 'addressSpace') 'addressPrefixes')
    if ($addressPrefixes.Count -ne 1 -or [string]$addressPrefixes[0] -cne '10.247.0.0/24') { throw 'Existing VNet address space has drifted.' }
    $subnets = @(Get-SantaProperty $vnetProperties 'subnets')
    if ($subnets.Count -ne 1) { throw 'Existing VNet contains additional subnets outside the template ownership boundary.' }
    $subnet = $subnets[0]
    Assert-SantaResourceId -Resource $subnet -ExpectedId $subnetId
    $subnetProperties = Get-SantaProperty $subnet 'properties'
    if ([string](Get-SantaProperty $subnet 'name') -cne 'host' -or
        [string](Get-SantaProperty $subnetProperties 'addressPrefix') -cne '10.247.0.0/27' -or
        (Get-SantaProperty $subnetProperties 'defaultOutboundAccess') -ne $false -or
        [string](Get-SantaProperty (Get-SantaProperty $subnetProperties 'networkSecurityGroup') 'id') -ine $nsgId) {
        throw 'Existing host subnet identity, address range, outbound policy or NSG linkage has drifted.'
    }
    foreach ($name in @('routeTable', 'natGateway', 'sharingScope', 'serviceGateway')) {
        if ($null -ne (Get-SantaProperty $subnetProperties $name)) { throw "Existing host subnet has unsupported '$name' configuration; refusing to overwrite it." }
    }
    foreach ($name in @('delegations', 'serviceEndpointPolicies', 'ipConfigurations', 'ipAllocations', 'ipamPoolPrefixAllocations', 'applicationGatewayIPConfigurations')) {
        Assert-SantaEmptyCollection -Object $subnetProperties -PropertyName $name
    }
    foreach ($name in @('dnsServers', 'ddosProtectionPlan', 'encryption', 'bgpCommunities')) {
        $vnetValue = Get-SantaProperty $vnetProperties $name
        if ($null -ne $vnetValue -and @($vnetValue).Count -gt 0) { throw "Existing VNet has unsupported '$name' configuration; refusing to overwrite it." }
    }

    $rules = @(Get-SantaProperty (Get-SantaProperty $nsg 'properties') 'securityRules')
    if ($rules.Count -ne 1 -or [string](Get-SantaProperty $rules[0] 'name') -cne 'deny-all-inbound') { throw 'Existing lab NSG has unreviewed rules; refusing to overwrite network security policy.' }
    $rule = Get-SantaProperty $rules[0] 'properties'
    if ([string](Get-SantaProperty $rule 'direction') -cne 'Inbound' -or [string](Get-SantaProperty $rule 'access') -cne 'Deny' -or
        [string](Get-SantaProperty $rule 'protocol') -cne '*' -or [int](Get-SantaProperty $rule 'priority') -ne 100 -or
        [string](Get-SantaProperty $rule 'sourcePortRange') -cne '*' -or [string](Get-SantaProperty $rule 'destinationPortRange') -cne '*' -or
        [string](Get-SantaProperty $rule 'sourceAddressPrefix') -cne '*' -or [string](Get-SantaProperty $rule 'destinationAddressPrefix') -cne '*') {
        throw 'Existing lab NSG deny-all rule has drifted.'
    }

    $nicProperties = Get-SantaProperty $nic 'properties'
    $ipConfigurations = @(Get-SantaProperty $nicProperties 'ipConfigurations')
    if ($ipConfigurations.Count -ne 1) { throw 'Existing lab NIC has unreviewed IP configurations.' }
    $ipProperties = Get-SantaProperty $ipConfigurations[0] 'properties'
    if ([string](Get-SantaProperty $ipConfigurations[0] 'name') -cne 'primary' -or
        [string](Get-SantaProperty $ipProperties 'privateIPAllocationMethod') -cne 'Dynamic' -or
        [string](Get-SantaProperty (Get-SantaProperty $ipProperties 'subnet') 'id') -ine $subnetId -or
        [string](Get-SantaProperty (Get-SantaProperty $ipProperties 'publicIPAddress') 'id') -ine $pipId) {
        throw 'Existing lab NIC does not link only to the selected host subnet and egress IP.'
    }
    $pipProperties = Get-SantaProperty $pip 'properties'
    if ([string](Get-SantaProperty (Get-SantaProperty $pip 'sku') 'name') -cne 'Standard' -or
        [string](Get-SantaProperty $pipProperties 'publicIPAllocationMethod') -cne 'Static' -or
        [string](Get-SantaProperty $pipProperties 'publicIPAddressVersion') -cne 'IPv4' -or
        [string](Get-SantaProperty (Get-SantaProperty $pipProperties 'dnsSettings') 'domainNameLabel') -cnotmatch
            ('^santa-' + [regex]::Escape((($SubscriptionId -replace '-', '').Substring(0,16))) + '-' + [regex]::Escape($EnvironmentName) + '-vm$')) {
        throw 'Existing lab egress public IP has drifted.'
    }
    $vmNicIds = @((Get-SantaProperty (Get-SantaProperty (Get-SantaProperty $vm 'properties') 'networkProfile') 'networkInterfaces') | ForEach-Object { [string](Get-SantaProperty $_ 'id') })
    if ($vmNicIds.Count -ne 1 -or $vmNicIds[0] -ine $nicId) { throw 'Existing lab VM does not link only to the selected NIC.' }
    $vmInstanceId = [string](Get-SantaProperty (Get-SantaProperty $vm 'properties') 'vmId')
    if ($vmInstanceId -cnotmatch '^[0-9a-fA-F-]{36}$' -or [guid]$vmInstanceId -ne $ExpectedVmInstanceId) {
        throw 'Current VM instance identity does not match the selected azd environment output.'
    }
    $privateEndpointPolicy = [string](Get-SantaProperty $subnetProperties 'privateEndpointNetworkPolicies')
    $privateLinkPolicy = [string](Get-SantaProperty $subnetProperties 'privateLinkServiceNetworkPolicies')
    if (($privateEndpointPolicy -and $privateEndpointPolicy -notin @('Disabled', 'Enabled', 'NetworkSecurityGroupEnabled', 'RouteTableEnabled')) -or
        ($privateLinkPolicy -and $privateLinkPolicy -notin @('Disabled', 'Enabled'))) {
        throw 'Existing host subnet network-policy values are unsupported.'
    }

    return [pscustomobject]@{
        resourceGroup = $group
        vnet = $vnet
        subnet = $subnet
        endpointList = ConvertTo-SantaServiceEndpointList (Get-SantaProperty $subnetProperties 'serviceEndpoints')
        privateEndpointNetworkPolicies = $privateEndpointPolicy
        privateLinkServiceNetworkPolicies = $privateLinkPolicy
        subnetId = $subnetId
        vmInstanceId = $vmInstanceId
    }
}

function New-SantaHostSubnetEndpointPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][guid] $SubscriptionId,
        [Parameter(Mandatory)][ValidatePattern('^[a-z0-9-]{2,32}$')][string] $EnvironmentName,
        [Parameter(Mandatory)][string] $Location,
        [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{40}$')][string] $SourceRevision,
        [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string] $SourceSha256,
        [Parameter(Mandatory)][guid] $PlanId,
        [Parameter(Mandatory)][bool] $EnableStorageEndpoint,
        [AllowNull()][object] $ValidatedNetwork
    )

    $subscription = $SubscriptionId.ToString()
    $resourceGroupName = "rg-azd-santa-vm-$EnvironmentName"
    $existing = @()
    if ($null -ne $ValidatedNetwork -and $null -ne $ValidatedNetwork.endpointList) { $existing = @($ValidatedNetwork.endpointList) }
    $storage = @($existing | Where-Object { [string]$_.service -ieq 'Microsoft.Storage' })
    $preserved = if ($EnableStorageEndpoint) { @($existing | Where-Object { [string]$_.service -ine 'Microsoft.Storage' }) } else { @($existing) }
    $storageEndpoint = if ($storage.Count -eq 1) { $storage[0] } else { [ordered]@{ service = 'Microsoft.Storage'; locations = @($Location) } }
    $desired = @($preserved)
    if ($EnableStorageEndpoint) { $desired += $storageEndpoint }
    $desired = @($desired | Sort-Object { $_.service.ToLowerInvariant() })
    $beforeJson = ConvertTo-Json -InputObject @($existing) -Depth 8 -Compress
    $afterJson = ConvertTo-Json -InputObject @($desired) -Depth 8 -Compress
    $requiresConfirmation = ($null -ne $ValidatedNetwork) -and ($beforeJson -cne $afterJson)
    $groupId = "/subscriptions/$subscription/resourceGroups/$resourceGroupName"
    $vnetId = "$groupId/providers/Microsoft.Network/virtualNetworks/vnet-santa-lab"
    $subnetId = "$vnetId/subnets/host"
    $nsgId = "$groupId/providers/Microsoft.Network/networkSecurityGroups/nsg-santa-lab"
    $nicId = "$groupId/providers/Microsoft.Network/networkInterfaces/nic-santa-lab"
    $publicIpId = "$groupId/providers/Microsoft.Network/publicIPAddresses/pip-santa-lab-egress"
    $vmId = "$groupId/providers/Microsoft.Compute/virtualMachines/vm-santa-lab"
    $material = [ordered]@{
        schemaVersion = '1.0'
        mode = 'review-required'
        performsMutation = $false
        subscriptionId = $subscription
        sourceRevision = $SourceRevision
        sourceSha256 = $SourceSha256
        planId = $PlanId.ToString()
        environmentName = $EnvironmentName
        resourceGroupId = $groupId
        virtualNetworkId = $vnetId
        subnetId = $subnetId
        vmInstanceId = if ($null -eq $ValidatedNetwork) { $null } else { [string]$ValidatedNetwork.vmInstanceId }
        networkSecurityGroupId = $nsgId
        networkInterfaceId = $nicId
        egressPublicIpId = $publicIpId
        vmResourceId = $vmId
        enableStorageServiceEndpoint = $EnableStorageEndpoint
        currentServiceEndpoints = @($existing)
        desiredServiceEndpoints = @($desired)
        ownership = if ($null -eq $ValidatedNetwork) { 'fresh-resource-group' } else { 'current-resource-identity-and-linkage-verified' }
        ownershipChecks = @('exact resource IDs', 'exact environment/purpose tags', 'prior azd VM resource and instance outputs', 'current VM-to-NIC-to-subnet and NIC-to-PIP linkage', 'host address range and deny-all NSG', 'no additional subnet or unsupported attachment')
        privateEndpointNetworkPolicies = if ($null -eq $ValidatedNetwork -or [string]::IsNullOrWhiteSpace($ValidatedNetwork.privateEndpointNetworkPolicies)) { 'Enabled' } else { [string]$ValidatedNetwork.privateEndpointNetworkPolicies }
        privateLinkServiceNetworkPolicies = if ($null -eq $ValidatedNetwork -or [string]::IsNullOrWhiteSpace($ValidatedNetwork.privateLinkServiceNetworkPolicies)) { 'Enabled' } else { [string]$ValidatedNetwork.privateLinkServiceNetworkPolicies }
        endpointIncrementalMonthlyCost = 0
        networkEffect = 'Changing a subnet service endpoint changes routing and can close existing TCP connections; do not proceed while critical host tasks are running.'
        storageAccountProvisioned = $false
        concurrency = 'Plan is bound to current IDs and observed endpoint values; ARM does not enforce an ETag condition for the subsequent azd deployment.'
    }
    $material.mode = if ($requiresConfirmation) { 'review-required' } else { 'no-network-change' }
    $canonical = ConvertTo-Json -InputObject $material -Depth 12 -Compress
    $hash = [Convert]::ToHexStringLower([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($canonical)))
    $plan = [ordered]@{ plan = $material; planSha256 = $hash; requiresConfirmation = $requiresConfirmation }
    return [pscustomobject]@{
        Plan = $plan
        ExistingServiceEndpointsJson = if ($EnableStorageEndpoint) { ConvertTo-Json -InputObject @($preserved) -Depth 8 -Compress } else { $beforeJson }
        StorageServiceEndpointJson = ConvertTo-Json -InputObject $storageEndpoint -Depth 8 -Compress
        EndpointBoolean = if ($EnableStorageEndpoint) { 'true' } else { 'false' }
        PrivateEndpointNetworkPolicies = if ($null -eq $ValidatedNetwork -or [string]::IsNullOrWhiteSpace($ValidatedNetwork.privateEndpointNetworkPolicies)) { 'Enabled' } else { [string]$ValidatedNetwork.privateEndpointNetworkPolicies }
        PrivateLinkServiceNetworkPolicies = if ($null -eq $ValidatedNetwork -or [string]::IsNullOrWhiteSpace($ValidatedNetwork.privateLinkServiceNetworkPolicies)) { 'Enabled' } else { [string]$ValidatedNetwork.privateLinkServiceNetworkPolicies }
        DesiredServiceEndpoints = @($desired)
    }
}

Export-ModuleMember -Function Get-SantaBooleanSetting, Assert-SantaOwnedHostNetwork, New-SantaHostSubnetEndpointPlan
