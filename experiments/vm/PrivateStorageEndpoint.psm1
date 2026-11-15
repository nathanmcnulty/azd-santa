#Requires -Version 7.6
# Original Unlicense. GET-only existing-network proposal; never applies it.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$script:networkReader=Import-Module (Join-Path $PSScriptRoot '../server/HttpsEndpoint.psm1') -PassThru -Force

function Assert-Network([bool]$Condition) {
    if (-not $Condition) { throw 'Selected network shape, ownership or observation rejected.' }
}
function Assert-NetworkKeys([hashtable]$Value,[string[]]$Allowed) {
    Assert-Network (@($Value.Keys | Where-Object { $_ -cnotin $Allowed }).Count -eq 0)
}
function Assert-NetworkTags([hashtable]$Tags,[string]$Environment) {
    $normalized=@{}
    foreach($key in $Tags.Keys) {
        $lower=$key.ToLowerInvariant();Assert-Network (-not $normalized.ContainsKey($lower));$normalized[$lower]=$Tags[$key]
    }
    Assert-Network ($normalized['azd-env-name'] -ceq $Environment -and $normalized['azd-solution'] -ceq 'azd-santa' -and
        $normalized['purpose'] -ceq 'synthetic-vm-lab')
}
function Read-Network([string[]]$Arguments) {
    & $script:networkReader {param([string[]]$a) Invoke-SantaEndpointAzJson -Arguments $a} $Arguments
}
function Network-Json($Value) { ConvertTo-Json -InputObject $Value -Depth 48 -Compress }

function New-SantaPrivateStorageEndpointPlan {
    [CmdletBinding()]
    param([Parameter(Mandatory)][guid]$TenantId,
        [Parameter(Mandatory)][guid]$SubscriptionId,
        [Parameter(Mandatory)][ValidatePattern('^[a-z0-9-]{2,32}$')][string]$EnvironmentName,
        [Parameter(Mandatory)][guid]$VmInstanceId,
        [switch]$EnableStorageEndpoint,[switch]$ReadArm)
    try {
        $sub=$SubscriptionId.ToString();$group="/subscriptions/$sub/resourceGroups/rg-azd-santa-vm-$EnvironmentName"
        $base="$group/providers/";$vnet=$base+'Microsoft.Network/virtualNetworks/vnet-santa-lab'
        $ids=[ordered]@{group=$group;vm=$base+'Microsoft.Compute/virtualMachines/vm-santa-lab'
            nic=$base+'Microsoft.Network/networkInterfaces/nic-santa-lab';vnet=$vnet;subnet="$vnet/subnets/host"
            nsg=$base+'Microsoft.Network/networkSecurityGroups/nsg-santa-lab'}
        $urls=[ordered]@{}
        foreach($name in $ids.Keys) {
            $version=if($name -eq 'group'){'2025-04-01'}elseif($name -eq 'vm'){'2024-11-01'}else{'2024-05-01'}
            $urls[$name]="https://management.azure.com$($ids[$name])?api-version=$version"
        }
        if (-not $ReadArm) {
            return [pscustomobject]@{scope='private-storage-endpoint-read-plan-v1';cloudWrite=$false;mutationAuthorized=$false
                enableStorageEndpoint=[bool]$EnableStorageEndpoint;selectedVmId=$ids.vm;selectedInstance=$VmInstanceId.ToString();urls=$urls}
        }
        $context=Read-Network @('account','show','--subscription',$sub)
        Assert-Network ($context.id -ieq $sub -and $context.tenantId -ieq $TenantId.ToString() -and
            $context.state -ceq 'Enabled' -and $context.environmentName -ceq 'AzureCloud')
        $before=@{};$after=@{}
        foreach($name in $urls.Keys) { $before[$name]=Read-Network @('rest','--method','get','--url',$urls[$name],'--subscription',$sub) }
        foreach($name in $urls.Keys) { $after[$name]=Read-Network @('rest','--method','get','--url',$urls[$name],'--subscription',$sub) }
        $finalContext=Read-Network @('account','show','--subscription',$sub)
        Assert-Network ((Network-Json $context) -ceq (Network-Json $finalContext))
        $etags=@{}
        foreach($name in $urls.Keys) {
            $row=$before[$name]
            Assert-Network ((Network-Json $row) -ceq (Network-Json $after[$name]))
            Assert-Network ($row.id -ieq $ids[$name] -and $row.properties.provisioningState -ceq 'Succeeded')
            if($name -ne 'subnet') { Assert-NetworkTags $row.tags $EnvironmentName }
            if($name -in @('vnet','subnet','nsg','nic')) {
                Assert-Network ($row.etag -cmatch '^(?:W/)?"[A-Za-z0-9-]{1,128}"$');$etags[$ids[$name]]=$row.etag
            }
        }
        $region=$before.vm.location
        Assert-Network ($region -cmatch '^[a-z0-9]{2,32}$' -and $before.vm.properties.vmId -ieq $VmInstanceId.ToString())
        foreach($name in @('group','vnet')) {
            if($before[$name].ContainsKey('managedBy')) { Assert-Network (-not $before[$name]['managedBy']) }
        }
        foreach($name in @('nic','vnet','nsg')) { Assert-Network ($before[$name].location -ceq $region) }
        $interfaces=@($before.vm.properties.networkProfile.networkInterfaces)
        Assert-Network ($interfaces.Count -eq 1 -and $interfaces[0].id -ieq $ids.nic -and
            $before.nic.properties.virtualMachine.id -ieq $ids.vm -and -not $before.nic.properties.ContainsKey('networkSecurityGroup'))
        $configs=@($before.nic.properties.ipConfigurations)
        Assert-Network ($configs.Count -eq 1 -and $configs[0].id -ieq ($ids.nic+'/ipConfigurations/primary') -and
            $configs[0].properties.subnet.id -ieq $ids.subnet)
        $net=$before.vnet.properties
        Assert-NetworkKeys $net @('provisioningState','resourceGuid','addressSpace','subnets','virtualNetworkPeerings','dhcpOptions','enableDdosProtection','enableVmProtection','privateEndpointVNetPolicies')
        if($net.ContainsKey('privateEndpointVNetPolicies')) { Assert-Network ($net.privateEndpointVNetPolicies -ceq 'Disabled') }
        Assert-NetworkKeys $net.addressSpace @('addressPrefixes')
        Assert-Network (@($net.addressSpace.addressPrefixes).Count -eq 1 -and $net.addressSpace.addressPrefixes[0] -ceq '10.247.0.0/24')
        foreach($key in @('virtualNetworkPeerings')) { if($net.ContainsKey($key)) { Assert-Network (@($net[$key]).Count -eq 0) } }
        foreach($key in @('enableDdosProtection','enableVmProtection')) { if($net.ContainsKey($key)) { Assert-Network ($net[$key] -eq $false) } }
        if($net.ContainsKey('dhcpOptions')) { Assert-NetworkKeys $net.dhcpOptions @('dnsServers');Assert-Network (@($net.dhcpOptions.dnsServers).Count -eq 0) }
        $subnets=@($net.subnets)
        Assert-Network ($subnets.Count -eq 1 -and $subnets[0].id -ieq $ids.subnet -and $subnets[0].etag -ceq $before.subnet.etag -and
            (Network-Json $subnets[0].properties) -ceq (Network-Json $before.subnet.properties))
        $props=$before.subnet.properties
        Assert-NetworkKeys $props @('provisioningState','addressPrefix','defaultOutboundAccess','networkSecurityGroup','serviceEndpoints',
            'privateEndpointNetworkPolicies','privateLinkServiceNetworkPolicies','ipConfigurations','delegations','serviceEndpointPolicies',
            'privateEndpoints','resourceNavigationLinks','serviceAssociationLinks','ipAllocations')
        Assert-Network ($props.addressPrefix -ceq '10.247.0.0/27' -and $props.defaultOutboundAccess -is [bool] -and $props.defaultOutboundAccess -eq $false -and
            $props.networkSecurityGroup.id -ieq $ids.nsg)
        Assert-NetworkKeys $props.networkSecurityGroup @('id')
        foreach($key in @('delegations','serviceEndpointPolicies','privateEndpoints','resourceNavigationLinks','serviceAssociationLinks','ipAllocations')) {
            if($props.ContainsKey($key)) { Assert-Network (@($props[$key]).Count -eq 0) }
        }
        Assert-Network ($props.ContainsKey('ipConfigurations'))
        $references=@($props.ipConfigurations)
        Assert-Network ($references.Count -eq 1 -and $references[0].id -ieq $configs[0].id)
        Assert-NetworkKeys $references[0] @('id')
        $rules=@($before.nsg.properties.securityRules)
        Assert-Network ($rules.Count -eq 1 -and $rules[0].name -ceq 'deny-all-inbound')
        $rule=$rules[0].properties
        foreach($pair in @{priority=100;direction='Inbound';access='Deny';protocol='*';sourcePortRange='*';destinationPortRange='*';sourceAddressPrefix='*';destinationAddressPrefix='*'}.GetEnumerator()) {
            Assert-Network ($rule[$pair.Key] -ceq $pair.Value)
        }
        $endpoints=@();$services=@{}
        if($props.ContainsKey('serviceEndpoints')) {
            foreach($endpoint in $props.serviceEndpoints) {
                Assert-NetworkKeys $endpoint @('service','locations','provisioningState')
                Assert-Network ($endpoint.service -cmatch '^Microsoft\.[A-Za-z0-9.]{1,80}$' -and
                    -not $services.ContainsKey($endpoint.service) -and $endpoint.service -ine 'Microsoft.Storage.Global' -and
                    $endpoint.provisioningState -ceq 'Succeeded')
                $locations=@($endpoint.locations)
                Assert-Network ($locations.Count -le 16 -and @($locations | Where-Object { $_ -cnotmatch '^(?:[a-z0-9]{2,32}|\*)$' }).Count -eq 0)
                $services[$endpoint.service]=$true;$endpoints+=@{service=$endpoint.service;locations=$locations}
            }
        }
        Assert-Network ($endpoints.Count -le 16)
        $originalEndpoints=@($endpoints)
        $changed=[bool]$EnableStorageEndpoint -and -not $services.ContainsKey('Microsoft.Storage')
        if($changed) { $endpoints+=@{service='Microsoft.Storage';locations=@($region)} }
        Assert-Network ($endpoints.Count -le 16)
        # Only reviewed writable subnet fields enter a potential future request.
        # ETags/read-only links remain observations, never blindly echoed in PUT.
        $desired=@{addressPrefix=$props.addressPrefix;defaultOutboundAccess=$false;networkSecurityGroup=@{id=$ids.nsg};serviceEndpoints=$endpoints}
        foreach($key in @('privateEndpointNetworkPolicies','privateLinkServiceNetworkPolicies')) {
            if($props.ContainsKey($key)) { Assert-Network ($props[$key] -cin @('Enabled','Disabled'));$desired[$key]=$props[$key] }
        }
        $hash=[Convert]::ToHexStringLower([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes((Network-Json $before))))
        [pscustomobject]@{scope='private-storage-endpoint-proposal-v1';cloudWrite=$false;mutationAuthorized=$false
            requiresFreshArmRead=$true;atomicPreconditionProven=$false;vnetUpdatePlanned=$false;changed=$changed
            selectedVmId=$ids.vm;selectedInstance=$VmInstanceId.ToString();subnetId=$ids.subnet;location=$region;expectedEtags=$etags;observationSha256=$hash
            resourceIds=$ids;observedSubnet=@{id=$before.subnet.id;etag=$before.subnet.etag;properties=$props}
            existingHostServiceEndpoints=$originalEndpoints;desiredServiceEndpoints=$endpoints
            suggestedParameters=@{backupStorageEndpoint=if($EnableStorageEndpoint){'true'}else{'false'};existingHostServiceEndpointsJson=(Network-Json $originalEndpoints)}
            proposedSubnetRequest=@{method='PUT';url=$urls.subnet;body=@{properties=$desired}}
            liveEndpointProven=$false;retentionProven=$false;restoreAccepted=$false}
    } catch { throw 'Storage endpoint plan failed or is unknown; preserve networking and inspect ownership, ETags and supported properties. No network write was attempted.' }
}

Export-ModuleMember -Function New-SantaPrivateStorageEndpointPlan
