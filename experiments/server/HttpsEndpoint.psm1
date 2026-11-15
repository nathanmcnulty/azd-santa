#Requires -Version 7.6
# Original Unlicense. Cached, selected ARM readback only; never authenticates.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-SantaEndpointAzJson {
    param([string[]]$Arguments)
    $raw = & az @Arguments --only-show-errors -o json 2>$null
    if ($LASTEXITCODE) { throw 'Selected cached ARM endpoint read failed; no authentication fallback.' }
    $text = $raw -join "`n"
    if ([Text.Encoding]::UTF8.GetByteCount($text) -gt 262144) { throw 'ARM endpoint response exceeded its bound.' }
    $text | ConvertFrom-Json -Depth 48 -AsHashtable -ErrorAction Stop
}

function Assert-SantaEndpoint {
    param([bool]$Condition)
    if (-not $Condition) { throw 'Selected ARM endpoint linkage or closed-ingress binding failed.' }
}

function Test-SantaEndpointIpv4 {
    param([string]$Address)
    $ip = $null
    if (-not [Net.IPAddress]::TryParse($Address, [ref]$ip) -or
        $ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or $ip.ToString() -cne $Address) { return $false }
    $b = $ip.GetAddressBytes()
    -not ($b[0] -in @(0,10,127) -or $b[0] -ge 224 -or
        ($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127) -or
        ($b[0] -eq 169 -and $b[1] -eq 254) -or
        ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) -or
        ($b[0] -eq 192 -and (($b[1] -eq 0 -and $b[2] -in @(0,2)) -or $b[1] -eq 168)) -or
        ($b[0] -eq 198 -and ($b[1] -in @(18,19) -or ($b[1] -eq 51 -and $b[2] -eq 100))) -or
        ($b[0] -eq 203 -and $b[1] -eq 0 -and $b[2] -eq 113))
}

function Get-SantaHttpsEndpointFacts {
    [CmdletBinding()]
    param([Parameter(Mandatory)][guid]$TenantId,
        [Parameter(Mandatory)][guid]$SubscriptionId,
        [Parameter(Mandatory)][guid]$VmInstanceId,
        [Parameter(Mandatory)][ValidatePattern('^[a-z0-9-]{2,32}$')][string]$EnvironmentName)
    $sub = $SubscriptionId.ToString(); $tenant = $TenantId.ToString()
    $group = "/subscriptions/$sub/resourceGroups/rg-azd-santa-vm-$EnvironmentName"
    $base = "$group/providers/"
    $vmId = $base + 'Microsoft.Compute/virtualMachines/vm-santa-lab'
    $nicId = $base + 'Microsoft.Network/networkInterfaces/nic-santa-lab'
    $ipId = "$nicId/ipConfigurations/primary"
    $pipId = $base + 'Microsoft.Network/publicIPAddresses/pip-santa-lab-egress'
    $subnetId = $base + 'Microsoft.Network/virtualNetworks/vnet-santa-lab/subnets/host'
    $nsgId = $base + 'Microsoft.Network/networkSecurityGroups/nsg-santa-lab'
    $account = Invoke-SantaEndpointAzJson @('account', 'show', '--subscription', $sub)
    Assert-SantaEndpoint ($account.id -ieq $sub -and $account.tenantId -ieq $tenant -and
        $account.state -ceq 'Enabled' -and $account.environmentName -ceq 'AzureCloud')
    $selection = [ordered]@{ group=$group; vm=$vmId; nic=$nicId; pip=$pipId; subnet=$subnetId; nsg=$nsgId }
    $observed = @{}
    foreach ($name in $selection.Keys) {
        $version = if ($name -eq 'group') { '2025-04-01' } elseif ($name -eq 'vm') { '2024-11-01' } else { '2024-05-01' }
        $observed[$name] = Invoke-SantaEndpointAzJson @('rest', '--method', 'get', '--url',
            "https://management.azure.com$($selection[$name])?api-version=$version", '--subscription', $sub)
        $row = $observed[$name]
        Assert-SantaEndpoint ($row.id -ieq $selection[$name])
        if ($name -ne 'subnet') {
            Assert-SantaEndpoint ($row.tags['azd-solution'] -ceq 'azd-santa' -and
                $row.tags.purpose -ceq 'synthetic-vm-lab' -and $row.tags['azd-env-name'] -ceq $EnvironmentName)
        }
        if ($name -ne 'group') { Assert-SantaEndpoint ($row.properties.provisioningState -ceq 'Succeeded') }
    }
    $vm=$observed.vm; $nic=$observed.nic; $pip=$observed.pip; $subnet=$observed.subnet; $nsg=$observed.nsg
    Assert-SantaEndpoint ($vm.properties.vmId -ieq $VmInstanceId.ToString())
    foreach ($row in @($nic,$pip,$nsg)) { Assert-SantaEndpoint ($row.location -ceq $vm.location) }
    $interfaces = @($vm.properties.networkProfile.networkInterfaces)
    Assert-SantaEndpoint ($interfaces.Count -eq 1 -and $interfaces[0].id -ieq $nicId -and
        $interfaces[0].properties.primary -eq $true)
    Assert-SantaEndpoint ($nic.properties.virtualMachine.id -ieq $vmId -and
        -not $nic.properties.ContainsKey('networkSecurityGroup'))
    $ips=@($nic.properties.ipConfigurations)
    Assert-SantaEndpoint ($ips.Count -eq 1 -and $ips[0].id -ieq $ipId -and $ips[0].name -ceq 'primary')
    Assert-SantaEndpoint ($ips[0].properties.publicIPAddress.id -ieq $pipId -and
        $ips[0].properties.subnet.id -ieq $subnetId -and $pip.properties.ipConfiguration.id -ieq $ipId)
    Assert-SantaEndpoint ($subnet.properties.networkSecurityGroup.id -ieq $nsgId -and
        $subnet.properties.defaultOutboundAccess -eq $false)
    Assert-SantaEndpoint ($pip.sku.name -ceq 'Standard' -and $pip.properties.publicIPAllocationMethod -ceq 'Static' -and
        $pip.properties.publicIPAddressVersion -ceq 'IPv4' -and (Test-SantaEndpointIpv4 $pip.properties.ipAddress))
    $label = 'santa-' + $sub.Replace('-','').Substring(0,16) + '-' + $EnvironmentName + '-vm'
    $fqdn = "$label.$($pip.location).cloudapp.azure.com"
    Assert-SantaEndpoint ($pip.location -cmatch '^[a-z0-9]+$' -and
        $pip.properties.dnsSettings.domainNameLabel -ceq $label -and $pip.properties.dnsSettings.fqdn -ceq $fqdn -and
        -not $pip.properties.dnsSettings.ContainsKey('domainNameLabelScope'))
    $rules=@($nsg.properties.securityRules)
    Assert-SantaEndpoint ($rules.Count -eq 1 -and $rules[0].name -ceq 'deny-all-inbound')
    $rule=$rules[0].properties
    Assert-SantaEndpoint ($rule.priority -eq 100 -and $rule.direction -ceq 'Inbound' -and
        $rule.access -ceq 'Deny' -and $rule.protocol -ceq '*')
    foreach ($key in @('sourcePortRange','destinationPortRange','sourceAddressPrefix','destinationAddressPrefix')) {
        Assert-SantaEndpoint ($rule[$key] -ceq '*')
    }
    # Re-read every selected resource; reject concurrent control-plane changes.
    foreach ($name in $selection.Keys) {
        $version = if ($name -eq 'group') { '2025-04-01' } elseif ($name -eq 'vm') { '2024-11-01' } else { '2024-05-01' }
        $again = Invoke-SantaEndpointAzJson @('rest', '--method', 'get', '--url',
            "https://management.azure.com$($selection[$name])?api-version=$version", '--subscription', $sub)
        Assert-SantaEndpoint (($again | ConvertTo-Json -Depth 48 -Compress) -ceq
            ($observed[$name] | ConvertTo-Json -Depth 48 -Compress))
    }
    [ordered]@{ scope='azd-santa-selected-arm-endpoint-v1'; TenantId=$tenant; SubscriptionId=$sub
        EnvironmentName=$EnvironmentName; VmId=$vmId; VmInstanceId=$VmInstanceId.ToString()
        NicId=$nicId; IpConfigurationId=$ipId; PublicIpId=$pipId
        PublicIpAddress=$pip.properties.ipAddress; Fqdn=$pip.properties.dnsSettings.fqdn }
}

Export-ModuleMember -Function Get-SantaHttpsEndpointFacts
