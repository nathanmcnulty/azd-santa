#Requires -Version 7.6
# Original Unlicense. Cached, selected ARM readback only; never authenticates.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-SantaEndpointProcess {
    param([string]$FileName,[string[]]$Arguments,[string]$InputText='',
        [ValidateRange(1,300)][int]$TimeoutSeconds=30,
        [ValidateRange(262144,8388608)][int]$InputLimit=262144)
    # Drain both streams concurrently into finite buffers. An outer deadline
    # covers startup, stdin, output and process exit; no unbounded ReadToEnd.
    if ([Text.Encoding]::UTF8.GetByteCount($InputText) -gt $InputLimit) { throw 'Bounded operator input rejected.' }
    $start=[Diagnostics.ProcessStartInfo]::new();$start.FileName=$FileName
    foreach($argument in $Arguments) { $start.ArgumentList.Add($argument) }
    $start.UseShellExecute=$false;$start.CreateNoWindow=$true
    $start.RedirectStandardInput=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
    $process=[Diagnostics.Process]::new();$process.StartInfo=$start;$started=$false
    $watch=[Diagnostics.Stopwatch]::StartNew()
    try {
        $null=$process.Start();$started=$true
        $writing=$process.StandardInput.WriteAsync($InputText);$inputClosed=$false
        $readers=@($process.StandardOutput,$process.StandardError)
        $buffers=@([char[]]::new(1024),[char[]]::new(512))
        $texts=@([Text.StringBuilder]::new(),[Text.StringBuilder]::new())
        $limits=@(262144,4096);$ended=@($false,$false);$pending=@($null,$null)
        while($true) {
            if($watch.Elapsed.TotalSeconds -ge $TimeoutSeconds) { throw 'Bounded operator process deadline exceeded.' }
            if(-not $inputClosed -and $writing.IsCompleted) {
                $null=$writing.GetAwaiter().GetResult();$process.StandardInput.Close();$inputClosed=$true
            }
            for($i=0;$i -lt 2;$i++) {
                if($ended[$i]) { continue }
                if($null -eq $pending[$i]) { $pending[$i]=$readers[$i].ReadAsync($buffers[$i],0,$buffers[$i].Length) }
                if($pending[$i].IsCompleted) {
                    $count=$pending[$i].GetAwaiter().GetResult();$pending[$i]=$null
                    if($count -eq 0) { $ended[$i]=$true;continue }
                    if($texts[$i].Length+$count -gt $limits[$i]) { throw 'Bounded operator output exceeded.' }
                    $null=$texts[$i].Append($buffers[$i],0,$count)
                }
            }
            if($process.HasExited -and $ended[0] -and $ended[1]) { break }
            $null=$process.WaitForExit(10)
        }
        if($process.ExitCode -ne 0 -or [Text.Encoding]::UTF8.GetByteCount($texts[0].ToString()) -gt $limits[0] -or
            [Text.Encoding]::UTF8.GetByteCount($texts[1].ToString()) -gt $limits[1]) { throw 'Bounded operator process failed.' }
        $texts[0].ToString()
    } catch { throw 'Cached operator process failed, exceeded its bound or timed out; inspect outcome before another action.' }
    finally {
        if($started -and -not $process.HasExited) {
            try { $process.Kill($true);$null=$process.WaitForExit(5000) } catch { }
        }
        $process.Dispose()
    }
}

function Invoke-SantaEndpointAzJson {
    param([string[]]$Arguments,[ValidateRange(1,300)][int]$TimeoutSeconds=30,[switch]$AllowEmpty)
    try {
        $az=@(Get-Command az -CommandType Application -ErrorAction Stop)[0].Source
        $args=@($Arguments)+@('--only-show-errors','-o','json')
        if($IsWindows -and [IO.Path]::GetExtension($az) -in @('.cmd','.bat')) {
            # Batch invocation retains Windows native argument semantics. The
            # maintained calls need no cmd metacharacters; reject rather than
            # let caller data become batch syntax or environment expansion.
            if(@($args | Where-Object { $_ -match '[\r\n"&|<>^%!]'}).Count) { throw 'Unsupported batch argument.' }
            # Windows CLI is a batch launcher. Pass data via stdin to a fixed
            # PowerShell program, never build a cmd.exe command string.
            $program='$ErrorActionPreference="Stop";$PSNativeCommandUseErrorActionPreference=$false;try{$p=[Console]::In.ReadToEnd()|ConvertFrom-Json;$a=@($p.arguments);$count=0;& $p.executable @a 2>$null|ForEach-Object{$line=[string]$_;$count+=[Text.Encoding]::UTF8.GetByteCount($line)+1;if($count -gt 262144){throw "Reply bound"};[Console]::Out.WriteLine($line)};exit $LASTEXITCODE}catch{exit 1}'
            $payload=@{executable=$az;arguments=$args}|ConvertTo-Json -Compress
            $text=Invoke-SantaEndpointProcess -FileName (Join-Path $PSHOME 'pwsh.exe') `
                -Arguments @('-NoProfile','-NonInteractive','-Command',$program) -InputText $payload -TimeoutSeconds $TimeoutSeconds
        } else { $text=Invoke-SantaEndpointProcess -FileName $az -Arguments $args -TimeoutSeconds $TimeoutSeconds }
        if([string]::IsNullOrWhiteSpace($text)) {
            if($AllowEmpty) { return }
            throw 'A complete JSON reply is required.'
        }
        $value=ConvertFrom-Json -InputObject $text -Depth 48 -AsHashtable -NoEnumerate -ErrorAction Stop
        return ,$value
    } catch { throw 'Selected cached ARM operation failed or is unknown; no authentication fallback or automatic retry.' }
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
