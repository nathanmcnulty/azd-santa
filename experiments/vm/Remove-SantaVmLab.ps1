#Requires -Version 7.6
# Original Unlicense. Explicit retirement of one disposable synthetic VM lab.
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)][guid]$TenantId,
    [Parameter(Mandatory)][guid]$SubscriptionId,
    [Parameter(Mandatory)][ValidatePattern('^[a-z0-9-]{2,32}$')][string]$EnvironmentName,
    [Parameter(Mandatory)][guid]$VmInstanceId
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot '../server/SetupTransport.psm1')

$subscription = $SubscriptionId.ToString()
$group = "rg-azd-santa-vm-$EnvironmentName"
$groupId = "/subscriptions/$subscription/resourceGroups/$group"
$root = "$groupId/providers"
$vmId = "$root/Microsoft.Compute/virtualMachines/vm-santa-lab"
$diskId = "$root/Microsoft.Compute/disks/os-santa-lab"
$nicId = "$root/Microsoft.Network/networkInterfaces/nic-santa-lab"
$vnetId = "$root/Microsoft.Network/virtualNetworks/vnet-santa-lab"
$nsgId = "$root/Microsoft.Network/networkSecurityGroups/nsg-santa-lab"
$pipId = "$root/Microsoft.Network/publicIPAddresses/pip-santa-lab-egress"
$required = @($vmId, $diskId, $nicId, $vnetId, $nsgId, $pipId)
$optional = @("$root/Microsoft.DevTestLab/schedules/shutdown-computevm-vm-santa-lab", "$vmId/extensions/MDE.Linux")

function Invoke-LabAzure {
    param([string[]]$Arguments)
    # Keep native diagnostics separate from the expected JSON response.
    $PSNativeCommandUseErrorActionPreference = $false
    $selectionArgs = if ('--subscription' -notin $Arguments) { @('--subscription', $subscription) } else { @() }
    $result = & az @Arguments @selectionArgs --only-show-errors -o json
    if ($LASTEXITCODE -ne 0) { throw "Azure CLI $($Arguments[0..1] -join ' ') failed for the selected subscription." }
    if ($result) { ($result -join "`n") | ConvertFrom-Json -AsHashtable }
}

function Get-LabInventory {
    $target = Get-SantaPrivateVmDeploymentTarget -SubscriptionId $SubscriptionId -EnvironmentName $EnvironmentName `
        -ReadAzure { param($Arguments) Invoke-LabAzure $Arguments }
    if ($target.TenantId -ine $TenantId.ToString() -or $target.VmInstanceId -ine $VmInstanceId.ToString() -or
        $target.VmId -ine $vmId) { throw 'Selected tenant or immutable VM identity differs.' }

    $vm = Invoke-LabAzure @('vm', 'get-instance-view', '--resource-group', $group, '--name', 'vm-santa-lab')
    if ($vm['vmId'] -ine $VmInstanceId.ToString() -or 'PowerState/deallocated' -notin $vm['instanceView']['statuses'].code) {
        throw 'Verify the selected VM is deallocated before retirement.'
    }
    $nics = @($vm['networkProfile']['networkInterfaces'])
    if ($vm['storageProfile']['osDisk']['managedDisk']['id'] -ine $diskId -or $vm['storageProfile']['dataDisks'] -or
        $nics.Count -ne 1 -or $nics[0]['id'] -ine $nicId) { throw 'The VM has an unexpected disk or network attachment.' }

    $nic = Invoke-LabAzure @('resource', 'show', '--ids', $nicId, '--api-version', '2024-05-01')
    $configs = @($nic['properties']['ipConfigurations'])
    if ($nic['id'] -ine $nicId -or $configs.Count -ne 1) { throw 'Unexpected lab NIC configuration.' }
    $ip = $configs[0]['properties']
    if ($ip['subnet']['id'] -ine "$vnetId/subnets/host" -or $ip['publicIPAddress']['id'] -ine $pipId) {
        throw 'The lab NIC uses an unexpected subnet or public IP.'
    }

    $locks = @(Invoke-LabAzure @('lock', 'list', '--resource-group', $group))
    if ($locks.Count) { throw 'The selected lab has management locks.' }
    $inventory = @(Invoke-LabAzure @('resource', 'list', '--resource-group', $group))
    $ids = @($inventory | ForEach-Object { $_['id'] })
    if (@($ids | Where-Object { $_ -notin ($required + $optional) }).Count -or
        @($required | Where-Object { $_ -notin $ids }).Count -or @($ids | Sort-Object -Unique).Count -ne $ids.Count) {
        throw 'The lab resource inventory is incomplete or includes unexpected resources.'
    }

    $storage = @(Invoke-LabAzure @('storage', 'account', 'list'))
    foreach ($account in $storage) {
        $network = $account['networkRuleSet']
        if ($null -eq $network) { continue }
        foreach ($rule in $network['virtualNetworkRules']) {
            if ($rule['virtualNetworkResourceId'] -like "$vnetId/subnets/*") {
                throw 'A storage account still references the lab subnet.'
            }
        }
    }
    $ids | Sort-Object
}

$initial = @(Get-LabInventory)
if (-not $PSCmdlet.ShouldProcess($groupId, 'Permanently delete this disposable VM lab, including disk and public IP')) { return }
$current = @(Get-LabInventory)
if (Compare-Object -ReferenceObject $initial -DifferenceObject $current) { throw 'Lab inventory changed before deletion.' }

try {
    $null = Invoke-LabAzure @('group', 'delete', '--name', $group, '--yes', '--no-wait')
} catch {
    Write-Warning 'Azure did not confirm the delete submission. Observing the same group without repeating the request.'
}
$null = Invoke-LabAzure @('group', 'wait', '--name', $group, '--deleted', '--interval', '10', '--timeout', '600')
$exists = Invoke-LabAzure @('group', 'exists', '--name', $group)
if ($exists -isnot [bool] -or $exists) { throw 'Azure has not confirmed that the selected resource group is gone.' }

[pscustomobject]@{
    State = 'deleted'
    ResourceGroupId = $groupId
    VmInstanceId = $VmInstanceId.ToString()
    DeletedResourceIds = $initial
}
