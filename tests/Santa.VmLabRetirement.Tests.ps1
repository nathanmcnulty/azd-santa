#Requires -Version 7.6
Describe 'Retire a disposable Santa VM lab' {
    BeforeAll {
        $script:retire = Join-Path (Split-Path $PSScriptRoot -Parent) 'experiments/vm/Remove-SantaVmLab.ps1'
        $script:subscription = '11111111-1111-4111-8111-111111111111'
        $script:tenant = '22222222-2222-4222-8222-222222222222'
        $script:instance = '33333333-3333-4333-8333-333333333333'
        $script:group = "/subscriptions/$script:subscription/resourceGroups/rg-azd-santa-vm-synthetic"
        $script:ids = @('Microsoft.Compute/virtualMachines/vm-santa-lab', 'Microsoft.Compute/disks/os-santa-lab',
                        'Microsoft.Network/networkInterfaces/nic-santa-lab', 'Microsoft.Network/virtualNetworks/vnet-santa-lab',
                        'Microsoft.Network/networkSecurityGroups/nsg-santa-lab', 'Microsoft.Network/publicIPAddresses/pip-santa-lab-egress' |
            ForEach-Object { "$script:group/providers/$_" })
        $script:selection = @{ TenantId=$script:tenant; SubscriptionId=$script:subscription; EnvironmentName='synthetic'; VmInstanceId=$script:instance }
        $script:fixtureCommand = {
            $global:LASTEXITCODE = 0
            $operation = $args[0..1] -join ' '
            $fixture.operations.Add($operation)
            $at = [array]::IndexOf($args,'--subscription')
            if ($at -lt 0 -or $args[$at+1] -cne $fixture.subscription) { throw 'Fixture requires the selected subscription.' }
            $tags = @{ 'azd-solution'='azd-santa'; purpose='synthetic-vm-lab'; 'azd-env-name'='synthetic' }
            switch ($operation) {
                'account show' { @{id=$fixture.subscription;tenantId=$fixture.tenant;state='Enabled'} | ConvertTo-Json -Compress }
                'group show' { @{id=$fixture.group;tags=$tags} | ConvertTo-Json -Compress }
                'vm show' { @{id=$fixture.ids[0];vmId=$fixture.instance;provisioningState='Succeeded';tags=$tags} | ConvertTo-Json -Compress }
                'vm get-instance-view' {
                    @{ vmId=$fixture.instance; instanceView=@{ statuses=@(@{code='PowerState/deallocated'}) }; storageProfile=@{
                        osDisk=@{managedDisk=@{id=$fixture.ids[1]}};dataDisks=@() }; networkProfile=@{networkInterfaces=@(@{id=$fixture.ids[2]})} } |
                        ConvertTo-Json -Depth 8 -Compress
                }
                'resource show' {
                    @{ id=$fixture.ids[2]; properties=@{ipConfigurations=@(@{properties=@{
                        subnet=@{id="$($fixture.ids[3])/subnets/host"};publicIPAddress=@{id=$fixture.ids[5]}}})} } |
                        ConvertTo-Json -Depth 8 -Compress
                }
                'lock list' { if ($fixture.locked) { '[{"name":"keep"}]' } else { '[]' } }
                'resource list' {
                    $fixture.observations++
                    $rows = @($fixture.ids | ForEach-Object { @{id=$_} })
                    if ($fixture.changeInventory -and $fixture.observations -eq 2) { $rows += @{id="$($fixture.ids[0])/extensions/MDE.Linux"} }
                    ConvertTo-Json -InputObject $rows -Compress
                }
                'storage account' {
                    $rows = @()
                    if ($fixture.storageLinked) { $rows += @{networkRuleSet=@{virtualNetworkRules=@(@{virtualNetworkResourceId="$($fixture.ids[3])/subnets/host"})}} }
                    ConvertTo-Json -InputObject $rows -Depth 6 -Compress
                }
                'group delete' { if ($fixture.uncertain) { $global:LASTEXITCODE = 1 } }
                'group wait' { }
                'group exists' { 'false' }
                default { throw "Unexpected fixture operation $operation" }
            }
        }
    }
    BeforeEach {
        $fixture = @{
            subscription=$script:subscription; tenant=$script:tenant; group=$script:group; ids=$script:ids; instance=$script:instance
            operations=[Collections.Generic.List[string]]::new(); observations=0; uncertain=$false
            storageLinked=$false; changeInventory=$false; locked=$false
        }
        $script:fixture = $fixture
        Set-Item Function:az -Value ($script:fixtureCommand.GetNewClosure())
        $selection = $script:selection.Clone()
    }
    It 'verifies the group is gone after one request' {
        $reply = & $script:retire @selection -Confirm:$false
        $reply.State | Should -BeExactly 'deleted'
        $reply.DeletedResourceIds.Count | Should -Be 6
        ($script:fixture.operations | Where-Object { $_ -like 'group d*' -or $_ -in @('group wait','group exists') }) -join ',' |
            Should -BeExactly 'group delete,group wait,group exists'
    }
    It 'keeps WhatIf read-only' {
        & $script:retire @selection -WhatIf
        $script:fixture.operations | Should -Not -Contain 'group delete'
    }
    It 'refuses a backup subnet dependency' {
        $script:fixture.storageLinked = $true
        { & $script:retire @selection -Confirm:$false } | Should -Throw '*references the lab subnet*'
        $script:fixture.operations | Should -Not -Contain 'group delete'
    }
    It 'refuses a changed VM instance' {
        $selection.VmInstanceId = '44444444-4444-4444-8444-444444444444'
        { & $script:retire @selection -Confirm:$false } | Should -Throw '*immutable VM identity differs*'
        $script:fixture.operations | Should -Not -Contain 'group delete'
    }
    It 'refuses management locks' {
        $script:fixture.locked = $true
        { & $script:retire @selection -Confirm:$false } | Should -Throw '*management locks*'
        $script:fixture.operations | Should -Not -Contain 'group delete'
    }
    It 'refuses changed inventory after confirmation' {
        $script:fixture.changeInventory = $true
        { & $script:retire @selection -Confirm:$false } | Should -Throw '*inventory changed*'
        $script:fixture.operations | Should -Not -Contain 'group delete'
    }
    It 'observes an uncertain delete without repeating it' {
        $script:fixture.uncertain = $true
        (& $script:retire @selection -Confirm:$false -WarningAction SilentlyContinue).State | Should -BeExactly 'deleted'
        @($script:fixture.operations | Where-Object { $_ -eq 'group delete' }).Count | Should -Be 1
    }
}
