#Requires -Version 7.6
Describe 'Optional synthetic VM lab boundaries' {
    BeforeAll {
        $root = Split-Path $PSScriptRoot -Parent
        $lab = Join-Path $root 'experiments/vm'
    }
    It 'keeps root deployment compute-free and the experiment free of Intune hooks' {
        Get-Content (Join-Path $root 'infra/main.bicep') -Raw | Should -Not -Match 'Microsoft.Compute/'
        Get-Content (Join-Path $lab 'azure.yaml') -Raw | Should -Not -Match '(?m)^hooks:'
        Get-Content (Join-Path $lab 'azure.yaml') -Raw | Should -Not -Match 'Post-Provision|New-SantaProfiles'
    }
    It 'declares deny-all ingress and explicit outbound rather than an SSH exception' {
        $hostTemplate = Get-Content (Join-Path $lab 'infra/host.bicep') -Raw
        $hostTemplate | Should -Match "name: 'deny-all-inbound'"
        $hostTemplate | Should -Match "access: 'Deny'"
        $hostTemplate | Should -Not -Match "access: 'Allow'"
        $hostTemplate | Should -Match 'defaultOutboundAccess: false'
        $hostTemplate | Should -Match 'publicIPAddress: \{ id: egress.id \}'
        $hostTemplate | Should -Not -Match 'roleAssignments|customData|extensions@'
    }
    It 'parses the privileged helper without invoking Azure' {
        $tokens = $null
        $errors = $null
        [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $lab 'Test-VmLab.ps1'), [ref]$tokens, [ref]$errors) | Out-Null
        $errors | Should -BeNullOrEmpty
    }
    It 'binds the new permission inventory to current source bytes' {
        $manifest = Get-Content (Join-Path $root 'azd-permissions.json') -Raw | ConvertFrom-Json
        $requirements = @($manifest.requirements | Where-Object feature -EQ 'synthetic-vm-lab')
        $requirements.Count | Should -Be 2
        foreach ($entry in $requirements.evidence) {
            (Get-FileHash (Join-Path $root $entry.path) -Algorithm SHA256).Hash.ToLowerInvariant() | Should -Be $entry.sha256
        }
    }
    It 'rejects an existing receipt before invoking privileged execution' {
        $receipt = Join-Path $TestDrive 'existing.json'
        [IO.File]::WriteAllText($receipt, 'preserve me')
        { & (Join-Path $lab 'Test-VmLab.ps1') -SubscriptionId '11111111-1111-4111-8111-111111111111' -EnvironmentName offline -ReceiptPath $receipt } | Should -Throw '*Refusing to overwrite*'
        [IO.File]::ReadAllText($receipt) | Should -Be 'preserve me'
    }
}
