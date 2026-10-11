#Requires -Version 7.6
BeforeAll {
    $script:root = Split-Path -Parent $PSScriptRoot
    $script:coordinatorPath = Join-Path $PSScriptRoot 'fixtures/graph-coordinator-0.1.1/Azd.GraphAuthentication.psm1'
    # Deliberately import the assessment fixture, not its manifest or any SDK.
    # These closed stubs make accidental unmocked authentication/request calls fail.
    function global:Get-MgEnvironment { throw 'Unmocked environment lookup' }
    function global:Get-MgContext { throw 'Unmocked context lookup' }
    function global:Connect-MgGraph { throw 'Unmocked authentication' }
    function global:Invoke-MgGraphRequest {
        [CmdletBinding()]
        param([string]$Method, [string]$Uri, [string]$OutputType)
        throw 'Unmocked Graph request'
    }
    Import-Module $script:coordinatorPath -Force
    Import-Module (Join-Path $script:root 'scripts/Santa.Template.psm1') -Force
    $script:tenant = '11111111-1111-4111-8111-111111111111'
    $script:scopes = @('DeviceManagementConfiguration.ReadWrite.All','Group.Read.All')
    $script:arguments = @{ TenantId=$script:tenant; ExpectedAccount='pilot@example.invalid'; Scopes=$script:scopes; ProbeUri='/v1.0/groups/22222222-2222-4222-8222-222222222222?$select=id' }
}
AfterAll {
    Remove-Module Azd.GraphAuthentication -Force
    Remove-Item Function:\Get-MgEnvironment,Function:\Get-MgContext,Function:\Connect-MgGraph,Function:\Invoke-MgGraphRequest -ErrorAction SilentlyContinue
}

Describe 'Assessment-only actual delegated coordinator' {
    BeforeEach {
        $script:context = [pscustomobject]@{TenantId=$script:tenant; Account='pilot@example.invalid'; Scopes=$script:scopes; Environment='Global'; AuthType='Delegated'; ContextScope='CurrentUser'}
        Mock Get-MgEnvironment -ModuleName Azd.GraphAuthentication { [pscustomobject]@{Name='Global'} }
        Mock Get-MgContext -ModuleName Azd.GraphAuthentication { $script:context }
        Mock Connect-MgGraph -ModuleName Azd.GraphAuthentication { throw 'Authentication must not start in this assessment' }
        Mock Invoke-MgGraphRequest -ModuleName Azd.GraphAuthentication { [pscustomobject]@{id='22222222-2222-4222-8222-222222222222'} }
    }
    It 'pins the unchanged immutable source fixture' {
        (Get-FileHash $script:coordinatorPath).Hash | Should -Be 'F727F0680A6F11BE057D5A0993C6FEC9917D7DE8870685427A5EC8CA4D739B5E'
    }
    It 'reuses the profile-shaped matching context with exactly one GET and zero connect' {
        $result = Connect-AzdGraphSession @script:arguments
        $result.contextReused | Should -BeTrue
        $result.connectInvoked | Should -BeFalse
        $result.grantedScopes | Should -Be $script:scopes
        Should -Invoke Invoke-MgGraphRequest -ModuleName Azd.GraphAuthentication -Times 1 -Exactly -ParameterFilter { $Method -eq 'GET' -and $Uri -eq '/v1.0/groups/22222222-2222-4222-8222-222222222222?$select=id' -and $OutputType -eq 'PSObject' }
        Should -Invoke Connect-MgGraph -ModuleName Azd.GraphAuthentication -Times 0 -Exactly
    }
    It 'refuses <Field> drift without replacing the existing context' -ForEach @(
        @{Field='ContextScope';Value='Process'}, @{Field='TenantId';Value='99999999-9999-4999-8999-999999999999'},
        @{Field='Account';Value='foreign@example.invalid'}, @{Field='Environment';Value='USGov'}, @{Field='AuthType';Value='AppOnly'},
        @{Field='Scopes';Value=@('Group.Read.All')}
    ) {
        $script:context.$Field = $Value
        { Connect-AzdGraphSession @script:arguments } | Should -Throw '*cannot be replaced without explicit authorization*'
        Should -Invoke Connect-MgGraph -ModuleName Azd.GraphAuthentication -Times 0 -Exactly
        Should -Invoke Invoke-MgGraphRequest -ModuleName Azd.GraphAuthentication -Times 0 -Exactly
    }
    It 'refuses missing context without implicit interaction' {
        $script:context = $null
        { Connect-AzdGraphSession @script:arguments } | Should -Throw '*noninteractive execution*'
        Should -Invoke Connect-MgGraph -ModuleName Azd.GraphAuthentication -Times 0 -Exactly
    }
    It 'refuses an expired-token-shaped 401 without implicit interaction' {
        Mock Invoke-MgGraphRequest -ModuleName Azd.GraphAuthentication {
            $failure = [Exception]::new('synthetic authentication failure')
            $failure | Add-Member NoteProperty ResponseStatusCode 401
            throw $failure
        }
        { Connect-AzdGraphSession @script:arguments } | Should -Throw '*not usable in this process*'
        Should -Invoke Connect-MgGraph -ModuleName Azd.GraphAuthentication -Times 0 -Exactly
    }
    It 'does not turn <Code> into an authentication attempt even with explicit interaction consent' -ForEach @(@{Code=403;Classification='authorization'},@{Code=429;Classification='throttled'},@{Code=500;Classification='provider'}) {
        Mock Invoke-MgGraphRequest -ModuleName Azd.GraphAuthentication {
            $failure = [Exception]::new('synthetic provider failure')
            $failure | Add-Member NoteProperty ResponseStatusCode $Code
            throw $failure
        }
        { Connect-AzdGraphSession @script:arguments -AllowInteractive } | Should -Throw "*without an authentication error*Classification: $Classification;*"
        Should -Invoke Connect-MgGraph -ModuleName Azd.GraphAuthentication -Times 0 -Exactly
    }
    It 'rejects an absolute probe before context lookup or request' {
        $invalid = $script:arguments.Clone()
        $invalid.ProbeUri = 'https://graph.microsoft.com/v1.0/groups'
        { Connect-AzdGraphSession @invalid } | Should -Throw '*relative*'
        Should -Invoke Get-MgContext -ModuleName Azd.GraphAuthentication -Times 0 -Exactly
        Should -Invoke Invoke-MgGraphRequest -ModuleName Azd.GraphAuthentication -Times 0 -Exactly
    }
}

Describe 'Unchanged publisher dry-run boundaries' {
    BeforeEach {
        Mock Get-MgContext { throw 'Publisher must not read a Graph context' }
        Mock Connect-MgGraph { throw 'Publisher must not authenticate' }
        Mock Invoke-MgGraphRequest { throw 'Publisher must not dispatch Graph' }
    }
    It 'executes the actual profile publisher dry run with zero Graph and no receipt' {
        $receipt = Join-Path $TestDrive 'profile-receipt.json'
        $result = & (Join-Path $script:root 'scripts/Invoke-SantaIntuneProfiles.ps1') -TenantId $script:tenant -PilotGroupId '22222222-2222-4222-8222-222222222222' -ExpectedGroupDisplayName 'Santa pilot' -ExpectedDeviceName 'Pilot-Mac' -ExpectedAccount 'pilot@example.invalid' -ReceiptPath $receipt | ConvertFrom-Json
        $result.mode | Should -Be 'what-if'
        @($result.profiles).Count | Should -Be 5
        Test-Path $receipt | Should -BeFalse
        Should -Invoke Get-MgContext -Times 0 -Exactly
        Should -Invoke Connect-MgGraph -Times 0 -Exactly
        Should -Invoke Invoke-MgGraphRequest -Times 0 -Exactly
    }
    It 'executes the actual package publisher dry run with the pinned package and synthetic status, without dispatch or receipt' {
        $status = Get-Content (Join-Path $PSScriptRoot 'fixtures/intune/profile-status-success.json') -Raw | ConvertFrom-Json -DateKind String
        $status.collectedAt = [DateTimeOffset]::UtcNow.ToString('o')
        $statusPath = Join-Path $TestDrive 'synthetic-status.json'
        $status | ConvertTo-Json -Depth 30 | Set-Content $statusPath
        $receipt = Join-Path $TestDrive 'package-receipt.json'
        & (Join-Path $script:root 'scripts/Invoke-SantaIntunePackage.ps1') -PackagePath (Join-Path $script:root 'package/vendor/santa-2026.8.pkg') -PackageVerificationReceiptPath (Join-Path $script:root 'package/verification/santa-2026.8.json') -ProfileStatusPath $statusPath -TenantId $script:tenant -PilotGroupId $status.pilotGroup.id -ExpectedPilotGroupName $status.pilotGroup.displayName -ExpectedDeviceName $status.pilotDevice.deviceName -ExpectedAccount $status.account -ReceiptPath $receipt
        Test-Path $receipt | Should -BeFalse
        Should -Invoke Get-MgContext -Times 0 -Exactly
        Should -Invoke Connect-MgGraph -Times 0 -Exactly
        Should -Invoke Invoke-MgGraphRequest -Times 0 -Exactly
    }
}
