#Requires -Version 7.6
BeforeDiscovery { Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts/Santa.GraphSession.psm1') -Force }
BeforeAll {
    function global:Get-MgContext { [CmdletBinding()] param() throw 'Unmocked context' }
    function global:Connect-MgGraph { throw 'Sign-in is forbidden in this adapter' }
    function global:Invoke-MgGraphRequest { [CmdletBinding()] param($Method,$Uri,$OutputType) throw 'Unmocked Graph request' }
    function global:Get-MgGraphOption { throw 'Option inspection is forbidden in this adapter' }
    function global:Set-MgGraphOption { throw 'Option changes are forbidden in this adapter' }
}
AfterAll {
    Remove-Module Santa.GraphSession -Force
    Remove-Item Function:\Get-MgContext,Function:\Connect-MgGraph,Function:\Invoke-MgGraphRequest,Function:\Get-MgGraphOption,Function:\Set-MgGraphOption -ErrorAction SilentlyContinue
}
Describe 'Santa cached Graph session validation' {
    InModuleScope Santa.GraphSession {
        BeforeEach {
            $script:context = [pscustomobject]@{
                TenantId = '00000000-0000-0000-0000-000000000001'; Account = 'operator@example.test'
                AuthType = 'Delegated'; Environment = 'Global'; ContextScope = 'Process'; TokenCredentialType = 'InteractiveBrowser'; WamEnabled = $false
                Scopes = @('Group.Read.All'); ClientId = '00000000-0000-0000-0000-000000000002'
            }
            $script:parameters = @{
                TenantId = $context.TenantId; ExpectedAccount = $context.Account; Scopes = @('Group.Read.All'); ContextScope = 'Process'
                ProbeUri = '/v1.0/groups/00000000-0000-0000-0000-000000000003?$select=id'
            }
            Mock Get-MgContext { $script:context }
            Mock Invoke-MgGraphRequest { @{ id = '00000000-0000-0000-0000-000000000003' } }
            Mock Connect-MgGraph { throw 'Forbidden sign-in' }
            Mock Get-MgGraphOption { throw 'Forbidden option read' }
            Mock Set-MgGraphOption { throw 'Forbidden option write' }
        }
        AfterEach {
            Should -Invoke Connect-MgGraph -Times 0 -Exactly
            Should -Invoke Get-MgGraphOption -Times 0 -Exactly
            Should -Invoke Set-MgGraphOption -Times 0 -Exactly
        }
        It 'reuses a usable exact cached context without sign-in or global preference access' {
            $result = Initialize-SantaGraphSession @script:parameters
            $result.Account | Should -Be 'operator@example.test'
            Should -Invoke Invoke-MgGraphRequest -Times 1 -Exactly -ParameterFilter { $Method -eq 'GET' -and $Uri -eq $script:parameters.ProbeUri }
        }
        It 'provides an explicit user-run browser route when context is absent' {
            $script:context = $null
            { Initialize-SantaGraphSession @script:parameters } | Should -Throw '*SantaGraph.SignInRequired*user-run custom-app browser route*'
            Should -Invoke Invoke-MgGraphRequest -Times 0 -Exactly
        }
        It 'refuses wrong tenant instead of replacing it' {
            $script:context.TenantId = '00000000-0000-0000-0000-000000000099'
            { Initialize-SantaGraphSession @script:parameters } | Should -Throw '*SantaGraph.WrongTenant*'
            Should -Invoke Invoke-MgGraphRequest -Times 0 -Exactly
        }
        It 'refuses missing scopes without requesting more permissions' {
            $script:context.Scopes = @('User.Read')
            { Initialize-SantaGraphSession @script:parameters } | Should -Throw '*SantaGraph.MissingScope*'
            Should -Invoke Invoke-MgGraphRequest -Times 0 -Exactly
        }
        It 'refuses incompatible auth type, environment and lifetime' -ForEach @(
            @{ Property = 'AuthType'; Value = 'AppOnly' }, @{ Property = 'Environment'; Value = 'USGov' }, @{ Property = 'ContextScope'; Value = 'CurrentUser' }
        ) {
            $script:context.$Property = $Value
            { Initialize-SantaGraphSession @script:parameters } | Should -Throw '*SantaGraph.IncompatibleContext*'
            Should -Invoke Invoke-MgGraphRequest -Times 0 -Exactly
        }
        It 'preserves the CurrentUser lifetime for profile paths' {
            $script:context.ContextScope = 'CurrentUser'; $script:parameters.ContextScope = 'CurrentUser'
            (Initialize-SantaGraphSession @script:parameters).ContextScope | Should -Be 'CurrentUser'
        }
        It 'refuses wrong account and selected client' {
            $script:context.Account = 'other@example.test'
            { Initialize-SantaGraphSession @script:parameters } | Should -Throw '*SantaGraph.WrongAccount*'
            $script:context.Account = 'operator@example.test'
            { Initialize-SantaGraphSession @script:parameters -GraphClientId '00000000-0000-0000-0000-000000000099' } | Should -Throw '*SantaGraph.WrongClient*'
            Should -Invoke Invoke-MgGraphRequest -Times 0 -Exactly
        }
        It 'rejects device-code, supplied-token or unknown credential contexts before the probe' -ForEach @(
            @{ Credential = 'DeviceCode' }, @{ Credential = 'UserProvidedAccessToken' }, @{ Credential = '' }
        ) {
            $script:context.TokenCredentialType = $Credential
            { Initialize-SantaGraphSession @script:parameters } | Should -Throw '*SantaGraph.UnsupportedCredential*'
            Should -Invoke Invoke-MgGraphRequest -Times 0 -Exactly
        }
        It 'validates a user-established normal-browser custom-app context' {
            (Initialize-SantaGraphSession @script:parameters -AuthenticationMode NormalBrowser -GraphClientId $script:context.ClientId).WamEnabled | Should -BeFalse
        }
        It 'rejects an unverified normal-browser context' -ForEach @(
            @{ Wam = $true }, @{ Wam = $null }, @{ Wam = 'false' }
        ) {
            $script:context.WamEnabled = $Wam
            { Initialize-SantaGraphSession @script:parameters -AuthenticationMode NormalBrowser -GraphClientId $script:context.ClientId } | Should -Throw '*SantaGraph.BrowserUnverified*'
            Should -Invoke Invoke-MgGraphRequest -Times 0 -Exactly
        }
        It 'rejects missing browser metadata before the probe' {
            $script:context.PSObject.Properties.Remove('WamEnabled')
            { Initialize-SantaGraphSession @script:parameters -AuthenticationMode NormalBrowser -GraphClientId $script:context.ClientId } | Should -Throw '*SantaGraph.BrowserUnverified*'
            Should -Invoke Invoke-MgGraphRequest -Times 0 -Exactly
        }
        It 'requires explicit custom-app identity for NormalBrowser validation' {
            { Initialize-SantaGraphSession @script:parameters -AuthenticationMode NormalBrowser } | Should -Throw '*SantaGraph.BrowserUnverified*'
            $script:context.ClientId = '14d82eec-204b-4c2f-b7e8-296a70dab67e'
            { Initialize-SantaGraphSession @script:parameters -AuthenticationMode NormalBrowser -GraphClientId $script:context.ClientId } | Should -Throw '*SantaGraph.BrowserUnverified*'
            Should -Invoke Invoke-MgGraphRequest -Times 0 -Exactly
        }
        It 'distinguishes authentication and authorization probe failures without reauth' -ForEach @(
            @{ Status = 401; Expected = 'AuthenticationFailed' }, @{ Status = 403; Expected = 'AuthorizationFailed' }, @{ Status = 429; Expected = 'ProbeFailed' }
        ) {
            $script:probeStatus = $Status
            Mock Invoke-MgGraphRequest {
                $error = [Exception]::new('Private response canary')
                $error | Add-Member -NotePropertyName ResponseStatusCode -NotePropertyValue $script:probeStatus
                throw $error
            }
            { Initialize-SantaGraphSession @script:parameters } | Should -Throw "*SantaGraph.$Expected*"
        }
        It 'gives WAM host guidance without exposing raw error details' {
            Mock Invoke-MgGraphRequest { throw 'A window handle must be configured; private-canary' }
            try { Initialize-SantaGraphSession @script:parameters; throw 'Expected refusal' }
            catch {
                $_.Exception.Message | Should -Match 'SantaGraph.WindowHandle'
                $_.Exception.Message | Should -Not -Match 'private-canary'
            }
        }
        It 'leaves nullable and stale persisted preference states untouched on success and failure' -ForEach @(
            @{ Cached = $null; Persisted = $false }, @{ Cached = $false; Persisted = $true }, @{ Cached = $true; Persisted = $null }
        ) {
            $script:cachedOption = $Cached; $script:persistedOption = $Persisted
            Mock Get-MgGraphOption { [pscustomobject]@{ DisableWAMForMSGraph = $script:cachedOption } }
            Mock Set-MgGraphOption { $script:persistedOption = $false; throw 'Unexpected preference write' }
            Initialize-SantaGraphSession @script:parameters | Out-Null
            Mock Invoke-MgGraphRequest { throw 'Synthetic failure' }
            { Initialize-SantaGraphSession @script:parameters } | Should -Throw '*SantaGraph.ProbeFailed*'
            $script:cachedOption | Should -Be $Cached
            $script:persistedOption | Should -Be $Persisted
        }
    }
}
