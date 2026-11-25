#Requires -Version 7.6
Set-StrictMode -Version Latest

function Assert-SantaGraphReadContext {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowNull()][object] $Context,
        [Parameter(Mandatory)][string] $TenantId,
        [Parameter(Mandatory)][string] $ExpectedAccount,
        [Parameter(Mandatory)][string[]] $Scopes,
        [string] $Environment
    )

    if ($null -eq $Context) {
        throw 'SantaGraph.NoSession: Run this collector in the PowerShell session that already has the approved Microsoft Graph sign-in.'
    }
    foreach ($property in @('TenantId', 'Account', 'AuthType', 'Environment', 'TokenCredentialType', 'Scopes')) {
        if (-not $Context.PSObject.Properties[$property]) {
            throw 'SantaGraph.IncompatibleSession: The session does not report the delegated Graph context required for this read.'
        }
    }
    if ($Context.TenantId -ine $TenantId) { throw 'SantaGraph.WrongTenant: Use the session for the selected tenant.' }
    if ($Context.Account -ine $ExpectedAccount) { throw 'SantaGraph.WrongAccount: Use the session for the selected account.' }
    if ([string]$Context.AuthType -cne 'Delegated' -or [string]$Context.TokenCredentialType -cne 'InteractiveBrowser' -or
        [string]::IsNullOrWhiteSpace([string]$Context.Environment) -or ($Environment -and $Context.Environment -cne $Environment)) {
        throw 'SantaGraph.IncompatibleSession: Use a delegated browser or broker Graph session for the selected cloud.'
    }
    foreach ($scope in $Scopes) {
        if ($scope -notin $Context.Scopes) {
            throw "SantaGraph.MissingScope: The session lacks the required delegated scope '$scope'."
        }
    }
}

Export-ModuleMember -Function Assert-SantaGraphReadContext
