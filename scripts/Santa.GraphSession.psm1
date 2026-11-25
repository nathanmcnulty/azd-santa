#Requires -Version 7.6
Set-StrictMode -Version Latest

function Initialize-SantaGraphSession {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][guid] $TenantId,
        [Parameter(Mandatory)][ValidatePattern('^[^@\s]+@[^@\s]+$')][string] $ExpectedAccount,
        [Parameter(Mandatory)][string[]] $Scopes,
        [Parameter(Mandatory)][ValidateSet('Process','CurrentUser')][string] $ContextScope,
        [Parameter(Mandatory)][ValidatePattern('^/v1\.0/groups/[0-9a-fA-F-]{36}\?\$select=id$')][string] $ProbeUri,
        [ValidateSet('Default','NormalBrowser')][string] $AuthenticationMode = 'Default',
        [string] $GraphClientId
    )
    $ErrorActionPreference = 'Stop'
    # Reuse first. Never mutate the SDK's persisted user-wide WAM preference.
    if ($GraphClientId) {
        $parsedClient = [guid]::Empty
        if (-not [guid]::TryParse($GraphClientId, [ref]$parsedClient) -or $parsedClient -eq [guid]::Empty) { throw 'SantaGraph.InvalidClient: GraphClientId must identify an existing approved application.' }
    }
    if ($AuthenticationMode -eq 'NormalBrowser' -and (-not $GraphClientId -or $GraphClientId -ieq '14d82eec-204b-4c2f-b7e8-296a70dab67e')) {
        throw 'SantaGraph.BrowserUnverified: Select an existing approved custom GraphClientId and configure the documented browser route before using NormalBrowser.'
    }
    try { $context = Get-MgContext -ErrorAction Stop }
    catch { throw 'SantaGraph.AuthenticationFailed: The SDK context could not be inspected. Check the installed SDK in a supported interactive host.' }
    if ($null -eq $context) {
        $connect = @{ TenantId = [string]$TenantId; Scopes = $Scopes; ContextScope = $ContextScope; Environment = 'Global'; NoWelcome = $true; ErrorAction = 'Stop' }
        if ($GraphClientId) { $connect.ClientId = $GraphClientId }
        try {
            Connect-MgGraph @connect | Out-Null
            $context = Get-MgContext -ErrorAction Stop
        }
        catch {
            if ($_.Exception.Message -match '(?i)window handle|\bWAM\b|broker') {
                throw 'SantaGraph.WindowHandle: Broker authentication is unavailable in this host. Use a supported interactive terminal or the approved custom-app browser route in docs/graph-session-recovery.md. No authentication preference was changed.'
            }
            throw 'SantaGraph.AuthenticationFailed: Graph sign-in did not complete. Retry in a supported interactive host with the intended tenant/account and approved scopes. No authentication preference was changed.'
        }
        if ($null -eq $context) { throw 'SantaGraph.AuthenticationFailed: Graph sign-in returned no context. Retry in a supported interactive host.' }
    }
    if ([string]$context.TenantId -ine [string]$TenantId) { throw 'SantaGraph.WrongTenant: Select the intended tenant explicitly in a supported host.' }
    if ([string]$context.Account -ine $ExpectedAccount) { throw 'SantaGraph.WrongAccount: Select the intended operator explicitly in a supported host.' }
    if ([string]$context.AuthType -cne 'Delegated' -or [string]$context.Environment -cne 'Global' -or [string]$context.ContextScope -cne $ContextScope) {
        throw 'SantaGraph.IncompatibleContext: Delegated Global Graph context with the selected session lifetime is required; no existing context was replaced.'
    }
    if (-not $context.PSObject.Properties['TokenCredentialType'] -or [string]$context.TokenCredentialType -cnotin @('InteractiveBrowser','DeviceCode')) {
        throw 'SantaGraph.UnsupportedCredential: An interactive delegated SDK context is required; supplied-token and unknown credential contexts are not accepted.'
    }
    foreach ($scope in $Scopes) {
        if ($scope -notin @($context.Scopes)) { throw "SantaGraph.MissingScope: Required delegated scope '$scope' is missing. Obtain separately authorized access; this adapter will not add consent." }
    }
    if ($GraphClientId) {
        $parsedClient = [guid]::Empty
        if (-not [guid]::TryParse($GraphClientId, [ref]$parsedClient) -or $parsedClient -eq [guid]::Empty) { throw 'SantaGraph.InvalidClient: GraphClientId must identify an existing approved application.' }
        if ([string]$context.ClientId -ine $GraphClientId) { throw 'SantaGraph.WrongClient: The cached context does not match the selected application.' }
    }
    if ($AuthenticationMode -eq 'NormalBrowser') {
        if (-not $GraphClientId -or $GraphClientId -ieq '14d82eec-204b-4c2f-b7e8-296a70dab67e') {
            throw 'SantaGraph.BrowserUnverified: Select the existing approved custom GraphClientId used for the operator-run browser sign-in.'
        }
        if (-not $context.PSObject.Properties['WamEnabled'] -or $context.WamEnabled -isnot [bool] -or $context.WamEnabled) {
            throw 'SantaGraph.BrowserUnverified: The current SDK context does not report WAM disabled. Use the documented user-run browser route; no preference was changed.'
        }
    }
    try { Invoke-MgGraphRequest -Method GET -Uri $ProbeUri -OutputType PSObject | Out-Null }
    catch {
        # Do not include raw SDK exceptions or response bodies in diagnostics.
        $status = $null
        if ($_.Exception.PSObject.Properties['ResponseStatusCode']) { $status = [string]$_.Exception.ResponseStatusCode }
        elseif ($_.Exception.PSObject.Properties['Response'] -and $_.Exception.Response -and $_.Exception.Response.PSObject.Properties['StatusCode']) { $status = [string]$_.Exception.Response.StatusCode }
        if ($status -in @('401','Unauthorized')) { throw 'SantaGraph.AuthenticationFailed: The cached session failed its read probe. Sign in explicitly in a supported host; no automatic reconnect was attempted.' }
        if ($status -in @('403','Forbidden')) { throw 'SantaGraph.AuthorizationFailed: The selected group read was forbidden. Check separately approved access; no scopes or roles were added.' }
        if ($_.Exception.Message -match '(?i)window handle|\bWAM\b|broker') { throw 'SantaGraph.WindowHandle: Broker authentication is unavailable in this host. Follow the user-run browser guidance in docs/graph-session-recovery.md; no fallback or preference change was attempted.' }
        throw 'SantaGraph.ProbeFailed: The selected group read could not be verified. No reconnect or permission changes were attempted.'
    }
    return $context
}

Export-ModuleMember -Function Initialize-SantaGraphSession
