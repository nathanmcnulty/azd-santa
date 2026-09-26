#requires -Version 7.0
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{40}$')][string] $MachineId,
    [Parameter(Mandatory)][string] $ExpectedMachineName,
    [Parameter(Mandatory)][string] $ExpectedTenantId,
    [Parameter(Mandatory)][string] $ExpectedAccount,
    [string] $ScriptName = 'Get-SantaHealth.sh',
    [ValidatePattern('^[0-9a-fA-F-]{36}$')][string] $ExistingActionId,
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$')][string] $EnvironmentName = 'default',
    [string] $ResultPath,
    [switch] $Apply,
    [ValidateRange(1,120)][int] $MaximumPolls = 60,
    [ValidateRange(0,60)][int] $PollIntervalSeconds = 10,
    [System.Net.Http.HttpClient] $HttpClient
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (-not $ResultPath) { $ResultPath = Join-Path $root ".azure/$EnvironmentName/santa-live-response-health-result.json" }
if ($ExpectedTenantId -notmatch '^[0-9a-fA-F-]{36}$') { throw 'ExpectedTenantId must be a tenant GUID.' }
if ($ExpectedAccount -notmatch '^[^@\s]+@[^@\s]+$') { throw 'ExpectedAccount must be the intended MDE administrator UPN.' }
if ($ExpectedMachineName -notmatch '^[A-Za-z0-9._-]{1,255}$') { throw 'ExpectedMachineName is not safe.' }
if ($ScriptName -notmatch '^[A-Za-z0-9._-]{1,128}$') { throw 'ScriptName is not safe.' }
if (-not (Get-Command az -ErrorAction SilentlyContinue)) { throw 'Azure CLI is required for its cached browser/WAM token.' }

if (-not $Apply) {
    [pscustomobject]@{ mode = 'what-if'; machineId = $MachineId; expectedMachineName = $ExpectedMachineName; scriptName = $ScriptName; existingActionId = $ExistingActionId; tenantId = $ExpectedTenantId; account = $ExpectedAccount } | ConvertTo-Json
    return
}
if (-not $PSCmdlet.ShouldProcess("$ExpectedMachineName ($MachineId)", "Run Defender Live Response script $ScriptName")) { return }

$accountJson = (& az account show --query '{tenantId:tenantId,user:user.name}' --output json --only-show-errors) -join [Environment]::NewLine
if ($LASTEXITCODE -ne 0) { throw 'Azure CLI could not inspect the active account.' }
$account = $accountJson | ConvertFrom-Json
if ([string]$account.tenantId -ine $ExpectedTenantId -or [string]$account.user -ine $ExpectedAccount) {
    throw "Azure CLI is signed into '$($account.user)' in tenant '$($account.tenantId)', not the selected MDE account and tenant."
}
$token = (& az account get-access-token --resource 'https://api.securitycenter.microsoft.com' --tenant $ExpectedTenantId --query accessToken --output tsv --only-show-errors).Trim()
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($token)) { throw 'Azure CLI could not obtain a Defender for Endpoint token.' }

$ownsClient = $null -eq $HttpClient
$client = if ($ownsClient) { [Net.Http.HttpClient]::new() } else { $HttpClient }
$client.DefaultRequestHeaders.Authorization = [Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', $token)
function Invoke-DefenderJson {
    param([Parameter(Mandatory)][ValidateSet('GET','POST')][string] $Method, [Parameter(Mandatory)][string] $Uri, [object] $Body, [switch] $AllowNotFound)
    $content = if ($null -ne $Body) { [Net.Http.StringContent]::new(($Body | ConvertTo-Json -Depth 12 -Compress), [Text.Encoding]::UTF8, 'application/json') } else { $null }
    try {
        $response = if ($Method -eq 'POST') { $client.PostAsync($Uri, $content).GetAwaiter().GetResult() } else { $client.GetAsync($Uri).GetAwaiter().GetResult() }
        $text = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        if ($AllowNotFound -and [int]$response.StatusCode -eq 404) { return $null }
        if (-not $response.IsSuccessStatusCode) { throw "Defender API $Method failed with HTTP $([int]$response.StatusCode): $text" }
        if ([string]::IsNullOrWhiteSpace($text)) { return $null }
        return $text | ConvertFrom-Json
    } finally { if ($content) { $content.Dispose() } }
}

try {
    $machine = Invoke-DefenderJson -Method GET -Uri "https://api.security.microsoft.com/api/machines/$MachineId"
    if ([string]$machine.id -ine $MachineId -or [string]$machine.computerDnsName -ine $ExpectedMachineName -or [string]$machine.osPlatform -ine 'macOS') {
        throw "Defender machine binding mismatch: $($machine.computerDnsName) / $($machine.osPlatform) / $($machine.id)"
    }
    if ([string]$machine.onboardingStatus -ine 'Onboarded') { throw "Defender machine '$ExpectedMachineName' is not onboarded." }

    $library = Invoke-DefenderJson -Method GET -Uri 'https://api.security.microsoft.com/api/libraryfiles'
    $scripts = @($library.value | Where-Object fileName -ieq $ScriptName)
    if ($scripts.Count -ne 1 -or [string]$scripts[0].description -notmatch '(?i)managed by azd-santa') {
        throw "The exact azd-santa-owned Live Response script '$ScriptName' is not published once in the library."
    }

    $action = if ($ExistingActionId) {
        [pscustomobject]@{ id = $ExistingActionId }
    } else {
        Invoke-DefenderJson -Method POST -Uri "https://api.security.microsoft.com/api/machines/$MachineId/runliveresponse" -Body ([ordered]@{
            Commands = @([ordered]@{ type = 'RunScript'; params = @([ordered]@{ key = 'ScriptName'; value = $ScriptName }) })
            Comment = "azd-santa health verification for $ExpectedMachineName"
        })
    }
    if ([string]::IsNullOrWhiteSpace([string]$action.id)) { throw 'Defender did not return a Live Response action ID.' }

    $completed = $null
    for ($poll = 0; $poll -lt $MaximumPolls; $poll++) {
        $completed = Invoke-DefenderJson -Method GET -Uri "https://api.security.microsoft.com/api/machineactions/$($action.id)" -AllowNotFound
        if ($null -eq $completed) {
            if ($PollIntervalSeconds -gt 0) { Start-Sleep -Seconds $PollIntervalSeconds }
            continue
        }
        if ([string]$completed.status -in @('Succeeded','Failed','Cancelled','Rejected')) { break }
        if ($PollIntervalSeconds -gt 0) { Start-Sleep -Seconds $PollIntervalSeconds }
    }
    if ([string]$completed.status -ne 'Succeeded') { throw "Live Response action '$($action.id)' ended with status '$($completed.status)'." }
    if ([string]$completed.machineId -ine $MachineId -or [string]$completed.computerDnsName -ine $ExpectedMachineName) { throw 'Live Response action was not bound to the expected machine.' }
    $command = @($completed.commands | Where-Object index -eq 0)
    if ($command.Count -ne 1 -or [string]$command[0].commandStatus -ne 'Completed') { throw 'Live Response RunScript command did not complete.' }

    $link = Invoke-DefenderJson -Method GET -Uri "https://api.security.microsoft.com/api/machineactions/$($action.id)/GetLiveResponseResultDownloadLink(index=0)"
    if ([string]::IsNullOrWhiteSpace([string]$link.value)) { throw 'Defender did not return a Live Response result link.' }
    $resultClient = [Net.Http.HttpClient]::new()
    try {
        $resultText = $resultClient.GetStringAsync([string]$link.value).GetAwaiter().GetResult()
    } finally { $resultClient.Dispose() }
    $result = $resultText | ConvertFrom-Json
    if ([int]$result.exit_code -ne 0 -or [string]$result.script_output -notmatch '(?m)^result=passed$') {
        throw "Santa Live Response health check failed: exit=$($result.exit_code); errors=$($result.script_errors)"
    }
    New-Item -ItemType Directory -Path (Split-Path -Parent $ResultPath) -Force | Out-Null
    [ordered]@{
        schemaVersion = '1.0'; template = 'azd-santa'; capturedUtc = [DateTime]::UtcNow.ToString('o')
        tenantId = $ExpectedTenantId; account = $ExpectedAccount
        machine = [ordered]@{ id = $machine.id; name = $machine.computerDnsName; osPlatform = $machine.osPlatform; version = $machine.version; lastSeen = $machine.lastSeen }
        action = [ordered]@{ id = $action.id; status = $completed.status; scriptName = $ScriptName }
        result = $result
    } | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $ResultPath -Encoding UTF8
    $completedLabel = if ($ScriptName -eq 'Get-SantaHealth.sh') { 'Live Response health check passed' } else { 'Live Response diagnostic completed' }
    Write-Host "$completedLabel for $ExpectedMachineName. Result: $ResultPath" -ForegroundColor Green
} finally {
    if ($ownsClient) { $client.Dispose() }
}
