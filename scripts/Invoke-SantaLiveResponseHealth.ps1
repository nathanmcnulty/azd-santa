#Requires -Version 7.6
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
    [string] $ReceiptPath,
    [switch] $Apply,
    [ValidateRange(1,120)][int] $MaximumPolls = 60,
    [ValidateRange(0,60)][int] $PollIntervalSeconds = 10,
    [System.Net.Http.HttpClient] $HttpClient,
    [System.Net.Http.HttpClient] $ResultHttpClient
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (-not $ResultPath) { $ResultPath = Join-Path $root ".azure/$EnvironmentName/santa-live-response-health-result.json" }
if (-not $ReceiptPath) { $ReceiptPath = "$ResultPath.action.json" }
$ReceiptPath = [IO.Path]::GetFullPath($ReceiptPath)
if ($ReceiptPath -eq [IO.Path]::GetFullPath($ResultPath)) { throw 'ReceiptPath must differ from ResultPath.' }
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
        if (-not $response.IsSuccessStatusCode) { throw "Defender API $Method failed with HTTP $([int]$response.StatusCode)." }
        if ([string]::IsNullOrWhiteSpace($text)) { return $null }
        try { return $text | ConvertFrom-Json } catch { throw 'Defender API returned unreadable JSON; response content is redacted.' }
    } finally {
        if ($content) { $content.Dispose() }
        if ($response) { $response.Dispose() }
    }
}

# A separate receipt preserves the existing v1 success evidence contract.
# Never store API response bodies, output, tokens or signed URLs here.
$receipt = $null
function Save-ActionReceipt {
    param([string] $State, [string] $Status = '')
    $receipt.state = $State
    $receipt.action.status = $Status
    $receipt.updatedUtc = [DateTime]::UtcNow.ToString('o')
    $directory = [IO.Path]::GetDirectoryName($ReceiptPath)
    [IO.Directory]::CreateDirectory($directory) | Out-Null
    $temporary = Join-Path $directory ([IO.Path]::GetRandomFileName())
    try {
        $options = [IO.FileStreamOptions]::new()
        $options.Mode = [IO.FileMode]::CreateNew
        $options.Access = [IO.FileAccess]::Write
        if (-not $IsWindows) { $options.UnixCreateMode = [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite }
        $stream = [IO.FileStream]::new($temporary, $options)
        try {
            if ($IsWindows) {
                $acl = [Security.AccessControl.FileSecurity]::new()
                $acl.SetAccessRuleProtection($true, $false)
                $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
                $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', 'Allow'))
                Set-Acl -LiteralPath $temporary -AclObject $acl
            }
            $bytes = [Text.Encoding]::UTF8.GetBytes(($receipt | ConvertTo-Json -Depth 12))
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush($true)
        } finally { $stream.Dispose() }
        [IO.File]::Move($temporary, $ReceiptPath, $true)
    } finally { if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force } }
}

# Serialize invocations sharing a receipt. Keep the empty lock file: deleting it
# after unlocking would let another invocation lock an unlinked file.
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($ReceiptPath)) | Out-Null
$lockOptions = [IO.FileStreamOptions]::new()
$lockOptions.Mode = [IO.FileMode]::OpenOrCreate
$lockOptions.Access = [IO.FileAccess]::Write
$lockOptions.Share = [IO.FileShare]::None
if (-not $IsWindows) { $lockOptions.UnixCreateMode = [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite }
try { $receiptLock = [IO.FileStream]::new("$ReceiptPath.lock", $lockOptions) }
catch { throw 'Another invocation holds this receipt, or the receipt directory is not writable.' }

try {
# Refuse accidental replay or resumption against a different target.
if (Test-Path -LiteralPath $ReceiptPath) {
    $saved = Get-Content -LiteralPath $ReceiptPath -Raw | ConvertFrom-Json
    if (-not $ExistingActionId) { throw 'An action receipt already exists. Resume with ExistingActionId; do not resubmit an uncertain action.' }
    if ($saved.schemaVersion -ne '1.0' -or $saved.tenantId -ine $ExpectedTenantId -or $saved.account -ine $ExpectedAccount -or
        $saved.machine.id -ine $MachineId -or $saved.machine.name -ine $ExpectedMachineName -or
        (-not [string]::IsNullOrWhiteSpace([string]$saved.action.id) -and $saved.action.id -ine $ExistingActionId) -or $saved.action.scriptName -ine $ScriptName) {
        throw 'Existing action receipt does not match the selected action, script, account, tenant and machine.'
    }
}

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

    $receipt = [ordered]@{
        schemaVersion = '1.0'; template = 'azd-santa'; updatedUtc = ''; state = 'submitted'
        tenantId = $ExpectedTenantId; account = $ExpectedAccount
        machine = [ordered]@{ id = $MachineId; name = $ExpectedMachineName }
        action = [ordered]@{ id = $ExistingActionId; status = ''; scriptName = $ScriptName }
    }
    Save-ActionReceipt -State 'submission-uncertain'
    $action = if ($ExistingActionId) {
        [pscustomobject]@{ id = $ExistingActionId }
    } else {
        Invoke-DefenderJson -Method POST -Uri "https://api.security.microsoft.com/api/machines/$MachineId/runliveresponse" -Body ([ordered]@{
            Commands = @([ordered]@{ type = 'RunScript'; params = @([ordered]@{ key = 'ScriptName'; value = $ScriptName }) })
            Comment = "azd-santa health verification for $ExpectedMachineName"
        })
    }
    if ([string]::IsNullOrWhiteSpace([string]$action.id)) { throw 'Defender did not return a Live Response action ID.' }

    $receipt.action.id = [string]$action.id
    Save-ActionReceipt -State 'submitted'
    $completed = $null
    for ($poll = 0; $poll -lt $MaximumPolls; $poll++) {
        $completed = Invoke-DefenderJson -Method GET -Uri "https://api.security.microsoft.com/api/machineactions/$($action.id)" -AllowNotFound
        if ($null -eq $completed) {
            Save-ActionReceipt -State 'not-yet-visible'
            if ($PollIntervalSeconds -gt 0) { Start-Sleep -Seconds $PollIntervalSeconds }
            continue
        }
        if ([string]$completed.type -ine 'LiveResponse' -or [string]$completed.id -ine [string]$action.id -or [string]$completed.machineId -ine $MachineId -or [string]$completed.computerDnsName -ine $ExpectedMachineName) {
            Save-ActionReceipt -State 'binding-mismatch'
            throw 'Live Response action was not bound to the expected action and machine.'
        }
        Save-ActionReceipt -State 'pending' -Status ([string]$completed.status)
        if ([string]$completed.status -in @('Succeeded','Failed','Cancelled','Rejected','TimeOut')) { break }
        if ($PollIntervalSeconds -gt 0) { Start-Sleep -Seconds $PollIntervalSeconds }
    }
    if ([string]$completed.status -eq 'TimeOut') {
        Save-ActionReceipt -State 'action-timeout' -Status 'TimeOut'
        throw 'Live Response action explicitly reported a service-side timeout. See the private receipt.'
    }
    if ([string]$completed.status -in @('Failed','Cancelled','Rejected')) {
        Save-ActionReceipt -State 'action-failed' -Status ([string]$completed.status)
        throw "Live Response action explicitly reported '$($completed.status)'. See the private receipt."
    }
    if ([string]$completed.status -ne 'Succeeded') {
        Save-ActionReceipt -State 'polling-timeout' -Status ([string]$completed.status)
        Write-Warning 'Live Response remains unverified after the polling window. Resume using ExistingActionId from the private receipt; do not submit again.'
        return [pscustomobject]@{ state = 'polling-timeout'; receiptPath = $ReceiptPath }
    }
    $command = @($completed.commands | Where-Object index -eq 0)
    $scriptParameters = @($command[0].command.params | Where-Object key -eq 'ScriptName')
    if ($command.Count -ne 1 -or [string]$command[0].command.type -ine 'RunScript' -or
        $scriptParameters.Count -ne 1 -or [string]$scriptParameters[0].value -cne $ScriptName) {
        Save-ActionReceipt -State 'binding-mismatch' -Status 'Succeeded'
        throw 'Live Response command was not bound to the selected script.'
    }
    if ($command.Count -ne 1 -or [string]$command[0].commandStatus -ne 'Completed') {
        $state = if ($command.Count -eq 1 -and [string]$command[0].commandStatus -in @('Failed','Cancelled','Rejected')) { 'command-failed' } else { 'command-unverified' }
        Save-ActionReceipt -State $state -Status 'Succeeded'
        throw 'Live Response RunScript command is not verified as complete. See the private receipt.'
    }

    Save-ActionReceipt -State 'result-unverified' -Status 'Succeeded'
    $link = Invoke-DefenderJson -Method GET -Uri "https://api.security.microsoft.com/api/machineactions/$($action.id)/GetLiveResponseResultDownloadLink(index=0)"
    if ([string]::IsNullOrWhiteSpace([string]$link.value)) { throw 'Defender did not return a Live Response result link.' }
    $ownsResultClient = $null -eq $ResultHttpClient
    $resultClient = if ($ownsResultClient) { [Net.Http.HttpClient]::new() } else { $ResultHttpClient }
    try {
        $resultText = $resultClient.GetStringAsync([string]$link.value).GetAwaiter().GetResult()
    } catch {
        throw 'Live Response result download could not be verified. The signed URL is redacted.'
    } finally { if ($ownsResultClient) { $resultClient.Dispose() } }
    try { $result = $resultText | ConvertFrom-Json } catch { throw 'Live Response output was unreadable JSON; content is redacted.' }
    if ([string]$result.script_name -cne $ScriptName) {
        Save-ActionReceipt -State 'binding-mismatch' -Status 'Succeeded'
        throw 'Live Response output was not bound to the selected script.'
    }
    $exitCode = 0
    $hasExitCode = $null -ne $result.exit_code -and [int]::TryParse([string]$result.exit_code, [ref]$exitCode)
    if (-not $hasExitCode -or $exitCode -ne 0 -or [string]$result.script_output -notmatch '(?m)^result=passed$') {
        $state = if ($hasExitCode -and $exitCode -ne 0) { 'command-failed' } elseif ([string]$result.script_output -match '(?m)^result=failed$') { 'command-failed' } else { 'result-unverified' }
        Save-ActionReceipt -State $state -Status 'Succeeded'
        throw 'Santa Live Response output did not verify a passed result.'
    }
    Save-ActionReceipt -State 'verified-completion' -Status 'Succeeded'
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
} catch {
    if ($null -ne $receipt -and $receipt.state -in @('submitted','pending','not-yet-visible')) {
        Save-ActionReceipt -State 'polling-error'
    }
    throw
} finally {
    $receiptLock.Dispose()
    if ($ownsClient) { $client.Dispose() }
}
