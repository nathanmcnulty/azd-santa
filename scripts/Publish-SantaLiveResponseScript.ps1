#requires -Version 7.0
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [string] $ScriptPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts/live-response/Get-SantaHealth.sh'),
    [Parameter(Mandatory)][string] $ExpectedTenantId,
    [Parameter(Mandatory)][string] $ExpectedAccount,
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$')][string] $EnvironmentName = 'default',
    [string] $ReceiptPath,
    [switch] $Apply,
    [System.Net.Http.HttpClient] $HttpClient
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (-not $ReceiptPath) { $ReceiptPath = Join-Path $root ".azure/$EnvironmentName/azd-santa-live-response-state.json" }
if (-not (Test-Path -LiteralPath $ScriptPath -PathType Leaf)) { throw "Live Response script not found: $ScriptPath" }
if ((Get-Item -LiteralPath $ScriptPath).Length -gt 20MB) { throw 'The Live Response library upload exceeds the 20 MB API limit.' }
if ($ExpectedTenantId -notmatch '^[0-9a-fA-F-]{36}$') { throw 'ExpectedTenantId must be a tenant GUID.' }
if ($ExpectedAccount -notmatch '^[^@\s]+@[^@\s]+$') { throw 'ExpectedAccount must be the intended MDE administrator UPN.' }
if (-not (Get-Command az -ErrorAction SilentlyContinue)) { throw 'Azure CLI is required for its cached browser/WAM token.' }

$fileName = [IO.Path]::GetFileName($ScriptPath)
$sha256 = (Get-FileHash -LiteralPath $ScriptPath -Algorithm SHA256).Hash.ToLowerInvariant()
$description = "Managed by azd-santa; Santa health verification; sha256=$sha256"
if (-not $Apply) {
    [pscustomobject]@{ mode = 'what-if'; fileName = $fileName; sha256 = $sha256; tenantId = $ExpectedTenantId; account = $ExpectedAccount } | ConvertTo-Json
    return
}
if (-not $PSCmdlet.ShouldProcess("Defender Live Response library in tenant $ExpectedTenantId", "Publish $fileName")) { return }

$accountJson = (& az account show --query '{tenantId:tenantId,user:user.name}' --output json --only-show-errors) -join [Environment]::NewLine
if ($LASTEXITCODE -ne 0) { throw 'Azure CLI could not inspect the active account.' }
$account = $accountJson | ConvertFrom-Json
if ([string]$account.tenantId -ine $ExpectedTenantId -or [string]$account.user -ine $ExpectedAccount) {
    throw "Azure CLI is signed into '$($account.user)' in tenant '$($account.tenantId)', not the selected MDE account and tenant."
}

# The REST endpoint uses api.security.microsoft.com, while the API requires a
# token for its legacy resource registration.
$token = (& az account get-access-token --resource 'https://api.securitycenter.microsoft.com' --tenant $ExpectedTenantId --query accessToken --output tsv --only-show-errors).Trim()
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($token)) { throw 'Azure CLI could not obtain a Defender for Endpoint token.' }

$ownsClient = $null -eq $HttpClient
$client = if ($ownsClient) { [Net.Http.HttpClient]::new() } else { $HttpClient }
$client.DefaultRequestHeaders.Authorization = [Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', $token)
$stream = $null
$fileContent = $null
$multipart = $null
try {
    $libraryResponse = $client.GetAsync('https://api.security.microsoft.com/api/libraryfiles').GetAwaiter().GetResult()
    $libraryBody = $libraryResponse.Content.ReadAsStringAsync().GetAwaiter().GetResult()
    if (-not $libraryResponse.IsSuccessStatusCode) { throw "Defender library query failed with HTTP $([int]$libraryResponse.StatusCode): $libraryBody" }
    $libraryMatches = @((ConvertFrom-Json $libraryBody).value | Where-Object fileName -ieq $fileName)
    if ($libraryMatches.Count -gt 1) { throw "More than one Live Response file is named '$fileName'." }
    if ($libraryMatches.Count -eq 1 -and [string]$libraryMatches[0].description -notmatch '(?i)managed by azd-santa') {
        throw "A Live Response file named '$fileName' exists but is not owned by azd-santa."
    }

    if ($libraryMatches.Count -eq 1 -and [string]$libraryMatches[0].sha256 -eq $sha256 -and [string]$libraryMatches[0].description -eq $description) {
        $action = 'verified'
        $published = $libraryMatches[0]
    } else {
        $stream = [IO.File]::OpenRead($ScriptPath)
        $fileContent = [Net.Http.StreamContent]::new($stream)
        $multipart = [Net.Http.MultipartFormDataContent]::new()
        $fileContent.Headers.ContentType = [Net.Http.Headers.MediaTypeHeaderValue]::new('text/plain')
        $multipart.Add($fileContent, 'file', $fileName)
        $multipart.Add([Net.Http.StringContent]::new($description), 'Description')
        $multipart.Add([Net.Http.StringContent]::new('false'), 'HasParameters')
        $multipart.Add([Net.Http.StringContent]::new([string]($libraryMatches.Count -eq 1)), 'OverrideIfExists')
        $response = $client.PostAsync('https://api.security.microsoft.com/api/libraryfiles', $multipart).GetAwaiter().GetResult()
        $body = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        if (-not $response.IsSuccessStatusCode) { throw "Defender library upload failed with HTTP $([int]$response.StatusCode): $body" }
        $action = if ($libraryMatches.Count -eq 1) { 'updated' } else { 'created' }

        $readbackResponse = $client.GetAsync('https://api.security.microsoft.com/api/libraryfiles').GetAwaiter().GetResult()
        $readbackBody = $readbackResponse.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        if (-not $readbackResponse.IsSuccessStatusCode) { throw "Defender library read-back failed with HTTP $([int]$readbackResponse.StatusCode): $readbackBody" }
        $readbackMatches = @((ConvertFrom-Json $readbackBody).value | Where-Object fileName -ieq $fileName)
        if ($readbackMatches.Count -ne 1 -or [string]$readbackMatches[0].sha256 -ne $sha256 -or [string]$readbackMatches[0].description -ne $description) {
            throw 'Defender Live Response library read-back did not match the published artifact.'
        }
        $published = $readbackMatches[0]
    }
    New-Item -ItemType Directory -Path (Split-Path -Parent $ReceiptPath) -Force | Out-Null
    [ordered]@{
        schemaVersion = '1.0'; template = 'azd-santa'; objectType = 'defender-live-response-library-file'
        fileName = $fileName; sha256 = $sha256; description = $description; tenantId = $ExpectedTenantId
        remoteSha256 = [string]$published.sha256; action = $action; lastUpdatedTime = [string]$published.lastUpdatedTime
        account = $ExpectedAccount; environmentName = $EnvironmentName; status = 'published'; recordedUtc = [DateTime]::UtcNow.ToString('o')
    } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $ReceiptPath -Encoding UTF8
    Write-Host "Published $fileName to the Defender Live Response library." -ForegroundColor Green
} finally {
    if ($multipart) { $multipart.Dispose() }
    if ($fileContent) { $fileContent.Dispose() }
    if ($stream) { $stream.Dispose() }
    if ($ownsClient) { $client.Dispose() }
}
