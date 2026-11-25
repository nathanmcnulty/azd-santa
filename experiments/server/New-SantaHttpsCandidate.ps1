#Requires -Version 7.6
[CmdletBinding()]
param([Parameter(Mandatory)][guid]$TenantId,
    [Parameter(Mandatory)][guid]$SubscriptionId,
    [Parameter(Mandatory)][guid]$VmInstanceId,
    [Parameter(Mandatory)][ValidatePattern('^[a-z0-9-]{2,32}$')][string]$EnvironmentName,
    [Parameter(Mandatory)][string]$Destination)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'HttpsEndpoint.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'SealedSetup.psm1') -Force
$factsPath = $Destination + '.arm-facts.json'
$receiptPath = $Destination + '.arm-readback.json'
foreach ($path in @($Destination,$factsPath,$receiptPath)) { Assert-SantaPrivateDestination $path }
if (Test-Path -LiteralPath $Destination) { throw 'An absent HTTPS candidate destination is required.' }
$facts = Get-SantaHttpsEndpointFacts -TenantId $TenantId -SubscriptionId $SubscriptionId -VmInstanceId $VmInstanceId -EnvironmentName $EnvironmentName
function Write-EndpointFile([string]$Path, [byte[]]$Bytes) {
    $options = [IO.FileStreamOptions]::new()
    $options.Mode = [IO.FileMode]::CreateNew; $options.Access = [IO.FileAccess]::Write; $options.Share = [IO.FileShare]::None
    if (-not $IsWindows) { $options.UnixCreateMode = [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite }
    $stream = [IO.FileStream]::new($Path, $options)
    try { $stream.Write($Bytes); $stream.Flush($true) } finally { $stream.Dispose() }
}
$bytes = [Text.Encoding]::UTF8.GetBytes(($facts | ConvertTo-Json -Depth 12 -Compress))
$digest = [Convert]::ToHexStringLower([Security.Cryptography.SHA256]::HashData($bytes))
Write-EndpointFile $factsPath $bytes
$renderer = Join-Path $PSScriptRoot 'prepare_https_proxy.py'
$sourceHashes = [ordered]@{}
foreach ($name in @('New-SantaHttpsCandidate.ps1','HttpsEndpoint.psm1','prepare_https_proxy.py')) {
    $sourceHashes[$name] = (Get-FileHash (Join-Path $PSScriptRoot $name) -Algorithm SHA256).Hash.ToLowerInvariant()
}
Write-EndpointFile $receiptPath ([Text.Encoding]::UTF8.GetBytes((@{
    scope='azd-santa-arm-endpoint-readback-v1'; facts_sha256=$digest; source_sha256=$sourceHashes
    admission='held-closed'; dns_resolution='not_run'; certificate='not_run'; effective_network='not_run'
} | ConvertTo-Json -Depth 8 -Compress)))
& python -I $renderer --facts $factsPath --expected-facts-sha256 $digest --destination $Destination
if ($LASTEXITCODE) { throw 'HTTPS offline rendering failed; preserve selected facts and use a new destination after inspection.' }
Write-Output ([pscustomobject]@{ CandidatePath=(Join-Path $Destination 'candidate.json'); FactsPath=$factsPath; ReadbackPath=$receiptPath })
