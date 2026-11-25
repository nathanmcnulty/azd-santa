#Requires -Version 7.6
[CmdletBinding(DefaultParameterSetName = 'File')]
param(
    [Parameter(Mandatory)][string]$DeploymentBindingPath,
    [Parameter(Mandatory)][ValidateSet('bootstrap', 'recover')][string]$Mode,
    [Parameter(Mandatory)][string]$Username, [Parameter(Mandatory)][string]$Email,
    [Parameter(Mandatory)][string]$Reason,
    [Parameter(Mandatory)][string]$CheckpointDirectory,
    [Parameter(Mandatory, ParameterSetName = 'File')][string]$PrivateOutputPath,
    [Parameter(Mandatory, ParameterSetName = 'Browser')][switch]$OpenBrowser,
    [switch]$ReadbackOnUnknown
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'SetupTransport.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'SealedSetup.psm1') -Force
if ($PSCmdlet.ParameterSetName -eq 'File') { Assert-SantaPrivateDestination $PrivateOutputPath }
elseif (-not $OpenBrowser) { throw 'Explicit browser delivery is required.' }
$binding = Get-Content -LiteralPath $DeploymentBindingPath -Raw | ConvertFrom-Json -AsHashtable
$fields = @('TenantId', 'SubscriptionId', 'EnvironmentName', 'ResourceGroup', 'VmName', 'VmId',
    'VmInstanceId', 'ImageId', 'ComposePath', 'ComposeSha256', 'Origin')
if ($binding.Count -ne $fields.Count -or @($binding.Keys | Where-Object { $_ -cnotin $fields }).Count) {
    throw 'Exact reviewed deployment-binding artifact required; no discovery or deployment is implicit.'
}
function Get-NormalizedSourceHash([string]$Path) {
    $text = [IO.File]::ReadAllText($Path, [Text.UTF8Encoding]::new($false, $true)).Replace("`r`n", "`n")
    [Convert]::ToHexStringLower([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($text)))
}
$program = Join-Path $PSScriptRoot 'operator_setup_host.py'
$binding.RemoteProgramSha256 = (Get-FileHash -LiteralPath $program -Algorithm SHA256).Hash.ToLowerInvariant()
$binding.SourceCommit = (Get-Content (Join-Path $PSScriptRoot 'zentral-source.lock.json') -Raw | ConvertFrom-Json).commit
$binding.AdmissionSha256 = Get-NormalizedSourceHash (Join-Path $PSScriptRoot 'santa_admission.py')
$binding.RecoverySha256 = Get-NormalizedSourceHash (Join-Path $PSScriptRoot 'operator_recovery.py')
$binding.SealedSha256 = Get-NormalizedSourceHash (Join-Path $PSScriptRoot 'sealed_setup.py')
$request = $null
try {
    $request = New-SantaSetupTransportRequest -Binding $binding -Mode $Mode -Username $Username -Email $Email -Reason $Reason
    try {
        $envelope = Send-SantaSetupRunCommand -Request $request -RemoteProgramPath $program -CheckpointDirectory $CheckpointDirectory -Operation create
    } catch {
        if (-not $ReadbackOnUnknown) { throw 'Setup outcome requires inspection. Preserve checkpoints; do not repeat create. Recipient will be disposed when this command exits.' }
        # Explicit caller opt-in only. Readback cannot re-run operator_access.
        $envelope = Send-SantaSetupRunCommand -Request $request -RemoteProgramPath $program -CheckpointDirectory $CheckpointDirectory -Operation readback
    }
    $delivery = @{ Recipient = $request.Recipient; EnvelopeJson = $envelope; ExpectedContext = $request.Context
        ExpectedMode = $request.Mode; ExpectedTargetDigest = $request.TargetDigest; ExpectedOrigin = $binding.Origin }
    if ($PSCmdlet.ParameterSetName -eq 'Browser') { $delivery.OpenBrowser = $OpenBrowser }
    else { $delivery.PrivateOutputPath = $PrivateOutputPath }
    Receive-SantaSetupEnvelope @delivery
} finally {
    if ($request) { $request.Recipient.Key.Dispose() }
}
