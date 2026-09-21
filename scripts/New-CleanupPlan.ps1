[CmdletBinding()]
param(
    [string] $ReceiptPath = (Join-Path (Split-Path -Parent $PSScriptRoot) '.azure/azd-santa/intune-profiles-receipt.json'),
    [string] $OutputPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'out/cleanup-plan.json')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Santa.Template.psm1') -Force

$plan = Get-SantaProfileCleanupPlan -ReceiptPath $ReceiptPath
New-Item -ItemType Directory -Path (Split-Path -Parent $OutputPath) -Force | Out-Null
[IO.File]::WriteAllText(
    $OutputPath,
    (($plan | ConvertTo-Json -Depth 20) + [Environment]::NewLine),
    [Text.UTF8Encoding]::new($false)
)
Write-Information 'WHAT-IF only; no Microsoft Graph or Intune mutation occurred.' -InformationAction Continue
Write-Information "Plan: $OutputPath" -InformationAction Continue
$plan.operations | ForEach-Object { [pscustomobject] $_ } | Select-Object profileId,objectId,action | Format-Table -AutoSize
