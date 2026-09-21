[CmdletBinding()]
param(
    [string] $Organization = $(if ($env:SANTA_ORGANIZATION) { $env:SANTA_ORGANIZATION } else { 'Contoso' }),
    [string] $OutputPath
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Santa.Template.psm1') -Force
$parameters = @{ Organization = $Organization }
if ($OutputPath) { $parameters.OutputPath = $OutputPath }
$files = New-SantaProfileSet @parameters
$files | ForEach-Object { Write-Information "Generated: $_" -InformationAction Continue }
