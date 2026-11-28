#Requires -Version 7.6
[CmdletBinding()]
param([Parameter(Mandatory)][ValidatePattern('^[a-z0-9-]{2,32}$')][string]$EnvironmentName)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'PrivateVmInstall.psm1') -Force
Get-PrivateVmHeldHttpsReadiness -EnvironmentName $EnvironmentName
