#Requires -Version 7.6
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][ValidatePattern('^[a-z0-9-]{2,32}$')][string]$EnvironmentName,
    [Parameter(Mandatory)][ValidateSet('bootstrap', 'recover')][string]$Mode,
    [Parameter(Mandatory)][string]$Username,
    [Parameter(Mandatory)][string]$Email,
    [Parameter(Mandatory)][string]$Reason,
    [ValidatePattern('^[a-z0-9][a-z0-9-]{0,31}$')][string]$RecoveryAttempt
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'PrivateVmInstall.psm1') -Force
Invoke-PrivateVmOperatorSetup @PSBoundParameters
