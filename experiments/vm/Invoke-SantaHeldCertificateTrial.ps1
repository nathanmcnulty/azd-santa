#Requires -Version 7.6
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param([Parameter(Mandatory)][ValidatePattern('^[a-z0-9-]{2,32}$')][string]$EnvironmentName,
    [ValidateSet('Issue', 'Renew')][string]$Mode = 'Issue')

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'PrivateVmInstall.psm1') -Force
Invoke-PrivateVmHeldCertificateTrial @PSBoundParameters
