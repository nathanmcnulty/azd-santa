#Requires -Version 7.6
[CmdletBinding()]
param([Parameter(Mandatory)][guid]$SubscriptionId,
    [Parameter(Mandatory)][ValidatePattern('^[a-z0-9-]{2,32}$')][string]$EnvironmentName,
    [switch]$Apply, [switch]$Observe)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'PrivatePreSnapshotRecovery.psm1') -Force
Repair-SantaPrivatePreSnapshotFailure @PSBoundParameters
