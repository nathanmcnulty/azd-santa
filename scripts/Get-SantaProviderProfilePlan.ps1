#Requires -Version 7.6
[CmdletBinding()]
param(
    [switch] $EnablePlanning,
    [string] $ProviderProfilePath,
    [string] $QualificationPath,
    [string] $ReviewEvidencePath,
    [string] $OwnedReceiptPath,
    [string] $ExpectedTenantId,
    [string] $ExpectedGroupId,
    [string] $ExpectedConfigurationObjectId
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Santa.ProviderPlan.psm1') -Force
Get-SantaProviderProfilePlan @PSBoundParameters | ConvertTo-Json -Depth 12
