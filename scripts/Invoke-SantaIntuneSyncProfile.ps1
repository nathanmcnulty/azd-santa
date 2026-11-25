#Requires -Version 7.6
[CmdletBinding()]
param([ValidateSet('Disabled','Inspect','Apply','Observe')][string]$Action='Disabled',
    [string]$ExpectedTenantId,[string]$ExpectedAccount,[string]$ExpectedGroupId,[string]$ExpectedGroupDisplayName,
    [string]$ExpectedDeviceObjectId,[string]$ExpectedDeviceId,[string]$ExpectedDeviceName,[string]$ExpectedConfigurationObjectId,
    [string]$OwnedReceiptPath,[string]$ProviderProfilePath,[string]$QualificationPath,[string]$ReviewEvidencePath,
    [string]$ExpectedSyncOrigin,[string]$ExpectedCurrentProfileSha256,[string]$CheckpointPath)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'Santa.SyncProfilePublisher.psm1') -Force
Invoke-SantaIntuneSyncProfile @PSBoundParameters
