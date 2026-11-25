#Requires -Version 7.6
[CmdletBinding()]
param([ValidateSet('Plan','Apply','Observe')][string]$Action='Plan',
    [guid]$TenantId,[guid]$SubscriptionId,[string]$Location,[string]$SourceEnvironment,[guid]$SourceVmInstanceId,
    [string]$VerifierEnvironment,[guid]$VerifierVmInstanceId,[string]$StateDirectory,[string]$Python)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'BackupStoreDeployment.psm1') -Force
Invoke-SantaBackupStoreDeployment @PSBoundParameters
