#Requires -Version 7.6
[CmdletBinding()]
param([Parameter(Mandatory)][string]$DeploymentBindingPath,[Parameter(Mandatory)][string]$Account,
 [Parameter(Mandatory)][string]$Serial,[Parameter(Mandatory)][guid]$HardwareUuid,
 [Parameter(Mandatory)][string]$OperatorUsername,[Parameter(Mandatory)][string]$OperatorEmail,
 [Parameter(Mandatory)][string]$PrivateOutputPath,[ValidateSet('Plan','Create')][string]$Action='Plan',[switch]$ReadbackOnUnknown)
$ErrorActionPreference='Stop'
try {
    Import-Module (Join-Path $PSScriptRoot 'PilotEnrollmentTransport.psm1') -Force
} catch { throw 'SantaEnrollment.LocalPrerequisite.NoCreateSubmitted: Check PowerShell support and the local enrollment module.' }
try {
    $binding=Get-Content -LiteralPath $DeploymentBindingPath -Raw|ConvertFrom-Json -AsHashtable
    if ($binding -isnot [hashtable]) { throw 'Invalid binding' }
} catch { throw 'SantaEnrollment.Input.NoCreateSubmitted: Check the local deployment binding.' }
$arguments=@{}+$PSBoundParameters;$arguments.Remove('DeploymentBindingPath');$arguments.Binding=$binding
Invoke-SantaPilotEnrollment @arguments
