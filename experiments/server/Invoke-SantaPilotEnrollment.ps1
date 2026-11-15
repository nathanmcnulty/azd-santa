#Requires -Version 7.6
[CmdletBinding()]
param([Parameter(Mandatory)][string]$DeploymentBindingPath,[Parameter(Mandatory)][string]$Account,
 [Parameter(Mandatory)][string]$Serial,[Parameter(Mandatory)][guid]$HardwareUuid,
 [Parameter(Mandatory)][string]$OperatorUsername,[Parameter(Mandatory)][string]$OperatorEmail,
 [Parameter(Mandatory)][string]$PrivateOutputPath,[ValidateSet('Plan','Create')][string]$Action='Plan',[switch]$ReadbackOnUnknown)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'PilotEnrollmentTransport.psm1') -Force
$binding=Get-Content -LiteralPath $DeploymentBindingPath -Raw|ConvertFrom-Json -AsHashtable
$arguments=@{}+$PSBoundParameters;$arguments.Remove('DeploymentBindingPath');$arguments.Binding=$binding
Invoke-SantaPilotEnrollment @arguments
