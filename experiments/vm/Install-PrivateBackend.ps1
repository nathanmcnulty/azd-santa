#Requires -Version 7.6
[CmdletBinding()]
param([Parameter(Mandatory)][ValidateSet('preprovision', 'postprovision')][string]$Phase)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'PrivateVmInstall.psm1') -Force
Invoke-PrivateVmAzdHook -Phase $Phase
