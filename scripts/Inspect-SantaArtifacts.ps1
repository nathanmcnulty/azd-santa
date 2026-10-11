#Requires -Version 7.6
[CmdletBinding()]
param([string] $TargetPath, [string] $ProfileReceiptPath, [string] $ProfileStatusPath, [string] $EndpointEvidencePath, [switch] $Plan)
$ErrorActionPreference = 'Stop'
$failed = $false
try {
    Import-Module (Join-Path $PSScriptRoot 'Santa.ArtifactInspection.psm1') -Force
    Invoke-SantaArtifactInspection @PSBoundParameters | ConvertTo-Json -Depth 32
} catch { $failed = $true }
if ($failed) { throw [InvalidOperationException]::new('SantaArtifactInspectionFailed') }
