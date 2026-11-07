#Requires -Version 7.6
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$InputPath,
    [Parameter(Mandatory)][ValidateSet('ALLOWLIST', 'BLOCKLIST')][string]$Policy,
    [Parameter(Mandatory)][datetimeoffset]$EvaluationTime,
    [Parameter(Mandatory)][datetimeoffset]$ReviewExpiresAt,
    [Parameter(Mandatory)][string]$OutputPath,
    [switch]$WhatIf
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Santa.Candidates.psm1') -Force
New-SantaRuleCandidate @PSBoundParameters
