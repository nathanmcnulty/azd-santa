#requires -Version 7.0
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

function Get-AzdSetting {
    param([Parameter(Mandatory)][string] $Name)
    $value = [Environment]::GetEnvironmentVariable($Name, 'Process')
    if (-not [string]::IsNullOrWhiteSpace($value)) { return $value }
    if (Get-Command azd -ErrorAction SilentlyContinue) {
        $value = (& azd env get-value $Name 2>$null | Select-Object -Last 1)
        if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($value) -and $value -ne 'null') { return ([string]$value).Trim() }
    }
    return $null
}
function Test-Enabled { param([string] $Value) return $Value -match '^(?i:true|1|yes|y|on)$' }
function Assert-Setting { param([string] $Name, [string] $Pattern = '.+') $value = Get-AzdSetting $Name; if ($value -notmatch $Pattern) { throw "Required AZD setting '$Name' is missing or invalid." }; return $value }

$publishIntune = Test-Enabled (Get-AzdSetting 'AZD_SANTA_DEPLOY_INTUNE_HEALTH_SCRIPT')
$publishLiveResponse = Test-Enabled (Get-AzdSetting 'AZD_SANTA_PUBLISH_LIVE_RESPONSE_LIBRARY')
$runLiveResponse = Test-Enabled (Get-AzdSetting 'AZD_SANTA_RUN_LIVE_RESPONSE_HEALTH')
if (-not ($publishIntune -or $publishLiveResponse -or $runLiveResponse)) {
    Write-Host 'No optional Santa health publication or execution channel is enabled.' -ForegroundColor DarkGray
    return
}
if ($runLiveResponse -and -not $publishLiveResponse) { throw 'AZD_SANTA_RUN_LIVE_RESPONSE_HEALTH requires AZD_SANTA_PUBLISH_LIVE_RESPONSE_LIBRARY=true.' }

$tenantId = Assert-Setting 'AZURE_TENANT_ID' '^[0-9a-fA-F-]{36}$'
$environmentName = Get-AzdSetting 'AZURE_ENV_NAME'
if ([string]::IsNullOrWhiteSpace($environmentName)) { $environmentName = 'default' }
if ($environmentName -notmatch '^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$') { throw 'AZURE_ENV_NAME is not safe for a receipt path.' }

if ($publishIntune) {
    & (Join-Path $PSScriptRoot 'Publish-SantaIntuneHealthScript.ps1') `
        -TenantId $tenantId `
        -PilotGroupId (Assert-Setting 'AZD_SANTA_PILOT_GROUP_ID' '^[0-9a-fA-F-]{36}$') `
        -ExpectedGroupDisplayName (Assert-Setting 'AZD_SANTA_PILOT_GROUP_NAME') `
        -ExpectedDeviceName (Assert-Setting 'AZD_SANTA_INTUNE_DEVICE_NAME' '^[A-Za-z0-9._-]{1,255}$') `
        -ExpectedAccount (Assert-Setting 'AZD_SANTA_INTUNE_ACCOUNT' '^[^@\s]+@[^@\s]+$') `
        -EnvironmentName $environmentName -Apply -Confirm:$false
    & (Join-Path $PSScriptRoot 'Get-SantaIntuneHealthStatus.ps1') `
        -TenantId $tenantId `
        -ExpectedAccount (Assert-Setting 'AZD_SANTA_INTUNE_ACCOUNT' '^[^@\s]+@[^@\s]+$') `
        -EnvironmentName $environmentName
}

if ($publishLiveResponse) {
    $mdeAccount = Assert-Setting 'AZD_SANTA_MDE_ACCOUNT' '^[^@\s]+@[^@\s]+$'
    & (Join-Path $PSScriptRoot 'Publish-SantaLiveResponseScript.ps1') `
        -ExpectedTenantId $tenantId -ExpectedAccount $mdeAccount `
        -EnvironmentName $environmentName -Apply -Confirm:$false
    if ($runLiveResponse) {
        & (Join-Path $PSScriptRoot 'Invoke-SantaLiveResponseHealth.ps1') `
            -MachineId (Assert-Setting 'AZD_SANTA_MDE_MACHINE_ID' '^[0-9a-fA-F]{40}$') `
            -ExpectedMachineName (Assert-Setting 'AZD_SANTA_MDE_MACHINE_NAME' '^[A-Za-z0-9._-]{1,255}$') `
            -ExpectedTenantId $tenantId -ExpectedAccount $mdeAccount `
            -EnvironmentName $environmentName -Apply -Confirm:$false
    }
}
