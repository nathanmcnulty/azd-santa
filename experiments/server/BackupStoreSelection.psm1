#Requires -Version 7.6
# Original Unlicense. Explicit cached ARM reads only. No deployment or SAS.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:EndpointReader = Import-Module (Join-Path $PSScriptRoot 'HttpsEndpoint.psm1') -PassThru -Force

function Invoke-SantaStoreBridge {
    param([hashtable]$Request, [string]$Python)
    $start = [Diagnostics.ProcessStartInfo]::new()
    # Get-Command can return every matching PATH application. Preserve ordinary
    # first-match command precedence instead of joining multiple executable paths.
    $start.FileName = @(Get-Command $Python -CommandType Application -ErrorAction Stop)[0].Source
    $start.ArgumentList.Add('-I')
    $start.ArgumentList.Add((Join-Path $PSScriptRoot 'backup_store_selection.py'))
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = [Diagnostics.Process]::new(); $process.StartInfo = $start
    try {
        $payload = $Request | ConvertTo-Json -Depth 48 -Compress
        if ([Text.Encoding]::UTF8.GetByteCount($payload) -gt 8388608) { throw 'Selection input bound exceeded.' }
        $null = $process.Start()
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $process.StandardInput.Write($payload); $process.StandardInput.Close()
        if (-not $process.WaitForExit(30000)) { $process.Kill($true); throw 'Selection bridge timed out.' }
        $output = $stdout.GetAwaiter().GetResult()
        $null = $stderr.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0 -or [Text.Encoding]::UTF8.GetByteCount($output) -gt 65536) { throw 'Selection bridge failed.' }
        $output | ConvertFrom-Json -Depth 48 -AsHashtable -ErrorAction Stop
    } finally { $process.Dispose() }
}

function Invoke-SantaStoreCachedRead {
    param([string[]]$Arguments)
    # Reuse the existing bounded cached CLI reader, without exporting its private API.
    & $script:EndpointReader { param([string[]]$a) Invoke-SantaEndpointAzJson -Arguments $a } $Arguments
}

function Get-SantaBackupStoreSelection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][guid]$TenantId,
        [Parameter(Mandatory)][guid]$SubscriptionId,
        [Parameter(Mandatory)][ValidatePattern('^[a-z0-9]{2,32}$')][string]$Location,
        [Parameter(Mandatory)][string]$BackupResourceGroupName,
        [Parameter(Mandatory)][ValidatePattern('^[a-z0-9]{3,24}$')][string]$BackupStoreName,
        [Parameter(Mandatory)][guid]$OwnershipId,
        [Parameter(Mandatory)][ValidatePattern('^[a-z0-9-]{2,32}$')][string]$SourceEnvironment,
        [Parameter(Mandatory)][guid]$SourceVmInstanceId,
        [ValidatePattern('^[a-z0-9-]{2,32}$')][string]$VerifierEnvironment,
        [guid]$VerifierVmInstanceId,
        [string]$Python = 'python',
        [switch]$ReadArm
    )
    try {
        if ([bool]$VerifierEnvironment -ne $PSBoundParameters.ContainsKey('VerifierVmInstanceId')) { throw 'Verifier selection must be complete.' }
        $intent = @{
            tenant=$TenantId.ToString(); subscription=$SubscriptionId.ToString(); region=$Location
            store_group=$BackupResourceGroupName; store_name=$BackupStoreName; owner=$OwnershipId.ToString()
            source=@{environment=$SourceEnvironment; instance=$SourceVmInstanceId.ToString()}; verifier=$null
        }
        if ($VerifierEnvironment) { $intent.verifier=@{environment=$VerifierEnvironment; instance=$VerifierVmInstanceId.ToString()} }
        $plan = Invoke-SantaStoreBridge -Request @{intent=$intent} -Python $Python
        if (-not $ReadArm) { return $plan }
        $arguments = @('account', 'show', '--subscription', $SubscriptionId.ToString())
        $contextBefore = Invoke-SantaStoreCachedRead $arguments
        # Reject wrong cached context before any resource reads.
        if ($contextBefore.id -ine $SubscriptionId.ToString() -or $contextBefore.tenantId -ine $TenantId.ToString() -or
            $contextBefore.state -cne 'Enabled' -or $contextBefore.environmentName -cne 'AzureCloud') { throw 'Cached context mismatch.' }
        $before=@{}; $after=@{}
        foreach ($url in $plan.urls) {
            $before[$url] = Invoke-SantaStoreCachedRead @('rest', '--method', 'get', '--url', $url, '--subscription', $SubscriptionId.ToString())
        }
        foreach ($url in $plan.urls) {
            $after[$url] = Invoke-SantaStoreCachedRead @('rest', '--method', 'get', '--url', $url, '--subscription', $SubscriptionId.ToString())
        }
        $contextAfter = Invoke-SantaStoreCachedRead $arguments
        Invoke-SantaStoreBridge -Request @{intent=$intent; context_before=$contextBefore; context_after=$contextAfter; before=$before; after=$after} -Python $Python
    } catch {
        # Missing/forbidden/deleted/stale/timeout facts are not creation authority.
        throw 'Backup-store selection failed or is unknown; preserve resources and reconcile ownership/network prerequisites. No cloud write was attempted.'
    }
}

Export-ModuleMember -Function Get-SantaBackupStoreSelection
