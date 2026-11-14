#Requires -Version 7.6
# Original Unlicense. Exact failed-case recovery, never generic backup resume.
Set-StrictMode -Version Latest
$script:transport = Import-Module (Join-Path $PSScriptRoot 'PrivateHelperUpgrade.psm1') -Force -PassThru
$script:recoveryProgram = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../server/presnapshot_recovery.py'))

function New-RecoveryBundle { & $script:transport { New-UpgradeBundle } }
function Get-RecoveryTarget([guid]$SubscriptionId, [string]$EnvironmentName) {
    & $script:transport { param($subscription,$environment) Get-UpgradeTarget $subscription $environment } $SubscriptionId $EnvironmentName
}
function Send-RecoveryCommand([hashtable]$Target, [hashtable]$Command) {
    & $script:transport { param($target,$command,$program) Send-UpgradeCommand $target $command -ProgramPath $program } $Target $Command $script:recoveryProgram
}

function Repair-SantaPrivatePreSnapshotFailure {
    [CmdletBinding()]
    param([Parameter(Mandatory)][guid]$SubscriptionId,
        [Parameter(Mandatory)][ValidatePattern('^[a-z0-9-]{2,32}$')][string]$EnvironmentName,
        [switch]$Apply, [switch]$Observe)
    if ($Apply -and $Observe) { throw 'Choose one Apply or Observe action.' }
    $bundle = New-RecoveryBundle
    if (-not $Apply -and -not $Observe) {
        return [pscustomobject]@{ scope='exact-presnapshot-recovery-plan-v1'; performsMutation=$false
            failedRequestSha256='a6386505ed6f97fbb92ed78823a819627fe866835f7b9b3a3b8e94421fd38a16'
            failedBackupOperation='368c81c41b584311b3e3cafe73264dd5'; newBundleSha256=$bundle.Sha256
            backupResume=$false; newBackupRequested=$false; requiresExplicitApply=$true }
    }
    $target = Get-RecoveryTarget $SubscriptionId $EnvironmentName
    $state = Send-RecoveryCommand $target @{ mode='observe'; target=$target; bundle_sha256=$bundle.Sha256 }
    if ($state.scope -cne 'exact-presnapshot-recovery-observation-v1') { throw 'Unexpected recovery observation.' }
    if ($Observe -or $state.state -cne 'not-requested') { return $state }
    for ($i=0; $i -lt $bundle.Chunks.Count; $i++) {
        $reply = Send-RecoveryCommand $target @{ mode='chunk'; target=$target; bundle_sha256=$bundle.Sha256
            archive_sha256=$bundle.ArchiveSha256; index=$i; count=$bundle.Chunks.Count; data=$bundle.Chunks[$i] }
        if ($reply.scope -cne 'exact-presnapshot-recovery-chunk-v1' -or $reply.index -ne $i) { throw 'Unconfirmed public source chunk; observe without replay.' }
    }
    Send-RecoveryCommand $target @{ mode='request'; target=$target; bundle_sha256=$bundle.Sha256
        archive_sha256=$bundle.ArchiveSha256; count=$bundle.Chunks.Count }
}

Export-ModuleMember -Function Repair-SantaPrivatePreSnapshotFailure
