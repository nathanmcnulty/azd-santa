#Requires -Version 7.6
# Original Unlicense. Explicit maintenance only; never an azd lifecycle hook.
Set-StrictMode -Version Latest
$script:installer = Import-Module (Join-Path $PSScriptRoot 'PrivateVmInstall.psm1') -Force -PassThru
$script:programPath = Join-Path $PSScriptRoot '../server/helper_upgrade.py'

function Get-UpgradeTarget([guid]$SubscriptionId, [string]$EnvironmentName) {
    & $script:installer { param($subscription, $environment)
        Get-SantaPrivateVmDeploymentTarget -SubscriptionId $subscription -EnvironmentName $environment
    } $SubscriptionId $EnvironmentName
}

function New-UpgradeBundle { & $script:installer { New-PrivateSourceBundle } }

function Invoke-UpgradeAzure([string[]]$Arguments) {
    # Reuse the existing cached CLI transport. No login/account changes/grants.
    & $script:installer { param($selectedArguments) Invoke-PrivateAzure -Arguments $selectedArguments } $Arguments
}

function Send-UpgradeCommand([hashtable]$Target, [hashtable]$Command, [string]$ProgramPath = $script:programPath) {
    $bytes = [IO.File]::ReadAllBytes($ProgramPath)
    if ($bytes.Length -gt 32768) { throw 'Upgrade source exceeded its transport bound.' }
    $hash = [Convert]::ToHexStringLower([Security.Cryptography.SHA256]::HashData($bytes))
    $memory = [IO.MemoryStream]::new()
    try {
        $compress = [IO.Compression.GZipStream]::new($memory, [IO.Compression.CompressionLevel]::Optimal, $true)
        try { $compress.Write($bytes) } finally { $compress.Dispose() }
        $program = [Convert]::ToBase64String($memory.ToArray())
    } finally { $memory.Dispose() }
    $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($Command | ConvertTo-Json -Depth 8 -Compress)))
    $nonce = [guid]::NewGuid().ToString('N')
    # The program is immutable and separate from all historical installer files.
    # Observe executes the supplied reviewed bytes without creating a program.
    $bootstrap = @'
import base64,gzip,hashlib,io,json,os
from pathlib import Path
with gzip.GzipFile(fileobj=io.BytesIO(base64.b64decode(os.environ['AZD_HELPER_PROGRAM'],validate=True))) as stream: raw=stream.read(32769)
assert len(raw)<=32768 and hashlib.sha256(raw).hexdigest()==os.environ['AZD_HELPER_PROGRAM_SHA']
value=json.loads(base64.b64decode(os.environ['AZD_HELPER_UPGRADE_COMMAND'],validate=True))
path=Path('/var/lib/azd-santa-qualification/helper-upgrades/programs')/os.environ['AZD_HELPER_PROGRAM_SHA']/'helper_upgrade.py'
if value['mode']!='observe':
 root=Path('/var/lib/azd-santa-qualification')
 for item in (root,*root.parents):
  info=item.stat();assert item==item.resolve(strict=True) and info.st_uid==0 and not info.st_mode&0o022
 current=root
 for part in path.parent.relative_to(root).parts:
  current=current/part;current.mkdir(mode=0o700,exist_ok=True)
  info=current.stat();assert current==current.resolve(strict=True) and info.st_uid==0 and not info.st_mode&0o022
 if path.exists():
  info=path.stat();assert path==path.resolve(strict=True) and info.st_uid==0 and not info.st_mode&0o022 and path.read_bytes()==raw
 else:
  fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,'wb') as output: output.write(raw);output.flush();os.fsync(output.fileno())
  fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
  try: os.fsync(fd)
  finally: os.close(fd)
exec(compile(raw,str(path),'exec'),{'__name__':'__main__','__file__':str(path)})
'@
    $body = "set -eu`nexport AZD_HELPER_PROGRAM='$program'`nexport AZD_HELPER_PROGRAM_SHA='$hash'`nexport AZD_HELPER_UPGRADE_COMMAND='$encoded'`npython3 -I - <<'HELPER_UPGRADE_PY'`n$bootstrap`nHELPER_UPGRADE_PY`nprintf '%s\n' 'SANTA_HELPER_UPGRADE_DONE:$nonce'`n"
    if ([Text.Encoding]::UTF8.GetByteCount($body) -gt 65536) { throw 'Upgrade transport exceeded 64KiB.' }
    $temporary = Join-Path ([IO.Path]::GetTempPath()) ('santa-helper-upgrade-' + [guid]::NewGuid() + '.sh')
    try {
        $stream = [IO.FileStream]::new($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $stream.Write([Text.Encoding]::UTF8.GetBytes($body)) } finally { $stream.Dispose() }
        $result = Invoke-UpgradeAzure @('vm','run-command','invoke','--subscription',$Target.SubscriptionId,
            '--resource-group',$Target.ResourceGroup,'--name',$Target.VmName,'--command-id','RunShellScript','--scripts',"@$temporary")
        if (-not $result.value -or @($result.value).Count -gt 4 -or
            @($result.value | Where-Object { $_.code -cnotmatch '/succeeded$' }).Count) { throw 'Upgrade transport outcome requires observation.' }
        $lines = ($result.value.message -join "`n") -split '\r?\n'
        $payload = @($lines | Where-Object { $_.StartsWith('SANTA_HELPER_UPGRADE_JSON:', [StringComparison]::Ordinal) })
        $done = @($lines | Where-Object { $_.StartsWith('SANTA_HELPER_UPGRADE_DONE:', [StringComparison]::Ordinal) })
        if ($payload.Count -ne 1 -or $done.Count -ne 1 -or $done[0] -cne "SANTA_HELPER_UPGRADE_DONE:$nonce" -or
            [Array]::IndexOf($lines,$done[0]) -lt [Array]::IndexOf($lines,$payload[0]) -or $payload[0].Length -gt 4096) { throw 'Upgrade receipt absent/truncated; observe the same operation.' }
        $value = $payload[0].Substring('SANTA_HELPER_UPGRADE_JSON:'.Length) | ConvertFrom-Json -AsHashtable
        if ($value.new_bundle_sha256 -cne $Command.bundle_sha256) { throw 'Upgrade bundle observation mismatch.' }
        $value
    } finally { if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) } }
}

function Invoke-SantaPrivateHelperUpgrade {
    [CmdletBinding()]
    param([Parameter(Mandatory)][guid]$SubscriptionId,
        [Parameter(Mandatory)][ValidatePattern('^[a-z0-9-]{2,32}$')][string]$EnvironmentName,
        [switch]$Apply, [switch]$Observe)
    if ($Apply -and $Observe) { throw 'Choose Apply once or Observe; they are separate actions.' }
    $bundle = New-UpgradeBundle
    if (-not $Apply -and -not $Observe) {
        return [pscustomobject]@{ scope='private-helper-upgrade-plan-v1'; performsMutation=$false
            newBundleSha256=$bundle.Sha256; imageChanges=$false; requiresExplicitApply=$true }
    }
    $target = Get-UpgradeTarget $SubscriptionId $EnvironmentName
    $state = Send-UpgradeCommand $target @{ mode='observe'; target=$target; bundle_sha256=$bundle.Sha256 }
    if ($state.scope -cne 'azd-santa-helper-upgrade-observation-v1') { throw 'Unexpected upgrade observation.' }
    if ($Observe -or $state.state -cne 'not-requested') { return $state }
    for ($i=0; $i -lt $bundle.Chunks.Count; $i++) {
        $chunk = Send-UpgradeCommand $target @{ mode='chunk'; target=$target; bundle_sha256=$bundle.Sha256
            archive_sha256=$bundle.ArchiveSha256; index=$i; count=$bundle.Chunks.Count; data=$bundle.Chunks[$i] }
        if ($chunk.scope -cne 'azd-santa-helper-upgrade-chunk-v1' -or $chunk.index -ne $i) { throw 'Unconfirmed upload chunk; observe without requesting maintenance.' }
    }
    # No retry on lost submission response; the durable server reservation and
    # explicit Observe command are the only way forward after an unknown result.
    Send-UpgradeCommand $target @{ mode='request'; target=$target; bundle_sha256=$bundle.Sha256
        archive_sha256=$bundle.ArchiveSha256; count=$bundle.Chunks.Count }
}

Export-ModuleMember -Function Invoke-SantaPrivateHelperUpgrade
