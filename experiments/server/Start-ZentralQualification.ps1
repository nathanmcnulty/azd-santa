#Requires -Version 7.6
[CmdletBinding()]
param(
    [Parameter(Mandatory)][guid]$SubscriptionId,
    [Parameter(Mandatory)][ValidatePattern('^[a-z0-9-]{2,32}$')][string]$EnvironmentName
)
$ErrorActionPreference = 'Stop'
$subscription = $SubscriptionId.ToString()
$group = "rg-azd-santa-vm-$EnvironmentName"
$metadataRaw = & az group show --subscription $subscription --name $group -o json
if ($LASTEXITCODE) { throw 'Selected qualification group could not be read.' }
$metadata = $metadataRaw | ConvertFrom-Json
if ($metadata.tags.'azd-solution' -ne 'azd-santa' -or $metadata.tags.purpose -ne 'synthetic-vm-lab' -or $metadata.tags.'azd-env-name' -ne $EnvironmentName) {
    throw 'Refusing an unrecognized qualification host.'
}
$shutdownUtc = [DateTimeOffset]::UtcNow.AddHours(2).ToString('HHmm')
& az vm auto-shutdown --subscription $subscription --resource-group $group --name vm-santa-lab --time $shutdownUtc --only-show-errors -o none
if ($LASTEXITCODE) { throw 'Qualification cost guard could not be configured; build not submitted.' }
$lock = Get-Content (Join-Path $PSScriptRoot 'zentral-source.lock.json') -Raw | ConvertFrom-Json
if ($lock.commit -notmatch '^[0-9a-f]{40}$') { throw 'Invalid source pin.' }
$encoded = [Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $PSScriptRoot 'prepare_source.py')))
$coreEncoded = [Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $PSScriptRoot 'prepare_core_build.py')))
$mfaEncoded = [Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $PSScriptRoot 'prepare_operator_mfa.py')))
$policyEncoded = [Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $PSScriptRoot 'operator_mfa.py')))
$recoveryEncoded = [Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $PSScriptRoot 'prepare_operator_recovery.py')))
$recoveryPolicyEncoded = [Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $PSScriptRoot 'operator_recovery.py')))
$script = @"
set -eu
umask 077
root=/var/lib/azd-santa-qualification
test -d "`$root"
docker version --format '{{.Server.Version}}'
# Elasticsearch's documented Linux mapping prerequisite, scoped to this lab VM.
sysctl -w vm.max_map_count=1048576
printf 'vm.max_map_count=1048576\n' > /etc/sysctl.d/90-azd-santa-qualification.conf
python3 - <<'PY'
import base64
from pathlib import Path
path = Path('/var/lib/azd-santa-qualification/prepare_source.py')
with path.open('xb') as output:
    output.write(base64.b64decode('$encoded'))
with path.with_name('prepare_core_build.py').open('xb') as output:
    output.write(base64.b64decode('$coreEncoded'))
with path.with_name('prepare_operator_mfa.py').open('xb') as output:
    output.write(base64.b64decode('$mfaEncoded'))
with path.with_name('operator_mfa.py').open('xb') as output:
    output.write(base64.b64decode('$policyEncoded'))
with path.with_name('prepare_operator_recovery.py').open('xb') as output:
    output.write(base64.b64decode('$recoveryEncoded'))
with path.with_name('operator_recovery.py').open('xb') as output:
    output.write(base64.b64decode('$recoveryPolicyEncoded'))
PY
python3 "`$root/prepare_source.py" "`$root/source-$($lock.commit)"
python3 "`$root/prepare_core_build.py" --source "`$root/source-$($lock.commit)/zentral-$($lock.commit)" --output "`$root/source-$($lock.commit)/zentral-$($lock.commit)/Dockerfile.core"
# systemd owns a real, bounded build process and its journal. Never start a new
# build just because observation times out; inspect this unit first.
systemd-run --unit=azd-santa-zentral-build --property=RuntimeMaxSec=1800 --working-directory="`$root/source-$($lock.commit)/zentral-$($lock.commit)" /usr/bin/docker build --file Dockerfile.core --memory 2500m --memory-swap 2500m --build-arg APP_ENV=core --build-arg APP_VERSION=$($lock.commit) --label org.opencontainers.image.revision=$($lock.commit) --label io.azd-santa.variant=core-experiment --tag azd-santa-zentral-core-eval:$($lock.commit) .
systemctl show azd-santa-zentral-build --property=ActiveState,SubState,Result,ExecMainStatus
echo SANTA_ZENTRAL_BUILD_SUBMITTED
"@
$temporary = Join-Path ([IO.Path]::GetTempPath()) ("santa-qualify-" + [guid]::NewGuid() + '.sh')
try {
    [IO.File]::WriteAllText($temporary, $script.Replace("`r`n", "`n"), [Text.UTF8Encoding]::new($false))
    $raw = & az vm run-command invoke --subscription $subscription --resource-group $group --name vm-santa-lab --command-id RunShellScript --scripts "@$temporary" -o json
    if ($LASTEXITCODE) { throw 'Azure build submission failed; inspect existing command/unit before retry.' }
    $result = $raw | ConvertFrom-Json
    $raw
    if (($result.value.message -join "`n") -notmatch '(?m)^SANTA_ZENTRAL_BUILD_SUBMITTED\r?$') {
        throw 'Build submission receipt absent. Inspect existing source and systemd unit, do not blindly retry.'
    }
} finally {
    if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary }
}
