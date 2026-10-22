#Requires -Version 7.6
[CmdletBinding()]
param(
    [Parameter(Mandatory)][guid]$SubscriptionId,
    [Parameter(Mandatory)][ValidatePattern('^[a-z0-9-]{2,32}$')][string]$EnvironmentName,
    [switch]$Initialize,
    [string]$ReceiptPath
)
$ErrorActionPreference = 'Stop'
if ($ReceiptPath -and (Test-Path -LiteralPath $ReceiptPath)) { throw 'Refusing to overwrite an existing receipt.' }
$subscription = $SubscriptionId.ToString()
$accountRaw = & az account show --subscription $subscription -o json
if ($LASTEXITCODE) { throw 'Selected subscription could not be read.' }
$account = $accountRaw | ConvertFrom-Json
if ($account.id -ne $subscription -or $account.state -ne 'Enabled') { throw 'Selected subscription is not enabled.' }
$group = "rg-azd-santa-vm-$EnvironmentName"
$groupRaw = & az group show --subscription $subscription --name $group -o json
if ($LASTEXITCODE) { throw 'Lab group could not be read.' }
$metadata = $groupRaw | ConvertFrom-Json
if ($metadata.tags.'azd-solution' -ne 'azd-santa' -or $metadata.tags.purpose -ne 'synthetic-vm-lab' -or $metadata.tags.'azd-env-name' -ne $EnvironmentName) {
    throw 'Refusing an unrecognized lab group.'
}
$source = Join-Path $PSScriptRoot '../..'
$payload = [ordered]@{}
foreach ($name in @('tools/sync_spike/model.py', 'tools/sync_spike/durable.py', 'tools/sync_spike/test_conformance.py', 'tools/sync_spike/test_durable.py', 'tools/sync_spike/vm_probe.py', 'tools/sync_spike/test_vm_probe.py', 'tests/fixtures/sync/clean-sync.json')) {
    $bytes = [IO.File]::ReadAllBytes((Join-Path $source $name))
    $payload[$name] = [ordered]@{
        content = [Convert]::ToBase64String($bytes)
        sha256 = [Convert]::ToHexStringLower([Security.Cryptography.SHA256]::HashData($bytes))
    }
}
$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($payload | ConvertTo-Json -Depth 5 -Compress)))
$initializeArgument = if ($Initialize) { '--initialize' } else { '' }
# Source is transported through the authenticated Azure agent, never a mutable URL.
# Everything runs as root via Run Command; use only the isolated tagged test VM.
$script = @"
set -eu
umask 077
python3 - <<'PY'
import base64, hashlib, json
from pathlib import Path
payload = json.loads(base64.b64decode('$encoded'))
root = Path('/opt/azd-santa-synthetic')
root.mkdir(mode=0o700, exist_ok=True)
version = hashlib.sha256(base64.b64decode('$encoded')).hexdigest()
code = root / version
code.mkdir(mode=0o700, exist_ok=True)
for name, entry in payload.items():
    content = base64.b64decode(entry['content'])
    relative = Path(name)
    if relative.is_absolute() or '..' in relative.parts or hashlib.sha256(content).hexdigest() != entry['sha256']:
        raise ValueError('source integrity check failed')
    (code / name).parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    (code / name).write_bytes(content)
(root / 'current-source').write_text(version)
print(json.dumps(dict(source_sha256=version, boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip())))
PY
cd /opt/azd-santa-synthetic/`$(cat /opt/azd-santa-synthetic/current-source)/tools/sync_spike
python3 test_conformance.py
python3 test_durable.py
python3 test_vm_probe.py
python3 vm_probe.py /opt/azd-santa-synthetic/receipt.db $initializeArgument
echo SANTA_VM_LAB_OK
"@
$temporary = Join-Path ([IO.Path]::GetTempPath()) ("santa-vm-" + [guid]::NewGuid() + '.sh')
try {
    [IO.File]::WriteAllText($temporary, $script.Replace("`r`n", "`n"), [Text.UTF8Encoding]::new($false))
    $resultRaw = & az vm run-command invoke --subscription $subscription --resource-group $group --name vm-santa-lab --command-id RunShellScript --scripts "@$temporary" -o json
    if ($LASTEXITCODE) { throw 'Azure Run Command failed; inspect the existing action before retrying.' }
    $result = $resultRaw | ConvertFrom-Json
    $messages = ($result.value.message -join "`n")
    $resultRaw
    if ($messages -notmatch '(?m)^SANTA_VM_LAB_OK\r?$') { throw 'Guest success receipt missing; do not claim VM tests passed.' }
    if ($ReceiptPath) {
        if (Test-Path -LiteralPath $ReceiptPath) { throw 'Refusing to overwrite an existing receipt.' }
        $receipt = [ordered]@{
            scope = 'synthetic-only'
            checkedAt = [DateTimeOffset]::UtcNow.ToString('o')
            vmId = "/subscriptions/$subscription/resourceGroups/$group/providers/Microsoft.Compute/virtualMachines/vm-santa-lab"
            initialized = [bool]$Initialize
            result = $result
        }
        $stream = [IO.File]::Open([IO.Path]::GetFullPath($ReceiptPath), [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try {
            $bytes = [Text.Encoding]::UTF8.GetBytes(($receipt | ConvertTo-Json -Depth 10))
            $stream.Write($bytes)
        } finally { $stream.Dispose() }
    }
} finally {
    if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary }
}
