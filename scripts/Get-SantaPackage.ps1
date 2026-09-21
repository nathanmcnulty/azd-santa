[CmdletBinding()]
param(
    [string] $Destination,
    [switch] $AllowUnverifiedPlatform
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Santa.Template.psm1') -Force
$lock = Get-SantaLock
if (-not $Destination) { $Destination = Join-Path (Split-Path -Parent $PSScriptRoot) ('package/downloads/' + $lock.package.assetName) }
$parent = Split-Path -Parent $Destination
New-Item -ItemType Directory -Path $parent -Force | Out-Null
$partial = "$Destination.partial"
$inspectPath = Join-Path ([IO.Path]::GetTempPath()) ("azd-santa-pkg-" + [guid]::NewGuid().ToString('N'))
$fullyVerified = $false
try {
    Invoke-WebRequest -Uri $lock.package.sourceUrl -OutFile $partial
    Test-SantaPackageHash -Path $partial | Out-Null
    if ($IsMacOS) {
        $signature = & pkgutil --check-signature $partial 2>&1
        $signatureText = $signature -join "`n"
        if ($LASTEXITCODE -ne 0 -or $signatureText -notmatch [regex]::Escape($lock.identity.teamId) -or $signatureText -notmatch [regex]::Escape($lock.identity.expectedInstallerCertificateCommonName)) { throw 'Package signature validation failed or the pinned installer identity was absent.' }
        & spctl --assess --type install --verbose=4 $partial
        if ($LASTEXITCODE -ne 0) { throw 'Gatekeeper rejected the package.' }
        & xcrun stapler validate $partial
        if ($LASTEXITCODE -ne 0) { throw 'The notarization staple did not validate.' }
        & pkgutil --expand $partial $inspectPath
        if ($LASTEXITCODE -ne 0) { throw 'Unable to expand the package for metadata validation.' }
        [xml]$packageInfo = Get-Content -LiteralPath (Join-Path $inspectPath 'app.pkg/PackageInfo') -Raw
        if ($packageInfo.'pkg-info'.identifier -ne $lock.package.packageIdentifier -or $packageInfo.'pkg-info'.version -ne $lock.package.packageVersion) { throw 'Expanded package identifier or version does not match the lock.' }
        $fullyVerified = $true
    } elseif (-not $AllowUnverifiedPlatform) {
        throw 'SHA-256 passed, but Apple signature and notarization checks require macOS. Re-run on macOS; -AllowUnverifiedPlatform is for offline inspection only and never makes the package deployable.'
    }
    Move-Item -LiteralPath $partial -Destination $Destination -Force
    if ($fullyVerified) { Write-Information "Hash, signature, Gatekeeper, notarization, and package metadata verified: $Destination" -InformationAction Continue }
    else { Write-Warning "Hash-verified inspection copy only; Apple signature and notarization remain unproven: $Destination" }
} finally {
    if (Test-Path -LiteralPath $partial) { Remove-Item -LiteralPath $partial -Force }
    if (Test-Path -LiteralPath $inspectPath) { Remove-Item -LiteralPath $inspectPath -Recurse -Force }
}
