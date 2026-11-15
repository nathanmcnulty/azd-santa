#Requires -Version 7.6
Describe 'Separate synthetic credential rotation harness' {
    It 'passes offline request, invariance, paging and collision guards without Docker or HTTP' {
        $result = & python -m unittest discover -s $PSScriptRoot -p test_credential_rotation_harness.py 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($result -join "`n")
    }
    It 'pins the versioned admission-aware helper without reinterpreting historical receipts' {
        $root = Split-Path $PSScriptRoot -Parent
        (Get-FileHash (Join-Path $root 'experiments/server/test_live_zentral.py') -Algorithm SHA256).Hash.ToLowerInvariant() |
            Should -BeExactly '49f6bf61f11563cc0bc69701b3529c6ce39569a1301a20fe965e9b2cfb8fec8e'
        (Get-Content (Join-Path $root 'experiments/server/test_live_zentral.py') -Raw) |
            Should -Match "QUALIFICATION_VERSION = 'synthetic-loopback-admission-six-volume-v2'"
        $code = Get-Content (Join-Path $root 'experiments/server/test_credential_rotation_live.py') -Raw
        $code | Should -Match 'old-header-over-new-url'
        $code | Should -Match 'malformed-header-no-url-fallback'
        $code | Should -Match 'replacement-reconciles-stale-cursor'
        $code | Should -Not -Match 'az login|Connect-MgGraph|https://|http://(?!127\.0\.0\.1)'
        (Get-Content (Join-Path $root 'azure.yaml') -Raw) | Should -Not -Match 'credential_rotation'
    }
}
