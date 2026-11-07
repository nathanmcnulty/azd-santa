#Requires -Version 7.6
Describe 'Separate synthetic credential rotation harness' {
    It 'passes offline request, invariance, paging and collision guards without Docker or HTTP' {
        $result = & python -m unittest discover -s $PSScriptRoot -p test_credential_rotation_harness.py 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($result -join "`n")
    }
    It 'keeps existing installed protocol helper immutable and isolates the new qualification tool' {
        $root = Split-Path $PSScriptRoot -Parent
        (Get-FileHash (Join-Path $root 'experiments/server/test_live_zentral.py') -Algorithm SHA256).Hash.ToLowerInvariant() |
            Should -BeExactly 'd0be67e5d8d8f134adb73dbe78cbab816aac110133f0ac7895dc1805f57a496f'
        $code = Get-Content (Join-Path $root 'experiments/server/test_credential_rotation_live.py') -Raw
        $code | Should -Match 'old-header-over-new-url'
        $code | Should -Match 'malformed-header-no-url-fallback'
        $code | Should -Match 'replacement-reconciles-stale-cursor'
        $code | Should -Not -Match 'az login|Connect-MgGraph|https://|http://(?!127\.0\.0\.1)'
        (Get-Content (Join-Path $root 'azure.yaml') -Raw) | Should -Not -Match 'credential_rotation'
    }
}
