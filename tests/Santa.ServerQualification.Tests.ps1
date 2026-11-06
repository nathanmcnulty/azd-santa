#Requires -Version 7.6
Describe 'Private server qualification tooling' {
    BeforeAll { $root = Split-Path $PSScriptRoot -Parent }
    It 'passes the offline pinned archive acquisition tests' {
        $output = & python (Join-Path $root 'tests/test_source_acquisition.py') 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($output -join "`n")
    }
    It 'passes the private configuration generator tests' {
        $output = & python (Join-Path $root 'tests/test_zentral_eval.py') 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($output -join "`n")
    }
    It 'passes canonical-byte core derivation tests' {
        $output = & python (Join-Path $root 'tests/test_core_build.py') 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($output -join "`n")
    }
    It 'passes the real-HTTP probe guards without Docker or tenant access' {
        $output = & python (Join-Path $root 'tests/test_live_zentral_harness.py') 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($output -join "`n")
    }
    It 'passes image-lock and failed-runtime receipt tests offline' {
        $output = & python (Join-Path $root 'tests/test_runtime_staging.py') 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($output -join "`n")
    }
    It 'does not confuse database receipts with event indexing' {
        $output = & python (Join-Path $root 'tests/test_indexing_receipt.py') 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($output -join "`n")
    }
    It 'preserves fixture identity and volumes across an explicit image-only transition' {
        $output = & python (Join-Path $root 'tests/test_runtime_upgrade.py') 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($output -join "`n")
    }
    It 'parses privileged build submission without invoking Azure' {
        $tokens = $null
        $errors = $null
        [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'experiments/server/Start-ZentralQualification.ps1'), [ref]$tokens, [ref]$errors) | Out-Null
        $errors | Should -BeNullOrEmpty
    }
    It 'records evaluation-only use instead of a production image claim' {
        $lock = Get-Content (Join-Path $root 'experiments/server/zentral-source.lock.json') -Raw | ConvertFrom-Json
        $lock.commit | Should -Match '^[0-9a-f]{40}$'
        $lock.archiveSha256 | Should -Match '^[0-9a-f]{64}$'
        $lock.purpose | Should -Match 'Not approved for production or redistribution'
    }
}
