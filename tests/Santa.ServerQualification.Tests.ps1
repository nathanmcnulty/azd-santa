#Requires -Version 7.6
Describe 'Private server qualification tooling' {
    BeforeAll { $root = Split-Path $PSScriptRoot -Parent }
    It 'guards owner-only recovery fixtures and restricted request binding offline' {
        $output = & python (Join-Path $root 'tests/test_recovery_fixture.py') 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($output -join "`n")
    }
    It 'guards separated database authority without claiming live SQL acceptance' {
        $output = & python (Join-Path $root 'tests/test_database_roles.py') 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($output -join "`n")
    }
    It 'fails closed at the durable security-store boundary without automatic initialization' {
        $output = & python (Join-Path $root 'tests/test_security_store.py') 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($output -join "`n")
    }
    It 'guards fresh Santa-only qualification without switching existing projects' {
        $output = & python (Join-Path $root 'tests/test_santa_profile_qualification.py') 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($output -join "`n")
    }
    It 'checks private operator recovery packaging without claiming runtime acceptance' {
        $output = & python (Join-Path $root 'tests/test_operator_recovery_package.py') 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($output -join "`n")
    }
    It 'bounds the real-server decoder and hash-bound integration offline' {
        $output = & python (Join-Path $root 'tests/test_santa_request_limits.py') 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($output -join "`n")
    }
    It 'checks operator policy package integrity without claiming real MFA acceptance' {
        $output = & python (Join-Path $root 'tests/test_operator_mfa_package.py') 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($output -join "`n")
    }
    It 'exports only a complete source-bound operator test receipt' {
        $output = & python (Join-Path $root 'tests/test_mfa_runner.py') 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($output -join "`n")
    }
    It 'passes the offline pinned archive acquisition tests' {
        $output = & python (Join-Path $root 'tests/test_source_acquisition.py') 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($output -join "`n")
    }
    It 'passes the private configuration generator tests' {
        $output = & python (Join-Path $root 'tests/test_zentral_eval.py') 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($output -join "`n")
    }
    It 'keeps event diagnostic errors redacted with application-only secrets' {
        $output = & python (Join-Path $root 'tests/test_event_diagnostics.py') 2>&1
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
    It 'does not accept partial stage rejection or mutated database state as credential safety' {
        $output = & python (Join-Path $root 'tests/test_lifecycle_harness.py') 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($output -join "`n")
    }
    It 'isolates the resume namespace from inherited Compose overrides on Linux' {
        $output = & python (Join-Path $root 'tests/test_resume_shell.py') 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($output -join "`n")
    }
    It 'keeps automatic runtime startup bound and fails before admission offline' {
        $output = & python (Join-Path $root 'tests/test_runtime_service.py') 2>&1
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
