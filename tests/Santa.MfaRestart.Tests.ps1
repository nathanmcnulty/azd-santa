#Requires -Version 7.6
Describe 'Cryptographic MFA restart qualification guards' {
    It 'rejects false replay causes and unsafe host selections offline' {
        $root = Split-Path $PSScriptRoot -Parent
        $output = & python (Join-Path $root 'tests/test_mfa_restart_driver.py') 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($output -join "`n")
    }
}
