#Requires -Version 7.6
Describe 'Cold encrypted backup qualification component' {
    It 'passes offline real crypto, filesystem and mocked cold identity guards' {
        $python = if ($env:SANTA_CRYPTO_PYTHON) { $env:SANTA_CRYPTO_PYTHON } else { 'python' }
        $result = & $python -m unittest discover -s $PSScriptRoot -p test_cold_backup.py 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($result -join "`n")
        $native = & $python -m unittest discover -s $PSScriptRoot -p test_native_snapshot.py 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($native -join "`n")
    }
}
