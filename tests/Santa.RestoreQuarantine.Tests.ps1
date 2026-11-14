#Requires -Version 7.6
Describe 'Authenticated archive quarantine primitive' {
    It 'passes strict producer crypto and archive preservation checks' {
        $python = if ($env:SANTA_CRYPTO_PYTHON) { $env:SANTA_CRYPTO_PYTHON } else { 'python' }
        $result = & $python -m unittest discover -s $PSScriptRoot -p test_restore_quarantine.py 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($result -join "`n")
    }
}
