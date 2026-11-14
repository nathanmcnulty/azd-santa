#Requires -Version 7.6
Describe 'Offline secret-engine preservation primitive' {
    It 'passes pinned-engine crypto and complete projection preservation checks' {
        $python = if ($env:SANTA_CRYPTO_PYTHON) { $env:SANTA_CRYPTO_PYTHON } else { 'python' }
        $result = & $python -m unittest discover -s $PSScriptRoot -p test_secret_rewrap.py 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($result -join "`n")
    }
}
