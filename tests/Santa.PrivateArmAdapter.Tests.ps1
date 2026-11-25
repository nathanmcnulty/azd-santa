#Requires -Version 7.6
Describe 'Private cached ARM capability callback' {
    It 'passes offline cached context, exact request, one attempt and transport boundary tests' {
        $python = if ($env:SANTA_CRYPTO_PYTHON) { $env:SANTA_CRYPTO_PYTHON } else { 'python' }
        $result = & $python -m unittest discover -s $PSScriptRoot -p test_private_arm_adapter.py 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($result -join "`n")
    }
}
