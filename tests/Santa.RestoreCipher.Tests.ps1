#Requires -Version 7.6
Describe 'Sealed backup authentication primitive' {
    It 'authenticates synthetic producer output without releasing plaintext' {
        $python = if ($env:SANTA_CRYPTO_PYTHON) { $env:SANTA_CRYPTO_PYTHON } else { 'python' }
        $result = & $python -m unittest discover -s $PSScriptRoot -p test_restore_cipher.py 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($result -join "`n")
    }
}
