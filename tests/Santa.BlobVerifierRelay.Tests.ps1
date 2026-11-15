#Requires -Version 7.6
Describe 'Confidential independent verifier Blob relay' {
    It 'passes real crypto and controlled identity, download, terminal and private-file checks' {
        $python = if ($env:SANTA_CRYPTO_PYTHON) { $env:SANTA_CRYPTO_PYTHON } else { 'python' }
        $result = & $python -m unittest discover -s $PSScriptRoot -p test_blob_verifier_relay.py 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($result -join "`n")
    }
}
