#Requires -Version 7.6
Describe 'Confidential one-capture source Blob capability relay' {
    It 'passes real crypto and controlled identity, journal, terminal and upload protocol checks' {
        $python = if ($env:SANTA_CRYPTO_PYTHON) { $env:SANTA_CRYPTO_PYTHON } else { 'python' }
        $result = & $python -m unittest discover -s $PSScriptRoot -p test_blob_capability_relay.py 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($result -join "`n")
    }
}
