#Requires -Version 7.6
Describe 'Explicit encrypted Blob retention protocol primitives' {
    It 'passes private capability, protocol, preservation and separate Linux filesystem cases' {
        $python = if ($env:SANTA_CRYPTO_PYTHON) { $env:SANTA_CRYPTO_PYTHON } else { 'python' }
        $result = & $python -m unittest discover -s $PSScriptRoot -p test_blob_retention.py 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($result -join "`n")
        $result | Where-Object { "$_" -match '^Ran \d+ tests? in |^OK(?: \(skipped=\d+\))?$' } | ForEach-Object { Write-Host "Blob retention protocol: $_" }
    }
    It 'seals the independent verifier capability and recovers a lost verification result' {
        $python = if ($env:SANTA_CRYPTO_PYTHON) { $env:SANTA_CRYPTO_PYTHON } else { 'python' }
        $result = & $python -m unittest discover -s $PSScriptRoot -p test_native_retention_verifier.py 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($result -join "`n")
    }
}
