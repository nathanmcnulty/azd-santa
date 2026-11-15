#Requires -Version 7.6
Describe 'Bounded stock HTTPS edge' {
    It 'keeps private TLS and restrictive firewall contracts separate from public admission' {
        $python=if($env:SANTA_CRYPTO_PYTHON){$env:SANTA_CRYPTO_PYTHON}else{'python'}
        $result=& $python -m unittest discover -s $PSScriptRoot -p test_https_edge.py 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($result -join "`n")
    }
}
