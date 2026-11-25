#Requires -Version 7.6
Describe 'Fresh selected HTTPS origin profile' {
    It 'passes guest origin, real rendered config and settings-hook boundaries offline' {
        $python=if($env:SANTA_CRYPTO_PYTHON){$env:SANTA_CRYPTO_PYTHON}else{'python'}
        $result=& $python -m unittest discover -s $PSScriptRoot -p test_fresh_https_origin.py 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($result -join "`n")
    }
}
