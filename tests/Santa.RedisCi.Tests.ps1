#Requires -Version 7.6
Describe 'Disposable Redis hosted CI boundaries' {
    It 'passes offline target, artifact, cleanup and optional-workflow guards without Docker' {
        $result = & python -m unittest discover -s $PSScriptRoot -p test_redis_ci.py 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($result -join "`n")
    }
}
