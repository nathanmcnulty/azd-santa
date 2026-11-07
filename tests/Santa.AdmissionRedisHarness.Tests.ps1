#Requires -Version 7.6
Describe 'Disposable actual Redis admission harness guards' {
    It 'passes offline parser, exact-target, source-pin and command guards without Docker or Redis' {
        $result = & python -m unittest discover -s $PSScriptRoot -p test_admission_redis_harness.py 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($result -join "`n")
    }
}
