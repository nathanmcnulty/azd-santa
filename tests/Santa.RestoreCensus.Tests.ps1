#Requires -Version 7.6
Describe 'Read-only isolated restore census primitive' {
    It 'passes controlled registry, SQL protocol, coverage and preservation checks' {
        $result = & python -m unittest discover -s $PSScriptRoot -p test_restore_census.py 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($result -join "`n")
    }
}
