#Requires -Version 7.6
Describe 'Santa restore authority planning' {
    It 'plans bounded dispositions for restored identities and credentials' {
        $result = & python -m unittest discover -s $PSScriptRoot -p test_restore_authority_plan.py 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($result -join "`n")
    }
}
