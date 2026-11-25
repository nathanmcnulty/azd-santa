#Requires -Version 7.6
Describe 'Private pilot enrollment worker' {
    It 'passes actual crypto and durable-attempt boundary tests without tenant access' {
        $root = Split-Path -Parent $PSScriptRoot
        $result = & python -m unittest discover -s (Join-Path $root 'tests') -p test_pilot_enrollment.py 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($result -join "`n")
    }
}
