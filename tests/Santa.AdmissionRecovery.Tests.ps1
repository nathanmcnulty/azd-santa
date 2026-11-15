#Requires -Version 7.6
Describe 'Fenced original-generation admission recovery' {
    It 'passes offline protocol and process/database quiescence guards without Redis or Docker' {
        $result = & python -m unittest discover -s $PSScriptRoot -p test_admission_recovery.py 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($result -join "`n")
    }
}
