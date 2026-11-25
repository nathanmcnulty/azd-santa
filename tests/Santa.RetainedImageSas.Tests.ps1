#Requires -Version 7.6
Describe 'Santa retained image SAS issuance' {
    It 'uses bounded cached context and exact, separately scoped object requests' {
        $result = & python -m unittest discover -s $PSScriptRoot -p test_retained_image_sas.py 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($result -join "`n")
    }
}
