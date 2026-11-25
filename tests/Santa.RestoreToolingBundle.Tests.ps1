#Requires -Version 7.6
Describe 'Santa restore tooling bundle' {
    It 'packages only reviewed Git blobs and stages independently verified bytes' {
        $result = & python -m unittest discover -s $PSScriptRoot -p test_restore_tooling_bundle.py 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($result -join "`n")
    }
}
