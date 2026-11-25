#Requires -Version 7.6
Describe 'Santa retained image archive' {
    It 'checks byte limits, archive identity, and platform without Docker' {
        $result = & python -m unittest discover -s $PSScriptRoot -p test_retained_image_archive.py 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($result -join "`n")
    }
}
