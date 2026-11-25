#Requires -Version 7.6
Describe 'Santa retained image Blob transport' {
    It 'checks create-only HTTP requests and independent journaled readback' -Skip:(-not $IsLinux) {
        $result = & python -m unittest discover -s $PSScriptRoot -p test_retained_image_blob.py 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($result -join "`n")
    }
}
