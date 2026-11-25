#Requires -Version 7.6
Describe 'Santa retained image readback' {
    It 'authenticates retained bytes and binds them to the independent selection' -Skip:(-not $IsLinux) {
        $result = & python -m unittest discover -s $PSScriptRoot -p test_retained_image_readback.py 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($result -join "`n")
    }
}
