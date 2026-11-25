#Requires -Version 7.6
Describe 'Santa encrypted image export' {
    It 'exercises the Linux private export and failure contract' -Skip:(-not $IsLinux) {
        $result = & python -m unittest discover -s $PSScriptRoot -p test_retained_image_export.py 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($result -join "`n")
    }
    It 'packages the selected export command and on Linux collects it after a lost reply' {
        $result = & python -m unittest discover -s $PSScriptRoot -p test_retained_image_export_command.py 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($result -join "`n")
    }
}
