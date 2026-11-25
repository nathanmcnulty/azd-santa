#Requires -Version 7.6
Describe 'Santa bounded retained image VM delivery' {
    It 'stages exact packets and observes a lost finish response without replay' -Skip:(-not $IsLinux) {
        $result = & python -m unittest discover -s $PSScriptRoot -p test_retained_image_delivery.py 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($result -join "`n")
    }
}
