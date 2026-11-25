#Requires -Version 7.6
Describe 'Santa retained image encrypted handoff' {
    It 'binds tokens to the exact boot and target and rejects replay' -Skip:(-not $IsLinux) {
        $result = & python -m unittest discover -s $PSScriptRoot -p test_retained_image_handoff.py 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($result -join "`n")
    }
}
