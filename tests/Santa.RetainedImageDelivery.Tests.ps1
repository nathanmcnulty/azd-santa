#Requires -Version 7.6
Describe 'Santa bounded retained image VM delivery' {
    It 'stages exact packets and observes a lost finish response without replay' -Skip:(-not $IsLinux) {
        $result = & python -m unittest discover -s $PSScriptRoot -p test_retained_image_delivery.py 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($result -join "`n")
    }
    It 'binds each Run Command frame to the selected VM and checks the response' {
        $result = & python -m unittest discover -s $PSScriptRoot -p test_retained_image_run_command.py 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($result -join "`n")
    }
    It 'packages the selected guest runner and dispatches against its private state' {
        $result = & python -m unittest discover -s $PSScriptRoot -p test_retained_image_runner.py 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($result -join "`n")
    }
}
