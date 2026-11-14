#Requires -Version 7.6
Describe 'Standalone POSIX probe offline guards' {
    It 'checks receipt, source, timeout cleanup and private failure retention without POSIX execution' {
        $result = & python -m unittest discover -s $PSScriptRoot -p test_worker_posix_probe.py 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($result -join "`n")
    }
}
