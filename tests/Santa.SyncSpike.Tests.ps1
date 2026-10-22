#Requires -Version 7.6
Describe 'Offline public sync protocol spike' {
    It 'passes the local HTTP synthetic conformance suite' {
        $root = Split-Path $PSScriptRoot -Parent
        $output = & python (Join-Path $root 'tools/sync_spike/test_conformance.py') 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($output -join "`n")
    }
    It 'passes the synthetic local durability suite' {
        $root = Split-Path $PSScriptRoot -Parent
        $output = & python (Join-Path $root 'tools/sync_spike/test_durable.py') 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($output -join "`n")
    }
}
