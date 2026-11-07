#Requires -Version 7.6
Describe 'Bounded worker lifecycle source candidate' {
    It 'passes synthetic process/callback/deadline/source guards without a broker or image' {
        $result = & python -m unittest discover -s $PSScriptRoot -p test_worker_lifecycle.py 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($result -join "`n")
    }
    It 'keeps lifecycle composition outside existing deployment and runtime defaults' {
        $root = Split-Path $PSScriptRoot -Parent
        (Get-Content (Join-Path $root 'azure.yaml') -Raw) | Should -Not -Match 'worker_lifecycle'
        (Get-Content (Join-Path $root 'experiments/vm/azure.yaml') -Raw) | Should -Not -Match 'worker_lifecycle'
        $helper = Get-Content (Join-Path $root 'experiments/server/worker_lifecycle.py') -Raw
        $helper | Should -Match 'SANTA_WORKERS_CLEAN_STOP_JSON:'
        $helper | Should -Match 'GRACE_SECONDS = 20'
    }
}
