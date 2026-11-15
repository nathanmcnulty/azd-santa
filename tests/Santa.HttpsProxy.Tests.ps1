#Requires -Version 7.6
Describe 'Offline held-closed HTTPS candidate' {
    It 'passes generator identity, configuration and overwrite guards without network calls' {
        $result = & python -m unittest discover -s $PSScriptRoot -p test_https_proxy.py 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($result -join "`n")
    }
    It 'pins official source and archives without activating a deployment hook' {
        $root = Split-Path $PSScriptRoot -Parent
        $lock = Get-Content (Join-Path $root 'experiments/server/caddy.lock.json') -Raw | ConvertFrom-Json
        $lock.sourceCommit | Should -Match '^[a-f0-9]{40}$'
        $lock.linuxAmd64.archiveSha256 | Should -Match '^[a-f0-9]{64}$'
        $lock.windowsAmd64Validation.binarySha256 | Should -Match '^[a-f0-9]{64}$'
        (Get-Content (Join-Path $root 'azure.yaml') -Raw) | Should -Not -Match 'caddy|https_proxy'
        (Get-Content (Join-Path $root 'experiments/vm/azure.yaml') -Raw) | Should -Not -Match 'caddy|https_proxy'
    }
}
