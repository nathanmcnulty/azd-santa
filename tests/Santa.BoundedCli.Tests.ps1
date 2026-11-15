#Requires -Version 7.6
BeforeDiscovery { Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'experiments/server/HttpsEndpoint.psm1') -Force }
Describe 'Bounded cached operator process reader' {
    InModuleScope HttpsEndpoint {
        BeforeAll { $script:python=@(Get-Command python -CommandType Application)[0].Source }
        It 'reads real child stdin and both streams without a cloud call' {
            $code='import sys,json;v=sys.stdin.read();sys.stderr.write("bounded");print(json.dumps({"input":v}))'
            $result=Invoke-SantaEndpointProcess -FileName $script:python -Arguments @('-I','-c',$code) -InputText 'ordinary-data' -TimeoutSeconds 5
            ($result | ConvertFrom-Json).input | Should -BeExactly 'ordinary-data'
        }
        It 'forces sensitive CLI settings only in the owned child environment' {
            $keys=@('AZURE_LOGGING_ENABLE_LOG_FILE','AZURE_CORE_COLLECT_TELEMETRY','AZURE_EXTENSION_USE_DYNAMIC_INSTALL','AZURE_AUTO_UPGRADE_ENABLE')
            $before=@{};foreach($key in $keys){$before[$key]=[Environment]::GetEnvironmentVariable($key)}
            try {
                foreach($key in $keys){[Environment]::SetEnvironmentVariable($key,'inherited-unsafe-value','Process')}
                $code='import os,json;print(json.dumps({k:os.getenv(k) for k in ("AZURE_LOGGING_ENABLE_LOG_FILE","AZURE_CORE_COLLECT_TELEMETRY","AZURE_EXTENSION_USE_DYNAMIC_INSTALL","AZURE_AUTO_UPGRADE_ENABLE")}))'
                $result=Invoke-SantaEndpointProcess -FileName $script:python -Arguments @('-I','-c',$code)
                $values=$result|ConvertFrom-Json -AsHashtable
                $values.AZURE_LOGGING_ENABLE_LOG_FILE|Should -BeExactly 'false'
                $values.AZURE_CORE_COLLECT_TELEMETRY|Should -BeExactly 'false'
                $values.AZURE_EXTENSION_USE_DYNAMIC_INSTALL|Should -BeExactly 'no'
                $values.AZURE_AUTO_UPGRADE_ENABLE|Should -BeExactly 'no'
                foreach($key in $keys){[Environment]::GetEnvironmentVariable($key)|Should -BeExactly 'inherited-unsafe-value'}
            } finally {foreach($key in $keys){[Environment]::SetEnvironmentVariable($key,$before[$key],'Process')}}
        }
        It 'kills and reaps its exact timed-out child without returning its output' {
            $pidFile=Join-Path $TestDrive 'child.pid'
            $code='import os,sys,time;from pathlib import Path;Path(sys.argv[1]).write_text(str(os.getpid()));time.sleep(30)'
            $watch=[Diagnostics.Stopwatch]::StartNew()
            { Invoke-SantaEndpointProcess -FileName $script:python -Arguments @('-I','-c',$code,$pidFile) -TimeoutSeconds 1 } | Should -Throw '*failed*'
            $watch.Elapsed.TotalSeconds | Should -BeLessThan 8
            $childId=[int](Get-Content $pidFile)
            Get-Process -Id $childId -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        }
        It 'bounds real stdout and stderr without exposing their contents' -ForEach @(
            @{channel='stdout';count=300000},@{channel='stderr';count=8192}
        ) {
            $code="import sys;sys.$channel.write('sensitive-value'*$count)"
            try { Invoke-SantaEndpointProcess -FileName $script:python -Arguments @('-I','-c',$code) -TimeoutSeconds 5;throw 'Expected failure' }
            catch { $_.Exception.Message | Should -Not -Match 'sensitive-value|Expected failure' }
        }
        It 'rejects nonzero exit and oversized input before output is returned' {
            { Invoke-SantaEndpointProcess -FileName $script:python -Arguments @('-I','-c','import sys;print("private-error");sys.exit(7)') } | Should -Throw '*failed*'
            { Invoke-SantaEndpointProcess -FileName $script:python -Arguments @() -InputText ('x'*262145) } | Should -Throw '*input*'
        }
        It 'keeps argv data separate and preserves JSON empty arrays and false' {
            Mock Get-Command { @([pscustomobject]@{Source='/unused/az'},[pscustomobject]@{Source='/never/second'}) }
            Mock Invoke-SantaEndpointProcess { '[]' }
            $value=Invoke-SantaEndpointAzJson @('deployment','sub','list','--subscription','selected')
            $value.GetType().IsArray | Should -BeTrue;$value.Count | Should -Be 0
            Should -Invoke Invoke-SantaEndpointProcess -Times 1 -Exactly -ParameterFilter { $TimeoutSeconds -eq 30 }
            Mock Invoke-SantaEndpointProcess { 'false' }
            (Invoke-SantaEndpointAzJson @('group','exists')) | Should -BeFalse
        }
        It 'does not expose malformed JSON or process errors' {
            Mock Get-Command { [pscustomobject]@{Source='/unused/az'} }
            Mock Invoke-SantaEndpointProcess { 'sensitive-value' }
            { Invoke-SantaEndpointAzJson @('account','show') } | Should -Throw '*no authentication fallback*'
        }
        It 'accepts an empty successful submission reply only when explicitly requested' {
            Mock Get-Command { [pscustomobject]@{Source='/unused/az'} }
            Mock Invoke-SantaEndpointProcess { '' }
            { Invoke-SantaEndpointAzJson @('account','show') } | Should -Throw
            (Invoke-SantaEndpointAzJson @('deployment','sub','create') -AllowEmpty) | Should -BeNullOrEmpty
        }
        It 'bounds actual Windows batch-wrapper output and deadline without running Azure CLI' {
            if(-not $IsWindows) { return }
            $fake=Join-Path $TestDrive 'ordinary-cli.cmd';$script:fakeCli=$fake
            Mock Get-Command { [pscustomobject]@{Source=$script:fakeCli} }
            $fixture=Join-Path $TestDrive 'ordinary-child.py'
            [IO.File]::WriteAllText($fixture,"import os,sys,time`nfrom pathlib import Path`nPath(sys.argv[1]).write_text(str(os.getpid()))`nif sys.argv[2]=='overflow':`n for _ in range(50000): print('ordinary-test-output',flush=True)`ntime.sleep(30)`n")
            foreach($mode in @('overflow','timeout')) {
                $pidFile=Join-Path $TestDrive ($mode+'.pid');$startedAt=Get-Date
                [IO.File]::WriteAllText($fake,('@echo off'+"`r`n"+'"'+$script:python+'" -I "'+$fixture+'" "'+$pidFile+'" '+$mode+"`r`n"))
                $watch=[Diagnostics.Stopwatch]::StartNew()
                { Invoke-SantaEndpointAzJson @('account','show') -TimeoutSeconds 3 } | Should -Throw '*failed or is unknown*'
                $watch.Elapsed.TotalSeconds | Should -BeLessThan 9
                Test-Path $pidFile | Should -BeTrue -Because 'the owned descendant must actually run'
                $childId=[int](Get-Content $pidFile);$child=Get-Process -Id $childId -ErrorAction SilentlyContinue
                $leftRunning=$false
                if($child) {
                    try {
                        # Never clean up an unrelated recycled PID.
                        if($child.ProcessName -notmatch '^python' -or $child.StartTime -lt $startedAt.AddSeconds(-1)) { throw 'Unexpected fixture process identity.' }
                        $leftRunning=-not $child.WaitForExit(1000)
                        if($leftRunning) { $child.Kill($true);$null=$child.WaitForExit(3000) }
                    } finally { $child.Dispose() }
                }
                $leftRunning | Should -BeFalse -Because "$mode must not leave the owned descendant alive"
            }
        }
    }
}
