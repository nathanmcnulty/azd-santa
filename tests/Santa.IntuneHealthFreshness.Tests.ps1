#Requires -Version 7.6
Describe 'Intune Santa health freshness' {
    BeforeAll {
        $root = Split-Path $PSScriptRoot -Parent
        $tenant = '11111111-1111-4111-8111-111111111111'
        $groupId = '22222222-2222-4222-8222-222222222222'
        $scriptId = '33333333-3333-4333-8333-333333333333'
        $account = 'operator@example.invalid'
        $receiptPath = Join-Path $TestDrive 'publication.json'
        $outputPath = Join-Path $TestDrive 'health.json'
        $healthBytes = [IO.File]::ReadAllBytes((Join-Path $root 'scripts/live-response/Get-SantaHealth.sh'))
        $version = (Get-Content "$root/package/santa.lock.json" -Raw | ConvertFrom-Json).release.tag
        @{
            template = 'azd-santa'; objectType = 'intune-device-shell-script'; tenantId = $tenant
            environmentName = 'default'; scriptId = $scriptId; assignmentGroupId = $groupId
            sha256 = [Convert]::ToHexStringLower([Security.Cryptography.SHA256]::HashData($healthBytes))
            assignmentGroupName = 'Pilot'; expectedDeviceName = 'Pilot Mac'; displayName = 'Health'
            description = 'Owned health script'
        } | ConvertTo-Json | Set-Content -LiteralPath $receiptPath
        function Connect-MgGraph { param($TenantId,$Scopes,$ContextScope,[switch]$NoWelcome); throw 'Unmocked sign-in' }
        function Get-MgContext { throw 'Unmocked Graph context' }
        function Invoke-MgGraphRequest { param($Method,$Uri,$OutputType); throw 'Unmocked Graph request' }
    }

    BeforeEach {
        $now = [DateTimeOffset]::UtcNow
        $published = $now.AddDays(-30)
        $reported = $now.AddMinutes(-10)
        Mock Connect-MgGraph {}
        Mock Get-MgContext {
            @{ tenantId = $tenant; account = $account; scopes = @(
                'DeviceManagementScripts.Read.All','DeviceManagementManagedDevices.Read.All','Group.Read.All','Device.Read.All'
            ) }
        }
        Mock Invoke-MgGraphRequest {
            $Method | Should -Be 'GET'
            switch -Regex ($Uri) {
                '/members\?' { return @{value=@(@{'@odata.type'='#microsoft.graph.device';displayName='Pilot Mac';deviceId='entra-device';operatingSystem='MacMDM'})} }
                '/groups/' { return @{displayName='Pilot';securityEnabled=$true;mailEnabled=$false} }
                '/managedDevices\?' { return @{value=@(@{id='managed-device';deviceName='Pilot Mac';operatingSystem='macOS'})} }
                '/deviceRunStates\?' { return @{value=$runs} }
                '/deviceShellScripts/' {
                    return @{
                        id=$scriptId;displayName='Health';description='Owned health script';runAsAccount='system'
                        scriptContent=[Convert]::ToBase64String($healthBytes);lastModifiedDateTime=$published
                        groupAssignments=@(@{targetGroupId=$groupId});assignments=@()
                    }
                }
                default { throw 'Unexpected Graph route' }
            }
        }
    }

    It 'reports <label> as <expected>' -ForEach @(
        @{label='fresh success with CRLF'; hours=-1; marker='normal'; state='success'; expected='passed'}
        @{label='stale success with recent service update'; hours=-48; marker='normal'; state='success'; expected='stale'}
        @{label='success within an explicit bound'; hours=-48; marker='normal'; state='success'; expected='passed'; maximum=72}
        @{label='missing capture'; hours=-1; marker='missing'; state='success'; expected='invalid-evidence'}
        @{label='malformed capture'; hours=-1; marker='malformed'; state='success'; expected='invalid-evidence'}
        @{label='duplicate capture'; hours=-1; marker='duplicate'; state='success'; expected='invalid-evidence'}
        @{label='future capture'; hours=2; marker='normal'; state='success'; expected='invalid-evidence'}
        @{label='future service update'; hours=-1; marker='normal'; state='success'; expected='invalid-evidence'; futureReport=$true}
        @{label='execution failed'; hours=-48; marker='malformed'; state='fail'; expected='failed'}
        @{label='pending work'; hours=-1; marker='missing'; state='pending'; expected='pending'}
        @{label='no run'; hours=-1; marker='missing'; state='absent'; expected='pending'}
        @{label='result for an earlier publication'; hours=-800; marker='normal'; state='success'; expected='pending'; earlierReport=$true}
    ) {
        $time = $now.AddHours($hours).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")
        $lines = @("computerName=Pilot Mac","expectedSantaVersion=$version",'result=passed')
        if ($marker -ne 'missing') {
            $lines += if ($marker -eq 'malformed') { 'capturedAtUtc=yesterday' } else { "capturedAtUtc=$time" }
        }
        if ($marker -eq 'duplicate') { $lines += "capturedAtUtc=$time" }
        $message = $lines -join ([string][char]13+[char]10)
        $update = if ($futureReport) { $now.AddHours(2) } elseif ($earlierReport) { $published.AddMinutes(-1) } else { $reported }
        $runs = if ($state -eq 'absent') { @() } else {
            @(@{id='run';managedDevice=@{id='managed-device'};resultMessage=$message;runState=$state;errorCode=0;lastStateUpdateDateTime=$update})
        }
        $parameters = @{TenantId=$tenant;ExpectedAccount=$account;PublicationReceiptPath=$receiptPath;OutputPath=$outputPath}
        if ($maximum) { $parameters.MaximumEvidenceAgeHours = $maximum }
        & "$root/scripts/Get-SantaIntuneHealthStatus.ps1" @parameters
        $result = Get-Content -LiteralPath $outputPath -Raw | ConvertFrom-Json -DateKind String
        $result.status | Should -BeExactly $expected
        $result.schemaVersion | Should -BeExactly '1.0'
        $result.maximumEvidenceAgeHours | Should -Be ($maximum ?? 24)
        ([DateTimeOffset]$result.collectedUtc) | Should -BeGreaterOrEqual $now
        if ($state -ne 'absent') { $result.run.resultMessage | Should -BeExactly $message }
        if ($marker -eq 'normal' -and $state -ne 'absent') {
            $result.captureAgeSeconds | Should -Be (([DateTimeOffset]$result.collectedUtc - [DateTimeOffset]$time).TotalSeconds)
        } else {
            $result.captureAgeSeconds | Should -BeNullOrEmpty
        }
    }
}
