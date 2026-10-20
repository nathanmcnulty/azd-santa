#Requires -Version 7.6
BeforeAll {
    $script:runner = Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts/Invoke-SantaLiveResponseHealth.ps1'
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Text.Json;
public class SantaReceiptHandler : HttpMessageHandler {
    public Queue<HttpResponseMessage> Responses = new Queue<HttpResponseMessage>();
    public List<string> Requests = new List<string>();
    public string ReceiptPath;
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) {
        Requests.Add(request.Method + " " + request.RequestUri.AbsolutePath);
        if (request.RequestUri.AbsolutePath.Contains("machineactions/")) {
            if (!File.Exists(ReceiptPath)) throw new Exception("Receipt missing before first poll");
            using (var document = JsonDocument.Parse(File.ReadAllText(ReceiptPath))) {
                var receipt = document.RootElement;
                if (receipt.GetProperty("action").GetProperty("id").GetString() != "00000000-0000-0000-0000-000000000002" ||
                    receipt.GetProperty("action").GetProperty("scriptName").GetString() != "Get-SantaHealth.sh" ||
                    receipt.GetProperty("machine").GetProperty("id").GetString() != new string('a', 40) ||
                    receipt.GetProperty("machine").GetProperty("name").GetString() != "fixture-mac" ||
                    receipt.GetProperty("tenantId").GetString() != "00000000-0000-0000-0000-000000000001")
                    throw new Exception("Action identity and target must be persisted before polling");
            }
        }
        if (Responses.Count == 0) throw new Exception("Unexpected request");
        return Task.FromResult(Responses.Dequeue());
    }
}
'@
    function global:az {
        $global:LASTEXITCODE = 0
        if ($args -contains 'show') { '{"tenantId":"00000000-0000-0000-0000-000000000001","user":"operator@example.test"}' }
        else { 'fixture-token' }
    }
    function Add-Response($Body, $Status = 200, $Handler = $script:handler) {
        $response = [Net.Http.HttpResponseMessage]::new([Net.HttpStatusCode]$Status)
        $response.Content = [Net.Http.StringContent]::new(($Body | ConvertTo-Json -Depth 12 -Compress))
        $Handler.Responses.Enqueue($response)
    }
    function Add-Action($Status, $Machine = ('a' * 40), $Command = 'Completed', $ScriptName = 'Get-SantaHealth.sh') {
        Add-Response @{ id = $script:actionId; type = 'LiveResponse'; machineId = $Machine; computerDnsName = 'fixture-mac'; status = $Status; commands = @(@{ index = 0; commandStatus = $Command; command = @{ type = 'RunScript'; params = @(@{ key = 'ScriptName'; value = $ScriptName }) } }) }
    }
    function Add-Success {
        Add-Action 'Succeeded'
        Add-Response @{ value = 'https://example.test/signed-fixture' }
        Add-Response @{ script_name = 'Get-SantaHealth.sh'; exit_code = 0; script_output = "result=passed`n"; script_errors = '' } -Handler $script:downloadHandler
    }
}
AfterAll { Remove-Item Function:global:az }
Describe 'Private Live Response receipts and bounded polling' {
    BeforeEach {
        $script:actionId = '00000000-0000-0000-0000-000000000002'
        $script:handler = [SantaReceiptHandler]::new()
        $script:downloadHandler = [SantaReceiptHandler]::new()
        $script:client = [Net.Http.HttpClient]::new($handler)
        $script:downloadClient = [Net.Http.HttpClient]::new($downloadHandler)
        $script:resultPath = Join-Path $TestDrive "$([guid]::NewGuid()).json"
        $script:receiptPath = "$resultPath.action.json"
        $handler.ReceiptPath = $receiptPath
        $script:parameters = @{
            MachineId = 'a' * 40; ExpectedMachineName = 'fixture-mac'; ExpectedTenantId = '00000000-0000-0000-0000-000000000001'
            ExpectedAccount = 'operator@example.test'; ResultPath = $resultPath; Apply = $true; Confirm = $false
            MaximumPolls = 2; PollIntervalSeconds = 0; HttpClient = $client; ResultHttpClient = $downloadClient
        }
        Add-Response @{ id = 'a' * 40; computerDnsName = 'fixture-mac'; osPlatform = 'macOS'; onboardingStatus = 'Onboarded' }
        Add-Response @{ value = @(@{ fileName = 'Get-SantaHealth.sh'; description = 'managed by azd-santa' }) }
    }
    AfterEach { $client.Dispose(); $downloadClient.Dispose() }
    It 'persists before polling, tolerates a transient 404, and preserves v1 success consumers' {
        Add-Response @{ id = $actionId }
        Add-Response @{} 404
        Add-Success
        & $runner @parameters
        $receipt = Get-Content $receiptPath -Raw | ConvertFrom-Json
        $receipt.state | Should -Be 'verified-completion'
        $receipt.action.id | Should -Be $actionId
        $result = Get-Content $resultPath -Raw | ConvertFrom-Json
        $result.schemaVersion | Should -Be '1.0'
        $result.action.status | Should -Be 'Succeeded'
        $result.result.exit_code | Should -Be 0
        Get-Content $receiptPath -Raw | Should -Not -Match 'fixture-token|signed-fixture|script_output'
        if (-not $IsWindows) { [int][IO.File]::GetUnixFileMode($receiptPath) | Should -Be 384 }
    }
    It 'returns timeout rather than failure for absent or pending rows and resumes without POST' {
        Add-Response @{ id = $actionId }
        Add-Response @{} 404
        Add-Action 'Pending'
        $outcome = & $runner @parameters -WarningAction SilentlyContinue
        $outcome.state | Should -Be 'polling-timeout'
        (Get-Content $receiptPath -Raw | ConvertFrom-Json).action.status | Should -Be 'Pending'
        Test-Path $resultPath | Should -BeFalse
        Add-Response @{ id = 'a' * 40; computerDnsName = 'fixture-mac'; osPlatform = 'macOS'; onboardingStatus = 'Onboarded' }
        Add-Response @{ value = @(@{ fileName = 'Get-SantaHealth.sh'; description = 'managed by azd-santa' }) }
        Add-Success
        & $runner @parameters -ExistingActionId $actionId
        @($handler.Requests | Where-Object { $_ -like 'POST *' }).Count | Should -Be 1
    }
    It 'retains a timeout receipt when every poll is not yet visible' {
        Add-Response @{ id = $actionId }; Add-Response @{} 404; Add-Response @{} 404
        (& $runner @parameters -WarningAction SilentlyContinue).state | Should -Be 'polling-timeout'
        (Get-Content $receiptPath -Raw | ConvertFrom-Json).action.id | Should -Be $actionId
    }
    It 'rejects wrong-target actions before interpreting failure or success' {
        Add-Response @{ id = $actionId }; Add-Action 'Failed' ('b' * 40)
        { & $runner @parameters } | Should -Throw '*expected action and machine*'
        (Get-Content $receiptPath -Raw | ConvertFrom-Json).state | Should -Be 'binding-mismatch'
    }
    It 'distinguishes explicit action failure from command failure' {
        Add-Response @{ id = $actionId }; Add-Action 'Failed'
        { & $runner @parameters } | Should -Throw '*explicitly reported*'
        (Get-Content $receiptPath -Raw | ConvertFrom-Json).state | Should -Be 'action-failed'
    }
    It 'distinguishes explicit service timeout from the local polling window' {
        Add-Response @{ id = $actionId }; Add-Action 'TimeOut'
        { & $runner @parameters } | Should -Throw '*service-side timeout*'
        (Get-Content $receiptPath -Raw | ConvertFrom-Json).state | Should -Be 'action-timeout'
        @($handler.Requests | Where-Object { $_ -like '*machineactions/*' }).Count | Should -Be 1
    }
    It 'captures explicit command failure' {
        Add-Response @{ id = $actionId }; Add-Action 'Succeeded' -Command 'Failed'
        { & $runner @parameters } | Should -Throw '*not verified*'
        (Get-Content $receiptPath -Raw | ConvertFrom-Json).state | Should -Be 'command-failed'
    }
    It 'does not call unknown command state failed' {
        Add-Response @{ id = $actionId }; Add-Action 'Succeeded' -Command 'Pending'
        { & $runner @parameters } | Should -Throw '*not verified*'
        (Get-Content $receiptPath -Raw | ConvertFrom-Json).state | Should -Be 'command-unverified'
    }
    It 'retains uncertain POST evidence, redacts API errors, and prevents replay' {
        Add-Response @{ secret = 'do-not-leak' } 500
        { & $runner @parameters } | Should -Throw '*HTTP 500.*'
        (Get-Content $receiptPath -Raw | ConvertFrom-Json).state | Should -Be 'submission-uncertain'
        { & $runner @parameters } | Should -Throw '*do not resubmit*'
        @($handler.Requests | Where-Object { $_ -like 'POST *' }).Count | Should -Be 1
    }
    It 'treats unknown service status as unverified timeout' {
        Add-Response @{ id = $actionId }; Add-Action 'FutureStatus'; Add-Action 'FutureStatus'
        (& $runner @parameters -WarningAction SilentlyContinue).state | Should -Be 'polling-timeout'
        Test-Path $resultPath | Should -BeFalse
    }
    It 'keeps the receipt on polling transport failure' {
        Add-Response @{ id = $actionId }; Add-Response @{} 503
        { & $runner @parameters } | Should -Throw '*HTTP 503*'
        $receipt = Get-Content $receiptPath -Raw | ConvertFrom-Json
        $receipt.state | Should -Be 'polling-error'
        $receipt.action.id | Should -Be $actionId
    }
    It 'does not fabricate success from missing exit-code evidence' {
        Add-Response @{ id = $actionId }; Add-Action 'Succeeded'
        Add-Response @{ value = 'https://example.test/signed-fixture' }
        Add-Response @{ script_name = 'Get-SantaHealth.sh'; script_output = "result=passed`n" } -Handler $downloadHandler
        { & $runner @parameters } | Should -Throw '*did not verify*'
        (Get-Content $receiptPath -Raw | ConvertFrom-Json).state | Should -Be 'result-unverified'
        Test-Path $resultPath | Should -BeFalse
    }
    It 'does not label unknown profile results as command failure' {
        Add-Response @{ id = $actionId }; Add-Action 'Succeeded'
        Add-Response @{ value = 'https://example.test/signed-fixture' }
        Add-Response @{ script_name = 'Get-SantaHealth.sh'; exit_code = 0; script_output = "result=unknown`n" } -Handler $downloadHandler
        { & $runner @parameters } | Should -Throw '*did not verify*'
        (Get-Content $receiptPath -Raw | ConvertFrom-Json).state | Should -Be 'result-unverified'
    }
    It 'redacts a signed URL on download failure' {
        Add-Response @{ id = $actionId }; Add-Action 'Succeeded'
        Add-Response @{ value = 'https://example.test/signed-fixture?sig=secret' }
        Add-Response @{} 403 -Handler $downloadHandler
        { & $runner @parameters } | Should -Throw '*signed URL is redacted*'
        (Get-Content $receiptPath -Raw | ConvertFrom-Json).state | Should -Be 'result-unverified'
        Get-Content $receiptPath -Raw | Should -Not -Match 'sig=|signed-fixture'
    }
    It 'allows a recovered ID to resume a target-matched uncertain submission' {
        Add-Response @{} 500
        { & $runner @parameters } | Should -Throw '*HTTP 500*'
        Add-Response @{ id = 'a' * 40; computerDnsName = 'fixture-mac'; osPlatform = 'macOS'; onboardingStatus = 'Onboarded' }
        Add-Response @{ value = @(@{ fileName = 'Get-SantaHealth.sh'; description = 'managed by azd-santa' }) }
        Add-Success
        & $runner @parameters -ExistingActionId $actionId
        @($handler.Requests | Where-Object { $_ -like 'POST *' }).Count | Should -Be 1
        (Get-Content $receiptPath -Raw | ConvertFrom-Json).state | Should -Be 'verified-completion'
    }
    It 'blocks concurrent invocations sharing a receipt before any request' {
        $lock = [IO.File]::Open("$receiptPath.lock", [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try {
            { & $runner @parameters } | Should -Throw '*Another invocation holds*'
            $handler.Requests.Count | Should -Be 0
        } finally { $lock.Dispose() }
    }
    It 'rejects a recovered action for a different script on the correct machine' {
        Add-Action 'Succeeded' -ScriptName 'Get-SantaProfileState.sh'
        { & $runner @parameters -ExistingActionId $actionId } | Should -Throw '*selected script*'
        (Get-Content $receiptPath -Raw | ConvertFrom-Json).state | Should -Be 'binding-mismatch'
        @($handler.Requests | Where-Object { $_ -like 'POST *' }).Count | Should -Be 0
    }
    It 'rejects a transcript from a different script' {
        Add-Response @{ id = $actionId }; Add-Action 'Succeeded'
        Add-Response @{ value = 'https://example.test/signed-fixture' }
        Add-Response @{ script_name = 'Get-SantaProfileState.sh'; exit_code = 0; script_output = "result=passed`n" } -Handler $downloadHandler
        { & $runner @parameters } | Should -Throw '*selected script*'
        (Get-Content $receiptPath -Raw | ConvertFrom-Json).state | Should -Be 'binding-mismatch'
        Test-Path $resultPath | Should -BeFalse
    }
    It 'rejects a wrong receipt target without issuing requests' {
        @{ schemaVersion = '1.0'; tenantId = 'wrong' } | ConvertTo-Json | Set-Content $receiptPath
        { & $runner @parameters -ExistingActionId $actionId } | Should -Throw '*receipt does not match*'
        $handler.Requests.Count | Should -Be 0
    }
}
