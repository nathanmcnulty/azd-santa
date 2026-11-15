#Requires -Version 7.6
BeforeDiscovery {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'experiments/vm/PrivateStorageEndpointUpdate.psm1') -Force
}
Describe 'One guarded existing-subnet Storage endpoint update' {
    InModuleScope PrivateStorageEndpointUpdate {
        BeforeAll {
            function New-UpdateFixture {
                $sub='11111111-1111-4111-8111-111111111111';$group="/subscriptions/$sub/resourceGroups/rg-azd-santa-vm-synthetic"
                $subnet="$group/providers/Microsoft.Network/virtualNetworks/vnet-santa-lab/subnets/host"
                $existing=@(@{service='Microsoft.Sql';locations=@('westus2')})
                $properties=@{addressPrefix='10.247.0.0/27';defaultOutboundAccess=$false;networkSecurityGroup=@{id="$group/providers/Microsoft.Network/networkSecurityGroups/nsg-santa-lab"}
                    ipConfigurations=@(@{id="$group/providers/Microsoft.Network/networkInterfaces/nic-santa-lab/ipConfigurations/primary"});privateEndpointNetworkPolicies='Disabled';privateLinkServiceNetworkPolicies='Enabled'}
                $before=@{scope='private-storage-endpoint-proposal-v1';selectedVmId="$group/providers/Microsoft.Compute/virtualMachines/vm-santa-lab"
                    selectedInstance='33333333-3333-4333-8333-333333333333';location='westus2';subnetId=$subnet;changed=$true;observationSha256='a'*64
                    observedSubnet=@{id=$subnet;etag='W/"expected"';properties=$properties};expectedEtags=@{$subnet='W/"expected"'};existingHostServiceEndpoints=$existing
                    proposedSubnetRequest=@{method='PUT';url="https://management.azure.com${subnet}?api-version=2024-05-01";body=@{properties=@{addressPrefix=$properties.addressPrefix;defaultOutboundAccess=$false;networkSecurityGroup=$properties.networkSecurityGroup
                        privateEndpointNetworkPolicies='Disabled';privateLinkServiceNetworkPolicies='Enabled';serviceEndpoints=@($existing)+@(@{service='Microsoft.Storage';locations=@('westus2')})}}}}
                $after=$before | ConvertTo-Json -Depth 48 | ConvertFrom-Json -Depth 48 -AsHashtable
                $after.changed=$false;$after.observationSha256='b'*64;$after.observedSubnet.etag='W/"after"'
                $after.existingHostServiceEndpoints=@($existing)+@(@{service='Microsoft.Storage';locations=@('westus2','westcentralus')})
                @{before=$before;after=$after;target=@{TenantId=[guid]'22222222-2222-4222-8222-222222222222';SubscriptionId=[guid]$sub;EnvironmentName='synthetic';VmInstanceId=[guid]'33333333-3333-4333-8333-333333333333'}}
            }
        }
        BeforeEach {
            $script:fixture=New-UpdateFixture;$script:target=$script:fixture.target;$script:plans=0;$script:secret='private-test-token-value'
            $script:path=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
            Mock New-SantaPrivateStorageEndpointPlan { @{scope='private-storage-endpoint-read-plan-v1';cloudWrite=$false} }
            Mock New-EndpointPlan {
                $script:plans++
                if($script:plans -le 2) {$script:fixture.before}else{$script:fixture.after}
            }
            Mock Get-EndpointToken {$script:secret}
            Mock Invoke-EndpointPut {param($Url,$Body,$Etag,$Token,$Seconds)
                $Etag | Should -BeExactly 'W/"expected"';$Token | Should -BeExactly $script:secret
                $Body.properties.serviceEndpoints | Should -HaveCount 2
                $Url | Should -BeExactly $script:fixture.before.proposedSubnetRequest.url
                200
            }
        }
        It 'defaults to no CLI token lookup journal or network write' {
            $p=Set-SantaPrivateStorageEndpoint @script:target
            $p.cloudWrite | Should -BeFalse;$p.automaticReplay | Should -BeFalse
            Should -Invoke New-EndpointPlan -Times 0;Should -Invoke Get-EndpointToken -Times 0;Should -Invoke Invoke-EndpointPut -Times 0
            Test-Path $script:path | Should -BeFalse
        }
        It 'uses fresh preflight and revalidation then one exact If-Match PUT and preservation readback' {
            $p=Set-SantaPrivateStorageEndpoint @script:target -Apply -AttemptDirectory $script:path
            $p.state | Should -BeExactly 'applied';$p.httpStatus | Should -Be 200;$p.desiredStateObserved | Should -BeTrue
            Should -Invoke New-EndpointPlan -Times 3 -Exactly;Should -Invoke Invoke-EndpointPut -Times 1 -Exactly
            Test-Path (Join-Path $script:path 'submission-intent.json') | Should -BeTrue
            Test-Path (Join-Path $script:path 'readback.json') | Should -BeTrue
            (Get-ChildItem $script:path -File | ForEach-Object {[IO.File]::ReadAllText($_.FullName)}) -join '' | Should -Not -Match ([regex]::Escape($script:secret))
            {Set-SantaPrivateStorageEndpoint @script:target -Apply -AttemptDirectory $script:path} | Should -Throw '*Never replay*'
            Should -Invoke Invoke-EndpointPut -Times 1 -Exactly
        }
        It 'does not acquire a token or PUT when already configured' {
            $script:fixture.before=$script:fixture.after
            $p=Set-SantaPrivateStorageEndpoint @script:target -Apply -AttemptDirectory $script:path
            $p.state | Should -BeExactly 'already-configured';$p.cloudWriteAttempted | Should -BeFalse
            Should -Invoke Get-EndpointToken -Times 0;Should -Invoke Invoke-EndpointPut -Times 0
        }
        It 'rejects changed graph ETags or request before submission' {
            Mock New-EndpointPlan {
                $script:plans++
                if($script:plans -eq 1){$script:fixture.before}else{$script:fixture.after}
            }
            {Set-SantaPrivateStorageEndpoint @script:target -Apply -AttemptDirectory $script:path} | Should -Throw '*failed or is unknown*'
            Should -Invoke Invoke-EndpointPut -Times 0
            Test-Path (Join-Path $script:path 'submission-intent.json') | Should -BeFalse
        }
        It 'stops cached token failures without fallback or secret diagnostics' {
            Mock Get-EndpointToken {throw 'private-test-token-value forbidden'}
            {Set-SantaPrivateStorageEndpoint @script:target -Apply -AttemptDirectory $script:path} | Should -Throw '*Never replay*'
            Should -Invoke Invoke-EndpointPut -Times 0
            [IO.File]::ReadAllText((Join-Path $script:path 'outcome.json')) | Should -Not -Match 'private-test-token'
        }
        It 'records conditional failure or unknown HTTP result without retry' -ForEach @(@{status=412;state='precondition-rejected'},@{status=202;state='unknown'},@{status=302;state='unknown'},@{status=403;state='unknown'}) {
            $script:statusToReturn=$status;Mock Invoke-EndpointPut {$script:statusToReturn}
            $p=Set-SantaPrivateStorageEndpoint @script:target -Apply -AttemptDirectory $script:path
            $p.state | Should -BeExactly $state;$p.httpStatus | Should -Be $status;$p.automaticReplay | Should -BeFalse
            Should -Invoke Invoke-EndpointPut -Times 1 -Exactly
        }
        It 'keeps lost responses unknown even after desired state readback and never PUTs on observation' {
            Mock Invoke-EndpointPut {throw 'private-test-token-value timeout'}
            $p=Set-SantaPrivateStorageEndpoint @script:target -Apply -AttemptDirectory $script:path
            $p.state | Should -BeExactly 'unknown';$p.desiredStateObserved | Should -BeTrue
            $result=Get-SantaPrivateStorageEndpointUpdate @script:target -AttemptDirectory $script:path -ReadArm
            $result.state | Should -BeExactly 'unknown';$result.desiredStateObserved | Should -BeTrue;$result.pastPutResultProven | Should -BeFalse
            Should -Invoke Invoke-EndpointPut -Times 1 -Exactly
        }
        It 'does not turn absent pending or failed readback into completion' {
            Mock New-EndpointPlan {
                $script:plans++;if($script:plans -gt 2){throw 'readback unknown raw secret'};$script:fixture.before
            }
            $p=Set-SantaPrivateStorageEndpoint @script:target -Apply -AttemptDirectory $script:path
            $p.state | Should -BeExactly 'unknown';$p.desiredStateObserved | Should -BeFalse
            Should -Invoke Invoke-EndpointPut -Times 1 -Exactly
        }
        It 'rejects lost endpoints changed policy or unrelated postflight despite HTTP success' -ForEach @(@{change='endpoint'},@{change='policy'},@{change='target'}) {
            switch($change){endpoint{$script:fixture.after.existingHostServiceEndpoints=$script:fixture.after.existingHostServiceEndpoints[1]}
                policy{$script:fixture.after.observedSubnet.properties.privateEndpointNetworkPolicies='Enabled'}
                target{$script:fixture.after.selectedInstance='44444444-4444-4444-8444-444444444444'}}
            $p=Set-SantaPrivateStorageEndpoint @script:target -Apply -AttemptDirectory $script:path
            $p.state | Should -BeExactly 'unknown';$p.desiredStateObserved | Should -BeFalse
        }
        It 'blocks preexisting attempt paths before any cached read' {
            New-Item -ItemType Directory -Path $script:path | Out-Null
            {Set-SantaPrivateStorageEndpoint @script:target -Apply -AttemptDirectory $script:path} | Should -Throw
            Should -Invoke New-EndpointPlan -Times 0;Should -Invoke Get-EndpointToken -Times 0;Should -Invoke Invoke-EndpointPut -Times 0
        }
        It 'observes local recorded state without CLI by default and rejects wrong target' {
            Set-SantaPrivateStorageEndpoint @script:target -Apply -AttemptDirectory $script:path | Out-Null
            $script:plans=0;$p=Get-SantaPrivateStorageEndpointUpdate @script:target -AttemptDirectory $script:path
            $p.cloudWrite | Should -BeFalse;$script:plans | Should -Be 0
            $wrong=$script:target.Clone();$wrong.VmInstanceId=[guid]'44444444-4444-4444-8444-444444444444'
            {Get-SantaPrivateStorageEndpointUpdate @wrong -AttemptDirectory $script:path -ReadArm} | Should -Throw
            $script:plans | Should -Be 0
        }
        It 'canonicalizes dictionary order for persisted cross-process target and endpoint comparisons' {
            $a=[ordered]@{z=@(@{b=2;a=1});a=[guid]'33333333-3333-4333-8333-333333333333'}
            $b=[ordered]@{a='33333333-3333-4333-8333-333333333333';z=@([ordered]@{a=1;b=2})}
            Endpoint-Json $a | Should -BeExactly (Endpoint-Json $b)
        }
    }
}
Describe 'Memory-only direct ARM subnet HTTP boundary' {
    InModuleScope PrivateStorageEndpointUpdate {
        BeforeAll {
            Add-Type -TypeDefinition @"
using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
public sealed class SantaEndpointMemoryHandler : HttpMessageHandler {
 public int Calls; public int Status=200; public string Mode="ok"; public string LastMatch; public string LastToken;
 protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken token) {
  Calls++; LastMatch=String.Join("",request.Headers.GetValues("If-Match")); LastToken=request.Headers.Authorization.Parameter;
  if(Mode=="cancel") await Task.Delay(Timeout.Infinite,token);
  var response=new HttpResponseMessage((HttpStatusCode)Status);
  response.Headers.Location=new Uri("https://unrelated.invalid/");
  response.Content=new StringContent(Mode=="large" ? new String('x',270000) : "raw-response-secret-must-not-escape");
  return response;
 }
}
"@
            $script:url='https://management.azure.com/subscriptions/11111111-1111-4111-8111-111111111111/resourceGroups/synthetic/providers/Microsoft.Network/virtualNetworks/vnet/subnets/host?api-version=2024-05-01'
        }
        BeforeEach {
            $script:handler=[SantaEndpointMemoryHandler]::new()
            Mock New-EndpointHttpClient {[Net.Http.HttpClient]::new($script:handler)}
        }
        It 'sends one PUT with exact If-Match and in-memory Authorization and discards an error body' {
            $script:handler.Status=403
            $status=Invoke-EndpointPut $script:url @{properties=@{}} 'W/"expected"' 'private-token-in-memory-only' 3
            $status | Should -Be 403;$script:handler.Calls | Should -Be 1
            $script:handler.LastMatch | Should -BeExactly 'W/"expected"'
            $script:handler.LastToken | Should -BeExactly 'private-token-in-memory-only'
        }
        It 'does not follow returned redirects' {
            $script:handler.Status=302
            Invoke-EndpointPut $script:url @{properties=@{}} 'W/"expected"' 'private-token-in-memory-only' 3 | Should -Be 302
            $script:handler.Calls | Should -Be 1
        }
        It 'rejects oversized response bytes and cancels blocked response work' {
            $script:handler.Mode='large'
            {Invoke-EndpointPut $script:url @{properties=@{}} 'W/"expected"' 'private-token-in-memory-only' 3} | Should -Throw
            $script:handler.Calls | Should -Be 1
            $script:handler=[SantaEndpointMemoryHandler]::new();$script:handler.Mode='cancel'
            $clock=[Diagnostics.Stopwatch]::StartNew()
            {Invoke-EndpointPut $script:url @{properties=@{}} 'W/"expected"' 'private-token-in-memory-only' 1} | Should -Throw
            $clock.Elapsed.TotalSeconds | Should -BeLessThan 5
            $script:handler.Calls | Should -Be 1
        }
        It 'rejects wrong protocol hosts or API versions before creating a client' {
            foreach($url in @('http://management.azure.com/?api-version=2024-05-01','https://unrelated.invalid/?api-version=2024-05-01','https://management.azure.com/?api-version=other')) {
                {Invoke-EndpointPut $url @{} 'W/"expected"' 'private-token-in-memory-only' 1} | Should -Throw
            }
            Should -Invoke New-EndpointHttpClient -Times 0
        }
    }
}
Describe 'Cached token and persisted unknown-state boundaries' {
    InModuleScope PrivateStorageEndpointUpdate {
        It 'captures only a matching cached token via the existing reader without token argv' {
            $target=@{TenantId=[guid]'22222222-2222-4222-8222-222222222222';SubscriptionId=[guid]'11111111-1111-4111-8111-111111111111'}
            Mock Read-Network -ModuleName PrivateStorageEndpoint {param($Arguments)
                $Arguments | Should -HaveCount 8
                ($Arguments[0..1] -join ' ') | Should -BeExactly 'account get-access-token'
                $Arguments | Should -Not -Contain 'private-token-in-memory-only'
                @{subscription='11111111-1111-4111-8111-111111111111';tenant='22222222-2222-4222-8222-222222222222';tokenType='Bearer';accessToken='private-token-in-memory-only'}
            }
            $token=Get-EndpointToken $target
            $token | Should -BeExactly 'private-token-in-memory-only'
            Should -Invoke Read-Network -ModuleName PrivateStorageEndpoint -Times 1 -Exactly
        }
        It 'rejects wrong token context type or header-injection values without fallback' -ForEach @(@{change='tenant'},@{change='type'},@{change='token'},@{change='array'}) {
            $script:tokenReply=@{subscription='11111111-1111-4111-8111-111111111111';tenant='22222222-2222-4222-8222-222222222222';tokenType='Bearer';accessToken='private-token-in-memory-only'}
            switch($change){tenant{$script:tokenReply.tenant='33333333-3333-4333-8333-333333333333'}type{$script:tokenReply.tokenType='Other'}token{$script:tokenReply.accessToken="private-token`r`nInjected: value"}array{$script:tokenReply.accessToken=@('private-token-in-memory-only','other')}}
            $reply=$script:tokenReply
            Mock Read-Network -ModuleName PrivateStorageEndpoint -MockWith ({ $reply }.GetNewClosure())
            $actualReply=& $script:planner { Read-Network @('account','get-access-token') };Endpoint-Json $actualReply | Should -BeExactly (Endpoint-Json $reply)
            {Get-EndpointToken @{TenantId=[guid]'22222222-2222-4222-8222-222222222222';SubscriptionId=[guid]'11111111-1111-4111-8111-111111111111'}} | Should -Throw
            Should -Invoke Read-Network -ModuleName PrivateStorageEndpoint -Times 2 -Exactly
        }
    }
}
