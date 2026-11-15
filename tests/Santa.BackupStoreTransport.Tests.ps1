#Requires -Version 7.6
BeforeDiscovery { Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'experiments/server/BackupStoreDeployment.psm1') -Force }
Describe 'Single fixed-ARM backup deployment transport' {
    InModuleScope BackupStoreDeployment {
        BeforeAll {
            if(-not ('SantaStoreTransportFixture.Handler' -as [type])) {
                Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
namespace SantaStoreTransportFixture {
 public sealed class BodyProbe : HttpContent {
  public int Reads; public bool Disposed;
  protected override bool TryComputeLength(out long length) {length=0;return false;}
  protected override Task SerializeToStreamAsync(Stream stream,TransportContext context) {Reads++;throw new Exception("response body must not be read");}
  protected override void Dispose(bool disposing) {Disposed=true;base.Dispose(disposing);}
 }
 public sealed class Handler : HttpMessageHandler {
  public int Calls; public int Status=202; public bool Fail,Cancel; public string Uri,Method,Body,Scheme; public bool CanCancel;
  public BodyProbe Probe=new BodyProbe();
  protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken cancellation) {
   Calls++;Uri=request.RequestUri.AbsoluteUri;Method=request.Method.Method;Scheme=request.Headers.Authorization.Scheme;
   CanCancel=cancellation.CanBeCanceled;Body=await request.Content.ReadAsStringAsync(cancellation);
   if(Fail)throw new HttpRequestException("private-sentinel");
   if(Cancel)throw new OperationCanceledException(cancellation);
   var result=new HttpResponseMessage((HttpStatusCode)Status);result.Content=Probe;
   result.Headers.Location=new System.Uri("https://foreign.example/private-sentinel");return result;
  }
 }
}
'@
            }
            $script:argsForPlan=@{TenantId='55555555-5555-4555-8555-555555555555';SubscriptionId='11111111-1111-4111-8111-111111111111'
                Location='westus2';SourceEnvironment='source';SourceVmInstanceId='33333333-3333-4333-8333-333333333333'}
        }
        It 'configures actual default handler without proxy, redirects or cookies' {
            $handler=New-StoreHttpHandler
            try {$handler.UseProxy|Should -BeFalse;$handler.AllowAutoRedirect|Should -BeFalse;$handler.UseCookies|Should -BeFalse;$handler.MaxResponseHeadersLength|Should -Be 16}
            finally {$handler.Dispose()}
        }
        It 'uses one cancellable PUT to only the generated URI and does not read body or Location' -ForEach @(@{status=202},@{status=307},@{status=403}) {
            $plan=New-SantaBackupStoreDeploymentPlan @script:argsForPlan
            $handler=[SantaStoreTransportFixture.Handler]::new();$handler.Status=$status
            $result=Send-StoreDeployment $plan @{resources=@()} @{parameters=@{location=@{value='westus2'}}} ('x'*64) $handler
            $result|Should -Be $status;$handler.Calls|Should -Be 1;$handler.Method|Should -BeExactly 'PUT'
            $handler.Uri|Should -BeExactly "https://management.azure.com/subscriptions/$($plan.selection.SubscriptionId)/providers/Microsoft.Resources/deployments/$($plan.deploymentName)?api-version=2025-04-01"
            $handler.Scheme|Should -BeExactly 'Bearer';$handler.CanCancel|Should -BeTrue
            $body=$handler.Body|ConvertFrom-Json -AsHashtable
            $body.properties.mode|Should -BeExactly 'Incremental'
            $body.properties.parameters.location.value|Should -BeExactly 'westus2'
            $handler.Body|Should -Not -Match ('x'*64)
            $handler.Probe.Reads|Should -Be 0;$handler.Probe.Disposed|Should -BeTrue
        }
        It 'never retries failed or cancelled sends or exposes raw errors' -ForEach @(@{fault='Fail'},@{fault='Cancel'}) {
            $plan=New-SantaBackupStoreDeploymentPlan @script:argsForPlan
            $handler=[SantaStoreTransportFixture.Handler]::new();$handler.$fault=$true
            try {Send-StoreDeployment $plan @{} @{parameters=@{}} ('x'*64) $handler;throw 'unexpected success'}
            catch {$_.Exception.Message|Should -Match 'unknown';$_.Exception.Message|Should -Not -Match 'private-sentinel|unexpected success'}
            $handler.Calls|Should -Be 1
        }
        It 'rejects malformed selected URI or credential before SendAsync' {
            $plan=New-SantaBackupStoreDeploymentPlan @script:argsForPlan;$plan.deploymentName='bad?redirect=foreign'
            $handler=[SantaStoreTransportFixture.Handler]::new()
            {Send-StoreDeployment $plan @{} @{parameters=@{}} ('x'*64) $handler}|Should -Throw
            $handler.Calls|Should -Be 0;$handler.Dispose()
        }
        It 'reads only selected cached token, validates returned authority/expiry and never changes account' -ForEach @(
            @{fault='none'},@{fault='tenant'},@{fault='subscription'},@{fault='expiry'},@{fault='format'},@{fault='context'}
        ) {
            $plan=New-SantaBackupStoreDeploymentPlan @script:argsForPlan
            $script:fault=$fault;$script:accounts=0
            $script:context=@{id=$plan.selection.SubscriptionId;tenantId=$plan.selection.TenantId;state='Enabled';environmentName='AzureCloud'}
            $script:token=@{tenant=$plan.selection.TenantId;subscription=$plan.selection.SubscriptionId;tokenType='Bearer'
                expires_on=([DateTimeOffset]::UtcNow.ToUnixTimeSeconds()+3600);accessToken=('x'*64)}
            if($fault -in @('tenant','subscription')){$script:token[$fault]='wrong'}
            if($fault -eq 'expiry'){$script:token.expires_on=0}
            if($fault -eq 'format'){$script:token.accessToken="bad`r`nheader"}
            Mock Invoke-StoreAzure {
                param($Arguments)
                $Arguments[0]|Should -BeExactly 'account';$Arguments|Should -Contain '--subscription';$Arguments|Should -Not -Contain '--tenant'
                if($Arguments[1] -eq 'get-access-token'){$Arguments|Should -Contain 'https://management.azure.com/';return $script:token}
                $script:accounts++
                if($script:fault -eq 'context' -and $script:accounts -gt 1){return @{changed=$true}}
                $script:context
            }
            $digest=Store-Hash (Store-Json $script:context)
            if($fault -eq 'none'){Get-StoreSubmissionToken $plan $digest|Should -BeExactly ('x'*64)}
            else{{Get-StoreSubmissionToken $plan $digest}|Should -Throw}
        }
    }
}
