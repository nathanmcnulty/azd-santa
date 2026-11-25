#Requires -Version 7.6
# Original Unlicense. One explicit enrollment attempt, no credential console output.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$script:setup=Import-Module (Join-Path $PSScriptRoot 'SetupTransport.psm1') -Force -PassThru
$script:files=Import-Module (Join-Path $PSScriptRoot 'SealedSetup.psm1') -Force -PassThru
$script:cli=Import-Module (Join-Path $PSScriptRoot 'HttpsEndpoint.psm1') -Force -PassThru
if(-not ('SantaPilot.Profile' -as [type])){Add-Type -Path (Join-Path $PSScriptRoot 'PilotEnrollmentProfile.cs')}
function Pilot-Hash([string]$Text){[Convert]::ToHexStringLower([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($Text)))}
function Pilot-Json([Collections.IDictionary]$Value){$ordered=[ordered]@{};[string[]]$keys=@($Value.Keys);[Array]::Sort($keys,[StringComparer]::Ordinal);foreach($key in $keys){$ordered[$key]=$Value[$key]};$ordered|ConvertTo-Json -Compress -EscapeHandling EscapeNonAscii}
function Pilot-Read([string[]]$Arguments){& $script:cli {param($a) Invoke-SantaEndpointAzJson -Arguments $a -TimeoutSeconds 300} $Arguments}
function Pilot-Compressed([string]$Path){
 $bytes=[IO.File]::ReadAllBytes($Path);if($bytes.Length -gt 65536){throw 'Enrollment source bound rejected.'}
 $stream=[IO.MemoryStream]::new();$gzip=[IO.Compression.GZipStream]::new($stream,[IO.Compression.CompressionLevel]::Optimal,$true)
 try{$gzip.Write($bytes)}finally{$gzip.Dispose()};try{[Convert]::ToBase64String($stream.ToArray())}finally{$stream.Dispose()}
}
function New-PilotEnrollmentProgram($SetupRequest,[hashtable]$Enrollment,[string]$Operation){
 if($Operation -cnotin @('create','observe')){throw 'Enrollment operation rejected.'}
 $attestor=Join-Path $PSScriptRoot 'operator_setup_host.py';$worker=Join-Path $PSScriptRoot 'pilot_enrollment.py';$hostProgram=Join-Path $PSScriptRoot 'pilot_enrollment_host.py'
 $context=@{attestor=(Pilot-Compressed $attestor);attestor_sha256=(Get-FileHash $attestor).Hash.ToLowerInvariant();worker=(Pilot-Compressed $worker);worker_sha256=(Get-FileHash $worker).Hash.ToLowerInvariant();setup_request=$SetupRequest.PayloadBase64;enrollment=$Enrollment;operation=$Operation}
 if($SetupRequest.Binding.RemoteProgramSha256 -cne $context.attestor_sha256){throw 'Host attestor source differs.'}
 $data=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($context|ConvertTo-Json -Depth 8 -Compress)))
 $body=Pilot-Compressed $hostProgram;$digest=(Get-FileHash $hostProgram).Hash.ToLowerInvariant()
 $program=@"
set -eu
python3 -I - <<'PILOT_HOST'
import base64,gzip,hashlib,io,json,sys,types
def unique(pairs):
 result={}
 for key,value in pairs:
  if key in result:raise ValueError('Duplicate field')
  result[key]=value
 return result
try:
 with gzip.GzipFile(fileobj=io.BytesIO(base64.b64decode('$body',validate=True))) as f: source=f.read(65537)
 assert len(source)<=65536 and hashlib.sha256(source).hexdigest()=='$digest'
 host=types.ModuleType('selected_pilot_host');exec(compile(source,'pilot_enrollment_host.py','exec'),host.__dict__)
 host.run(json.loads(base64.b64decode('$data',validate=True),object_pairs_hook=unique))
except BaseException:
 sys.stderr.write('Pilot transport failed or unknown; preserve intent.\n');sys.exit(1)
PILOT_HOST
"@
 if([Text.Encoding]::UTF8.GetByteCount($program) -gt 65536){throw 'Enrollment transport exceeds packet bound.'};$program
}
function Send-PilotEnrollment($SetupRequest,[hashtable]$Enrollment,[string]$Operation){
 $program=New-PilotEnrollmentProgram $SetupRequest $Enrollment $Operation
 $path=Join-Path ([IO.Path]::GetTempPath()) ('santa-pilot-'+[guid]::NewGuid().ToString('N')+'.sh')
 try{
  & $script:files {param($p,$b) Write-SantaPrivateBytes $p $b} $path ([Text.Encoding]::UTF8.GetBytes($program))
  $b=$SetupRequest.Binding
  $result=Pilot-Read @('vm','run-command','invoke','--subscription',$b.SubscriptionId,'--resource-group',$b.ResourceGroup,'--name',$b.VmName,'--command-id','RunShellScript','--scripts',('@'+$path))
  & $script:setup {param($r,$n) Read-SantaRunCommandPayload -Result $r -Context $n -Marker 'SANTA_PILOT_ENVELOPE:' -DoneMarker 'SANTA_PILOT_DONE:' -MaximumBytes 4096} $result (Pilot-Hash (Pilot-Json $Enrollment))
 }finally{if([IO.File]::Exists($path)){[IO.File]::Delete($path)}}
}
function Invoke-SantaPilotEnrollment{
 [CmdletBinding()]
 param([Parameter(Mandatory)][hashtable]$Binding,[Parameter(Mandatory)][string]$Account,
  [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9]{8,32}$')][string]$Serial,
  [Parameter(Mandatory)][guid]$HardwareUuid,[Parameter(Mandatory)][string]$OperatorUsername,[Parameter(Mandatory)][string]$OperatorEmail,
  [Parameter(Mandatory)][string]$PrivateOutputPath,[ValidateSet('Plan','Create')][string]$Action='Plan',[switch]$ReadbackOnUnknown)
 $stage='Input'; $submission='NoCreateSubmitted'
 $request=$null;$profile=$null
 try{
  & $script:setup {param($b) Assert-SantaSetupBinding $b} $Binding
  if($HardwareUuid -eq [guid]::Empty -or $OperatorUsername -cnotmatch '^[A-Za-z0-9@.+_-]{1,150}$' -or $Account -cnotmatch '^[A-Za-z0-9@.+_-]{1,254}$'){throw 'Exact selected identity required.'}
  $baseline=[IO.File]::ReadAllBytes((Join-Path $PSScriptRoot '../../profiles/generated/40-configuration.mobileconfig'))
  [SantaPilot.Profile]::CheckBaseline($baseline,$Binding.Origin)
  $PrivateOutputPath=[IO.Path]::GetFullPath($PrivateOutputPath);$intent=$PrivateOutputPath+'.intent.json';$sealed=$PrivateOutputPath+'.sealed.json'
  foreach($p in @($PrivateOutputPath,$intent,$sealed)){& $script:files {param($v) Assert-SantaPrivateDestination $v} $p}
  if($Action -ceq 'Plan'){return @{scope='santa-pilot-enrollment-plan-v1';cloudWrite=$false;profileExported=$false}}
  $bound=@{}+$Binding
  $bound.RemoteProgramSha256=(Get-FileHash (Join-Path $PSScriptRoot 'operator_setup_host.py')).Hash.ToLowerInvariant()
  $bound.SourceCommit=(Get-Content (Join-Path $PSScriptRoot 'zentral-source.lock.json') -Raw|ConvertFrom-Json).commit
  foreach($pair in @(@('AdmissionSha256','santa_admission.py'),@('RecoverySha256','operator_recovery.py'),@('SealedSha256','sealed_setup.py'))){$bound[$pair[0]]=Pilot-Hash ([IO.File]::ReadAllText((Join-Path $PSScriptRoot $pair[1])).Replace("`r`n","`n"))}
  $request=New-SantaSetupTransportRequest -Binding $bound -Mode bootstrap -Username $OperatorUsername -Email $OperatorEmail -Reason 'Read-only pilot enrollment attestation'
  $stage='CachedIdentity'
  $context=Pilot-Read @('account','show','--subscription',$bound.SubscriptionId)
  if($context.id -cne $bound.SubscriptionId -or $context.state -cne 'Enabled' -or $context.tenantId -cne $bound.TenantId -or $context.user.type -cne 'user' -or $context.user.name -cne $Account -or $context.environmentName -cne 'AzureCloud'){throw 'Selected cached account differs.'}
  $stage='TargetRead'
  $reader=${function:Pilot-Read}
  & $script:setup {param($r,$read) Assert-SantaSetupAzureTarget $r -ReadAzure $read} $request $reader
  $enrollment=[ordered]@{deployment_sha256=(Pilot-Hash (Pilot-Json $request.Binding));hardware_uuid=$HardwareUuid.ToString().ToUpperInvariant();nonce=[guid]::NewGuid().ToString('N');operator_username=$OperatorUsername;origin=$bound.Origin;recipient_public_key=$request.Recipient.PublicKeyBase64;scope='azd-santa-pilot-enrollment-v1';serial=$Serial;source_commit=$bound.SourceCommit}
  $digest=Pilot-Hash (Pilot-Json $enrollment)
  $stage='CachedIdentityRecheck'
  if(($context|ConvertTo-Json -Depth 16 -Compress) -cne ((Pilot-Read @('account','show','--subscription',$bound.SubscriptionId))|ConvertTo-Json -Depth 16 -Compress)){throw 'Selected account drift.'}
  $stage='Intent'
  & $script:files {param($p,$b) Write-SantaPrivateBytes $p $b} $intent ([Text.Encoding]::UTF8.GetBytes((@{scope='one-pilot-enrollment-attempt-v1';context_sha256=$digest;binding=$request.Binding;request=$enrollment}|ConvertTo-Json -Depth 8 -Compress)))
  $stage='Create'; $submission='CreateMayHaveStarted'
  try{$envelope=Send-PilotEnrollment $request $enrollment create}catch{if(-not $ReadbackOnUnknown){throw};$stage='Observe';$envelope=Send-PilotEnrollment $request $enrollment observe}
  $stage='EnvelopeReadback'
  $profile=[SantaPilot.Profile]::Receive($envelope,$digest,$request.Recipient.KeyId,$request.Recipient.Key,$baseline,$bound.Origin)
  $submission='CreateVerified'; $stage='PrivateExport'
  & $script:files {param($p,$b) Write-SantaPrivateBytes $p $b} $sealed ([Text.Encoding]::UTF8.GetBytes($envelope))
  & $script:files {param($p,$b) Write-SantaPrivateBytes $p $b} $PrivateOutputPath $profile
  @{scope='santa-pilot-enrollment-export-v1';profileExported=$true;privateOutputPath=$PrivateOutputPath;deviceDeliveryProven=$false;monitor=$true}
 } catch {
  $guidance = if ($submission -eq 'NoCreateSubmitted') { 'Check the named stage. Preserve any existing checkpoint.' }
      else { 'Preserve the local intent and any ciphertext. Do not replay Create.' }
  throw "SantaEnrollment.${stage}.${submission}: $guidance"
 }
 finally{if($profile){[Array]::Clear($profile,0,$profile.Length)};if($request){$request.Recipient.Key.Dispose()}}
}
Export-ModuleMember -Function Invoke-SantaPilotEnrollment
