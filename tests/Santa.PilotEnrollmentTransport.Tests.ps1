#Requires -Version 7.6
BeforeDiscovery{Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'experiments/server/PilotEnrollmentTransport.psm1') -Force}
Describe 'One bound recipient-sealed pilot profile export'{
 InModuleScope PilotEnrollmentTransport {
  BeforeAll{
   $script:binding=@{TenantId='22222222-2222-4222-8222-222222222222';SubscriptionId='11111111-1111-4111-8111-111111111111';EnvironmentName='synthetic';ResourceGroup='rg-azd-santa-vm-synthetic';VmName='vm-santa-lab';VmId='/subscriptions/11111111-1111-4111-8111-111111111111/resourceGroups/rg-azd-santa-vm-synthetic/providers/Microsoft.Compute/virtualMachines/vm-santa-lab';VmInstanceId='33333333-3333-4333-8333-333333333333';ImageId='sha256:'+('a'*64);ComposePath='/var/lib/azd-santa-qualification/runtime/compose.json';ComposeSha256='b'*64;Origin='https://santa-test.westus2.cloudapp.azure.com'}
   function Synthetic-Envelope($request,$enrollment){
    $digest=Pilot-Hash (Pilot-Json $enrollment)
    $python=if($env:SANTA_CRYPTO_PYTHON){$env:SANTA_CRYPTO_PYTHON}else{'python'}
    $fixture=$script:output+'.boundary.json'
    [IO.File]::WriteAllText($fixture,(@{enrollment=$enrollment;setup=$request.PayloadBase64;expected=$digest}|ConvertTo-Json -Depth 12 -Compress))
    $source=Join-Path $PSScriptRoot '../experiments/server'
    $code='import sys,json,base64,hashlib;from pathlib import Path;sys.path.insert(0,sys.argv[2]);import pilot_enrollment as worker;p=json.loads(Path(sys.argv[1]).read_text());b=json.loads(base64.b64decode(p["setup"]))["context"]["binding"];assert hashlib.sha256(worker.canonical(b)).hexdigest()==p["enrollment"]["deployment_sha256"];digest,_=worker.validate(p["enrollment"]);assert digest==p["expected"];print("canonical-bound")'
    $checked=& $python -c $code $fixture $source
    $LASTEXITCODE|Should -Be 0;$checked|Should -BeExactly 'canonical-bound'
    $program=New-PilotEnrollmentProgram $request $enrollment create
    $match=[regex]::Match($program,"(?s)python3 -I - <<'PILOT_HOST'\r?\n(?<body>.*)\r?\nPILOT_HOST")
    $match.Success|Should -BeTrue
    [IO.File]::WriteAllText($fixture,$match.Groups['body'].Value)
    & $python -c 'import sys;from pathlib import Path;compile(Path(sys.argv[1]).read_text(),"bound_host","exec")' $fixture
    $LASTEXITCODE|Should -Be 0

    $plain=[Text.Encoding]::UTF8.GetBytes((@{context_sha256=$digest;secret='synthetic_secret_never_real';configuration_id=17;enrollment_id=23}|ConvertTo-Json -Compress))
    $cipher=$request.Recipient.Key.Encrypt($plain,[Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
    @{scope='azd-santa-pilot-enrollment-v1';context_sha256=$digest;recipient_sha256=$request.Recipient.KeyId;configuration_id=17;enrollment_id=23;ciphertext_base64=[Convert]::ToBase64String($cipher)}|ConvertTo-Json -Compress
   }
  }
  BeforeEach{
   $script:output=Join-Path $TestDrive ([guid]::NewGuid().ToString('N')+'.mobileconfig')
   $script:pilotArguments=@{Binding=$script:binding;Account='operator@example.test';Serial='C02GF7BBQ6L4';HardwareUuid='E4C44AEC-8B94-5686-988A-835DB7BDB6C1';OperatorUsername='existing-admin';OperatorEmail='existing@example.test';PrivateOutputPath=$script:output}
   Mock Invoke-SantaEndpointAzJson -ModuleName HttpsEndpoint {param($Arguments)
    switch($Arguments[0]){
     account {@{id='11111111-1111-4111-8111-111111111111';tenantId='22222222-2222-4222-8222-222222222222';state='Enabled';environmentName='AzureCloud';user=@{name='operator@example.test';type='user'}}}
     group {@{id='/subscriptions/'+'11111111-1111-4111-8111-111111111111'+'/resourceGroups/'+'rg-azd-santa-vm-synthetic';tags=@{'azd-solution'='azd-santa';purpose='synthetic-vm-lab';'azd-env-name'='synthetic'}}}
     vm {@{id='/subscriptions/11111111-1111-4111-8111-111111111111/resourceGroups/rg-azd-santa-vm-synthetic/providers/Microsoft.Compute/virtualMachines/vm-santa-lab';vmId='33333333-3333-4333-8333-333333333333';provisioningState='Succeeded';tags=@{'azd-solution'='azd-santa';purpose='synthetic-vm-lab';'azd-env-name'='synthetic'}}}
     default {throw 'Unexpected CLI'}
    }
   }
   Mock Pilot-Read {param($Arguments) & $script:cli {param($a) Invoke-SantaEndpointAzJson -Arguments $a} $Arguments}
   Mock Invoke-SantaEndpointProcess -ModuleName HttpsEndpoint {throw 'Offline process tripwire'}
   Mock Invoke-SantaSetupAzJson -ModuleName SetupTransport {throw 'Legacy reader tripwire'}
   Mock Send-PilotEnrollment {param($SetupRequest,$Enrollment,$Operation)
    Test-Path ($script:output+'.intent.json')|Should -BeTrue
    Synthetic-Envelope $SetupRequest $Enrollment
   }
  }
  It 'defaults to no cloud, files, request key or enrollment attempt'{
   (Invoke-SantaPilotEnrollment @script:pilotArguments).cloudWrite|Should -BeFalse
   Should -Invoke Pilot-Read -Times 0;Should -Invoke Send-PilotEnrollment -Times 0
   Test-Path $script:output|Should -BeFalse;Test-Path ($script:output+'.intent.json')|Should -BeFalse
  }
  It 'exports a full Monitor baseline preserving IDs and static rules with only two added keys'{
   $result=Invoke-SantaPilotEnrollment @script:pilotArguments -Action Create
   $result.profileExported|Should -BeTrue;$result.deviceDeliveryProven|Should -BeFalse
   $text=[IO.File]::ReadAllText($script:output);[xml]$xml=$text
   $xml.SelectSingleNode("/plist/dict/key[.='PayloadUUID']/following-sibling::*[1]").InnerText|Should -BeExactly '4D0DFE79-A7B0-4D0E-91AF-B9C7286DE299'
   $xml.SelectSingleNode("/plist/dict/array/dict/key[.='ClientMode']/following-sibling::*[1]").InnerText|Should -BeExactly '1'
   $xml.SelectSingleNode("/plist/dict/array/dict/key[.='SyncBaseURL']/following-sibling::*[1]").InnerText|Should -BeExactly ($script:binding.Origin+'/public/santa/sync/')
   $xml.SelectSingleNode("/plist/dict/array/dict/key[.='SyncExtraHeaders']/following-sibling::dict/key[.='Zentral-Authorization']/following-sibling::string").InnerText|Should -BeExactly 'Bearer synthetic_secret_never_real'
   $xml.SelectNodes("/plist/dict/array/dict/key[.='StaticRules']/following-sibling::array/dict").Count|Should -Be 7
   foreach($path in @(($script:output+'.intent.json'),($script:output+'.sealed.json'))){[IO.File]::ReadAllText($path)|Should -Not -Match 'synthetic_secret_never_real|Bearer '}
   Should -Invoke Send-PilotEnrollment -Times 1 -Exactly -ParameterFilter{$Operation -ceq 'create'}
   {Invoke-SantaPilotEnrollment @script:pilotArguments -Action Create}|Should -Throw
   Should -Invoke Send-PilotEnrollment -Times 1 -Exactly
  }
  It 'uses same in-memory recipient/request for explicit observe after unknown, never a second create'{
   $script:first=$null
   Mock Send-PilotEnrollment {param($SetupRequest,$Enrollment,$Operation)
    if($Operation -ceq 'create'){$script:first=$SetupRequest;throw 'synthetic uncertainty'}
    [object]::ReferenceEquals($SetupRequest,$script:first)|Should -BeTrue
    Synthetic-Envelope $SetupRequest $Enrollment
   }
   (Invoke-SantaPilotEnrollment @script:pilotArguments -Action Create -ReadbackOnUnknown).profileExported|Should -BeTrue
   Should -Invoke Send-PilotEnrollment -Times 1 -Exactly -ParameterFilter{$Operation -ceq 'create'}
   Should -Invoke Send-PilotEnrollment -Times 1 -Exactly -ParameterFilter{$Operation -ceq 'observe'}
  }
  It 'retains intent on unknown and rejects plaintext/error/cross-context responses without profile'{
   Mock Send-PilotEnrollment {throw 'private-canary'}
   try{Invoke-SantaPilotEnrollment @script:pilotArguments -Action Create;throw 'unexpected'}catch{$_.Exception.Message|Should -Not -Match 'private-canary|unexpected'}
   Test-Path ($script:output+'.intent.json')|Should -BeTrue;Test-Path $script:output|Should -BeFalse
   Should -Invoke Send-PilotEnrollment -Times 1 -Exactly
  }
  It 'does not persist an unvalidated response containing plaintext extra fields' {
   Mock Send-PilotEnrollment { '{"secret":"plaintext-canary"}' }
   {Invoke-SantaPilotEnrollment @script:pilotArguments -Action Create}|Should -Throw
   Test-Path ($script:output+'.intent.json')|Should -BeTrue
   Test-Path ($script:output+'.sealed.json')|Should -BeFalse
   Test-Path $script:output|Should -BeFalse
   [IO.File]::ReadAllText($script:output+'.intent.json')|Should -Not -Match 'plaintext-canary'
  }
  It 'rejects an existing output before any cloud request'{
   [IO.File]::WriteAllText($script:output,'retained')
   {Invoke-SantaPilotEnrollment @script:pilotArguments -Action Create}|Should -Throw
   [IO.File]::ReadAllText($script:output)|Should -BeExactly 'retained';Should -Invoke Pilot-Read -Times 0
  }
  It 'rejects a different cached principal before reserving or creating'{
   $script:pilotArguments.Account='someone-else@example.test'
   {Invoke-SantaPilotEnrollment @script:pilotArguments -Action Create}|Should -Throw
   Test-Path ($script:output+'.intent.json')|Should -BeFalse;Should -Invoke Send-PilotEnrollment -Times 0
  }
  It 'rejects tampered context, IDs, recipient and extra plaintext fields with real OAEP' {
   $key=[Security.Cryptography.RSA]::Create(3072)
   try {
    $public=$key.ExportSubjectPublicKeyInfo();$recipient=[pscustomobject]@{Key=$key;KeyId=[Convert]::ToHexStringLower([Security.Cryptography.SHA256]::HashData($public))}
    $request=[pscustomobject]@{Recipient=$recipient};$enrollment=@{nonce='a'*32};$digest=Pilot-Hash (Pilot-Json $enrollment)
    $plain=[Text.Encoding]::UTF8.GetBytes((@{context_sha256=$digest;secret='synthetic_secret_never_real';configuration_id=17;enrollment_id=23}|ConvertTo-Json -Compress))
    $cipher=$key.Encrypt($plain,[Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
    $original=@{scope='azd-santa-pilot-enrollment-v1';context_sha256=$digest;recipient_sha256=$recipient.KeyId;configuration_id=17;enrollment_id=23;ciphertext_base64=[Convert]::ToBase64String($cipher)}
    $baseline=[IO.File]::ReadAllBytes((Join-Path $PSScriptRoot '../profiles/generated/40-configuration.mobileconfig'))
    foreach($change in @(@{context_sha256='0'*64},@{recipient_sha256='0'*64},@{enrollment_id=24},@{secret='plaintext-canary'})) {
     $value=@{}+$original;foreach($k in $change.Keys){$value[$k]=$change[$k]}
     {[SantaPilot.Profile]::Receive(($value|ConvertTo-Json -Compress),$digest,$recipient.KeyId,$key,$baseline,$script:binding.Origin)}|Should -Throw
    }
    [xml]$custom=[Text.Encoding]::UTF8.GetString($baseline);$root=$custom.SelectSingleNode('/plist/dict');$anchor=$root.FirstChild
    $metadataKey=$custom.CreateElement('key');$metadataKey.InnerText='Metadata';$metadata=$custom.CreateElement('array');$metadata.InnerXml='<dict><key>marker</key><string>retain</string></dict>'
    $null=$root.InsertBefore($metadataKey,$anchor);$null=$root.InsertBefore($metadata,$anchor)
    $received=[SantaPilot.Profile]::Receive(($original|ConvertTo-Json -Compress),$digest,$recipient.KeyId,$key,[Text.Encoding]::UTF8.GetBytes($custom.OuterXml),$script:binding.Origin)
    [xml]$verified=[Text.Encoding]::UTF8.GetString($received)
    $verified.SelectSingleNode("/plist/dict/key[.='Metadata']/following-sibling::array[1]/dict/key[.='SyncBaseURL']")|Should -BeNullOrEmpty
    $verified.SelectSingleNode("/plist/dict/key[.='PayloadContent']/following-sibling::array[1]/dict/key[.='SyncBaseURL']")|Should -Not -BeNullOrEmpty
   } finally{$key.Dispose()}
  }
  It 'passes controlled Python host ordering, binding, source and no-plaintext boundaries' {
   $python=if($env:SANTA_CRYPTO_PYTHON){$env:SANTA_CRYPTO_PYTHON}else{'python'}
   $result=& $python -m unittest discover -s $PSScriptRoot -p test_pilot_enrollment_host.py 2>&1
   $LASTEXITCODE|Should -Be 0 -Because ($result -join "`n")
  }
  It 'binds compressed source and attestation only, keeps complete packet bounded'{
   $bound=@{}+$script:binding;$bound.RemoteProgramSha256=(Get-FileHash (Join-Path $PSScriptRoot '../experiments/server/operator_setup_host.py')).Hash.ToLowerInvariant()
   $setup=[pscustomobject]@{Binding=$bound;PayloadBase64='e30='}
   $enrollment=@{nonce='a'*32}
   $program=New-PilotEnrollmentProgram $setup $enrollment create
   [Text.Encoding]::UTF8.GetByteCount($program)|Should -BeLessOrEqual 65536
   $program|Should -Not -Match 'operator_access|run_setup|create_operator'
  }
 }
}
