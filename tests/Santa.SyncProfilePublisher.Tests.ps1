#Requires -Version 7.6
BeforeAll {
    $root=Split-Path $PSScriptRoot -Parent
    Import-Module "$root/scripts/Santa.SyncProfilePublisher.psm1" -Force
    # Closed command metadata stubs: tests never require or contact Graph.
    & (Get-Module Santa.SyncProfilePublisher) {
        function script:Get-MgContext { [CmdletBinding()]param();throw 'Unmocked Graph context' }
        function script:Get-MgRequestContext { [CmdletBinding()]param();throw 'Unmocked Graph settings' }
        function script:Set-MgRequestContext { [CmdletBinding(SupportsShouldProcess)]param($MaxRetry,$ClientTimeout);throw 'Unmocked Graph settings' }
        function script:Invoke-MgGraphRequest { [CmdletBinding()]param($Method,$Uri,$OutputType,$Body,$ContentType,$Headers);throw 'Unmocked Graph request' }
    }
}
Describe 'Single owned sync profile publisher (offline)' {
    BeforeEach {
        $caseDir=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory $caseDir
        $script:target=@{tenant='11111111-1111-4111-8111-111111111111';account='operator@example.invalid';group='22222222-2222-4222-8222-222222222222';groupName='Pilot';deviceObject='44444444-4444-4444-8444-444444444444';device='55555555-5555-4555-8555-555555555555';deviceName='Pilot Mac';configuration='33333333-3333-4333-8333-333333333333'}
        $script:baseline=Get-Content "$root/profiles/generated/40-configuration.mobileconfig" -Raw
        $script:remoteText=$script:baseline.Replace('Contoso','PilotOrg').Replace('com.contoso','com.pilot')
        $script:remote=@{id=$script:target.configuration;'@odata.type'='#microsoft.graph.macOSCustomConfiguration';displayName='Owned configuration';description='[azd-santa:2026.8:configuration] Template-owned Intune profile.';payloadName='40-configuration.mobileconfig';payload=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($script:remoteText))}
        $script:receipt=@{schemaVersion='1.0';tenantId=$script:target.tenant;account=$script:target.account;release='2026.8';pilotGroup=@{id=$script:target.group;displayName='Pilot';memberId=$script:target.deviceObject;memberDisplayName='Pilot Mac'};package=@{status='unknown'};profiles=@(foreach($i in 0..4){@{id=@('system-extension','tcc','service-management','configuration','notifications')[$i];objectId=if($i -eq 3){$script:target.configuration}else{'66666666-6666-4666-8666-66666666666'+$i};displayName=if($i -eq 3){'Owned configuration'}else{'Other'+$i};action='verify';assignmentGroupId=$script:target.group}})}
        $script:receiptPath=Join-Path $caseDir 'receipt.json'; $script:receipt|ConvertTo-Json -Depth 12|Set-Content $script:receiptPath
        $script:providerPath=Join-Path $caseDir 'provider.mobileconfig'
        $providerText=(Get-Content "$PSScriptRoot/fixtures/provider-plan/synthetic.mobileconfig" -Raw).Replace('https://synthetic-provider.invalid/santa/','https://santa.example.invalid/public/santa/sync/').Replace('<key>Authorization</key>','<key>Zentral-Authorization</key>').Replace('Bearer SYNTHETIC-CANARY-NOT-A-CREDENTIAL',('Bearer '+('A'*64)))
        Set-Content $script:providerPath $providerText
        $script:reviewPath=Join-Path $caseDir 'review.txt';'Source review only, not native acceptance.'|Set-Content $script:reviewPath
        $script:qualification=@{schemaVersion='1.0';clientVersion='2026.8.244';clientSourceCommit='dbe97b0aa0f5929feece5f4cbd2c69362c271abc';providerRevision='88e67b3ce49033aab028029937a6e14f7c489073';protocol='public-v1-json';authMode='header-token';authHeaderName='Zentral-Authorization';secretReferenceId='private-reference';profileSha256=(Get-FileHash $script:providerPath).Hash.ToLowerInvariant();baselineSha256=(Get-FileHash "$root/profiles/generated/40-configuration.mobileconfig").Hash.ToLowerInvariant();reviewEvidenceSha256=(Get-FileHash $script:reviewPath).Hash.ToLowerInvariant();evidenceKind='offline-source-review';configurationDisposition='replace-owned-preserve-baseline'}
        $script:qualPath=Join-Path $caseDir 'qualification.json';$script:qualification|ConvertTo-Json|Set-Content $script:qualPath
        $script:params=@{Action='Apply';ExpectedTenantId=$script:target.tenant;ExpectedAccount=$script:target.account;ExpectedGroupId=$script:target.group;ExpectedGroupDisplayName='Pilot';ExpectedDeviceObjectId=$script:target.deviceObject;ExpectedDeviceId=$script:target.device;ExpectedDeviceName='Pilot Mac';ExpectedConfigurationObjectId=$script:target.configuration;OwnedReceiptPath=$script:receiptPath;ProviderProfilePath=$script:providerPath;QualificationPath=$script:qualPath;ReviewEvidencePath=$script:reviewPath;ExpectedSyncOrigin='https://santa.example.invalid';ExpectedCurrentProfileSha256=[Convert]::ToHexStringLower([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($script:remoteText)));CheckpointPath=(Join-Path $caseDir 'intent.json')}
        $script:badMode='';$script:patches=0;$script:paginated=$false;$script:wrongDevice=$false;$script:failPatch=$false;$script:drift=$false;$script:reads=0
        Mock Get-MgContext -ModuleName Santa.SyncProfilePublisher { [pscustomobject]@{TenantId=$script:target.tenant;Account=$script:target.account;AuthType='Delegated';Environment='Global';TokenCredentialType='InteractiveBrowser';Scopes=@('DeviceManagementConfiguration.ReadWrite.All','Group.Read.All','Device.Read.All')} }
        Mock Get-MgRequestContext -ModuleName Santa.SyncProfilePublisher { [pscustomobject]@{MaxRetry=3;ClientTimeout=[TimeSpan]::FromSeconds(300)} }
        Mock Set-MgRequestContext -ModuleName Santa.SyncProfilePublisher { }
        Mock Invoke-MgGraphRequest -ModuleName Santa.SyncProfilePublisher {
            if($Method -eq 'PATCH') {
                Test-Path $script:params.CheckpointPath | Should -BeTrue
                $Uri | Should -BeExactly "/v1.0/deviceManagement/deviceConfigurations/$($script:target.configuration)"
                $b=ConvertFrom-Json $Body -AsHashtable;($b.Keys|Sort-Object)-join ','|Should -Be '@odata.type,payload,payloadName';$b['@odata.type']|Should -BeExactly '#microsoft.graph.macOSCustomConfiguration'
                $script:patches++;if($script:failPatch){throw ('SECRET-CANARY '+('A'*64))};$script:remote.payload=$b.payload;return
            }
            if($script:badMode -eq 'assignments' -and $Uri -match '/assignments$'){return @{value=@();'@odata.nextLink'='https://graph.microsoft.com/next'}}
            if($script:badMode -eq 'dynamic' -and $Uri -match '/groups/.+\?' -and $Uri -notmatch '/members'){return @{id=$script:target.group;displayName='Pilot';securityEnabled=$true;mailEnabled=$false;groupTypes=@('DynamicMembership');membershipRule='rule'}}
            if($script:badMode -eq 'two_members' -and $Uri -match '/members\?'){return @{value=@(@{},@{})}}
            if($Uri -match '/members\?') {return @{value=@(@{'@odata.type'='#microsoft.graph.device';id=$script:target.deviceObject;deviceId=if($script:wrongDevice){[guid]::Empty.ToString()}else{$script:target.device};displayName='Pilot Mac';operatingSystem='MacMDM'});'@odata.nextLink'=if($script:paginated){'https://graph.microsoft.com/next'}else{$null}}|ForEach-Object{if(-not $script:paginated){$_.Remove('@odata.nextLink')};$_}}
            if($Uri -match '/groups/.+\?') {return @{id=$script:target.group;displayName='Pilot';securityEnabled=$true;mailEnabled=$false;groupTypes=@();membershipRule=$null}}
            if($Uri -match '/devices/') {return @{id=$script:target.deviceObject;deviceId=$script:target.device;displayName='Pilot Mac';operatingSystem='MacMDM'}}
            if($Uri -match '/assignments$') {return @{value=@(@{id='assignment';target=@{'@odata.type'='#microsoft.graph.groupAssignmentTarget';groupId=$script:target.group}})}}
            if($Uri -match 'deviceConfigurations\?') {return @{value=@(@{id=$script:remote.id;displayName=$script:remote.displayName;description=$script:remote.description})}}
            if($Uri -match 'deviceConfigurations/') {$script:reads++;if($script:drift -and $script:reads -eq 2){$script:remote.payload=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($script:remoteText+'<!--changed-->'))};return $script:remote}
            throw 'Unexpected request'
        }
    }
    It 'is disabled without reading inputs or requesting context' {
        (Invoke-SantaIntuneSyncProfile).state|Should -Be 'disabled'
        Should -Invoke Get-MgContext -ModuleName Santa.SyncProfilePublisher -Times 0
        Should -Invoke Invoke-MgGraphRequest -ModuleName Santa.SyncProfilePublisher -Times 0
    }
    It 'rejects mismatched cached identity, missing scope or DeviceCode before changing SDK settings' -ForEach @('tenant','account','credential','scope') {
        $script:badContext=$_
        Mock Get-MgContext -ModuleName Santa.SyncProfilePublisher {
            $c=[pscustomobject]@{TenantId=$script:target.tenant;Account=$script:target.account;AuthType='Delegated';Environment='Global';TokenCredentialType='InteractiveBrowser';Scopes=@('DeviceManagementConfiguration.ReadWrite.All','Group.Read.All','Device.Read.All')}
            switch($script:badContext){tenant{$c.TenantId=[guid]::Empty.ToString()} account{$c.Account='other@example.invalid'} credential{$c.TokenCredentialType='DeviceCode'} scope{$c.Scopes=@('Group.Read.All')}}
            $c
        }
        {Invoke-SantaIntuneSyncProfile @script:params}|Should -Throw '*SantaSync.*'
        Should -Invoke Set-MgRequestContext -ModuleName Santa.SyncProfilePublisher -Times 0
        Should -Invoke Invoke-MgGraphRequest -ModuleName Santa.SyncProfilePublisher -Times 0
    }
    It 'inspects the immutable target read-only and restores SDK settings' {
        $script:params.Action='Inspect';$result=Invoke-SantaIntuneSyncProfile @script:params
        $result.currentProfileSha256|Should -Be $script:params.ExpectedCurrentProfileSha256
        $script:patches|Should -Be 0
        Should -Invoke Set-MgRequestContext -ModuleName Santa.SyncProfilePublisher -Times 1 -ParameterFilter {$MaxRetry -eq 0 -and $ClientTimeout -eq 30}
        Should -Invoke Set-MgRequestContext -ModuleName Santa.SyncProfilePublisher -Times 1 -ParameterFilter {$MaxRetry -eq 3 -and $ClientTimeout -eq 300}
    }
    It 'patches exactly once, preserving actual profile metadata and every baseline setting' {
        $result=Invoke-SantaIntuneSyncProfile @script:params
        $script:patches|Should -Be 1;$result.state|Should -Be 'payload-readback-verified'
        $xml=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($script:remote.payload))
        $xml|Should -Match 'com.pilot.santa.configuration';$xml|Should -Match 'PilotOrg';$xml|Should -Match '<key>ClientMode</key>\s*<integer>1</integer>'
        $xml|Should -Match '<key>StaticRules</key>';$xml|Should -Match 'Zentral-Authorization';$xml|Should -Not -Match 'synthetic-provider'
        ($result|ConvertTo-Json)|Should -Not -Match 'Bearer|A{64}|payload"'
        (Get-Content $script:params.CheckpointPath -Raw)|Should -Not -Match 'Bearer|A{64}|SyncBaseURL'
    }
    It 'rejects array-valued metadata preceding PayloadContent instead of misplacing the credential' {
        $script:remoteText=$script:remoteText.Replace('<string>PilotOrg</string>','<array><dict/></array>')
        $script:remote.payload=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($script:remoteText))
        $script:params.ExpectedCurrentProfileSha256=[Convert]::ToHexStringLower([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($script:remoteText)))
        {Invoke-SantaIntuneSyncProfile @script:params}|Should -Throw '*SantaSync.*'
        $script:patches|Should -Be 0
        Test-Path $script:params.CheckpointPath|Should -BeFalse
    }
    It 'rejects nonintegral, zero or out-of-Int32 timeout values before changing SDK settings' -ForEach @('fraction','zero','overflow') {
        $script:badTimeout=switch($_){fraction{[TimeSpan]::FromMilliseconds(1500)} zero{[TimeSpan]::Zero} overflow{[TimeSpan]::FromSeconds([double][int]::MaxValue+1)}}
        Mock Get-MgRequestContext -ModuleName Santa.SyncProfilePublisher {[pscustomobject]@{MaxRetry=3;ClientTimeout=$script:badTimeout}}
        {Invoke-SantaIntuneSyncProfile @script:params}|Should -Throw '*SantaSync.*'
        Should -Invoke Set-MgRequestContext -ModuleName Santa.SyncProfilePublisher -Times 0
        $script:patches|Should -Be 0
    }
    It 'rejects pagination and substituted immutable device ID before PATCH' -ForEach @('paginated','wrongDevice') {
        Set-Variable -Scope Script -Name $_ -Value $true
        {Invoke-SantaIntuneSyncProfile @script:params}|Should -Throw '*SantaSync.*';$script:patches|Should -Be 0
    }
    It 'rejects dynamic, multiple-member and paginated assignment scope' -ForEach @('dynamic','two_members','assignments') {
        $script:badMode=$_
        {Invoke-SantaIntuneSyncProfile @script:params}|Should -Throw '*SantaSync.*';$script:patches|Should -Be 0
    }
    It 'rejects stale hash and between-read profile drift' -ForEach @('hash','drift') {
        if($_ -eq 'hash'){$script:params.ExpectedCurrentProfileSha256='0'*64}else{$script:drift=$true}
        {Invoke-SantaIntuneSyncProfile @script:params}|Should -Throw '*SantaSync.*';$script:patches|Should -Be 0
    }
    It 'rejects synthetic qualification and incorrect provider revision' -ForEach @('evidenceKind','providerRevision') {
        $script:qualification[$_]=if($_ -eq 'evidenceKind'){'synthetic-fixture'}else{'a'*40};$script:qualification|ConvertTo-Json|Set-Content $script:qualPath
        {Invoke-SantaIntuneSyncProfile @script:params}|Should -Throw '*SantaSync.*';$script:patches|Should -Be 0
    }
    It 'rejects wildcard or malformed returned ETags without PATCH' -ForEach @('*','not-quoted', '"one","two"') {
        $script:remote['@odata.etag']=$_
        {Invoke-SantaIntuneSyncProfile @script:params}|Should -Throw '*SantaSync.*';$script:patches|Should -Be 0
    }
    It 'passes an actual quoted weak ETag as If-Match' {
        $script:remote['@odata.etag']='W/"opaque-version"'
        $null=Invoke-SantaIntuneSyncProfile @script:params
        Should -Invoke Invoke-MgGraphRequest -ModuleName Santa.SyncProfilePublisher -Times 1 -ParameterFilter {$Method -eq 'PATCH' -and $Headers['If-Match'] -ceq 'W/"opaque-version"'}
    }
    It 'rejects a different HTTPS origin' {
        $script:params.ExpectedSyncOrigin='https://other.example.invalid'
        {Invoke-SantaIntuneSyncProfile @script:params}|Should -Throw '*SantaSync.*';$script:patches|Should -Be 0
    }
    It 'preserves ambiguous intent, redacts raw errors and Observe never replays' {
        $script:failPatch=$true
        try {Invoke-SantaIntuneSyncProfile @script:params;throw 'Should fail'}catch{$_.Exception.Message|Should -BeExactly 'SantaSync.FailedOrUnknownPreserveCheckpointNoReplay';$_.Exception.Message|Should -Not -Match 'SECRET-CANARY|A{64}'}
        Test-Path $script:params.CheckpointPath|Should -BeTrue
        {Invoke-SantaIntuneSyncProfile @script:params}|Should -Throw '*SantaSync.*';$script:patches|Should -Be 1
        $script:params.Action='Observe';(Invoke-SantaIntuneSyncProfile @script:params).state|Should -Be 'previous-payload-observed-no-retry';$script:patches|Should -Be 1
    }
    It 'Observe verifies a completed write without another PATCH' {
        $null=Invoke-SantaIntuneSyncProfile @script:params;$script:params.Action='Observe'
        (Invoke-SantaIntuneSyncProfile @script:params).state|Should -Be 'payload-readback-verified';$script:patches|Should -Be 1
    }
    It 'requires a separate explicit removal flag for baseline updates to active sync' {
        $module=& (Get-Module Santa.SyncProfilePublisher) {$script:provider}
        & $module {param($p) Assert-SantaBaselineSyncRemoval $p $false} $script:remote.payload
        $null=Invoke-SantaIntuneSyncProfile @script:params
        {& $module {param($p) Assert-SantaBaselineSyncRemoval $p $false} $script:remote.payload}|Should -Throw '*ExplicitSyncRemovalRequired*'
        & $module {param($p) Assert-SantaBaselineSyncRemoval $p $true} $script:remote.payload
        {& $module {Assert-SantaBaselineSyncRemoval 'invalid' $true}}|Should -Throw '*RemoteConfigurationRejected*'
    }
}
