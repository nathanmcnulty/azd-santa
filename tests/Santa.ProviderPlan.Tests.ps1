#Requires -Version 7.6
BeforeAll {
    $script:root = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $script:root 'scripts/Santa.ProviderPlan.psm1') -Force
    function Write-Qualification {
        $script:qualification.profileSha256 = (Get-FileHash $script:provider -Algorithm SHA256).Hash.ToLowerInvariant()
        $script:qualification | ConvertTo-Json -Depth 12 | Set-Content $script:qualificationPath
    }
    function Write-Receipt { $script:receipt | ConvertTo-Json -Depth 12 | Set-Content $script:receiptPath }
}
Describe 'Offline provider-profile planning' {
    BeforeEach {
        $script:provider = Join-Path $TestDrive 'provider.mobileconfig'
        $script:qualificationPath = Join-Path $TestDrive 'qualification.json'
        $script:receiptPath = Join-Path $TestDrive 'receipt.json'
        $script:reviewPath = Join-Path $TestDrive 'review.txt'
        'Synthetic offline review only. No native qualification.' | Set-Content $script:reviewPath
        Copy-Item (Join-Path $PSScriptRoot 'fixtures/provider-plan/synthetic.mobileconfig') $script:provider
        $script:qualification = @{
            schemaVersion = '1.0'; clientVersion = '2026.8.244'; clientSourceCommit = 'dbe97b0aa0f5929feece5f4cbd2c69362c271abc'
            providerRevision = ('a' * 40); protocol = 'public-v1-json'; authMode = 'header-token'; authHeaderName = 'Authorization'
            secretReferenceId = 'synthetic-enrollment'; profileSha256 = ''; baselineSha256 = (Get-FileHash (Join-Path $script:root 'profiles/generated/40-configuration.mobileconfig')).Hash.ToLowerInvariant()
            reviewEvidenceSha256 = (Get-FileHash $script:reviewPath).Hash.ToLowerInvariant(); evidenceKind = 'synthetic-fixture'; configurationDisposition = 'replace-owned-preserve-baseline'
        }
        $script:receipt = @{
            schemaVersion = '1.0'; tenantId = '11111111-1111-4111-8111-111111111111'; release = '2026.8'
            pilotGroup = @{ id = '22222222-2222-4222-8222-222222222222'; displayName = 'Synthetic pilot' }; package = @{ status = 'unknown' }
            profiles = @(foreach ($i in 0..4) { @{ id = @('system-extension','tcc','service-management','configuration','notifications')[$i]; objectId = ('33333333-3333-4333-8333-33333333333' + $i); displayName = 'Synthetic'; action = 'verify'; assignmentGroupId = '22222222-2222-4222-8222-222222222222' } })
        }
        Write-Qualification; Write-Receipt
        $script:params = @{ EnablePlanning = $true; ProviderProfilePath = $script:provider; QualificationPath = $script:qualificationPath; ReviewEvidencePath = $script:reviewPath; OwnedReceiptPath = $script:receiptPath; ExpectedTenantId = $script:receipt.tenantId; ExpectedGroupId = $script:receipt.pilotGroup.id; ExpectedConfigurationObjectId = $script:receipt.profiles[3].objectId }
    }
    It 'does not read inputs by default' {
        $plan = Get-SantaProviderProfilePlan -ProviderProfilePath '/not/a/file'
        $plan.state | Should -Be 'disabled'; $plan.syncEnabled | Should -BeFalse; $plan.publicationAllowed | Should -BeFalse
    }
    It 'plans a single replacement without exporting credentials or modifying inputs' {
        $before = (Get-FileHash $script:provider).Hash
        $plan = Get-SantaProviderProfilePlan @script:params
        $plan.state | Should -Be 'draft-native-qualification-required'
        $plan.syncEnabled | Should -BeFalse; $plan.publicationAllowed | Should -BeFalse; $plan.additionalProfileAllowed | Should -BeFalse
        $plan.overlappingSettings | Should -Contain 'ClientMode'
        $plan.target.configurationObjectId | Should -Be $script:params.ExpectedConfigurationObjectId
        ($plan | ConvertTo-Json -Depth 12) | Should -Not -Match 'SYNTHETIC-CANARY|synthetic-provider|Bearer|SyncBaseURL'
        (Get-FileHash $script:provider).Hash | Should -Be $before
    }
    It 'rejects unqualified contracts' -ForEach @(
        @{ Field = 'clientVersion'; Value = '2026.1.1' }, @{ Field = 'providerRevision'; Value = ('0' * 40) },
        @{ Field = 'authMode'; Value = 'mutual-tls' }, @{ Field = 'protocol'; Value = 'private' },
        @{ Field = 'baselineSha256'; Value = ('0' * 64) }, @{ Field = 'reviewEvidenceSha256'; Value = ('0' * 64) }
    ) {
        $script:qualification[$Field] = $Value; Write-Qualification
        { Get-SantaProviderProfilePlan @script:params } | Should -Throw '*SantaPlan.*'
    }
    It 'binds the exact profile bytes to review evidence' {
        Add-Content $script:provider '<!-- changed -->'
        { Get-SantaProviderProfilePlan @script:params } | Should -Throw '*ProfileReviewBindingMismatch*'
    }
    It 'refuses wrong owned targets' -ForEach @('ExpectedTenantId','ExpectedGroupId','ExpectedConfigurationObjectId') {
        $script:params[$_] = '99999999-9999-4999-8999-999999999999'
        { Get-SantaProviderProfilePlan @script:params } | Should -Throw '*OwnershipTargetMismatch*'
    }
    It 'refuses duplicate owned object IDs' {
        $script:receipt.profiles[0].objectId = $script:receipt.profiles[1].objectId; Write-Receipt
        { Get-SantaProviderProfilePlan @script:params } | Should -Throw '*OwnershipSetMismatch*'
    }
    It 'rejects unsafe provider content with redacted diagnostics' -ForEach @(
        @{ Old = '<integer>1</integer>'; New = '<integer>2</integer>' },
        @{ Old = '<key>ClientMode</key>'; New = '<key>PayloadEnabled</key><false/><key>ClientMode</key>' },
        @{ Old = '<key>ClientMode</key>'; New = '<key>PayloadEnabled</key><true><dict/></true><key>ClientMode</key>' },
        @{ Old = 'https://synthetic-provider.invalid/santa/'; New = 'http://synthetic-provider.invalid/PRIVATE-CANARY' },
        @{ Old = 'https://synthetic-provider.invalid/santa/'; New = 'https://synthetic-provider.invalid/?token=PRIVATE-CANARY' },
        @{ Old = 'Bearer SYNTHETIC-CANARY-NOT-A-CREDENTIAL'; New = 'PRIVATE-CANARY' },
        @{ Old = '<key>ClientMode</key>'; New = '<key>UnknownSecret</key>' },
        @{ Old = '<key>ClientMode</key>'; New = '<key>ClientMode</key><integer>1</integer><key>ClientMode</key>' }
    ) {
        (Get-Content $script:provider -Raw).Replace($Old,$New) | Set-Content $script:provider; Write-Qualification
        try { Get-SantaProviderProfilePlan @script:params; throw 'Expected failure' }
        catch { $_.Exception.Message | Should -Match '^SantaPlan\.'; $_.Exception.Message | Should -Not -Match 'PRIVATE-CANARY|SYNTHETIC-CANARY|synthetic-provider' }
    }
    It 'rejects duplicate GUID identities with different string formats' {
        $script:receipt.profiles[0].objectId = ([guid]$script:receipt.profiles[1].objectId).ToString('N'); Write-Receipt
        { Get-SantaProviderProfilePlan @script:params } | Should -Throw '*OwnershipSetMismatch*'
    }
    It 'validates every owned object ID beyond schema format annotations' {
        $script:receipt.profiles[0].objectId = 'not-a-guid'; Write-Receipt
        { Get-SantaProviderProfilePlan @script:params } | Should -Throw '*InvalidOwnedObjectId*'
    }
    It 'refuses normalized URL controls' {
        (Get-Content $script:provider -Raw).Replace('https://synthetic-provider.invalid/santa/', "https://synthetic-provider.invalid/san`nta/") | Set-Content $script:provider
        Write-Qualification
        { Get-SantaProviderProfilePlan @script:params } | Should -Throw '*UnsafeSyncUrl*'
    }
    It 'refuses oversized inputs before parsing' {
        ('x' * (1MB + 1)) | Set-Content $script:provider
        { Get-SantaProviderProfilePlan @script:params } | Should -Throw '*InputTooLarge*'
    }
    It 'rejects remote input paths without opening them' {
        $script:params.ProviderProfilePath = 'https://synthetic.invalid/PRIVATE-CANARY'
        { Get-SantaProviderProfilePlan @script:params } | Should -Throw '*LocalInputRequired*'
    }
    It 'requires PayloadContent to be an array' {
        (Get-Content $script:provider -Raw).Replace('<array>','').Replace('</array>','') | Set-Content $script:provider
        Write-Qualification
        { Get-SantaProviderProfilePlan @script:params } | Should -Throw '*PayloadArrayRequired*'
    }
    It 'binds the actual offline review artifact' {
        Add-Content $script:reviewPath 'Changed review'
        { Get-SantaProviderProfilePlan @script:params } | Should -Throw '*ReviewEvidenceBindingMismatch*'
    }
    It 'allows identical baseline overlaps and rejects conflicting ones' {
        $base = [xml](Get-Content (Join-Path $script:root 'profiles/generated/40-configuration.mobileconfig') -Raw)
        $nodes = $base.SelectSingleNode('/plist/dict/array/dict').ChildNodes
        $extra = ''
        for ($i=0; $i -lt $nodes.Count; $i++) {
            if ($nodes[$i].Name -eq 'key' -and $nodes[$i].InnerText -eq 'EnableSilentMode') { $extra = $nodes[$i].OuterXml + $nodes[$i+1].OuterXml }
        }
        $extra | Should -Not -BeNullOrEmpty
        (Get-Content $script:provider -Raw).Replace('<key>ClientMode</key>', "$extra<key>ClientMode</key>") | Set-Content $script:provider
        Write-Qualification
        (Get-SantaProviderProfilePlan @script:params).overlappingSettings | Should -Contain 'EnableSilentMode'
        (Get-Content $script:provider -Raw).Replace($extra, '<key>EnableSilentMode</key><true/>') | Set-Content $script:provider
        Write-Qualification
        { Get-SantaProviderProfilePlan @script:params } | Should -Throw '*ConflictingBaselineSetting*'
    }
    It 'redacts malformed input and file paths' {
        'PRIVATE-CANARY <bad>' | Set-Content $script:provider; Write-Qualification
        { Get-SantaProviderProfilePlan @script:params } | Should -Throw '*SantaPlan.InvalidInputOrUnavailableFile*'
    }
}
