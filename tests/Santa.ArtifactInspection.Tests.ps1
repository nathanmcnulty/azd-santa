#Requires -Version 7.6
BeforeAll {
    $script:root = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $script:root 'scripts/Santa.ArtifactInspection.psm1') -Force
    $script:now = [datetimeoffset]::UtcNow
    $global:SantaInspectionDispatches = 0
    function global:az { $global:SantaInspectionDispatches++; throw 'Unpermitted CLI' }
    function global:Connect-MgGraph { $global:SantaInspectionDispatches++; throw 'Unpermitted auth' }
    function global:Get-MgContext { $global:SantaInspectionDispatches++; throw 'Unpermitted context' }
    function global:Invoke-MgGraphRequest { $global:SantaInspectionDispatches++; throw 'Unpermitted Graph' }
    function Save-InspectionJson($Path, $Value) {
        [IO.File]::WriteAllText($Path, ($Value | ConvertTo-Json -Depth 32) + "`n", [Text.UTF8Encoding]::new($false))
    }
    function Read-InspectionJson($Path) { Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -Depth 32 }
    function Invoke-FixtureInspection { Invoke-SantaArtifactInspection @script:inspectionArguments -Now $script:now }
    function Get-Check($Report, $Domain) { @($Report.checks | Where-Object id -EQ "artifact.$Domain")[0] }
}
AfterAll {
    Remove-Item Function:\az,Function:\Connect-MgGraph,Function:\Get-MgContext,Function:\Invoke-MgGraphRequest -ErrorAction SilentlyContinue
    Remove-Variable SantaInspectionDispatches -Scope Global -ErrorAction SilentlyContinue
}
Describe 'Actual local Santa artifact inspector' {
    BeforeEach {
        $script:dir = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $script:dir | Out-Null
        $script:inspectionArguments = @{ TargetPath=Join-Path $script:dir 'target.json'; ProfileReceiptPath=Join-Path $script:dir 'assignment.json'; ProfileStatusPath=Join-Path $script:dir 'profiles.json'; EndpointEvidencePath=Join-Path $script:dir 'endpoint.json' }
        Copy-Item (Join-Path $script:root 'tests/fixtures/inspection/target.json') $script:inspectionArguments.TargetPath
        Copy-Item (Join-Path $script:root 'tests/fixtures/intune/profile-receipt.json') $script:inspectionArguments.ProfileReceiptPath
        $profiles = Read-InspectionJson (Join-Path $script:root 'tests/fixtures/intune/profile-status-success.json')
        $profiles.collectedAt = $script:now.ToString('o')
        Save-InspectionJson $script:inspectionArguments.ProfileStatusPath $profiles
        $endpoint = [ordered]@{ schemaVersion='1.0'; targetSha256=(Get-FileHash $script:inspectionArguments.TargetPath).Hash.ToLowerInvariant(); sourceSha256=Get-SantaInspectionSourceHash; collectedAt=$script:now.ToString('o'); payload=Read-InspectionJson (Join-Path $script:root 'tests/fixtures/endpoint/healthy.json') }
        Save-InspectionJson $script:inspectionArguments.EndpointEvidencePath $endpoint
    }
    It 'conforms in all four independent saved domains without claiming current Mac readiness or Azure subscription' {
        $r = Invoke-FixtureInspection
        @($r.checks).Count | Should -Be 4
        @($r.checks | Where-Object status -EQ pass).Count | Should -Be 4
        $r.environment.metadata.currentMacReadiness | Should -Be 'pending'
        $r.environment.metadata.evidence | Should -Be 'savedArtifactsOnly'
        $r.schemaVersion | Should -Be '1.0'
        $r.environment.PSObject.Properties.Name | Should -Not -Contain 'subscriptionId'
        Test-Json -Json ($r | ConvertTo-Json -Depth 32) -SchemaFile (Join-Path $script:root 'scripts/vendor/Azd.DeploymentValidation/deployment-validation.schema.json') | Should -BeTrue
    }
    It 'keeps missing <Domain> independent of other evidence' -ForEach @(
        @{Domain='assignment';Parameter='ProfileReceiptPath'}, @{Domain='profiles';Parameter='ProfileStatusPath'}, @{Domain='endpoint';Parameter='EndpointEvidencePath'}
    ) {
        $script:inspectionArguments[$Parameter] = $null
        $r = Invoke-FixtureInspection
        (Get-Check $r $Domain).status | Should -Be 'warning'
        @($r.checks | Where-Object status -EQ pass).Count | Should -Be 3
    }
    It 'plans through the actual component without reading supplied target or artifact files' {
        Mock Read-SantaInspectionJson -ModuleName Santa.ArtifactInspection { throw 'Must not inspect caller files in Plan' }
        $r = Invoke-SantaArtifactInspection -TargetPath 'https://invalid.example/secret' -Plan
        @($r.checks | Where-Object status -EQ planned).Count | Should -Be 4
        Should -Invoke Read-SantaInspectionJson -ModuleName Santa.ArtifactInspection -Times 0 -Exactly
    }
    It 'refuses malformed, wrong-release, control-terminated and unknown target fields: <Case>' -ForEach @(
        @{Case='foreignRelease'}, @{Case='tenantLF'}, @{Case='groupCRLF'}, @{Case='environmentLF'}, @{Case='unknownSecret'}, @{Case='badJSON'}, @{Case='oversize'}
    ) {
        $t = Read-InspectionJson $script:inspectionArguments.TargetPath
        switch ($Case) {
            foreignRelease {$t.release='2026.7'}
            tenantLF {$t.tenantId += "`n"}
            groupCRLF {$t.pilotGroupId += "`r`n"}
            environmentLF {$t.environmentName += "`n"}
            unknownSecret {$t|Add-Member secret 'CANARY_BEARER_superSecret'}
        }
        Save-InspectionJson $script:inspectionArguments.TargetPath $t
        if ($Case -eq 'badJSON') { [IO.File]::WriteAllText($script:inspectionArguments.TargetPath, '{CANARY_BEARER_superSecret') }
        if ($Case -eq 'oversize') { [IO.File]::WriteAllText($script:inspectionArguments.TargetPath, ('X'*1048577)) }
        $r = Invoke-FixtureInspection
        @($r.checks | Where-Object { $_.id -ne 'artifact.package' -and $_.status -eq 'warning' }).Count | Should -Be 3
        (Get-Check $r package).status | Should -Be 'pass'
        ($r|ConvertTo-Json -Depth 32) | Should -Not -Match 'CANARY|superSecret|tenantId|pilotGroupId'
    }
    It 'requires actual target and source byte hashes for endpoint metadata: <Field>' -ForEach @(@{Field='targetSha256'},@{Field='sourceSha256'}) {
        $e = Read-InspectionJson $script:inspectionArguments.EndpointEvidencePath
        $e.$Field = 'a'*64
        Save-InspectionJson $script:inspectionArguments.EndpointEvidencePath $e
        $r = Invoke-FixtureInspection
        (Get-Check $r endpoint).actual.code | Should -Be 'UnboundArtifact'
        (Get-Check $r endpoint).status | Should -Be 'warning'
        @($r.checks|Where-Object status -EQ pass).Count | Should -Be 3
    }
    It 'refuses unbound historical healthy endpoint JSON rather than promoting its legacy ready flag' {
        Copy-Item (Join-Path $script:root 'tests/fixtures/endpoint/healthy.json') $script:inspectionArguments.EndpointEvidencePath -Force
        (Get-Check (Invoke-FixtureInspection) endpoint).status | Should -Be 'warning'
    }
    It 'rejects unsafe endpoint payload types and duplicates: <Case>' -ForEach @(
        @{Case='falseAge'},@{Case='stringAge'},@{Case='negativeAge'},@{Case='fractionalAge'},@{Case='doctorString'},@{Case='syncString'},@{Case='duplicateProfile'},@{Case='extraSecret'},@{Case='offsetlessDate'}
    ) {
        $e = Read-InspectionJson $script:inspectionArguments.EndpointEvidencePath
        switch ($Case) {
            falseAge {$e.payload.lastCheckAgeMinutes=$false}
            stringAge {$e.payload.lastCheckAgeMinutes='5'}
            negativeAge {$e.payload.lastCheckAgeMinutes=-1}
            fractionalAge {$e.payload.lastCheckAgeMinutes=0.5}
            doctorString {$e.payload.santa.doctorHealthy='false'}
            syncString {$e.payload.santa.syncConfigured='false'}
            duplicateProfile {$e.payload.profiles[1].id=$e.payload.profiles[0].id}
            extraSecret {$e.payload|Add-Member callbackUrl 'https://canary.example/?sig=CANARY_TOKEN'}
            offsetlessDate {$e.collectedAt='2026-10-11T01:00:00'}
        }
        Save-InspectionJson $script:inspectionArguments.EndpointEvidencePath $e
        $r=Invoke-FixtureInspection
        (Get-Check $r endpoint).status | Should -Be 'warning'
        ($r|ConvertTo-Json -Depth 32) | Should -Not -Match 'CANARY|canary.example|callbackUrl'
    }
    It 'keeps endpoint semantic failure separate from other conforming artifacts' {
        $e = Read-InspectionJson $script:inspectionArguments.EndpointEvidencePath
        $e.payload.santa.mode='LOCKDOWN'
        Save-InspectionJson $script:inspectionArguments.EndpointEvidencePath $e
        (Get-Check (Invoke-FixtureInspection) endpoint).actual.code | Should -Be 'EndpointArtifactPending'
    }
    It 'refuses stale/future saved <Domain> metadata: <When>' -ForEach @(
        @{Domain='profiles';When='stale';Offset=-25},@{Domain='profiles';When='future';Offset=1},@{Domain='endpoint';When='stale';Offset=-25},@{Domain='endpoint';When='future';Offset=1}
    ) {
        $path = if ($Domain -eq 'profiles') {$script:inspectionArguments.ProfileStatusPath} else {$script:inspectionArguments.EndpointEvidencePath}
        $e = Read-InspectionJson $path
        $e.collectedAt=$script:now.AddHours($Offset).ToString('o')
        Save-InspectionJson $path $e
        (Get-Check (Invoke-FixtureInspection) $Domain).actual.code | Should -Be 'StaleArtifact'
    }
    It 'keeps a pending required profile separate from acknowledged assignment and package availability' {
        $e = Read-InspectionJson $script:inspectionArguments.ProfileStatusPath
        $e.pilotDevice.configurationStates[0].state='pending'
        Save-InspectionJson $script:inspectionArguments.ProfileStatusPath $e
        $r = Invoke-FixtureInspection
        (Get-Check $r profiles).actual.code | Should -Be 'ProfilesPending'
        (Get-Check $r assignment).status | Should -Be 'pass'
        (Get-Check $r package).status | Should -Be 'pass'
    }
    It 'refuses cross-target saved <Domain> state: <Field>' -ForEach @(
        @{Domain='assignment';Field='tenantId'},@{Domain='profiles';Field='managedDeviceId'}
    ) {
        $path = if ($Domain -eq 'assignment') {$script:inspectionArguments.ProfileReceiptPath} else {$script:inspectionArguments.ProfileStatusPath}
        $e=Read-InspectionJson $path
        if ($Domain -eq 'assignment') {$e.tenantId='99999999-9999-4999-8999-999999999999'} else {$e.pilotDevice.managedDeviceId='99999999-9999-4999-8999-999999999999'}
        Save-InspectionJson $path $e
        (Get-Check (Invoke-FixtureInspection) $Domain).actual.code | Should -Be 'TargetMismatch'
    }
    It 'emits a redacted actual CLI report with no CLI/network/auth/publisher dispatch or evidence writes' {
        $before = @(Get-ChildItem $script:dir -File | ForEach-Object {(Get-FileHash $_.FullName).Hash})
        Mock Invoke-WebRequest { throw 'Unpermitted network' }
        Mock Invoke-RestMethod { throw 'Unpermitted network' }
        $raw = & (Join-Path $script:root 'scripts/Inspect-SantaArtifacts.ps1') @script:inspectionArguments
        $r = $raw | ConvertFrom-Json -Depth 32
        @($r.checks|Where-Object status -EQ pass).Count | Should -Be 4
        $r.environment.metadata.currentMacReadiness | Should -Be 'pending'
        $raw | Should -Not -Match 'pilot@example|11111111-|22222222-|77777777-|C00000000000|resultMessage|script_output'
        $global:SantaInspectionDispatches | Should -Be 0
        Should -Invoke Invoke-WebRequest -Times 0 -Exactly
        Should -Invoke Invoke-RestMethod -Times 0 -Exactly
        @(Get-ChildItem $script:dir -File | ForEach-Object {(Get-FileHash $_.FullName).Hash}) | Should -Be $before
    }
}

Describe 'Actual private-copy integrity boundaries' {
    BeforeAll {
        $script:copy = Join-Path $TestDrive 'private-copy'
        New-Item -ItemType Directory -Path $script:copy | Out-Null
        foreach ($directory in 'scripts','schemas','package','profiles') { Copy-Item -LiteralPath (Join-Path $script:root $directory) -Destination $script:copy -Recurse }
        Copy-Item -LiteralPath (Join-Path $script:root 'azd-components.lock.json') -Destination $script:copy
    }
    AfterEach { Import-Module (Join-Path $script:root 'scripts/Santa.ArtifactInspection.psm1') -Force }
    It 'detects real package-byte corruption in a private copy without changing the repository package' {
        $lock = Get-Content (Join-Path $script:copy 'package/santa.lock.json') -Raw | ConvertFrom-Json
        $packagePath = Join-Path $script:copy ('package/vendor/'+$lock.package.assetName)
        $stream=[IO.File]::Open($packagePath,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite)
        try {$byte=$stream.ReadByte();$stream.Position=0;$stream.WriteByte([byte]($byte -bxor 1))}finally{$stream.Dispose()}
        Import-Module (Join-Path $script:copy 'scripts/Santa.ArtifactInspection.psm1') -Force
        (Get-Check (Invoke-SantaArtifactInspection) package).actual.code | Should -Be 'ArtifactUnavailable'
        Import-Module (Join-Path $script:root 'scripts/Santa.ArtifactInspection.psm1') -Force
        (Get-Check (Invoke-SantaArtifactInspection) package).status | Should -Be 'pass'
    }
    It 'refuses real vendor byte drift before evaluating any user artifact through the actual CLI with a fixed outer error' {
        $vendor=Join-Path $script:copy 'scripts/vendor/Azd.DeploymentValidation/Azd.DeploymentValidation.psm1'
        [IO.File]::AppendAllText($vendor,"`n# CANARY_VENDOR_SECRET",[Text.UTF8Encoding]::new($false))
        $caught=$null
        try {& (Join-Path $script:copy 'scripts/Inspect-SantaArtifacts.ps1') -Plan}catch{$caught=$_}
        $caught | Should -Not -BeNullOrEmpty
        $caught.Exception.Message | Should -Be 'SantaArtifactInspectionFailed'
        $caught.Exception.InnerException | Should -BeNullOrEmpty
        ($caught|Out-String) | Should -Not -Match 'CANARY_VENDOR_SECRET|ComponentBytesMismatch'
    }
}

Describe 'Actual Git checkout preserves immutable component bytes' {
    It 'materializes an autocrlf=true checkout and executes the actual vendor guard and inspector' {
        $fixture = Join-Path $TestDrive 'checkout-source'
        $checkout = Join-Path $TestDrive 'fresh-checkout'
        New-Item -ItemType Directory -Path $fixture,$checkout | Out-Null
        foreach ($directory in 'scripts','schemas','package','profiles') {
            Copy-Item -LiteralPath (Join-Path $script:root $directory) -Destination $fixture -Recurse
        }
        foreach ($file in '.gitattributes','azd-components.lock.json') {
            Copy-Item -LiteralPath (Join-Path $script:root $file) -Destination $fixture
        }
        & git -C $fixture init --quiet
        $LASTEXITCODE | Should -Be 0
        & git -C $fixture -c core.autocrlf=true -c core.safecrlf=false add --all
        $LASTEXITCODE | Should -Be 0
        & git -C $fixture -c core.autocrlf=true checkout-index --all ('--prefix='+$checkout.Replace('\','/')+'/')
        $LASTEXITCODE | Should -Be 0
        $lock = Get-Content (Join-Path $checkout 'azd-components.lock.json') -Raw | ConvertFrom-Json
        foreach ($file in $lock.components[0].files) {
            (Get-FileHash -LiteralPath (Join-Path $checkout $file.target)).Hash.ToLowerInvariant() | Should -BeExactly $file.sha256
        }
        try {
            $raw = & (Join-Path $checkout 'scripts/Inspect-SantaArtifacts.ps1') -TargetPath (Join-Path $script:root 'tests/fixtures/inspection/target.json')
            $report = $raw | ConvertFrom-Json -Depth 32
            (Get-Check $report package).status | Should -Be 'pass'
            @($report.checks).Count | Should -Be 4
            $report.environment.metadata.currentMacReadiness | Should -Be 'pending'
            $global:SantaInspectionDispatches | Should -Be 0
        } finally {
            Import-Module (Join-Path $script:root 'scripts/Santa.ArtifactInspection.psm1') -Force
        }
    }
}
