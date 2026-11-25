#Requires -Version 7.6
BeforeAll {
    $script:root = Split-Path $PSScriptRoot -Parent
    Import-Module (Join-Path $script:root 'scripts/Santa.Candidates.psm1') -Force
    $script:fixture = Get-Content (Join-Path $PSScriptRoot 'fixtures/candidates/events.json') -Raw
    $script:evaluation = [datetimeoffset]'2026-09-22T00:00:00Z'
    $script:expiry = $script:evaluation.AddDays(7)
    function Write-Input([string]$Text) {
        $path = Join-Path $TestDrive ([guid]::NewGuid().ToString() + '.json')
        [IO.File]::WriteAllText($path, $Text, [Text.UTF8Encoding]::new($false))
        $path
    }
    function New-Draft([string]$Text = $script:fixture, [string]$Policy = 'BLOCKLIST') {
        $output = Join-Path $TestDrive ([guid]::NewGuid().ToString() + '.json')
        New-SantaRuleCandidate -InputPath (Write-Input $Text) -OutputPath $output -Policy $Policy -EvaluationTime $script:evaluation -ReviewExpiresAt $script:expiry | Out-Null
        Get-Content -LiteralPath $output -Raw
    }
    function Get-Hash([string]$Text) {
        [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($Text))).ToLowerInvariant()
    }
    function Get-Event {
        ($script:fixture | ConvertFrom-Json -AsHashtable -DateKind String -NoEnumerate)[0]
    }
}

Describe 'Offline Santa candidate boundary' {
    It 'emits a reproducible schema-valid draft and independent digest chain' {
        $json = New-Draft
        $draft = $json | ConvertFrom-Json -DateKind String
        ($json | Test-Json -SchemaFile (Join-Path $script:root 'schemas/candidate-1.1.schema.json')) | Should -BeTrue
        $draft.state | Should -Be 'draft'
        $draft.counterfactual.affectedBinaryCount | Should -BeNullOrEmpty
        $draft.evidenceDigest | Should -Be '780da2bc46578d8a1935dee9c5c06e12fb81f544c0771c5fadac2e8c22e1f642'
        # Recompute directly from public output bytes; no production hash/encoder helper.
        $withoutOutputDigest = $json.Substring(0, $json.LastIndexOf(',"outputDigest":')) + '}'
        $draft.outputDigest | Should -Be (Get-Hash $withoutOutputDigest)
        $identity = $withoutOutputDigest -replace ',"candidateId":"candidate-[0-9a-f]{64}"', ''
        $draft.candidateId | Should -Be ('candidate-' + (Get-Hash ("santa/candidate/1.1`n" + $identity)))
        $json | Should -Be (New-Draft)
        $json | Should -Match '"evaluationTime":"2026-09-22T00:00:00.0000000Z"'
    }
    It 'is stable across event/property order, duplicates and cultures' {
        $event = Get-Event
        $other = Get-Event; $other.eventId = 'EVT-002'; $other.decision = 'ALLOW'; $other.device.pseudonymousId = 'DEVICE-OTHER'
        $first = ConvertTo-Json -InputObject @($event, $other) -Depth 20 -Compress
        $reversed = [ordered]@{}
        $keys = [string[]]@($event.Keys); [Array]::Reverse($keys)
        foreach ($key in $keys) { $reversed[$key] = $event[$key] }
        $second = ConvertTo-Json -InputObject @($other, $reversed, $event) -Depth 20
        $culture = [Threading.Thread]::CurrentThread.CurrentCulture
        try {
            [Threading.Thread]::CurrentThread.CurrentCulture = [Globalization.CultureInfo]'en-US'
            $a = New-Draft $first
            [Threading.Thread]::CurrentThread.CurrentCulture = [Globalization.CultureInfo]'tr-TR'
            $b = New-Draft $second
            $a | Should -Be $b
            ($b | ConvertFrom-Json).observation.eventCount | Should -Be 2
        } finally { [Threading.Thread]::CurrentThread.CurrentCulture = $culture }
    }
    It 'treats IDs and device pseudonyms case-sensitively' {
        $event = Get-Event; $other = Get-Event
        $other.eventId = $event.eventId.ToUpperInvariant()
        $other.device.pseudonymousId = $event.device.pseudonymousId.ToUpperInvariant()
        $draft = New-Draft (ConvertTo-Json -InputObject @($event, $other) -Depth 20) | ConvertFrom-Json
        $draft.observation.eventCount | Should -Be 2
        $draft.observation.deviceCount | Should -Be 2
    }
    It 'requires an explicit policy rather than deriving approval from a decision' {
        $allowed = $script:fixture.Replace('"DENY"', '"ALLOW"')
        (New-Draft $allowed 'ALLOWLIST' | ConvertFrom-Json).proposedRule.policy | Should -Be 'ALLOWLIST'
        (New-Draft $allowed 'BLOCKLIST' | ConvertFrom-Json).proposedRule.policy | Should -Be 'BLOCKLIST'
        (New-Draft $script:fixture 'allowlist' | ConvertFrom-Json).proposedRule.policy | Should -Be 'ALLOWLIST'
    }
    It 'rejects conflicting duplicate IDs even when only ignored metadata changes' {
        $event = Get-Event; $other = Get-Event; $other.rawEvidence.reference = 'private://changed'
        { New-Draft (ConvertTo-Json -InputObject @($event, $other) -Depth 20) } | Should -Throw '*different content*'
    }
    It 'rejects duplicate property names including escaped names and nested objects' {
        { New-Draft '[{"eventId":"a","event\u0049d":"b"}]' } | Should -Throw '*Duplicate JSON property*'
        { New-Draft '[{"device":{"pseudonymousId":"a","pseudonymousId":"b"}}]' } | Should -Throw '*Duplicate JSON property*'
    }
    It 'rejects empty, nonarray, malformed, mixed-binary and invalid-schema input' {
        { New-Draft '[]' } | Should -Throw '*1 to 256*'
        { New-Draft '{}' } | Should -Throw '*1 to 256*'
        { New-Draft '[null]' } | Should -Throw '*event.schema.json*'
        { New-Draft '[{' } | Should -Throw
        $event = Get-Event; $other = Get-Event; $other.eventId = 'another'; $other.binary.sha256 = 'c' * 64
        { New-Draft (ConvertTo-Json -InputObject @($event, $other) -Depth 20) } | Should -Throw '*one binary SHA*'
        { New-Draft $script:fixture.Replace('"DENY"', '"INVALID"') } | Should -Throw '*event.schema.json*'
    }
    It 'rejects future events and invalid review windows' {
        { New-Draft $script:fixture.Replace('2026-09-21T18:00:00Z', '2026-09-23T18:00:00Z') } | Should -Throw '*after EvaluationTime*'
        $path = Write-Input $script:fixture; $out = Join-Path $TestDrive 'invalid-ttl.json'
        foreach ($end in @($script:evaluation, $script:evaluation.AddDays(-1), $script:evaluation.AddDays(30).AddTicks(1))) {
            { New-SantaRuleCandidate -InputPath $path -OutputPath $out -Policy BLOCKLIST -EvaluationTime $script:evaluation -ReviewExpiresAt $end } | Should -Throw '*within 30 days*'
        }
    }
    It 'requires exact lowercase hexadecimal hashes without trailing whitespace' {
        $event = Get-Event; $event.binary.sha256 = ('a' * 64) + "`n"
        { New-Draft (ConvertTo-Json -InputObject @($event) -Depth 20) } | Should -Throw
        $event = Get-Event; $event.rawEvidence.sha256 = 'B' * 64
        { New-Draft (ConvertTo-Json -InputObject @($event) -Depth 20) } | Should -Throw
    }
    It 'enforces byte, event, UTF-8 and JSON-depth limits' {
        { New-Draft (' ' * (1MB + 1)) } | Should -Throw '*1 MiB*'
        $event = ($script:fixture | ConvertFrom-Json -DateKind String)[0] | ConvertTo-Json -Depth 20 -Compress
        { New-Draft ('[' + ((@($event) * 257) -join ',') + ']') } | Should -Throw '*1 to 256*'
        (New-Draft ('[' + ((@($event) * 256) -join ',') + ']') | ConvertFrom-Json).observation.eventCount | Should -Be 1
        { New-Draft (('[' * 34) + '0' + (']' * 34)) } | Should -Throw
        $path = Write-Input ''; [IO.File]::WriteAllBytes($path, [byte[]]@(0xff, 0xfe))
        { New-SantaRuleCandidate -InputPath $path -OutputPath (Join-Path $TestDrive 'utf8.json') -Policy BLOCKLIST -EvaluationTime $script:evaluation -ReviewExpiresAt $script:expiry } | Should -Throw
    }
    It 'omits planted source identifiers, paths, references and signing metadata' {
        $event = Get-Event
        $event.eventId = 'EVENT-SECRET-CANARY'; $event.device.pseudonymousId = 'DEVICE-SECRET-CANARY'
        $event.binary.path = '/PRIVATE-PATH-CANARY'; $event.binary.teamId = 'TEAM-SECRET-CANARY'; $event.binary.signingId = 'SIGNING-SECRET-CANARY'
        $event.rawEvidence.reference = 'https://PRIVATE-REF-CANARY/?token=SECRET'
        $json = New-Draft (ConvertTo-Json -InputObject @($event) -Depth 20)
        $json | Should -Not -Match 'CANARY|token=|eventId|pseudonymousId|rawEvidence|signingId'
    }
    It 'keeps WhatIf mutation-free and never overwrites an existing file' {
        $path = Write-Input $script:fixture; $hash = (Get-FileHash $path).Hash
        $out = Join-Path $TestDrive 'whatif.json'
        $result = & (Join-Path $script:root 'scripts/New-SantaRuleCandidate.ps1') -InputPath $path -OutputPath $out -Policy BLOCKLIST -EvaluationTime $script:evaluation -ReviewExpiresAt $script:expiry -WhatIf
        $result.whatIf | Should -BeTrue
        Test-Path $out | Should -BeFalse
        (Get-FileHash $path).Hash | Should -Be $hash
        [IO.File]::WriteAllText($out, 'preserve')
        { New-SantaRuleCandidate -InputPath $path -OutputPath $out -Policy BLOCKLIST -EvaluationTime $script:evaluation -ReviewExpiresAt $script:expiry } | Should -Throw '*already exists*'
        Get-Content $out -Raw | Should -Be 'preserve'
    }
    It 'rejects remote, nonfilesystem, missing-parent and reparse paths' {
        $path = Write-Input $script:fixture
        foreach ($out in @('https://example.invalid/x', '\\server\share\x', 'env:PATH', (Join-Path $TestDrive 'missing/candidate.json'))) {
            { New-SantaRuleCandidate -InputPath $path -OutputPath $out -Policy BLOCKLIST -EvaluationTime $script:evaluation -ReviewExpiresAt $script:expiry } | Should -Throw
        }
        Test-Path (Join-Path $TestDrive 'missing') | Should -BeFalse
        $target = Join-Path $TestDrive 'target'; $null = New-Item -ItemType Directory -Path $target
        $link = Join-Path $TestDrive 'link'
        $kind = if ($IsWindows) { 'Junction' } else { 'SymbolicLink' }
        $null = New-Item -ItemType $kind -Path $link -Target $target
        try {
            { New-SantaRuleCandidate -InputPath $path -OutputPath (Join-Path $link 'draft.json') -Policy BLOCKLIST -EvaluationTime $script:evaluation -ReviewExpiresAt $script:expiry } | Should -Throw '*Reparse*'
        } finally { Remove-Item -LiteralPath $link -Force }
    }
    It 'keeps the draft contract closed and cannot claim a measured counterfactual or omit risks' {
        $schema = Join-Path $script:root 'schemas/candidate-1.1.schema.json'
        $draft = New-Draft | ConvertFrom-Json -AsHashtable -DateKind String
        $draft.counterfactual.affectedBinaryCount = 0
        (ConvertTo-Json $draft -Depth 20 | Test-Json -SchemaFile $schema -ErrorAction SilentlyContinue) | Should -BeFalse
        $draft.counterfactual.affectedBinaryCount = $null; $draft.riskFlags = @()
        (ConvertTo-Json $draft -Depth 20 | Test-Json -SchemaFile $schema -ErrorAction SilentlyContinue) | Should -BeFalse
        $draft = New-Draft | ConvertFrom-Json -AsHashtable -DateKind String
        $draft.proposedRule.target = 'unapproved'
        (ConvertTo-Json $draft -Depth 20 | Test-Json -SchemaFile $schema -ErrorAction SilentlyContinue) | Should -BeFalse
    }
}
