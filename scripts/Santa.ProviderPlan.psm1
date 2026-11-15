#Requires -Version 7.6
Set-StrictMode -Version Latest

function Read-SantaPlanInput {
    param([string] $Path)
    if (-not $Path -or $Path -match '^[a-zA-Z]+:' -and $Path -notmatch '^[a-zA-Z]:[\\/]' -or $Path.StartsWith('\\') -or $Path.StartsWith('//')) { throw 'SantaPlan.LocalInputRequired' }
    $full = [IO.Path]::GetFullPath($Path)
    if (-not [IO.File]::Exists($full)) { throw 'SantaPlan.InputUnavailable' }
    for ($cursor = $full; $cursor; $cursor = [IO.Path]::GetDirectoryName($cursor)) {
        if ([IO.File]::GetAttributes($cursor) -band [IO.FileAttributes]::ReparsePoint) { throw 'SantaPlan.ReparseInputRejected' }
    }
    $stream = [IO.File]::Open($full, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        if ($stream.Length -gt 1MB) { throw 'SantaPlan.InputTooLarge' }
        $bytes = [byte[]]::new([int]$stream.Length)
        $stream.ReadExactly($bytes, 0, $bytes.Length)
    } finally { $stream.Dispose() }
    [pscustomobject]@{ text = [Text.UTF8Encoding]::new($false, $true).GetString($bytes); sha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant() }
}

function ConvertFrom-SantaPlanPlist {
    param([string] $Text)
    $settings = [Xml.XmlReaderSettings]::new()
    $settings.DtdProcessing = [Xml.DtdProcessing]::Ignore
    $settings.XmlResolver = $null
    $settings.MaxCharactersInDocument = 1MB
    $reader = [Xml.XmlReader]::Create([IO.StringReader]::new($Text), $settings)
    $document = [Xml.XmlDocument]::new(); $document.XmlResolver = $null
    try { $document.Load($reader) } finally { $reader.Dispose() }
    function Read-Value($Node, [int]$Depth = 0) {
        if ($Depth -gt 32) { throw 'SantaPlan.ProfileTooDeep' }
        $children = @($Node.ChildNodes | Where-Object NodeType -eq ([Xml.XmlNodeType]::Element))
        switch -CaseSensitive ($Node.Name) {
            'dict' {
                if ($children.Count % 2 -ne 0) { throw 'SantaPlan.MalformedDictionary' }
                $result = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
                for ($i = 0; $i -lt $children.Count; $i += 2) {
                    if ($children[$i].Name -cne 'key' -or $result.ContainsKey($children[$i].InnerText)) { throw 'SantaPlan.DuplicateOrInvalidKey' }
                    $result.Add($children[$i].InnerText, (Read-Value $children[$i + 1] ($Depth + 1)))
                }
                return ,$result
            }
            'array' { $values = @($children | ForEach-Object { Read-Value $_ ($Depth + 1) }); return ,$values }
            'string' { if ($children.Count) { throw 'SantaPlan.MalformedScalar' }; return [string]$Node.InnerText }
            'integer' { if ($children.Count) { throw 'SantaPlan.MalformedScalar' }; return [long]::Parse($Node.InnerText, [Globalization.CultureInfo]::InvariantCulture) }
            'true' { if ($Node.InnerText.Trim() -or $children.Count) { throw 'SantaPlan.MalformedScalar' }; return $true }
            'false' { if ($Node.InnerText.Trim() -or $children.Count) { throw 'SantaPlan.MalformedScalar' }; return $false }
            default { throw 'SantaPlan.UnsupportedPlistValue' }
        }
    }
    if ($document.DocumentElement.Name -cne 'plist') { throw 'SantaPlan.ProfileRequired' }
    $rootNodes = @($document.DocumentElement.ChildNodes | Where-Object NodeType -eq ([Xml.XmlNodeType]::Element))
    if ($rootNodes.Count -ne 1 -or $rootNodes[0].Name -cne 'dict') { throw 'SantaPlan.ProfileRequired' }
    return Read-Value $rootNodes[0]
}

function Get-SantaPlanPayload {
    param($Profile)
    if (-not $Profile.ContainsKey('PayloadType') -or $Profile['PayloadType'] -cne 'Configuration' -or -not $Profile.ContainsKey('PayloadContent')) { throw 'SantaPlan.ConfigurationProfileRequired' }
    if ($Profile['PayloadContent'] -isnot [array]) { throw 'SantaPlan.PayloadArrayRequired' }
    if ($Profile.ContainsKey('PayloadEnabled') -and ($Profile['PayloadEnabled'] -isnot [bool] -or -not $Profile['PayloadEnabled'])) { throw 'SantaPlan.DisabledProfileRejected' }
    $payloads = @($Profile['PayloadContent'])
    if ($payloads.Count -ne 1 -or $payloads[0] -isnot [Collections.Generic.Dictionary[string,object]] -or
        -not $payloads[0].ContainsKey('PayloadType') -or $payloads[0]['PayloadType'] -cne 'com.northpolesec.santa') { throw 'SantaPlan.SingleSantaPayloadRequired' }
    if ($payloads[0].ContainsKey('PayloadEnabled') -and ($payloads[0]['PayloadEnabled'] -isnot [bool] -or -not $payloads[0]['PayloadEnabled'])) { throw 'SantaPlan.DisabledProfileRejected' }
    return ,$payloads[0]
}

function ConvertTo-SantaPlanCanonicalValue {
    param($Value)
    if ($Value -is [Collections.IDictionary] -or $Value -is [Collections.Generic.Dictionary[string,object]]) {
        $result = [ordered]@{}; $keys = [string[]]@($Value.Keys); [Array]::Sort($keys, [StringComparer]::Ordinal)
        foreach ($key in $keys) { $result[$key] = ConvertTo-SantaPlanCanonicalValue $Value[$key] }
        return $result
    }
    if ($Value -is [array]) { return ,@($Value | ForEach-Object { ConvertTo-SantaPlanCanonicalValue $_ }) }
    return $Value
}

function Get-SantaProviderProfilePlan {
    [CmdletBinding()]
    param(
        [switch] $EnablePlanning,
        [string] $ProviderProfilePath,
        [string] $QualificationPath,
        [string] $ReviewEvidencePath,
        [string] $OwnedReceiptPath,
        [string] $ExpectedTenantId,
        [string] $ExpectedGroupId,
        [string] $ExpectedConfigurationObjectId
    )
    if (-not $EnablePlanning) {
        return [pscustomobject]@{ schemaVersion = '1.0'; state = 'disabled'; syncEnabled = $false; publicationAllowed = $false }
    }
    try {
        $root = Split-Path -Parent $PSScriptRoot
        foreach ($id in @($ExpectedTenantId,$ExpectedGroupId,$ExpectedConfigurationObjectId)) {
            $parsed = [guid]::Empty
            if (-not [guid]::TryParse($id, [ref]$parsed) -or $parsed -eq [guid]::Empty) { throw 'SantaPlan.ExactTargetRequired' }
        }
        $providerInput = Read-SantaPlanInput $ProviderProfilePath
        $qualificationInput = Read-SantaPlanInput $QualificationPath
        $receiptInput = Read-SantaPlanInput $OwnedReceiptPath
        $reviewInput = Read-SantaPlanInput $ReviewEvidencePath
        # Schema validation emits no raw input or parser diagnostics to callers.
        if (-not (Test-Json -Json $qualificationInput.text -SchemaFile (Join-Path $root 'schemas/provider-plan-qualification.schema.json') -ErrorAction SilentlyContinue)) { throw 'SantaPlan.UnqualifiedContract' }
        $qualification = ConvertFrom-Json -InputObject $qualificationInput.text -AsHashtable -DateKind String
        $lock = Get-Content -LiteralPath (Join-Path $root 'package/santa.lock.json') -Raw | ConvertFrom-Json
        if ($qualification.clientVersion -cne $lock.package.packageVersion -or $qualification.clientSourceCommit -cne $lock.release.sourceCommit) { throw 'SantaPlan.UnqualifiedClientVersion' }
        if ($qualification.providerRevision -match '^0+$' -or $qualification.reviewEvidenceSha256 -match '^0+$') { throw 'SantaPlan.UnqualifiedProviderVersion' }
        if ($qualification.reviewEvidenceSha256 -cne $reviewInput.sha256) { throw 'SantaPlan.ReviewEvidenceBindingMismatch' }
        if ($qualification.profileSha256 -cne $providerInput.sha256) { throw 'SantaPlan.ProfileReviewBindingMismatch' }
        if (-not (Test-Json -Json $receiptInput.text -SchemaFile (Join-Path $root 'schemas/intune-profile-receipt.schema.json') -ErrorAction SilentlyContinue)) { throw 'SantaPlan.InvalidOwnershipReceipt' }
        $receipt = ConvertFrom-Json -InputObject $receiptInput.text -AsHashtable -DateKind String
        if ($receipt.tenantId -ine $ExpectedTenantId -or $receipt.pilotGroup.id -ine $ExpectedGroupId -or $receipt.release -cne $lock.release.tag) { throw 'SantaPlan.OwnershipTargetMismatch' }
        $expectedProfiles = @('system-extension','tcc','service-management','configuration','notifications')
        if (@($receipt.profiles.id | Sort-Object -Unique).Count -ne 5 -or @($receipt.profiles | Where-Object { $_.id -notin $expectedProfiles -or $_.assignmentGroupId -ine $ExpectedGroupId }).Count) { throw 'SantaPlan.OwnershipSetMismatch' }
        $canonicalObjectIds = @(foreach ($profileId in $receipt.profiles.objectId) {
            $parsedObject = [guid]::Empty
            if (-not [guid]::TryParse($profileId, [ref]$parsedObject) -or $parsedObject -eq [guid]::Empty) { throw 'SantaPlan.InvalidOwnedObjectId' }
            $parsedObject.ToString('D')
        })
        if (@($canonicalObjectIds | Sort-Object -Unique).Count -ne 5) { throw 'SantaPlan.OwnershipSetMismatch' }
        $owned = @($receipt.profiles | Where-Object id -eq 'configuration')
        if ($owned.Count -ne 1 -or $owned[0].objectId -ine $ExpectedConfigurationObjectId) { throw 'SantaPlan.OwnershipTargetMismatch' }
        $baselineInput = Read-SantaPlanInput (Join-Path $root 'profiles/generated/40-configuration.mobileconfig')
        if ($qualification.baselineSha256 -cne $baselineInput.sha256) { throw 'SantaPlan.BaselineReviewBindingMismatch' }
        $baseline = Get-SantaPlanPayload (ConvertFrom-SantaPlanPlist $baselineInput.text)
        if (-not $baseline.ContainsKey('ClientMode') -or $baseline['ClientMode'] -isnot [long] -or $baseline['ClientMode'] -ne 1 -or $baseline.ContainsKey('SyncBaseURL')) { throw 'SantaPlan.UnsafeBaseline' }
        $profile = ConvertFrom-SantaPlanPlist $providerInput.text
        $payload = Get-SantaPlanPayload $profile
        $metadata = @('PayloadType','PayloadVersion','PayloadUUID','PayloadIdentifier','PayloadDisplayName','PayloadDescription','PayloadOrganization','PayloadEnabled')
        $allowed = @($metadata) + @($baseline.Keys) + @('SyncBaseURL','SyncExtraHeaders')
        foreach ($key in $payload.Keys) { if ($key -cnotin $allowed) { throw 'SantaPlan.UnsupportedSettingOrAuthMode' } }
        if (-not $payload.ContainsKey('SyncBaseURL') -or $payload['SyncBaseURL'] -isnot [string] -or -not $payload.ContainsKey('SyncExtraHeaders')) { throw 'SantaPlan.IncompleteProviderInput' }
        if ($payload['SyncBaseURL'] -match '[\x00-\x20\x7f]' -or $payload['SyncBaseURL'] -cne $payload['SyncBaseURL'].Trim()) { throw 'SantaPlan.UnsafeSyncUrl' }
        $uri = $null
        if (-not [uri]::TryCreate($payload['SyncBaseURL'], [UriKind]::Absolute, [ref]$uri) -or $uri.Scheme -cne 'https' -or -not $uri.Host -or $uri.UserInfo -or $uri.Query -or $uri.Fragment) { throw 'SantaPlan.UnsafeSyncUrl' }
        $headers = $payload['SyncExtraHeaders']
        if ($headers -isnot [Collections.Generic.Dictionary[string,object]] -or $headers.Count -ne 1 -or -not $headers.ContainsKey($qualification.authHeaderName) -or
            $headers[$qualification.authHeaderName] -isnot [string] -or $headers[$qualification.authHeaderName] -cnotmatch '\ABearer [^\s]+\z') { throw 'SantaPlan.AmbiguousOrIncompleteAuthentication' }
        if ($payload.ContainsKey('ClientMode') -and ($payload['ClientMode'] -isnot [long] -or $payload['ClientMode'] -ne 1)) { throw 'SantaPlan.ModeChangeRejected' }
        $effective = [ordered]@{}; $overlaps = @()
        foreach ($key in $baseline.Keys) { if ($key -cnotin $metadata) { $effective[$key] = $baseline[$key] } }
        foreach ($key in $payload.Keys) {
            if ($key -cin $metadata) { continue }
            if ($effective.Contains($key)) {
                $overlaps += $key
                $old = ConvertTo-Json -InputObject (ConvertTo-SantaPlanCanonicalValue $effective[$key]) -Depth 32 -Compress
                $new = ConvertTo-Json -InputObject (ConvertTo-SantaPlanCanonicalValue $payload[$key]) -Depth 32 -Compress
                if ($old -cne $new) { throw 'SantaPlan.ConflictingBaselineSetting' }
            }
            $effective[$key] = $payload[$key]
        }
        # Only a digest of the in-memory effective settings leaves this function.
        $canonical = ConvertTo-Json -InputObject (ConvertTo-SantaPlanCanonicalValue $effective) -Depth 32 -Compress
        $effectiveDigest = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($canonical))).ToLowerInvariant()
        [pscustomobject][ordered]@{
            schemaVersion = '1.0'; state = 'draft-native-qualification-required'; syncEnabled = $false; publicationAllowed = $false; providerSelection = 'unresolved'
            target = [ordered]@{ tenantId = $ExpectedTenantId; groupId = $ExpectedGroupId; configurationObjectId = $ExpectedConfigurationObjectId }
            operation = 'replace-owned-configuration-after-separate-approval'; additionalProfileAllowed = $false
            clientVersion = $lock.package.packageVersion; providerRevision = $qualification.providerRevision; protocol = $qualification.protocol; authMode = $qualification.authMode
            secretReferenceId = $qualification.secretReferenceId; qualificationKind = $qualification.evidenceKind
            fingerprints = [ordered]@{ providerProfile = $providerInput.sha256; baseline = $baselineInput.sha256; qualification = $qualificationInput.sha256; ownershipReceipt = $receiptInput.sha256; effectiveSettings = $effectiveDigest }
            overlappingSettings = @($overlaps | Sort-Object); preservedBaselineSettings = @('ClientMode','EnableSilentMode','ModeNotificationMonitor','StaticRules')
            remainingGates = @('provider-selection','operator-MFA-and-enrollment','single-effective-configuration-review','exact-target-publication-approval','native-client-rule-and-rollback-proof')
        }
    } catch {
        if ($_.Exception.Message -cmatch '^SantaPlan\.[A-Za-z]+$') { throw }
        throw 'SantaPlan.InvalidInputOrUnavailableFile'
    }
}

Export-ModuleMember -Function Get-SantaProviderProfilePlan
