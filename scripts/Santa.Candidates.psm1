#Requires -Version 7.6
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# JsonElement preserves source types and case; explicitly reject duplicate keys.
if (-not ('AzdSanta.CandidateJson' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Linq;
using System.Collections.Generic;
using System.Text.Json;
namespace AzdSanta {
  public static class CandidateJson {
    public static byte[] Canonical(JsonElement value) {
      using var stream = new MemoryStream();
      using (var writer = new Utf8JsonWriter(stream)) Write(writer, value);
      return stream.ToArray();
    }
    static void Write(Utf8JsonWriter writer, JsonElement value) {
      if (value.ValueKind == JsonValueKind.Object) {
        var properties = value.EnumerateObject().ToArray();
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in properties)
          if (!names.Add(property.Name)) throw new InvalidDataException("Duplicate JSON property name.");
        writer.WriteStartObject();
        foreach (var property in properties.OrderBy(p => p.Name, StringComparer.Ordinal)) {
          writer.WritePropertyName(property.Name); Write(writer, property.Value);
        }
        writer.WriteEndObject();
      } else if (value.ValueKind == JsonValueKind.Array) {
        writer.WriteStartArray(); foreach (var item in value.EnumerateArray()) Write(writer, item); writer.WriteEndArray();
      } else value.WriteTo(writer);
    }
  }
}
'@
}

function Write-SantaJsonValue {
    param([System.Text.Json.Utf8JsonWriter]$Writer, [AllowNull()][object]$Value)
    if ($null -eq $Value) { $Writer.WriteNullValue() }
    elseif ($Value -is [string]) { $Writer.WriteStringValue([string]$Value) }
    elseif ($Value -is [int] -or $Value -is [long]) { $Writer.WriteNumberValue([long]$Value) }
    elseif ($Value -is [Collections.IDictionary]) {
        $Writer.WriteStartObject()
        foreach ($key in $Value.Keys) { $Writer.WritePropertyName([string]$key); Write-SantaJsonValue $Writer $Value[$key] }
        $Writer.WriteEndObject()
    }
    elseif ($Value -is [array]) {
        $Writer.WriteStartArray()
        foreach ($item in $Value) { Write-SantaJsonValue $Writer $item }
        $Writer.WriteEndArray()
    }
    else { throw 'Unsupported canonical JSON value type.' }
}

function ConvertTo-SantaJsonByteArray {
    param([object]$Value)
    $stream = [IO.MemoryStream]::new()
    $writer = [System.Text.Json.Utf8JsonWriter]::new($stream)
    try { Write-SantaJsonValue $writer $Value; $writer.Flush(); return ,$stream.ToArray() }
    finally { $writer.Dispose(); $stream.Dispose() }
}

function Get-SantaDigest {
    param([byte[]]$Bytes, [string]$Domain = '')
    if ($Domain) { $Bytes = [Text.Encoding]::UTF8.GetBytes("$Domain`n") + $Bytes }
    [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Bytes)).ToLowerInvariant()
}

function Resolve-SantaCandidatePath {
    param([string]$Path, [switch]$NewFile)
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path -match '^(?:[\\/]{2}|[a-z][a-z0-9+.-]*://)') {
        throw 'Paths must be local filesystem paths.'
    }
    $provider = $null; $drive = $null
    $full = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path, [ref]$provider, [ref]$drive)
    if ($provider.Name -ne 'FileSystem' -or ($IsWindows -and $full.Substring(2).Contains(':'))) { throw 'Paths must be local filesystem paths.' }
    if ($IsWindows -and [IO.DriveInfo]::new([IO.Path]::GetPathRoot($full)).DriveType -eq 'Network') { throw 'Network drives are not supported.' }
    $parent = [IO.Path]::GetDirectoryName($full)
    if (-not [IO.Directory]::Exists($parent)) { throw 'The parent directory must already exist.' }
    for ($cursor = $parent; $cursor; $cursor = [IO.Path]::GetDirectoryName($cursor)) {
        if ([IO.File]::GetAttributes($cursor) -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse paths are not supported.' }
    }
    if ($NewFile) {
        if (Test-Path -LiteralPath $full) { throw 'Output already exists.' }
    } elseif (-not [IO.File]::Exists($full) -or ([IO.File]::GetAttributes($full) -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'Input must be a regular non-reparse file.'
    }
    $full
}

function New-SantaRuleCandidate {
    <#
    .SYNOPSIS
    Creates one offline Santa candidate draft from selected normalized events.
    .DESCRIPTION
    Validates bounded local input and writes a new deterministic, privacy-reduced
    draft. No authentication, publication, assignment or endpoint action occurs.
    .EXAMPLE
    New-SantaRuleCandidate -InputPath ./events.json -Policy BLOCKLIST -EvaluationTime '2026-09-22T00:00:00Z' -ReviewExpiresAt '2026-09-29T00:00:00Z' -OutputPath ./draft.json -WhatIf
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$InputPath,
        [Parameter(Mandatory)][ValidateSet('ALLOWLIST', 'BLOCKLIST')][string]$Policy,
        [Parameter(Mandatory)][datetimeoffset]$EvaluationTime,
        [Parameter(Mandatory)][datetimeoffset]$ReviewExpiresAt,
        [Parameter(Mandatory)][string]$OutputPath
    )
    if ($ReviewExpiresAt -le $EvaluationTime -or ($ReviewExpiresAt - $EvaluationTime).TotalDays -gt 30) {
        throw 'ReviewExpiresAt must be after EvaluationTime and within 30 days.'
    }
    $inputFile = Resolve-SantaCandidatePath $InputPath
    $outputFile = Resolve-SantaCandidatePath $OutputPath -NewFile
    $stream = [IO.File]::Open($inputFile, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        if ($stream.Length -gt 1MB) { throw 'Input exceeds the 1 MiB limit.' }
        $bytes = [byte[]]::new([int]$stream.Length)
        $stream.ReadExactly($bytes, 0, $bytes.Length)
    } finally { $stream.Dispose() }
    $null = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    $options = [System.Text.Json.JsonDocumentOptions]::new(); $options.MaxDepth = 32
    $document = [System.Text.Json.JsonDocument]::Parse([ReadOnlyMemory[byte]]::new($bytes), $options)
    try {
        # Validate duplicate keys across the whole tree before schema conversion.
        $null = [AzdSanta.CandidateJson]::Canonical($document.RootElement)
        if ($document.RootElement.ValueKind -ne 'Array' -or $document.RootElement.GetArrayLength() -notin 1..256) {
            throw 'Input must be a JSON array of 1 to 256 events.'
        }
        $events = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
        $schema = Join-Path $PSScriptRoot '../schemas/event.schema.json'
        foreach ($element in $document.RootElement.EnumerateArray()) {
            $raw = $element.GetRawText()
            if (-not (Test-Json -Json $raw -SchemaFile $schema -ErrorAction SilentlyContinue)) { throw 'Event does not satisfy event.schema.json.' }
            $normalizedEvent = ConvertFrom-Json -InputObject $raw -AsHashtable -DateKind String -Depth 32
            if ($normalizedEvent.binary.sha256 -cnotmatch '\A[0-9a-f]{64}\z' -or $normalizedEvent.rawEvidence.sha256 -cnotmatch '\A[0-9a-f]{64}\z') {
                throw 'Event SHA-256 values must be exactly 64 lowercase hexadecimal characters.'
            }
            $observed = [datetimeoffset]::Parse($normalizedEvent.observedAt, [Globalization.CultureInfo]::InvariantCulture)
            if ($observed -gt $EvaluationTime) { throw 'Event timestamp is after EvaluationTime.' }
            $fingerprint = Get-SantaDigest ([AzdSanta.CandidateJson]::Canonical($element))
            if ($events.ContainsKey($normalizedEvent.eventId)) {
                if ($events[$normalizedEvent.eventId].fingerprint -cne $fingerprint) { throw 'Duplicate event ID has different content.' }
                continue
            }
            $events.Add($normalizedEvent.eventId, @{ event = $normalizedEvent; observed = $observed; fingerprint = $fingerprint })
        }
    } finally { $document.Dispose() }
    $ids = [string[]]@($events.Keys); [Array]::Sort($ids, [StringComparer]::Ordinal)
    $devices = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $evidence = @(); $binary = $null; $first = [datetimeoffset]::MaxValue; $last = [datetimeoffset]::MinValue
    foreach ($id in $ids) {
        $item = $events[$id]; $normalizedEvent = $item.event
        if ($null -ne $binary -and $binary -cne $normalizedEvent.binary.sha256) { throw 'Events must select exactly one binary SHA-256.' }
        $binary = $normalizedEvent.binary.sha256
        $null = $devices.Add($normalizedEvent.device.pseudonymousId)
        if ($item.observed -lt $first) { $first = $item.observed }
        if ($item.observed -gt $last) { $last = $item.observed }
        $evidence += [ordered]@{
            observedAt = $item.observed.UtcDateTime.ToString('o'); decision = $normalizedEvent.decision
            binarySha256 = $binary; devicePseudonymousId = $normalizedEvent.device.pseudonymousId; rawEvidenceSha256 = $normalizedEvent.rawEvidence.sha256
        }
    }
    $candidate = [ordered]@{
        schemaVersion = '1.1'; state = 'draft'
        evaluationTime = $EvaluationTime.UtcDateTime.ToString('o'); reviewExpiresAt = $ReviewExpiresAt.UtcDateTime.ToString('o')
        evidenceDigest = Get-SantaDigest (ConvertTo-SantaJsonByteArray $evidence) 'santa/evidence/1.1'
        observation = [ordered]@{ firstSeen = $first.UtcDateTime.ToString('o'); lastSeen = $last.UtcDateTime.ToString('o'); eventCount = $ids.Length; deviceCount = $devices.Count }
        proposedRule = [ordered]@{ ruleType = 'BINARY'; identifier = $binary; policy = $Policy.ToUpperInvariant(); scope = 'global' }
        counterfactual = [ordered]@{ status = 'not-performed'; affectedBinaryCount = $null }
        riskFlags = @('review-required', 'counterfactual-not-performed', 'raw-evidence-unverified', 'client-application-unproven')
        generator = [ordered]@{ name = 'azd-santa'; version = '0.1.0' }
    }
    $candidate.Insert(1, 'candidateId', 'candidate-' + (Get-SantaDigest (ConvertTo-SantaJsonByteArray $candidate) 'santa/candidate/1.1'))
    $candidate.Add('outputDigest', (Get-SantaDigest (ConvertTo-SantaJsonByteArray $candidate)))
    $outputBytes = ConvertTo-SantaJsonByteArray $candidate
    if ($PSCmdlet.ShouldProcess($outputFile, 'Create offline Santa draft (no rule publication)')) {
        $output = [IO.File]::Open($outputFile, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $output.Write($outputBytes, 0, $outputBytes.Length) } finally { $output.Dispose() }
    }
    [pscustomobject]@{ candidateId = $candidate.candidateId; outputDigest = $candidate.outputDigest; eventCount = $ids.Length; outputPath = $outputFile; whatIf = [bool]$WhatIfPreference }
}

Export-ModuleMember -Function New-SantaRuleCandidate
