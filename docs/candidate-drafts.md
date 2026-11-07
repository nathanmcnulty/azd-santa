# Offline Santa rule-candidate drafts

This source phase advances SANTA-004; it does not complete its approval, performed
counterfactual, publication, rollback or endpoint gates. The baseline profile and
one-device Monitor pilot are unchanged. Nothing invokes this generator during
`azd up`, changes an Intune assignment, configures sync or sends a rule.

The command accepts a local JSON array of normalized 1.0 events selected by an
operator. Each selection must describe exactly one binary SHA-256. It emits one
candidate 1.1 draft for an explicitly selected ALLOWLIST or BLOCKLIST policy;
it does not infer that a successful or denied execution deserves that policy.
The fixed global scope describes matching that hash on a host, not a fleet/group
assignment. The draft has no selected target and grants no publication authority.

## Inputs and privacy

For synthetic input, run this from the repository root after creating a private
output directory. Choose a new output filename for each run:

```powershell
./scripts/New-SantaRuleCandidate.ps1 `
  -InputPath ./tests/fixtures/candidates/events.json `
  -Policy BLOCKLIST `
  -EvaluationTime '2026-09-22T00:00:00Z' `
  -ReviewExpiresAt '2026-09-29T00:00:00Z' `
  -OutputPath ./out/candidate.json -WhatIf
```

Remove `-WhatIf` to create the draft. The output parent must already exist;
existing files are never overwritten. Input is limited to 1 MiB, 256 events and
32 JSON levels. UNC/URL paths, network drives on Windows, non-filesystem paths
and files/directories reached through reparse points are rejected. These checks
do not make an attacker-controlled filesystem safe against concurrent changes;
use an access-controlled local directory.

Keep real normalized input and raw evidence outside the repository in an
access-controlled working directory. Normalization and pseudonymization remain
the producer's responsibility; a digest does not authenticate a device, establish
provenance or prove the referenced raw evidence was obtained or inspected.

The parser accepts bounded UTF-8 JSON with no duplicate properties, validates
against the existing event schema and rejects malformed input before producing
a draft. Empty/mixed-binary selections and conflicting duplicate IDs fail.
Identical duplicates collapse. Sorting is ordinal; input event/property order
must not affect the resulting bytes. The same explicit evaluation time and
review-expiry inputs are required to reproduce a draft.

Output contains aggregate times/counts and evidence hashes. It omits source event
IDs, device identifiers, paths, enrollment/reference URLs and signing metadata.
This reduces disclosure; hashes and counts are not anonymization or authenticity
proof. Do not attach the original input or provider profile to a public PR.

Counterfactual status is not-performed and affectedBinaryCount is null. No
counterfactual execution or zero-impact result is claimed. Review expiry limits
use of this draft for approval; the command does not enforce expiry in Santa or
revoke an already published rule. A future publisher must check current time
again, even if the draft was valid at generation.

## Compatibility and deterministic bytes

`candidate-1.1.schema.json` is separate from the unchanged 1.0 schema and fixtures.
Consumers must explicitly implement 1.1; never relabel the result as an approved
1.0 rule. Every object in the new schema is closed. There is no approval record,
reviewed commit or publication receipt in a generated draft.

Canonical encoding uses typed UTF-8 JSON without a BOM, fixed field order,
lowercase hex, UTC Z timestamps and ordinal-sorted evidence. Domain separators
make evidence and candidate-identity hashes distinct. The candidate identity is
computed before it is inserted; outputDigest covers the complete canonical
candidate with its identity but without outputDigest. Hashes do not include their
own fields. The output file and a digest payload are distinct byte sequences.

Encoding uses `System.Text.Json.Utf8JsonWriter` default escaping, no indentation
or trailing newline. Times use seven fractional digits. The evidence payload is
an array sorted by case-sensitive ordinal source event ID after deduplication.
Each object's fields, in order, are observedAt, decision, binarySha256,
devicePseudonymousId and rawEvidenceSha256. EvidenceDigest hashes UTF-8
`santa/evidence/1.1` plus one LF byte, then those canonical array bytes.

The identity payload fields, in order, are schemaVersion, state, evaluationTime,
reviewExpiresAt, evidenceDigest, observation, proposedRule, counterfactual,
riskFlags and generator. Nested field order matches the schema's required lists;
riskFlags uses the schema's exact array order. CandidateId is `candidate-` plus
SHA-256 of UTF-8 `santa/candidate/1.1` plus LF and the identity payload. Insert
candidateId immediately after schemaVersion, then compute outputDigest as plain
SHA-256 of that object. Append outputDigest last to obtain the output file bytes.

Evidence hashes bind only this projection; ignored metadata is not certified.
Duplicate-ID checks compare complete source events after recursively sorting
object property names ordinally and preserving JSON types, array order and string
values. Thus equivalent property order/escaping collapses, but changed metadata
or a differently written timestamp under the same ID conflicts. Source event IDs
and pseudonymous device identifiers are also compared case-sensitively.

## Review, conflicts and publication gates

Before a draft can become a publishable rule:

1. Verify the private evidence origin, normalized inputs, exact candidate bytes,
   generator source and immutable reviewed commit. Independently recompute the
   digests. A matching hash or schema-valid file is not human approval.
2. Review the requested binary/policy and expiry, resolve risk flags and perform
   a counterfactual against the exact effective rule/configuration snapshot.
   Unknown results cannot become a zero-impact approval. Conflicting existing
   rules or stale snapshots require a new decision and new bound draft.
3. Bind the selected provider configuration, exact pilot target and rule identity
   in an approval record. Any byte, target, policy or evidence change invalidates
   that approval. Expired drafts need renewed review, not a changed timestamp.
4. GitHub and Azure DevOps may transport the same reviewed artifacts; neither
   may publish automatically from telemetry, a generated draft, an AI explanation
   or PR existence. Publisher credentials and authority remain separate.
5. Obtain explicit authorization for the selected server/one-device pilot, prove
   server acceptance and actual client application separately, and retain exact
   owned-rule/configuration receipts. Do not widen assignments or promote
   Monitor to Lockdown from an offline result.
6. Prove rollback on that client using the server's supported owned-rule operation
   and preserved approved configuration. Removing a Git file or disabling sync
   does not establish rule removal. Re-enrollment/clean-sync state changes need
   their own plan; never delete unrelated rules or the client's whole database.

These gates remain open in SANTA-004 and the provider pilot SANTA-007. The offline
producer is independently usable without Azure compute, sync, Graph, GitHub,
Azure DevOps or an azd-reference runtime dependency. Any future shared extraction
requires proven real consumers and normal immutable component governance.
