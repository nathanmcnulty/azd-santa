# Offline provider-profile planning

Issue #36 adds a default-off planner, not a sync publisher or provider selection.
The baseline generator, generated profiles, one-device Monitor boundary and
existing server architecture remain unchanged. No Graph, Azure, network, account,
enrollment or permission operation occurs. The output is never an apply receipt.

## Bounded input contract

Run `scripts/Get-SantaProviderProfilePlan.ps1` without arguments to obtain a
`disabled` result without reading inputs. To opt into local planning supply:

- `-EnablePlanning`
- `-ProviderProfilePath`: a privately stored UTF-8 XML configuration profile with
  exactly one `com.northpolesec.santa` payload.
- `-QualificationPath`: JSON matching
  `schemas/provider-plan-qualification.schema.json`.
- `-ReviewEvidencePath`: the local offline review artifact whose bytes match the
  qualification's `reviewEvidenceSha256`.
- `-OwnedReceiptPath`: the existing private Intune profile ownership receipt.
- `-ExpectedTenantId`, `-ExpectedGroupId`, and
  `-ExpectedConfigurationObjectId`: exact intended existing targets.

Use private local paths, never inline enrollment data or complete profiles in
commands, issues or Git. Inputs are bounded to 1 MiB each; remote paths and
reparse-point inputs are rejected. This is not a secure storage or secret-manager
implementation. Keep source files and the target-bearing plan in private storage.
The script prints JSON to standard output; it writes no files.

This initial planning slice supports only HTTPS plus one explicit Bearer token
header (`Authorization` or `Zentral-Authorization`), public-v1 JSON and the pinned
Santa client. URL queries, fragments and user information, additional headers,
unknown settings, ambiguous credentials, extra payloads and mode changes are
rejected. Mutual TLS, URL-only enrollment, binary/signed profiles and Workshop
private protocol require separate reviewed support; rejection does not mean the
provider itself is unsupported. The planner neither chooses a server nor claims
any profile works against a real provider. Never rewrite a vendor-generated
profile simply to satisfy this restricted input contract.

## Review and effective configuration

Qualification binds exact provider bytes, generated baseline bytes, pinned client
version/source, provider revision and offline review artifact. These hashes prove
input consistency only. The caller supplies the review and revision assertions;
they are not signatures, independently verified provenance, or native-client proof.
`synthetic-fixture` evidence remains synthetic. The output always retains native
qualification and separate publication gates.

The ownership receipt must contain the five distinct baseline objects, all for
the intended group. The plan binds the existing configuration object rather than
inventing another object or stacking conflicting profiles. Receipt matching does
not establish present service state or grant permission to replace it.

Baseline settings are retained. Identical overlaps are recorded; differing values
are refused. An optional provider ClientMode must be integer 1 (Monitor). Disabled
profiles/payloads are refused. The only added settings are the sync URL and its
single authentication header. Effective settings exist only in memory; output
contains fingerprints, safe setting names, a nonsecret credential-reference label
and the explicitly supplied target IDs, not URL/header/profile bodies. Error
messages are fixed diagnostic codes, not raw parser errors or provider content.

`publicationAllowed`, `syncEnabled` and `additionalProfileAllowed` remain false.
The proposed operation is replacement of the exact owned configuration only
*after* a separate full effective-configuration review and explicit approval.
No publisher consumes this plan. Existing profile generation is byte-unchanged.

## Rotation, rollback and switching providers

Before any separately authorized integration, verify the current exact objects,
assignments, device and provider revision. Use the selected provider's secure
credential channel to prepare rotation; independently review its enrollment
binding, overlap window and revocation. Replan from the new profile and review
bytes. Never automatically revoke a credential or assume it is unshared.

Retain the approved prior profile/rule snapshot and recovery procedure privately.
A profile rollback or URL switch does not prove downloaded rules were removed.
The single-Mac qualification must observe effective Monitor settings, complete
rule download, failure/offline recovery, old/new credential behavior, provider
rule-state migration and rollback. Issue #33 owns native evidence; #37 and the
existing architecture drafts own server design. No source-only test closes them.

## Permissions and validation

Reviewed `azd-permissions.json`: this local planner requires no additional Graph,
Azure or provider permission, so metadata is unchanged. Metadata never grants
consent. Tests use synthetic fixtures only and cover default-off behavior, exact
target and input binding, overlap/conflict handling, malformed/disabled profiles,
auth/mode rejection and redaction. Run the existing template validation and full
Pester suite on PowerShell 7.6+ / Pester 6.2.0 before publication.
