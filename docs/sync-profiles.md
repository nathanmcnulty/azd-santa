# Optional Santa sync profiles

Assessed 2026-10-16 at repository revision
`b636b4c10cf2947348114839a3c4b226558c6de5` for SANTA-003. This is setup and
qualification guidance, not an enabled integration or server compatibility claim.
The deployment-only baseline remains independent of sync, Azure compute, GitHub
and Azure DevOps. Its generated configuration remains Monitor mode with no
`SyncBaseURL`; keep the one-device pilot and existing profile ownership receipts.

## Version and protocol evidence

The package lock selects Santa **2026.8.244**, upstream commit
`dbe97b0aa0f5929feece5f4cbd2c69362c271abc`. The
[pinned sync documentation](https://github.com/northpolesec/santa/blob/dbe97b0aa0f5929feece5f4cbd2c69362c271abc/docs/docs/features/sync.md)
describes preflight, optional event upload, rule download and postflight. JSON is
the default; binary protobuf requires explicit compatibility qualification.
Server acceptance and postflight are distinct from proof that an intended rule
actually controls execution. Local `santactl rule` management is disabled when
sync is configured. Do not enable sync as an incidental configuration cleanup.

The [2026.8 release notes](https://github.com/northpolesec/santa/releases/tag/2026.8)
record interrupted clean-sync handling and clearing server-provided settings/state
after a sync URL change. Switching providers needs a planned rule/state migration;
restoring a profile alone is not proof of rule rollback.

| Profile | Evidence available | Still required |
| --- | --- | --- |
| Deployment-only | Existing generated profiles, static validation and fixtures | The SANTA-002 real-Mac deployment/health gate |
| Workshop | Official managed service and current vendor setup documentation | Selected tenant/config revision, authentication, pinned-client compatibility and one-Mac wire/rule/rollback evidence |
| Existing Zentral server | Documented configuration/enrollment/profile workflow | Exact installed server release/commit, supported feature intersection and the same one-Mac qualification |
| Azure-native | Local protocol fixtures only | Separate value/security design and wire conformance before implementing a service |

Current service documentation can describe features newer than the pinned client.
Record the provider release/build or dated configuration revision and capability
list during qualification. An undocumented version/capability pair is unproven.

## Workshop setup packet

An administrator selects the Workshop tenant, pilot host/tag scope, data residency,
retention and authentication policy. Retrieve the tenant-generated configuration
through the vendor's secure administration interface. Current
[Workshop settings](https://northpole.security/docs/workshop/settings) describe
token and mutual-TLS enrollment; use the generated profile for the selected
method rather than constructing its URL or combining authentication modes.

Review the complete profile and effective server settings for Monitor mode,
event collection and rule scope before any assignment. Keep the baseline
Endpoint Security, TCC, background-service and notification requirements. Do not
add the Workshop network extension merely to enable sync. Configuration downloaded
from a live tenant is credential-bearing material, not a repository fixture.

## Existing Zentral setup packet

Following the [Zentral Santa guide](https://www.zentral.com/docs/zentral/apps/santa/),
an administrator identifies the exact server version and configuration, creates
or selects an enrollment restricted to the approved pilot, and retrieves its
profile or preference plist securely. The enrollment secret is embedded in the
sync URL. Never paste that URL into an issue, shell history, agent conversation,
Git artifact or diagnostic receipt. API enrollment listings can also return
secrets; do not use their raw output as read-only evidence.

Review the server's authentication, TLS, supported rule types/policies and JSON
protocol against the pinned client before distribution. Re-enrollment can replace
the prior configuration's rules, so preserve an approved rule/configuration
snapshot and verify rollback with the chosen server. A current setup guide does
not establish compatibility with a particular installed release.

## Profile distribution and credential boundaries

The existing baseline generator and `Invoke-SantaIntuneProfiles.ps1` publish only
the baseline set; they do not merge, upload or rotate a provider profile. Do not
drop a provider profile into `profiles/generated` or layer competing values for
`com.northpolesec.santa`. Prepare one reviewed effective configuration and an
explicit MDM object/assignment/ownership plan. The
[Santa configuration-profile guide](https://northpole.security/docs/santa/deployment/profile-configuration)
describes MDM custom-profile distribution; this repository does not automate it
for sync providers.

Treat enrollment URLs, tokens, extra authorization headers, private keys and
certificate passwords as secrets. Keep private keys in the managed device
credential channel and retain only nonsecret profile/configuration fingerprints,
provider revision, pilot scope and receipt identifiers. Do not log complete
profiles or raw provider responses. Local planning needs no new Graph scope;
provider administration and MDM publication need their own selected-target
authorization and permission review. Metadata does not grant either authority.

## Qualification and rollback gate

SANTA-007 tracks the separately authorized integration pilot. Before it runs,
bind the exact Mac, approved MDM group/profile IDs, server configuration, client
version and harmless test rule. Preserve the current Monitor configuration and
owned-object receipts; agree on the collection window and removal/rotation plan.

Record each outcome separately: profile delivery, effective Monitor mode and
prerequisites, authenticated preflight, event handling, complete paged rule
download, postflight, controlled execution against the intended rule, and rollback
observed on the Mac. Include authentication failure, interrupted download,
stale/offline client and provider-switch cases. A fixture, HTTP success or server
receipt cannot substitute for client behavior.

Remove only the exact pilot artifacts and assignments recorded in the approved
ownership plan. Revoke only
the exact enrollment/token/certificate selected for this pilot, after confirming
it is not shared. Verify server rule/configuration rollback and effective client
state independently; do not assume that disabling sync removes previously
downloaded rules. Preserve SANTA-002 and the broader live gates until proven.
