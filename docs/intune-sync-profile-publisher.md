# Publishing the owned Santa sync profile

`scripts/Invoke-SantaIntuneSyncProfile.ps1` defaults to `-Action Disabled` and
makes no requests. `Inspect`, `Apply`, and `Observe` use an already authenticated
Microsoft Graph delegated context; this command never signs in or requests consent.
Use PowerShell 7.6 and Microsoft.Graph.Authentication in a dedicated process with
no concurrent Graph work. It temporarily sets SDK MaxRetry=0 and ClientTimeout=30,
then restores both settings. Install/import the SDK separately if unavailable.

Supply the exact expected tenant/account, static pilot group ID/name, Entra device
**object ID and deviceId**/name, existing configuration object ID, and original
five-profile ownership receipt. Inspection verifies complete unpaginated membership,
exactly one Mac, the device identity, one owned configuration, and its sole unchanged
group assignment. It returns a current payload SHA-256 for review. It does not
retrieve or report endpoint health.

For explicit `-Action Apply`, also supply `-ExpectedCurrentProfileSha256`,
`-ExpectedSyncOrigin`, `-ProviderProfilePath`, `-QualificationPath`,
`-ReviewEvidencePath`, and a fresh absolute `-CheckpointPath` in an existing local
directory. The provider plan qualification must bind the exact reviewed profile
bytes, current client/baseline, pinned Zentral revision and offline source review.
Synthetic fixtures are rejected. The expected origin is an HTTPS origin without
userinfo, path, query or fragment; the only accepted sync path is
`/public/santa/sync/`, with one `Zentral-Authorization: Bearer ...` enrollment header.
Provider inputs contain a credential: retain them only in an operator-controlled
private directory, avoid transcripts/debuggers and delete them through your normal
secret-handling process when no longer needed. Do not paste them in issues or logs.
The public offline plan remains digest-only and `publicationAllowed=false`.
Explicit Apply is a separate operator action, not authorization inferred from a plan.

The command preserves the current owned profile's organization, identifiers and
UUIDs, requires every baseline setting (including Monitor mode and StaticRules),
and merges only the two sync settings. It reads the full scope again, writes an
exclusive nonsecret intent checkpoint, and submits one PATCH to that configuration
object containing the fixed macOSCustomConfiguration type plus only payload and
payloadName. It never creates profiles, posts
assignments, changes the other four profiles, or changes the device mode. The three
required cached scopes are DeviceManagementConfiguration.ReadWrite.All,
Group.Read.All and Device.Read.All; metadata is not permission to grant them.

A fresh payload and complete assignment readback must match before success is
reported. Concurrent tenant changes remain possible between read and PATCH;
If-Match is supplied only when Graph returns an ETag, and this command does not
claim transactional assignment/membership protection. Limit unrelated tenant edits
during this one-device operation. SDK timeout bounds each request, not the entire
workflow or server-side execution.

Any uncertain PATCH result preserves the checkpoint and does not retry. Keep the
same selected target and receipt, and use `-Action Observe -CheckpointPath ...` to
read the exact object. Observe reports desired, previous or drifted payload with
no mutation. Reusing the same intent path for Apply fails. A new path is not a
safe way to retry an ambiguous operation: resolve Observe/drift and review first.
Checkpoints/results contain only identifiers and hashes, never the profile or token.
Local privileged tampering with inputs/checkpoints is outside this boundary.

The ordinary baseline publisher now rejects updating an active sync payload unless
both `-AllowProfileUpdate` and the distinct `-AllowSyncRemoval` are explicit.
Removing the sync settings from a profile does **not** establish that previously
downloaded rules were cleared. Native macOS profile delivery, Santa sync/rule receipt,
execution and rollback behavior remain separate unproven gates. Offline mocked
publisher tests are not Intune acceptance or native qualification.
