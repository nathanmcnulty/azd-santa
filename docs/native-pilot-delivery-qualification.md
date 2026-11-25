# Selected native-pilot delivery qualification

On 2026-11-15 UTC, the selected private VM completed actual one-device backend
enrollment and owner-private profile export, followed by an Intune payload update.
These operations prepare the device for policy sync. The November 25 endpoint
readback below records what the Mac reported and where sync stopped.

## Maintained path and verified boundaries

The source is [PR #110](https://github.com/nathanmcnulty/azd-santa/pull/110)
(owned-profile publication, merge `d14656211323a67767b8115dc2777987497c3295`)
and [PR #112](https://github.com/nathanmcnulty/azd-santa/pull/112)
(enrollment/export, merge `af1387aefc82bcb467d0156fbe06a200a922504d`). Both
passed their hosted checks and independent source review. Integrated local
template/schema validation and 64 focused checks passed before live invocation.

The default no-cloud enrollment Plan was verified first. Explicit Create then
verified the selected cached account, immutable VM instance and original running
runtime, created a separate Monitor configuration and serial/hardware-UUID-bound
quota-one enrollment, and returned recipient-encrypted credentials. The complete
profile was written with owner-private access. Only nonsecret record IDs, hashes
and the output path were printed. No administrator account was created or reset
by this enrollment operation.

An initial read-only publisher check exposed a real SDK boundary: Graph
Authentication 2.38 returns ClientTimeout as TimeSpan but its setter accepts
integer seconds. The corrected command passed actual inspection of the selected
tenant/account, static one-Mac group, immutable Entra object/device IDs, exact
owned configuration and sole assignment. SDK settings were restored to three
retries and 300 seconds afterward. Offline mocks alone did not prove this boundary.

The source-reviewed provider material matched the pinned client, backend revision
and baseline. Explicit Apply updated the existing configuration, retained its
identifiers, organization, Monitor settings and StaticRules, and verified the
complete resulting payload and unchanged assignment. No extra profile was created
and the other four profiles were not updated. Graph accepted a subsequent sync
request using an already available delegated permission; no new consent or grant
was requested. Acceptance of that request does not establish device delivery.

## Bounded live window

The original application generation and all seven running containers were retained.
The production certificate remained the previously qualified certificate, verified
with ordinary Linux trust against the selected hostname; the proxied login returned
HTTP200. No certificate trust bypass was used.

A separate native trial limited inbound TCP443 to one canonical global IPv4, taken
from the selected Defender pilot's last reported external address, and the exact
VM private address. That address was a connectivity hint, not device identity or
current-network proof. The app still required its separate administrator MFA and
device credentials. Source-IP restriction does not distinguish devices sharing NAT.

Fresh guest checks verified the exact pinned proxy/configuration, loaded unit,
service-user configuration validation, firewall and application security store.
The listener started at 07:50:10 UTC with a 30-minute maximum. After the operator
confirmed the Mac was unavailable, conditional NSG restoration verified Succeeded
and the original sole deny-all rule at priority100. A guest readback confirmed the
listener stopped and TCP443 unbound; Azure then confirmed PowerState/deallocated
at 08:06 UTC. Disks, application data and private receipts were retained. A listener
timeout alone does not restore Azure networking. This is not a general public
endpoint or completed automated customer deployment.

The selected Monitor configuration contains one qualification BLOCKLIST rule for a
synthetic hash with no test executable deployed. This permits rule-receipt checking
without changing execution mode or blocking a real application. All-event upload
remained disabled (shard zero); no background collection expansion was introduced.

## Endpoint readback on November 25

The selected Defender macOS record's Entra device ID matched the retained Intune
report for the authorized pilot. On November 25 at 12:58 UTC, the revised
published health script ran through Defender Live Response. Its library digest
matched the reviewed script. The endpoint reported Monitor mode and an active
and enabled Santa Endpoint Security extension with the expected team ID. The
local checks confirmed System Integrity Protection and reported no configuration
errors.

The Mac's configured sync hostname matched the selected HTTPS pilot. Santa
reported no successful full or rule sync and its preflight timed out. Azure
reported the HTTPS pilot VM deallocated. Defender marked the action succeeded
and the diagnostic returned a nonzero script exit. The receipt preserved both
outcomes.

At 13:10 UTC, the profile diagnostic on the same Mac successfully read both
the text and XML inventories. It found the Santa configuration identifier and
the expected inner payload UUID. The template's outer payload UUID was absent
from the device XML. This establishes the observed local payload markers and
runtime sync hostname. The complete installed payload bytes and a fresh Intune
service report remain unverified. No Intune object or assignment was changed
during these checks.

## Evidence still required

At publication, the control-plane payload readback was verified, while the Mac's
prior profile-status report predated the update. That old compliant status cannot
prove the new payload arrived. The backend readback still had zero enrollment
requests and no native machine; the device's last check-in remained 06:47:46 UTC.
The November 25 readbacks add current local profile and health evidence.
Successful preflight and postflight, native rule receipt, event ingestion,
execution and rollback remain separate gates. The original baseline snapshot
and new intent/ciphertext receipts remain private.

The offline planner intentionally continues to report publicationAllowed=false;
its assertions and hashes are not deployment authority or native acceptance.
Actual publication was a separate explicit operation under the authorized pilot.
Stable azd orchestration, current-authority recovery, renewal, supported upgrades,
full backup/restore and Container Apps parity remain unfinished. Entra Easy Auth
is deferred in [roadmap #108](https://github.com/nathanmcnulty/azd-santa/issues/108).

## Resume

Wake the same selected Mac and keep it online before starting another bounded
window. Reuse the retained installation binding, existing enrollment and private
profile/Intune intent; do not run Create again or reset the administrator. Recheck
the current account, device/group/profile identities, network address and runtime.
Verify current Intune receipt and actual backend preflight/postflight before
advancing to rule, event and rollback checks. Keep Monitor mode and the one-device
scope, and close the window/deallocate idle compute again afterward.
