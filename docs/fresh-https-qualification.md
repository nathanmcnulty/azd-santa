# Fresh hostname-enabled private pilot

On 2026-11-15, `azd up --environment httpspilot-20261115 --no-prompt`
completed its first cold installation and normal client finalization in28m32s.
The selected environment enabled `SANTA_PRIVATE_BACKEND_INSTALL=true` and
`SANTA_PRIVATE_HTTPS_ORIGIN=true`. No build, initialization or finalizer replay
was required. This is a private qualification, not a customer-ready public service.

## Installation and application readback

The deployed source was PR104 head
`50a505a75ce645e2abc81a9f2e3f8a17660190ba`, subsequently merged as
`c0114a86330f6e163dd14b857a40ec1abe095867`.

| Binding | Observed value |
| --- | --- |
| VM instance | `d981aaca-d6ee-4f40-bf1a-d7688b8d1fac` |
| Installer bundle | `b22ccef25f99b11183fce59e931d6b7fcc3d016cb51e7fca997905c658c82546` |
| Application image | `sha256:9116cf15ab24d26cc88be86e5ae7f7485b8c6a09ea44f62aa8fc5082cd0d30eb` |
| Compose SHA256 | `4b8ad773bcbcfe3c1fa10233e1cc25a56cb95efa7d29e346ee57e0cc850a3e53` |
| Runtime manifest SHA256 | `1ed5c5b7a15f2d01280462d2417bcebbc6c0f50a62e1e5b22e838c91fcfe214c` |
| Container generation SHA256 | `a1750d8b4ee25dff71392bffcbb1ece24fa4ea49494132c057c5c27b6e5d878c` |

Fresh cached ARM ownership/linkage checks passed, and DNS resolved the owned
Azure hostname to its selected public IP. These reads did not open ingress.
Readonly guest inspection verified the immutable VM instance, active runtime,
seven running original containers and exact application image.

Inspection inside the actual web container confirmed the Azure HTTPS origin,
allowed hosts containing only localhost/127.0.0.1 plus that hostname, the exact
HTTPS CSRF origin, fixed-protocol proxy trust, forwarded-host trust disabled and
secure session/CSRF cookies. This qualifies delivery of the fresh settings hook,
rather than relying only on generated JSON or a mocked settings namespace.

## Private TLS policy and event loop

Pinned stock Caddy2.11.9 ran as the dedicated bounded service on loopback8443.
It used a two-hour synthetic certificate with the selected hostname as its SAN;
automatic certificate issuance remained disabled. The qualification configuration
used the selected hostname for the upstream Host, matching the public profile's
origin metadata. It did not expose TCP443, obtain an ACME certificate or change
the NSG. Edge configuration SHA256 was
`515c3aca1576021e09393194f19b73fb22efd7b078ab8ca3b4024d4ba0f1e544`.
The existing backend manifest and container generation were preserved.

The installed `test_live_zentral.py` suite then ran through this TLS proxy,
using explicit certificate verification/SNI and a connection pinned to IPv4
loopback. Ambient proxies and redirect following were disabled. A new private
synthetic fixture was created once; no real Mac profile or enrollment changed.

All24 semantic HTTP requests completed in24 attempts, with no429 pacing:

- Missing, invalid and cross-device credentials were rejected.
- Both synthetic devices received Monitor preflight and the expected six rules
  across two pages, then committed their rule ledgers through postflight.
- Empty and populated event uploads succeeded; the PostgreSQL synthetic event
  counter increased by two.

The retained guest receipt is
`/var/lib/azd-santa-qualification/https-sync-fresh-20261115/fixture.receipt-3f62fd7681654c3eb885e0d397954532.json`.
Fixture/ORM artifacts remain private because enrollment data is sensitive.
The HTTP client explicitly pins TLS1.2 or newer. Server event indexing was not
checked by this probe.

## Bounded integrated admission faults

A separate probe reused the already committed synthetic fixture. It did not
reinitialize the application, credentials, volumes or admission store.

- A six-second PostgreSQL table lock held one authenticated request inside the
  real application. Three competing TLS requests returned429 with Retry-After1;
  the held request completed with200 after the lock released.
- Pausing the original Redis container before permit acquisition caused503 with
  Retry-After1. Unpausing it restored200 without store initialization, permit
  reclamation or an application restart. The admission generation and empty
  occupancy matched the pre-fault state.
- A1,048,577-byte body returned413, and an oversized header returned431.
- All seven original containers remained running and unpaused; the runtime
  remained active and its generation file was unchanged.

The initial probe failed in its Python client's TLS write while the server was
rejecting the oversized body early. That failed case remains retained. The revised
probe used curl for body/header rejection and saved capacity/Redis checkpoints
before later cases. Its complete receipt is
`/var/lib/azd-santa-qualification/https-admission-fresh-20261115-v2/result.json`.
No fixture creation or database initialization was replayed.

These cases prove selected bounded contention, pre-acquisition Redis outage and
size rejection. They do not prove sustained-load resource containment, Redis loss
during held application work, the complete recovery fault matrix or native retries.

## Native-device and remaining gates

A separate Graph read confirmed the selected Mac was still managed and had
recently checked in. Filtered Intune report exports reported the Santa package
installed with no app error code, and returned all five Santa baseline profiles.
The last app-state change was in September; profile records were modified on
November5. These service records are distinct from a new endpoint execution.

The existing one-device health-script readback verified its ownership, content
hash and assignment, but its successful endpoint capture was from September27.
It does not prove current health. Issue105 tracks explicit stale-evidence handling.
No new backend SyncBaseURL or credential was delivered to the Mac.

Subsequent [held certificate trials](azure-hostname-tls-qualification.md) verified
production trust and certificate reuse after restart on the selected hostname.
Remaining pilot gates include broader stress/held-work failures, renewal and
automated public application deployment, automated customer setup,
Intune delivery and actual native rule/event receipt. Selected human browser
MFA enrollment/login is recorded in the subsequent trial report. Backup/restore,
upgrades and Container Apps parity remain broader open requirements. This result
does not qualify any of them or authorize wider deployment or Lockdown mode.
