# Affordable community deployment and optional Workshop

Research update: **2026-10-19**. This supplements [the reviewed offline spike](azure-sync-spike.md)
and does not replace its historical evidence. The goal is minimal total cost for
schools and other resource-constrained organizations, not a promise of zero cost.
Offer a free-software community path and preserve an optional North Pole Security
Workshop path. No server, SKU, enrollment implementation, or production license
choice is approved by this document.

## Recommended direction

1. Keep Intune delivery of Santa alongside Defender, initially Monitor and one
   device. Santa supplies execution policy; Defender supplies complementary
   antivirus/EDR and response. Intune distributes the package and profiles.
   The existing deployment-only baseline needs no Azure sync compute. It does
   not imply free Microsoft licenses or free administration.
2. Evaluate maintained **Zentral core** before committing to a custom server.
   Qualify its free-software runtime, operator MFA, device authentication, and
   operating footprint. A VM is a compatibility reference for its multi-service
   stack, not an approved production architecture or sizing recommendation.
3. If those gates fail or operating burden is disproportionate, evaluate a small
   independently implemented open-source public-protocol service. Container Apps
   is the initial hosting candidate; App Service is an alternative where existing
   expertise or warm capacity makes it worthwhile. This adds substantial software
   maintenance responsibility, not merely four HTTP handlers.
4. Offer Workshop through vendor-supported configuration for customers with the
   appropriate subscription. Do not duplicate its private protocol or claim
   feature parity, endorsement, or seamless migration.

Primary sources: [Santa sync](https://northpole.security/docs/santa/features/sync),
[Defender for macOS](https://learn.microsoft.com/defender-endpoint/microsoft-defender-endpoint-mac),
[Intune PKG deployment](https://learn.microsoft.com/intune/app-management/deployment/add-unmanaged-pkg-macos),
[public/private protocol commitment](https://northpole.security/blog/private-sync-protocol-for-workshop),
[Workshop configuration](https://northpole.security/docs/workshop/settings).
Current Workshop features must not be inferred to exist in pinned Santa 2026.8.244.
Monitor permits unknown executions; it is not a guarantee that explicit block
rules have no effect.

## Free-software qualification, not a blanket license claim

Zentral v2026.5.16 is pinned to
`feede7e0c28226ae25df87339cdda24f704ecf6f`. Its [license](https://github.com/zentralopensource/zentral/blob/feede7e0c28226ae25df87339cdda24f704ecf6f/LICENSE)
places `ee/` and other explicitly marked files under Zentral Pro Evaluation
License 1.0, which requires a separate commercial agreement for production use.
Other first-party files default to Apache 2.0; dependencies retain their own
licenses. Native [SAML/OIDC backends](https://github.com/zentralopensource/zentral/tree/feede7e0c28226ae25df87339cdda24f704ecf6f/ee/server/realms/backends)
are in `ee/`. Do not make paid Zentral Entra SSO a community prerequisite.

[Local login](https://github.com/zentralopensource/zentral/blob/feede7e0c28226ae25df87339cdda24f704ecf6f/server/accounts/views/auth.py)
and [TOTP/WebAuthn devices](https://github.com/zentralopensource/zentral/blob/feede7e0c28226ae25df87339cdda24f704ecf6f/server/accounts/models.py)
are outside `ee/`, but login permits password-only authentication when no
verification device is configured. Mandatory operator MFA, recovery, and least
privilege remain qualification gates. The [Dockerfile](https://github.com/zentralopensource/zentral/blob/feede7e0c28226ae25df87339cdda24f704ecf6f/Dockerfile)
copies `ee/`: disabling a feature is not proof of a free-only distributable image.
Before recommending a community package, inventory all runtime dependencies,
verify a core-only build/startup, preserve notices, and resolve license ambiguity.
No enterprise-code copying, license bypass, or production legal clearance is
implied. No qualified free-only Zentral deployment is delivered here.

## Identity: security is part of the community baseline

Human operators and devices have separate trust boundaries. A community server
must provide operator MFA, least privilege, audit history, and explicit rule
approval. Local MFA is a candidate for Zentral core. Optional Entra perimeter
authentication would not automatically map users or roles into Zentral: retain
application authentication and prevent direct access around the gateway. Native
Entra integration requires its applicable license or a separately reviewed,
independent integration; do not reuse proprietary backend code.

A custom operator application can evaluate [Azure built-in authentication](https://learn.microsoft.com/en-us/azure/container-apps/authentication)
with explicit authorization. Keep browser authentication off device-sync routes.
Do not assume every tenant user is an administrator or promise premium identity
features without [licensing checks](https://learn.microsoft.com/en-us/entra/fundamentals/licensing).
Santa's pinned client has no verified native Entra OAuth acquisition flow.

Unique device credentials, trusted enrollment binding, rotation, revocation,
request bounds, and secret-safe logging are minimum requirements, not paid
features. Never substitute a shared fleet secret or a claimed machine ID.
[Intune device-channel SCEP](https://learn.microsoft.com/en-us/intune/device-configuration/certificates/scep-profiles)
can deliver certificates to the macOS system keychain. Reuse a suitable existing
CA where available. [Cloud PKI](https://learn.microsoft.com/en-us/intune/cloud-pki/)
is optional and requires applicable licensing; an additional purchase may be
needed. Schools without an existing CA still
need a separately qualified no-license-fee enrollment solution; none is validated
by this document. Existing Intune, CA, and staffing resources are assumptions to
check, not universal school entitlements.

Santa's [pinned certificate code](https://github.com/northpolesec/santa/blob/dbe97b0aa0f5929feece5f4cbd2c69362c271abc/Source/common/MOLAuthenticatingURLSession.mm)
checks private-key access and signing. Test unattended service-context access,
renewal, and overlapping certificates; installation alone is insufficient.
Do not automatically grant all applications access to the key. Both
[Container Apps](https://learn.microsoft.com/en-us/azure/container-apps/client-certificate-authorization)
and [App Service](https://learn.microsoft.com/en-us/azure/app-service/app-service-web-configure-tls-mutual-auth)
forward certificates: the application must validate trust and device binding.
Combine immediate service-side disable with revocation checking and bounded
caches. Cloud PKI updates its CRL upon revocation; relying-party caching still
controls rejection latency. Zentral's existing auth gaps in the spike remain open.

## Rules, telemetry, and total operating cost

Distribute immutable, explicitly approved rule snapshots. Telemetry and AI must
never directly grant execution. Preserve the pinned client's empty-clean-sync
and postflight limitations from the spike; server receipts alone do not prove
endpoint application. Back up approved rules, device mappings, revocations, and
durable delivery state. Test restore without reviving revoked devices or rolling
policy backward. Define retention and recovery objectives before deployment.

Sentinel is optional. A filtered asynchronous [Logs Ingestion API](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-ingestion-api-overview)
integration is a possible design, not a verified built-in Santa connector.
Telemetry outages must not block rule synchronization. Minimize raw-event
collection, especially on school devices, and set explicit retention/access rules.

Compare total hosting, storage, backups, logs, networking, licenses, updates,
incident response, and operator hours. Existing dated [cost assumptions](../tools/sync_spike/cost-assumptions.json)
are illustrative meters, not equivalent full architectures, actual sizing, or
price guarantees. Free allowances may already be used. Keep the low-resource
baseline small; do not mandate Sentinel, Cloud PKI, Kubernetes, or enterprise SSO.
A larger established server may still cost less overall than maintaining custom
security software. Conversely, a multi-service stack may exceed a small school's
operating capacity. Measure rather than choose on compute price alone.

## Bounded evaluation and decision gates

First qualify software licensing, operator MFA, and device enrollment. No paid
experiment proceeds until exact resources, region, budget cap, duration, cleanup,
and permissions are separately approved. Proposed comparisons:

- Zentral: establish a VM reference; assess managed-container decomposition only
  if it can reduce measured burden. This is an architecture comparison, not a
  pure compute A/B test. Do not put production databases on ephemeral storage.
- Custom: initially compare Container Apps minimum replicas zero versus one.
  Add App Service only for a concrete warm-latency or operations question.
  [Functions hosting](https://learn.microsoft.com/en-us/azure/azure-functions/functions-scale)
  is a potential asynchronous telemetry component, not a default rewrite of the
  sync service. Do not force a four-platform test.

Hold client pin, fixtures, auth policy, region, and durability semantics constant.
Measure warm/cold sync latency against the pinned 30-second request timeout,
retry amplification, durable acknowledgments during interruption, duplicate and
cursor handling, revocation latency, cross-device isolation, restore safety,
monthly full cost, and operator hours. Set numerical acceptance thresholds before
testing; proposed latency targets are not platform guarantees. Stop for auth
bypass, acknowledged data loss, or unapproved rule exposure. Choose the simplest
passing design within the approved budget. Synthetic success still requires the
separately approved exact-version one-Mac qualification before interoperability
claims, expansion, or enforcement promotion.

## Follow-on ownership and unchanged authority

- [#37](https://github.com/nathanmcnulty/azd-santa/issues/37): affordable community
  architecture, core-only license/MFA/enrollment gates, optional paid Workshop.
- [#36](https://github.com/nathanmcnulty/azd-santa/issues/36): non-mutating planner
  distinguishes standalone, community public-sync, and Workshop capabilities.
  Never silently translate private features or create two rule authorities.
- [#33](https://github.com/nathanmcnulty/azd-santa/issues/33): actual credential,
  native sync, and safe provider-switch qualification, with owner approval.
- [#32](https://github.com/nathanmcnulty/azd-santa/issues/32): prior profile review
  remains unchanged. This document does not reopen or replace its evidence.

This is a docs-only continuation of draft #38. No executable code, profile bytes,
permission manifest, credential, resource, deployment, rule publication, merge,
or release changes are included. Proposed access requirements are gaps to assess,
not grants. Existing pilot and pending Live Response ownership remain unchanged.
