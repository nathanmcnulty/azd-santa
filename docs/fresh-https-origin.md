# Fresh selected HTTPS origin

The optional private VM postprovision hook accepts the exact string
`SANTA_PRIVATE_HTTPS_ORIGIN=true` only alongside
`SANTA_PRIVATE_BACKEND_INSTALL=true`. Missing or `false` preserves the private
`https://localhost:8000` profile. This is fresh installation only: it never adopts
or edits an existing runtime, database, volume, image, configuration or container.
Old immutable bundles and their contexts remain historical.

The hook obtains the origin from `Get-SantaHttpsEndpointFacts`, using the selected
tenant, subscription, immutable VM instance and azd environment. The existing
cached ARM producer verifies the owned VM/NIC/PIP/DNS graph twice; there is no
administrator-authored URL or JSON. The selected `https_origin` is bound into the
exclusive installer context/ACTIVE reservation. A repeated submission cannot
change it. Before any package/runtime operation, the guest verifies its existing
IMDS VM/subscription/tag bindings and derives the one canonical Azure hostname
from the selected subscription/environment and IMDS region. Wrong-region,
cross-target, path/query/port/userinfo and noncanonical origins reject.

The fresh generator sets `api.fqdn` to that hostname. Pinned upstream
`zentral/conf/__init__.py` derives `api.tls_hostname` and `api_base_url()` as HTTPS;
there is no invented `api.tls` switch. Allowed hosts retain localhost/127.0.0.1 for
private health checks and add only the selected hostname. CSRF trusts only that
exact HTTPS origin. The existing settings-load policy hook consumes the explicit
profile and installs `SECURE_PROXY_SSL_HEADER=('HTTP_X_FORWARDED_PROTO','https')`,
keeps forwarded-host trust disabled and preserves secure session/CSRF cookies.
This hook is needed because pinned upstream does not copy arbitrary Django JSON
keys into settings. No secret or admission policy is changed: direct admission
retains the same fingerprint and deliberately shares the backend peer budget.

The web listener stays published only at `127.0.0.1:8000`. Trusting the protocol
header requires the separately reviewed host edge to replace client forwarding
headers and forward only its own fixed HTTPS indication. This profile creates no
Caddy service, listener, ingress rule, certificate or DNS allocation; existing
endpoint facts must already be available. It does not release the held proxy.
There is no existing-config migration or automatic upgrade path.

Stage propagation, completion `Origin` and client finalization all retain the
selected origin. The host rejects completion for a different profile; guest
terminal observation additionally binds the opted-in completion origin to its
context. Existing operator setup already checks the binding against actual
`api_base_url()`.

Offline tests cover real generated configuration/settings-hook behavior, default
private behavior, canonical target/region rejection before mutation, context
preservation/non-replay, stage propagation and selected cached-facts integration.
They do not prove Azure DNS/IMDS delivery, a built image, trusted TLS, browser MFA,
native Mac synchronization or ingress/load safety. Those remain separate actual
pilot acceptance; no cloud/authentication/guest operation was performed here.
