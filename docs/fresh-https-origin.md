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
administrator-authored URL or JSON. The origin and ARM endpoint facts are bound
into the exclusive installer context/ACTIVE reservation. A repeated submission
cannot change either. Before any package/runtime operation, the guest verifies its
IMDS VM/subscription/tag bindings and derives the one canonical Azure hostname
from the selected subscription/environment and IMDS region. Wrong-region,
cross-target, path/query/port/userinfo and noncanonical origins reject.

On the first run Azure can report a selected resource still provisioning, omit
pending endpoint details, or change a resource between consecutive reads.
The install hook takes up to two additional read-only observations in those
cases, with 5 and 10 seconds between attempts. It still requires two matching
reads and the original deny-all inbound policy before submitting installation.
Unexpected identity, linkage, network policy, and CLI errors stop the hook.

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
headers and forward only its own fixed HTTPS indication. The installer stages
the [held certificate service](https-edge.md#held-certificate-qualification)
and its private state on the VM. It downloads and verifies the locked Caddy
release on the guest and records `install-evidence/held-https.json` after checking
that TCP443 remains unbound. The staged service files contain no application
route. Staging leaves systemd activation, the NSG, and certificate issuance to a
separate trial. A failure retains the original install job and private evidence.
Existing runtime and HTTPS service files are never adopted or migrated.

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

Subsequent [fresh private qualification](fresh-https-qualification.md) passed cold
azd installation/finalization, actual image/settings readback and24 synthetic
policy/event requests through loopback TLS. Trusted public TLS, browser MFA,
integrated admission faults and native Mac acceptance remain open.
