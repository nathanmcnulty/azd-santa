# Offline Azure-hostname HTTPS candidate

This is an unactivated developer candidate for [#64](https://github.com/nathanmcnulty/azd-santa/issues/64),
with [#58](https://github.com/nathanmcnulty/azd-santa/issues/58) still blocking ingress.
It changes no Bicep, NSG, DNS, installed service, azd hook or native policy.
`prepare_https_proxy.prepare(facts, absent_destination)` creates a private local
configuration and preparation receipt. It has no download, deploy or start command.
There is no switch that enables requests to reach Zentral: an unconditional 503
with Retry-After precedes the dormant reverse-proxy handler. Keeping that handler
allows Caddy to validate its actual transport/header fields without admitting traffic.

The facts interface is reserved for a future installer reading selected ARM
outputs. It binds tenant/subscription/environment, immutable VM ID, selected
`nic-santa-lab` and its `primary` IP configuration, the existing
`pip-santa-lab-egress` resource ID, public IPv4 and the exact lowercase
regional `cloudapp.azure.com` FQDN. It rejects URLs, wildcards, custom domains,
trailing dots and differently selected network resources. This input shape is
not an ARM attestation. The authoritative producer, NIC/PIP attachment/DNS
readback and tamper-bound azd output integration remain unimplemented; admins
must not construct deployment JSON manually. The existing Standard static PIP
is attached directly to that NIC; its current use for egress does not require a
second PIP, NAT gateway or NIC. It can be reused only after authoritative
VM/NIC/IP-configuration/PIP/DNS readback and separately approved TCP443 admission.
The current lab's deny-all ingress remains unchanged.

The rendered configuration has TCP443 only, HTTP/1.1 only, no HTTP redirect or
HTTP challenge, fixed staging ACME issuer, TLS-ALPN challenge only, exact host/SNI,
no on-demand issuance and a disabled admin API. Fresh owner-private state paths
hold ACME data persistently across future process restarts. Unix directories are
0700 and files 0600, under an owner-controlled parent without concurrent writers;
Windows preparation must never contain real ACME keys.
No remote proxy is trusted. Forwarded and client-certificate/remote-user headers
are deleted; any future upstream gets fixed host/protocol and direct remote IP.
Gunicorn remains at loopback8000 and datastores remain unpublished.

Declared candidate limits are 1MiB compressed request body, 16KiB headers,
5s header/10s request/15s response/30s idle timeouts, and four HTTP/1.1 upstream
connections with bounded dial/header/read/write timeouts. Logs exclude HTTP
access/error request records and use a private bounded rolling file. These
settings **do not establish** a hard inbound-connection or active-request limit.
Core Caddy's connection cap can queue requests; it is not #58's concurrency gate.
Shared Redis fail-closed budgets, credential HMAC, bounded key retention and
cardinality, deliberate 429 behavior, safe actionable admission diagnostics,
overload/Redis-failure/recovery and native retry proof are all outstanding.
Do not remove the 503 hold or expose this candidate before those gates pass.

`caddy.lock.json` pins official Caddy 2.11.9, source commit, archive digests and
the Windows validation binary digest. No custom plugins or unpinned Docker image
are required. The development binary was downloaded to ignored `out/` and is not
redistributed. SHA verification provides release integrity, not independent
signature/SBOM/vulnerability acceptance; a deployment must retain upstream notices.

`validate_windows` hashes the explicit binary, rejects configuration drift and
nonempty ACME storage, and invokes only `caddy validate`. The pinned
[Validate implementation](https://github.com/caddyserver/caddy/blob/0d98caea58f794f88e709b1bef2880996a471bca/caddy.go#L692)
uses `run(cfg, false)` and cleans up without starting applications. The fixed
[ACME issuer](https://github.com/caddyserver/caddy/blob/0d98caea58f794f88e709b1bef2880996a471bca/modules/caddytls/acmeissuer.go)
only prepares its issuer during Provision; issuance is separate. Fresh storage
contains no certificate needing background renewal. This bounded validation path
starts no listener and orders no certificate. It appends a separate exclusive
validation receipt; the original preparation snapshot keeps its not-run gates.

The exact pinned Windows binary successfully provision-validated a generated
synthetic configuration, with empty ACME storage afterward. This proves neither
Linux behavior nor resource limits, real traffic, DNS, trusted TLS or renewal.
Linux validation, actual controlled HTTP overload, staging issuance, a trusted
certificate and restart/renewal need separate authorized qualification.

Azure FQDN ownership/reuse and CA registered-domain rate limits still require
review; provider hostname convenience does not establish a certificate quota or
production guarantee. Primary references: [Azure DNS labels](https://learn.microsoft.com/azure/virtual-network/ip-services/public-ip-addresses#domain-name-label),
[label scope preview](https://learn.microsoft.com/azure/virtual-network/ip-services/public-ip-addresses#domain-name-label-scope-preview),
[Caddy release](https://github.com/caddyserver/caddy/releases/tag/v2.11.9),
[server limits/source](https://github.com/caddyserver/caddy/blob/0d98caea58f794f88e709b1bef2880996a471bca/modules/caddyhttp/server.go),
[HTTP transport/source](https://github.com/caddyserver/caddy/blob/0d98caea58f794f88e709b1bef2880996a471bca/modules/caddyhttp/reverseproxy/httptransport.go),
[CA rate limits](https://letsencrypt.org/docs/rate-limits/).
