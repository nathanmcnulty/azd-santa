# Guarded HTTPS pilot edge

`https_edge.py` reuses the pinned stock Caddy configuration. Its default private
profile binds IPv4 loopback port 8443, loads an explicit development certificate
and disables automatic issuance. Rendering starts nothing and changes no Azure
resource. The historical held candidate remains unchanged.

Staging and production profiles render only IPv4 TCP443, exact host/SNI,
HTTP/1.1, fixed ACME issuers and no HTTP challenge/redirect or admin API.
Production never falls back to staging. Public profiles require the separately
qualified hostname, operator MFA, admission and selected-network activation;
rendering a file does not satisfy those gates.

The pilot retains direct application admission. Requests conservatively share
the backend transport-peer source budget; this is not per-client attribution or
fleet fairness. Caller forwarding/identity headers are removed, the upstream
host/protocol are fixed, ambient upstream proxies are disabled and upstream
connections are capped at four. Existing body/header/time limits remain.

The Caddy unit runs as the dedicated unprivileged `azd-santa-https` account, with
192 MiB memory, no swap, 50% of one CPU, 64 tasks and 256 file descriptors. Its
only capability is low-port binding; its filesystem is read-only except its
dedicated private state directory. Provisioning must validate the account and
root-owned executable/configuration, and assign only new proxy state to it.
This component does not create/adopt accounts or install services automatically.

The required root firewall unit establishes a dedicated INPUT chain before
Caddy starts, including after reboot. A global IPv4 SYN connection limit of 16
rejects excess TCP connections with reset. It does not modify unrelated rules,
flush tables, open NSGs or allow new traffic. Existing/partial/unexpected chain
state rejects instead of being reset. A missing/moved INPUT jump also rejects.
The xtables lock must exist and connlimit must be available on the selected host.
Concurrent unrelated firewall writers and arbitrary later root changes are not
contained by this helper. Failures preserve the restrictive partial state.

Seven offline cases cover configuration, header trust, service bounds and firewall
preservation/rejection. An opt-in pinned-binary loopback regression also checks
the actual headers received by an echo backend. Set `SANTA_CADDY_EXE` to the pinned
binary when running `tests/test_https_edge_live.py`; no ACME request is made.

On 2026-11-15, the selected Ubuntu pilot started the dedicated unprivileged
private service, preserved its original backend generation and returned HTTP302
through synthetic-certificate TLS. Kernel connection qualification accepted16
simultaneous connections and rejected the next4; systemd resource limits matched
the rendered unit. This observes configured limits, not stress/CPU containment.

Actual Linux header inspection found that proxy wildcard deletion also erased
the fixed HTTPS metadata. The correction removes incoming wildcard headers in
an earlier handler, retains fixed Host/X-Forwarded-Host/X-Forwarded-Proto and
deletes the proxy-generated X-Forwarded-For. Both the pinned Windows regression
and a separate Linux loopback echo fixture passed the corrected behavior.
The running private service remains the original staged version; its old
configuration and the failed header observation are retained as evidence.

These are private component proofs. Integrated overload/dependency failure,
renewal/reboot, trusted certificates, operator enrollment and actual Mac sync
remain unqualified. Public ingress remains closed.
