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
Provisioning installs `lock_tmpfiles_text()` as
`/etc/tmpfiles.d/azd-santa-https-lock.conf` and applies that exact file with
`systemd-tmpfiles --create` before first service startup. The non-truncating entry
creates the standard root-owned0600 xtables lock after each boot; the firewall
unit orders after tmpfiles setup. Its sandbox requires that file to exist before
systemd starts the process. Connlimit must also be available on the selected host.
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

These component proofs do not qualify the full overload/dependency fault matrix,
renewal, automated customer enrollment or actual Mac sync. Selected reboot and
[held certificate trials](azure-hostname-tls-qualification.md) have separate
evidence below; the trial report also records a separate restricted human
administrator enrollment/login. These do not establish general public
application readiness or a native Mac result.

## Held certificate qualification

`experiments/server/prepare_held_https.py` builds the held-service package from
the verified ARM endpoint facts and the pinned Caddy Linux AMD64 release archive.
It verifies the release SHA-256 before reading archive members and includes the
upstream license and readme. The package contains the selected endpoint identity,
held production config, five-minute service unit, firewall unit and boot lock
configuration. It has no
application service, proxy handler, enablement link or ACME state. Building it
does not write to Azure or start a listener. The opted-in fresh VM installer
uses the same file renderer after verifying the selected VM and endpoint. It
stages the files and creates the private service state while leaving the service
stopped. A certificate trial still requires an explicit activation step.

Before a certificate trial, use the same checkout and nested `azd` environment
that staged the service. With the selected VM running, run this from
`experiments/vm`.

```powershell
./Get-SantaHeldHttpsReadiness.ps1 -EnvironmentName $environment
```

The check confirms the ARM endpoint still has closed ingress. On the guest it
matches the VM identity, pinned binary, held configuration, and effective
systemd unit definitions. It requires private state, a disabled held unit, and
an unbound TCP443. It reports whether ACME storage is empty without reading the
contents. Use this check before activation. Kernel firewall enforcement, trusted
TLS, and certificate renewal require their own evidence.

`held_configuration()` supports only staging/production issuers and removes the
application proxy entirely. The selected hostname receives503 with Retry-After60;
the wrong-host route retains421. Certificate challenges do not admit application
requests. The pinned-binary loopback test verifies503 and no additional backend
call, using an explicit synthetic certificate without contacting ACME.

During a certificate trial, an external workstation can check the held HTTPS
response using the endpoint facts and digest captured before the trial. Reuse
the `.arm-facts.json` and its `facts_sha256` from the corresponding
`.arm-readback.json` produced by `New-SantaHttpsCandidate.ps1`.

```powershell
python -I ./experiments/server/probe_held_https.py `
  --facts <arm-facts-file> --expected-facts-sha256 <captured-sha256>
```

The probe checks the IPv4 DNS mapping and connects directly to the selected
address with the exact TLS server name and HTTP host. It uses the workstation's
default trust and accepts only the held response. Its JSON receipt includes the
certificate fingerprint and expiry. Compare fresh observations with the previous
certificate when qualifying renewal. This client check depends on current DNS
and workstation trust. Guest configuration and NSG state require separate proof.

`certificate_ingress_candidate()` is a pure proposed NSG body, not a writer or
deployment authorization. It requires the owned closed NSG, its single selected
subnet and exactly the selected NIC IP configuration; unknown/extra assignments
or rules reject. It preserves tags, proposes only TCP443 allow100 plus all-inbound
deny110 and returns the observed ETag for a mandatory conditional write. Fresh
cached ARM graph verification and a positively held guest configuration remain
caller prerequisites. No Azure call, grant, ingress change or certificate order
occurs by rendering. A live trial must retain its original policy and reconcile
an unknown write by reading that same target, without resubmitting it.

`certificate_ingress.py` pairs that proposal with the selected NIC's private
address. Its transaction saves the original and temporary policy before a
single conditional opening, requires exact readback before running the TLS
probe, and conditionally restores the original policy after the probe. An
unrelated rule, attachment, or tag change stops restoration. If the opening
outcome is unknown, observing the original policy alone cannot establish that
the opening will never take effect. Keep the attempt and reconcile that outcome.
The transaction requires a caller that checks the live held listener and
firewall and supplies bounded Azure transport and durable attempt storage.

Run the initial laboratory trial from `experiments/vm` with an existing,
running VM and empty ACME state. The command reuses the selected nested `azd`
environment and asks before any guest activation or Azure network write.

```powershell
./Invoke-SantaHeldCertificateTrial.ps1 -EnvironmentName $environment
```

`-WhatIf` checks the Azure selection without activating the guest service.
The trial records receipts in the environment's `certificate-*` directory.
It verifies the kernel TCP cap, starts only the five-minute held unit, checks
the trusted HTTPS response, restores the original rules, and stops the unit.
If the workstation exits during the window, the unit's five-minute limit still
applies. Use the saved ingress intent to reconcile the same NSG before retrying.
The command leaves VM power and the root Intune project under their existing
lifecycle controls. Fixture tests cover the new command path. A detached West US
2 NSG test against API `2024-05-01` verified that the current ETag allowed an
update and a stale ETag returned HTTP 412 with the new tag retained. The test
used no VM and the resource group was removed. The integrated command and
certificate renewal still need live VM validation.

On 2026-11-15, cold startup exposed a missing `/run/xtables.lock`: systemd rejected
the firewall namespace before its helper executed. Installing the fixed tmpfiles
entry restored the private service. Another Azure restart then verified the
proxy/firewall active, all seven original containers preserved, and the saved
synthetic database projection unchanged at SHA256
`83fdb03336b3c791b41eaf5d68a6ea0ea59c2628a6d08c5a3c031054def49c81`.
No public ingress was opened by this repair or reboot test.
