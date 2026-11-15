# Selected Azure-hostname TLS qualification

On 2026-11-15, the `httpspilot-20261115` VM qualified bounded staging and
production certificate issuance on its existing Azure-provided hostname. This
demonstrates one selected pilot, not a supported production default or completed
azd/browser/native-Mac setup.

The source was PR107 head `a6f0a191545549055e6c853ffb4f643f882c1759`, merged as
`ab405d800c68ad421e73fcceed32c0366c219503`. The original application image,
seven-container generation and Monitor boundary were preserved.

## Guarded trials and observations

Each trial started from fresh cached ARM ownership/linkage checks and a current
guest attestation. The latter bound the immutable VM instance, original runtime,
pinned Caddy binary, exact held configuration and loaded systemd command/unit,
absence of drop-ins/reload drift, unprivileged account, five-minute service limit,
connection-cap firewall and initially unbound TCP443.

The held configuration contained no reverse-proxy handler. It could return only
the selected503/Retry-After60 hold response or the wrong-host rejection; no
application request was admitted during these trials.

The operator retained the original NSG policy, then attempted one conditional
PUT using its observed quoted ETag. The temporary rule allowed only TCP443 to
the selected NIC's private IPv4 address, above the all-inbound deny. Ownership
and single-device/subnet constraints were checked separately; copied metadata
was not treated as write authorization. No port80 or SSH ingress was added.

| Observation | Result |
| --- | --- |
| ACME staging | TLS-ALPN issuance succeeded; isolated test client verified hostname/chain using only the four official staging roots |
| Staging certificate SHA256 | `f06b14253c1814d4a57e6951b12ce2fcda37177ac58b30891c459600ad95859c` |
| Production | Issuance succeeded; external Windows client verified hostname and chain with ordinary system trust and no staging roots |
| Production issuer | Let's Encrypt YE1 |
| Production expiry | 2027-02-13 05:18:48 UTC |
| Production certificate SHA256 | `a64a1858fd5840161048d3e7914cf567f543f006bcb922fbf8eae9f659868d78` |
| HTTP after each issuance |503, Retry-After60, exact application-held-closed body |
| Private production restart | Same certificate fingerprint and503 verified from loopback using ordinary Linux system trust |

Staging trust was confined to one test SSL context. No operating-system trust
store was modified, and no credentials or application data were sent to the
held public endpoint. Production used a separate private ACME state directory
and production-only issuer/fallback settings.

After each trial, a fresh conditional restore was attempted only against the
exact expected temporary policy. Readback confirmed `Succeeded` and the original
single deny-all rule at priority100. Both public listeners were stopped; ingress
was closed at the end. Successful source commands alone were not used as proof
of either an applied rule or a restored policy.

The retained production restart receipt is
`/var/lib/azd-santa-qualification/held-production-restart-20261115/complete.json`.
ACME account/certificate private keys remain on the selected VM in the protected
service state directories. They were not exported to chat, Git or diagnostics.

## Remaining acceptance

Actual scheduled/forced renewal, long-term DNS-name ownership and retirement,
CA rate-limit behavior across deployments, complete load/failure qualification
and automated customer deployment remain open. Reusing a certificate after a
restart does not prove renewal. Existing backup inventory/restore work must also
cover ACME state before production or wider rollout.

After the certificate trials, a separate 15-minute operator window restricted
TCP443 to the operator's source IPv4 and the selected VM private address. The
human administrator completed password and TOTP enrollment; computer-use
observation showed the signed-in Zentral welcome page with Santa configured.
Backend readback confirmed an active administrator, an enrolled TOTP factor
and a successful login at 2026-11-15 06:58:32 UTC. Conditional NSG restoration
then confirmed `Succeeded` and the original sole deny-all rule at priority100.
No setup token, password or factor seed is included in this evidence.

Automated customer setup and Intune-delivered native Mac sync/rule/event proof
remain separate. No new Mac SyncBaseURL or device credential was delivered.
Root Intune-only deployment, existing pilot assignments and Monitor mode remain
unchanged. Entra Easy Auth is deferred roadmap work in
[issue #108](https://github.com/nathanmcnulty/azd-santa/issues/108).
