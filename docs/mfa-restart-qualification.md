# Cryptographic MFA across Redis restart

Private developer qualification; actual acceptance is recorded below. Adding
the files or passing storage-helper tests alone does not establish this
captured-request gate.

`run_mfa_restart.py` is a Linux host driver for one explicitly selected private
durable seven-service Compose. It requires `--allow-redis-restart`, exact image,
policy and harness hashes, and an absent private output directory. It checks
actual application images, project/network/volume bindings and the selected
Redis process before starting a newly named one-off test container. No Docker
socket is mounted into the app, and no new Azure service/grant is created.

The installed `test_mfa_restart_live.py` uses a newly named, absent-checked,
disposable PostgreSQL database and one explicitly initialized test Redis prefix.
Its synthetic passwords, keys, cookies and assertions stay in process memory and
the private test database; raw process diagnostics remain in host-created 0600
files. Shared-media IPC contains only bounded context hashes and phase/result
flags, published atomically. Audit event posting is mocked to avoid inserting
test-database identities into the main event store; delivery is not tested.

The request script constructs a genuine counterless ES256/COSE WebAuthn assertion.
It starts a second real CSRF-protected Django request which preloads the original
signed challenge/session before the first request succeeds. It also starts a
second independent TOTP challenge using the same actual, still-current code
after the first succeeds. Five real invalid MFA requests exhaust a third user's
budget. Pending requests wait inside an observing middleware wrapper; no verifier,
password authentication, outcome or clock is mocked.

Only after the ready phase does the host SIGKILL/start the selected Redis, retaining
the same actual container/image and project-local volume. Both mutations and
the readiness probe use the full previously inspected container ID; a removed
container fails the gate without touching a replacement resolved by service name.
The app confirms the
Redis process changed and the marker/settings are admitted before releasing its
pending requests. It discards idle pre-crash client connections so transport
errors cannot masquerade as replay protection. WebAuthn must reach the real
nonce claim and observe `False`; TOTP must observe its independent nonce claim
`True` followed by its used timestep claim `False`. Both requests must return
403 without proof, while the budget request must observe the real budget helper
return `False` and HTTP 429. Exactly the two first requests may emit successful
login signals, and those accepted sessions must still reach their profiles.

The restart has an 18-second wall-clock headroom bound. The TOTP code is checked
against real time before either replay is released; expiry, missing sessions,
connection errors, missing claims or disabled authentication cannot pass the gate.
The host requires a complete strict result and terminal process success. Failures
retain private logs, the one-off container and IPC for inspection; the driver may
stop only its own verified test container to bound execution. Failed isolated DB
cleanup requires inspection using its private logged name. Nothing is pruned or
automatically reinitialized, and the prior deployment is never switched.

Offline guard tests exercise rejection causality and host scope, not the real
database/Redis/crypto path. A future successful receipt would prove genuine Django
request/cryptographic replay rejection across one Redis process restart. It would
not prove TCP/browser/TLS/native-Mac behavior, host power loss, AOF corruption or
rewrite/load behavior, or current authority after an old backup restore (#54).
## Actual private acceptance, 2026-11-06

The real held-request test passed on the fresh nine-app Santa profile, using
image `sha256:04dad3522af470586d04ddd8ed555cc49e51cbc42756f5e202db8bef1131efef`
and policy SHA-256
`ca212a3ae403776e62f13708feb97e149684379359bb8f095b0c3712a39ed759`.
Compose SHA-256:
`21bee0c9cd7a7a54c1d61ac399c5814b302ed9f83b7f4dab82b8b91a29e25d55`;
request harness SHA-256:
`902b7c3f9570f48af5dbfe58fa41bb8fa625946612fb8dbe855bea40a455ede6`;
host driver SHA-256:
`2ac5274f5cdb3a26dd73f5607b276743997d51cc29e1b04844bb8bda85452738`.

After the inspected Redis container was killed and restarted with the same data
volume, its process identity changed and the admitted marker/settings passed.
The held counterless ES256/COSE assertion observed the real nonce claim return
false. The held still-valid TOTP assertion observed its new nonce claim succeed
and its already-used timestep claim return false. The exhausted real MFA budget
still returned false/429. Exactly the two original accepted logins were observed;
their sessions still accessed protected profiles. Expiry, transport errors or a
missing session were not credited as replay proof.

The private receipt is `runtime-santa-durable/held-mfa-restart/receipt.json`.
Its test process exited successfully after cleanup, and an independent query
still found exactly two Santa events for the device fixture. No real user,
native Mac, TCP admin login, physical security key or public TLS was involved.
Audit delivery was deliberately mocked for the isolated database. Host power
loss, old-backup authority reconciliation and workload sizing remain separate.
