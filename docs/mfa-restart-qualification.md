# Cryptographic MFA across Redis restart

Candidate developer qualification, not a live acceptance receipt. Neither the
driver nor the request script has been executed against a VM by adding these
files. Existing storage-helper tests cannot establish this captured-request gate.

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
the same actual container/image and project-local volume. The app confirms the
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
