# Synthetic server credential rotation qualification

`experiments/server/test_credential_rotation_live.py` extends the evidence for
[#52](https://github.com/nathanmcnulty/azd-santa/issues/52). It does not implement
an administrator rotation API or change Intune/native profiles. The installed
`test_live_zentral.py` and earlier `test_credential_lifecycle.py` remain unchanged.
No tenant/guest/service operation was performed while preparing this harness.
Offline mocks and syntax checks are not real HTTP/DB or native acceptance.

The explicit run creates **one new unique configuration, business unit, two
enrollments and six rules**. Both devices are fake reserved UUIDs/serials; secrets
remain independently bound to UDID, serial and quota1. Configuration and requests
remain Monitor. Runtime view bytes must match the pinned continuing-authority
guard plus bounded decoder before any fixture is created. Compose must retain
the seven-service loopback-only contract and all three apps must match the
selected immutable image. Both local helper files must match explicit hashes
before either helper executes; no global test package installation is needed.
Read-only Docker inspection binds the actual selected web container, image and
exact loopback listener before fixture writes and again before success. It
collects no container environment secrets and rejects a replaced container.

The harness checks fresh revoked/expired enrollment, replacement credentials and
wrong serial/UUID without consuming quota; then checks continuing authority after
an interrupted page. A repeated unacknowledged page must return the exact same
five rules while retaining the same open session/postflight/counter state. The
entire staged ledger must match page identifiers, policy/version, session and
prior committed fields before and after retry. Selected rule-row IDs and the
page cursor may regenerate, while normalized semantics must remain equal. The
old credential is revoked and rotated with different bytes. All four stages
reject revoked, expired, retired and cross-device credentials with an exact
before/after comparison of selected authority, machine/rule-ledger and
application event-counter fields after **each** request. This is not an audit of
every database side effect. A positive-shaped denied
event guards against hidden counter mutation. Legacy URL credentials are tested
only because the pinned upstream supports them: a header takes precedence,
malformed/wrong-scheme headers cannot fall back, and both valid header-over-old-URL
and valid replacement legacy requests complete. Production clients should use
headers; URL credentials can enter ordinary access logs.

Exactly one rule actually present in the interrupted page changes from Blocklist
version1 to Allowlist version2. The fixture must retain `ruleset_id=None`;
validation excludes only the pinned model's nullable/nonblank RuleSet relation,
matching the upstream update form's omission, while preserving policy/version,
model, uniqueness and constraint validation. Replacement preflight must reconcile the lost
clean session **without requesting a clean** and with coherent nonzero reported
counts (six binary rules, zero other types). The prior session must still be
open/clean with no queued forced sync, so a forced clean or zero-count fallback
cannot mask reconciliation. A stale cursor cannot skip the current rule set. Both devices
receive two exact pages and finish with the exact committed server ledger,
including the changed rule and no pending cursor/session/staged-removal state.
The unchanged second credential remains functional until its deliberate expiry;
the rotated first credential remains functional afterward. Enrollment counters
must remain1 despite repeated successful syncs. This proves no client-local rule
application or physical hardware identity from the wire.
A positive event using the replacement credential must increment the isolated
application counter once. Event-store indexing remains a separate gate.

## Coordinator-only private live-run contract

Execute later only on the explicitly selected initialized private Linux host,
as root, with cached deployment/source/readiness evidence already accepted. Do
not upload or run this through an azd production hook. Copy the reviewed new
harness beside the unchanged selected helper files under a root-owned private
qualification source directory; verify their exact bytes and the selected image
before invocation. Use an absent owner-private evidence directory. A bounded
coordinator-owned job (for example 30 minutes) must own timeout/termination and
observation; the harness itself never restarts a test or service.

```text
python3 -I /var/lib/azd-santa-qualification/<reviewed-source>/test_credential_rotation_live.py \
  --compose /var/lib/azd-santa-qualification/<selected-runtime>/compose.json \
  --destination /var/lib/azd-santa-qualification/<absent-private-evidence> \
  --expected-image sha256:<selected-reviewed-image-id> \
  --expected-helper-sha256 d0be67e5d8d8f134adb73dbe78cbab816aac110133f0ac7895dc1805f57a496f \
  --expected-generator-sha256 112977b1598649c088e646d40df919ec810fd0ff8541e1d294f8894698ea8304
```

The example placeholders are coordinator deployment bindings, not customer JSON
or remote-script tasks. The expected view SHA is
`205315d6cf592fe53efaebb58fb6843c4f17f842d85b7c74816964385df1ec6a`.
The command prints only `SANTA_CREDENTIAL_ROTATION_OK` after complete success.
Require exit0 and the unique private `receipt.json` with `passed:true`, matching
source/helper/view/image/Compose hashes and all observations. `attempt.json`,
private immutable fixture epochs and partial ledger snapshots are retained.
Existing helper ORM output is also captured privately beside Compose; it can
contain fixture secrets and must never be pasted into public issues or chat.

A timeout/disconnect is an unknown mutation outcome. Preserve the same evidence
and synthetic objects; inspect before any deliberate new run. Do not overwrite,
reinitialize, silently resume, delete unrelated objects or restore old secrets.
The in-place synthetic secret replacement is a test primitive, not a supported
customer lifecycle workflow. No privileged migration/owner DB credential is used:
ORM requests run in the existing application container as its restricted runtime
principal. Backup restoration must remain closed until authoritative revocation
and rotation state is reconciled; this harness does not qualify restore behavior.
Native MDM delivery, profile rotation, endpoint retry/application and #52 completion
remain separate gates.
