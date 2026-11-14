# Synthetic server credential rotation qualification

`experiments/server/test_credential_rotation_live.py` extends the evidence for
[#52](https://github.com/nathanmcnulty/azd-santa/issues/52). It does not implement
an administrator rotation API or change Intune/native profiles. The earlier
`test_credential_lifecycle.py` remains unchanged. The live helper is now explicitly
versioned for the six-volume admission candidate; historical receipts below
continue to identify their original helper/image and are not reinterpreted.
Harness preparation used offline mocks and syntax checks. The subsequent
selected private server run passed the actual HTTP/DB checks below; neither
stage establishes native acceptance.

## Selected private server result

On 2026-11-07, the reviewed harness (SHA-256
`776a1c3f8d96849091e3c3aa85f4f02bea19d1055fd05befb0ceb371f9c97433`)
completed with exit0, `passed:true` and 76 observations on the private VM in
`rg-azd-santa-vm-privatehook2-20261107`. The selected application image was
`sha256:0ba39cf8b1d2a14b49797220d5ef319f08b9d6fcd61d457f08f359472b98e93a`;
the Compose SHA-256 was
`d9f939ce2147d6503c5cdf152ecf3db4eb63e4f9d890dc3c71544e417a80c2ca`.
The retained job was `azd-santa-rotation-a1b0fccc.service`, invocation
`8c7a6ef7df2040e8b9406a0dea4b8f4b`. Its owner-private evidence directory is
`/var/lib/azd-santa-qualification/rotation-a1b0fccc`; do not publish its fixtures.

The run covered denial across all four sync stages, replacement credentials,
interrupted page retries, reconciliation without a forced clean, changed rule
policy/version, exact selected rule ledgers and enrollment counters, and one
positive application event-counter increment. Denied-request invariance covers
the inspected database projection, not all possible database side effects.
The event counter does not prove search indexing or native event delivery.
This image predates the admission-control candidate; it does not qualify that
candidate. Failed earlier harness attempts remain retained separately.

That historical helper SHA was
`d0be67e5d8d8f134adb73dbe78cbab816aac110133f0ac7895dc1805f57a496f`.
The subsequent mount-only six-volume adaptation had SHA
`9ffc5d414a17bb85c15a96e7b5b3bc5b9fe296457aa34ac2f153b70ff7397987`.
The current `synthetic-loopback-admission-six-volume-v2` helper has SHA
`49f6bf61f11563cc0bc69701b3529c6ce39569a1301a20fe965e9b2cfb8fec8e`.
Its retry/pacing behavior and new source bindings are offline-tested only;
the selected private server result above does not qualify these new bytes.

The subsequent controlled VM reboot returned all seven original container IDs
with the same image and Compose bytes. Boot ID changed from
`ebf57b43-745d-4b0d-9394-f9637e7a8bfb` to
`c1c34482-647f-455c-abbb-05d1e4f93baa`; the selected state SHA-256 remained
`f6aa986e9c77ef63514d4d8539437d8e99596300a4559ea691dc7c7efc52f8fd`
(two machines, twelve ledger rows, enrollment counts `[1,1]`, one expired
credential). Comparison occurred before further HTTP requests. Afterward,
sixteen actual HTTP denials covered retired header/legacy credentials, expiry
and cross-device use across all four stages, with the selected database
projection unchanged after each denial. An empty event upload using the current
credential returned200. The exclusive `selected-reboot-before.json`,
`selected-reboot-after.json` and `selected-reboot-http.json` receipts remain
beside the private runtime Compose file. This is ordinary reboot persistence,
not backup/restore or graceful worker-drain acceptance.

The explicit run creates **one new unique configuration, business unit, two
enrollments and six rules**. Both devices are fake reserved UUIDs/serials; secrets
remain independently bound to UDID, serial and quota1. Configuration and requests
remain Monitor. Runtime view bytes must match the pinned continuing-authority
guard plus bounded decoder, with or without the separately reviewed admission
overlay, before any fixture is created. The expected view hash is required and
must be one of the two known revisions below; unknown revisions fail before
helpers or fixture actions. Compose must retain
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
harness beside the exact selected, reviewed helper files under a root-owned private
qualification source directory; verify their exact bytes and the selected image
before invocation. Use an absent owner-private evidence directory. A bounded
coordinator-owned job (for example 30 minutes) must own timeout/termination and
observation; the harness itself never restarts a test or service.

```text
python3 -I /var/lib/azd-santa-qualification/<reviewed-source>/test_credential_rotation_live.py \
  --compose /var/lib/azd-santa-qualification/<selected-runtime>/compose.json \
  --destination /var/lib/azd-santa-qualification/<absent-private-evidence> \
  --expected-image sha256:<selected-reviewed-image-id> \
  --expected-helper-sha256 49f6bf61f11563cc0bc69701b3529c6ce39569a1301a20fe965e9b2cfb8fec8e \
  --expected-generator-sha256 facf4584ce9e7dfe6fb67685b9618d33f89b816fae48234334360f055c318e01 \
  --expected-view-sha256 55efd66eb2f7a281d7182a6aaa392f54fb449e5035213a22ce28253b9635ef32
```

The example placeholders are coordinator deployment bindings, not customer JSON
or remote-script tasks. The legacy decoder/continuing-authority view SHA is
`205315d6cf592fe53efaebb58fb6843c4f17f842d85b7c74816964385df1ec6a`;
the admission-aware view is
`55efd66eb2f7a281d7182a6aaa392f54fb449e5035213a22ce28253b9635ef32`.
Select the known reviewed image's actual view; do not discover/adopt unknown bytes.
The command prints only `SANTA_CREDENTIAL_ROTATION_OK` after complete success.
Require exit0 and the unique private `receipt.json` with `passed:true`, matching
source/helper/view/image/Compose hashes and all observations. `attempt.json`,
private immutable fixture epochs and partial ledger snapshots are retained.
The full 76-observation rotation inventory remains required; the request-limit
harness retains all 89 semantic cases. Both clients reuse `http_send` inside
the selected live helper. Only explicit 429 is paced/retried, using exactly one
decimal `Retry-After` value from 1 through 60 seconds. Missing/duplicate/date,
malformed or oversized headers fail. No transport error or other HTTP status is
retried, and 429 never counts as an expected 401/403/400/413/415 or success.
The same request bytes/headers are resent after the admission rejection.

Nonsecret `http_transport` metadata records 429 waits separately from semantic
case results, including request/attempt ordinal, requested delay and completion.
Rotation failure receipts retain that metadata too. The transport allows at most
four attempts per request, 512 total HTTP attempts and 600 seconds of requested
waits. Monotonic budget checks use 240 seconds per request and 1200 seconds per
HTTP session, with each network call bounded by a 15-second socket timeout.
These checks do not cancel server work or replace the coordinator's absolute
30-minute job/termination bound. A network timeout remains an unknown outcome,
with no automatic retry, fixture replay or admission-state reset.

Because the helper bytes change, any existing source-bound runtime manifest,
installer bundle or supervisor inventory must be deliberately rebuilt/rebound
by its owner before installing this revision. Do not overwrite an existing
controller's bound helper to make a qualification run pass. Historical evidence
continues to use its original source; this candidate is not a native retry proof.
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
