# Local operator bootstrap and lost-factor recovery

Private qualification tooling; actual Django acceptance is recorded below and
does not prove browser/TLS or customer deployment readiness. The core image builder installs the original Unlicense command and
locked reset view automatically. No customer SQL, paid SSO, SMTP service, or
customer-authored script is required.

The authority is existing privileged host/container management access. This is
not a public recovery endpoint or a way for a browser operator to bypass MFA.
Recover only an independently verified owner; the command records a reason but
does not pretend an OS process proves a particular human's identity.

## One management command

The following is a developer qualification invocation. The final `azd` setup
and recovery flow must invoke it and privately deliver the short-lived link
without asking an admin to locate files inside a remote container. That wrapper
is still part of #53; this command alone does not complete customer setup.

Run through the selected deployment's existing authenticated management channel:

```sh
docker compose -f /private/evaluation/compose.json exec -T web \
  python server/manage.py operator_access bootstrap \
  --username admin --email admin@example.org --reason 'Initial administrator' \
  --output /var/zentral/operator-bootstrap.json
```

Bootstrap requires **no human account at all**, including inactive and remote
humans. Service accounts do not block it. Two concurrent bootstraps serialize
on an existing database row; they cannot both create a first administrator.
For an existing active local human, use `recover` with the exact stored username
and email and a new absent output path. Recovery does not promote, activate,
convert, or change that user's roles.

The command rotates an unknown password, deletes that human's TOTP/WebAuthn
factors and API tokens/OIDC issuers, and generates a ten-minute password-setup
link using the existing Django reset mechanism. Password/auth-hash rotation
invalidates old sessions, enrollment seeds, challenges and reset links; it does
not physically delete every stored session row. Other accounts, service tokens
and Santa device credentials remain untouched.

The private JSON output is created exclusively with mode 0600. The link is never
printed. Retrieve/open it through a trusted private operator channel; do not
paste it into Git, issues, chat logs, hosted CI, or Azure Run Command output.
The email address is an identity check, not a requirement to send mail.

The owner sets a password, signs in normally, enrolls TOTP, is logged out, then
signs in with password plus MFA. Password setup itself never logs the owner in.
Add a second verification method afterward to reduce future recovery work.
Invalid password submissions do not consume the link; successful password setup
does. The reset-confirm view locks the target row through token validation and
save, preventing two concurrently valid setup submissions.

An expired link requires an explicit new targeted recovery. Existing artifacts
are never overwritten. A failed command leaves its reserved artifact for
inspection. If access was committed but artifact writing/audit submission failed,
the error says so; do not assume rollback or blindly replay bootstrap. Inspect
the exact target and choose a fresh absent path for any deliberate recovery.
Audit submission is not proof of event-store indexing or delivery. Backup/restore
revocation continuity remains a separate qualification gate.

## Validation gates

Offline packaging/helper tests do not prove Django behavior. The separate
`test_operator_recovery_live.py` harness uses a newly named, absent-checked,
disposable PostgreSQL test database, never wipes/reuses the main database, and
tests actual management commands and CSRF-protected Django requests. It requires
the lab database role's test-database creation permission; it grants nothing.

Use the existing private runner with that harness and both the exact installed
MFA and recovery source SHA-256 values (`--policy-sha256`, `--recovery-sha256`).
The runner derives the expected explicit test count from the source and rejects
skips, mismatched hashes, partial or secret-bearing exported receipts.
`BaseEvent.post` is deliberately mocked in this isolated test database to avoid
mixing its user IDs into the main event store. Intended audit metadata is tested;
delivery/indexing, a real browser and real HTTPS remain separate unproven gates.
The runtime harness also submits genuinely signed counterless WebAuthn assertions
concurrently with recovery, in both user-row lock acquisition orders. It observes
real PostgreSQL locks with bounded waits, checks the final revoked-factor/session
state and new-password setup, and does not mock cryptographic verification. This
case requires the MFA form's user-first locking integration; it is not an offline
concurrency acceptance claim.
Security-cache keys use a unique namespace per harness run and test method while
retaining the actual shared Redis backend/options. Tests neither flush shared
caches nor collide with main-application budgets when test user IDs reset.

## Actual private acceptance, 2026-11-06

The combined core image
`sha256:44c06dadff5bc3a3182eec49b4c87ed8ee256a93c6a6da62622da1ce5a088921`
passed all **11 actual Django/PostgreSQL recovery cases**, with zero failures,
errors or skipped tests. The accepted recovery module SHA-256 is
`9fdddd7d3da5a629f18ecb731bd2f1f2d63849a87240036962ddbfc0282136b5`;
harness SHA-256 is
`d7d5db80284a6a725b5da33b3500662fc4c1cc89576fb0095d4f6ea90f53b28c`;
Compose SHA-256 is
`8280c8b972d698a0ce8b7d64ed7580988e894a8b8a732352b192216117125a8d`.
The private receipt is
`runtime-fixed/backend-hardening-recovery-current-user/receipt.json` under the
qualification root.

The cases exercised first-admin setup through password, TOTP and normal MFA;
existing-human/bootstrap conflicts; exact target/type checks; preserved roles
and other accounts; removed human factors/tokens/issuers; old session, challenge,
seed and reset-link invalidation; expired and reused links; simultaneous reset
and bootstrap requests; output collisions; and truthful post-commit output/audit
failure handling. The counterless security-key race used genuine ES256/COSE
verification in both recovery/login orders. PostgreSQL's `pg_blocking_pids`
confirmed the follower actually waited for the leader before release. Verification
now locks the user before its factor, matching recovery/factor-management order.

The same image passed all fourteen operator-MFA request cases, all 89 bounded
request HTTP checks, and the retained two-device full HTTP sync regression.
A separate event-store query counted exactly ten Santa events for that fixture.
The full-sync receipt is
`runtime-fixed/synthetic-fixture-backend-hardening.receipt-fb36ee760e534144b037ef29bab62e4a.json`.
The 139-test offline suite and hosted checks passed; independent review checked
the source transforms and recovery/security boundaries.

Earlier failed evidence remains private. The first recovery harness collided
with Django's reserved `client` attribute. After renaming the helper, two
assertions were corrected to accept a safe local login `next` query and one
baseline reset link was regenerated from current `last_login` state. These were
test fixes; the installed recovery module was unchanged. Subtest failure receipts
now export validated parent method names without private parameter values.
The failed process output in `runtime-fixed/backend-hardening-recovery-blocked/`
and failed receipt in `runtime-fixed/backend-hardening-recovery-clients-fixed/`
remain retained; the accepted run used a new namespace and evidence directory.

Audit delivery remains unproven because this suite deliberately mocks event
posting in its disposable database. The `azd` setup-link transport, fresh
Santa-only app profile, durable replay state/restore, real browser/TLS and native
Mac validation remain separate gates; #51/#53 are not closed by this result.

The later durable image passed the same eleven cases on a fresh nine-app Santa
profile, including its authenticated empty Santa page. The harness explicitly
closes each worker thread's persistent database connections and retains private
logs even if database cleanup fails. See [profile acceptance](santa-profile-qualification.md)
and [durable store acceptance](security-store-durability.md) for the newer bindings.
These results still do not prove indexed audit delivery or the final customer
setup-link transport.

The subsequent sealed-output image passed thirteen recovery cases, adding
recipient validation, real encryption and transactional/output-failure checks.
See [sealed setup acceptance](sealed-operator-setup.md) for exact image, module,
harness and receipt bindings. This extends private Django acceptance; the complete
Azure handoff and real browser/TLS setup remain open.

## Restricted-role recovery qualification fixture

`experiments/server/run_recovery_fixture.py` is the opt-in host wrapper for the
role-separated fresh core image. Supply the selected `--compose`, reviewed
`--harness` (`test_operator_recovery_live.py`), new `--destination`, immutable
`--image`, `--policy-sha256`, and `--recovery-sha256`. Run it only on the selected
privileged private Linux qualification host after fresh database/security-store
initialization. It is not a startup hook or a retry/upgrade tool.

The owner-only job consumes `migration.env`, creates a uniquely named absent
`azd_recovery_<24 hex>` database, migrates it, and grants the already-existing
runtime role CONNECT/TEMP, table DML and sequence access. It grants no permanent
schema CREATE, database/role creation, ownership or TRUNCATE. The migration
ledger remains read-only to runtime. A job-only configuration copy overrides
POSTGRES_NAME before Django loads; the selected main configuration is unchanged.

The subsequent request container inherits only normal `runtime.env`. It receives
read-only secret-free fixture configuration and a receipt binding the database
name/OID, image, Compose, environment and source hashes. It receives neither the
owner env file nor owner credentials. The harness verifies actual SQL identity
`zentral_runtime`, DB name/OID, role flags and denied permanent-schema/ledger/
TRUNCATE authority before any fixture cleanup. All 13 cases and their genuine
PostgreSQL row-lock/concurrent WebAuthn checks are preserved. `SimpleTestCase`
allows explicit database access without a global transaction or Django's
privileged CREATE DATABASE/flush machinery. Cleanup deletes only suite-prefixed
users (including their dependent credentials) and its exact group. Unknown rows
fail closed. Session rows can remain in this disposable DB until teardown;
sequences are never reset. Audit posting stays mocked to prevent isolated DB
object IDs entering the main pipeline.

Only accepted, known-terminal requests permit a separate owner teardown job.
It checks exact name/OID/owner and absence of active database backends before
DROP; it does not terminate other sessions. This assumes the selected trusted
host/DB owner serializes the private namespace, not a malicious concurrent DBA.
Timeouts, setup/request failures, identity changes and unknown outcomes retain
private evidence and the fixture for deliberate inspection. No automatic retry,
existing-volume migration, runtime privilege broadening or held-restart
adaptation is supplied.

Offline guards are not real PostgreSQL or request acceptance. Selected live
success-path qualification is recorded below; retained-fixture behavior on an
actual failed/unknown request still needs fault qualification. Broader main-data
isolation auditing, browser/TLS/native Mac, audit delivery and restore safety
remain separate gates.

### Actual restricted-role fixture, 2026-11-06

The fresh role-separated image and configuration in
[database-role qualification](database-role-separation.md#actual-private-qualification-2026-11-06)
passed owner fixture creation/migration, all 13 request cases with zero skips or
failures, and guarded owner teardown. Every request used SQL identity
`zentral_runtime` in `azd_recovery_938443ab9e854a5e91c64134`, OID `20123`.
The runtime had no CREATEDB, permanent-schema CREATE/ownership or TRUNCATE
authority. The owner credential remained outside the request process.

Recovery harness SHA-256:
`80fd82b20f5368a9390b8d8972a9e6e9e2e8ae3c72a498c92fa0fbf450c2aaa1`;
fixture module SHA-256:
`199bb4a26b106c3e7974abda2f05751ab7f89c6337c720a2087c92a604f45b1e`.
The receipt-bound fixture JSON SHA-256 was
`d0d30329306597097931199d9f8bb4976ac035bc931e6d10527ec8581d7dcf32`.
These are distinct source and identity-artifact bindings.

The accepted request result was followed by exact-name/OID/no-active-backend
DROP. A separate query through the main runtime then confirmed that database
was absent and that normal database authority still passed. The selected main
operator and Santa-state checks passed separately. This is not an audit of every
main database row or schema object. Audit posting inside Recovery13 remains
mocked; the real main-stack bootstrap/recovery audit delivery has its own receipt.

Private evidence under `runtime-santa-role-split-searchwait/` includes
`recovery-runtime-fixture/initialize-process.json`,
`recovery-runtime-fixture/requests/receipt.json`,
`recovery-runtime-fixture/teardown-process.json`,
`recovery-runtime-fixture/receipt.json` and the independent reboot-state receipts.
All 13 original method source slices remain pinned. Their preservation guard
uses normalized source rather than Python-version-dependent AST formatting;
the Windows CI failure was confined to that earlier test oracle, not runtime or
harness bytes.
