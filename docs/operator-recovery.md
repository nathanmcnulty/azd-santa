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
