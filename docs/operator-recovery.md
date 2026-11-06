# Local operator bootstrap and lost-factor recovery

Candidate qualification tooling, not a live recovery or browser/TLS acceptance
receipt. The core image builder installs the original Unlicense command and
locked reset view automatically. No customer SQL, paid SSO, SMTP service, or
customer-authored script is required.

The authority is existing privileged host/container management access. This is
not a public recovery endpoint or a way for a browser operator to bypass MFA.
Recover only an independently verified owner; the command records a reason but
does not pretend an OS process proves a particular human's identity.

## One management command

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
