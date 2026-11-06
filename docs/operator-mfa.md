# Local operator MFA qualification

The optional private core image installs the original `operator_mfa.py` policy
automatically. Customers must not assemble middleware or edit Django settings.
This is work toward #51, not a production or native-Mac acceptance claim.

The intended flow is password sign-in, scan the supplied authenticator QR code,
confirm the code, then sign in with password plus authenticator. First-time
password authority lasts ten minutes and permits only TOTP setup and logout.
The setup seed is bound to the server-side session. Existing password-only or
legacy boolean-MFA sessions must sign in again.

A successful core TOTP/security-key assertion creates a versioned proof bound
to the user, password/session-auth hash and stable verification-method material.
Names, WebAuthn counters and update timestamps are excluded. Proof lasts at most
eight hours from actual MFA; factor changes do not renew that clock.
Password/factor changes invalidate other sessions. All local human
operators are covered, including superusers and users without staff status.
Remote/realm and service-account browser sign-in are unavailable in this policy.
Existing PBAC authorization still runs after the MFA gate.

Human API tokens are rejected centrally, including existing tokens. Dedicated
service-account tokens retain upstream active/expiry and PBAC restrictions;
no role or token is granted by installing this policy. Device sync continues
to use the independent per-device credential boundary. No broad `/accounts/`
exemption exists, including for the nginx authorization endpoint.

Setup and factor deletion serialize on the user row; removing the last factor
is refused. A password-only setup session is cleared after successful enrollment
and must perform normal MFA login. Password-reset/invitation routes retain their
standard password workflow; changing a password cannot clear factors or mint
MFA authority. Pending challenges bind the password auth hash and expire after
five minutes.

The existing shared Redis supplies atomic budgets: ten password attempts per
identifier and five MFA submissions per user in five minutes. A dedicated
security cache alias has strict errors and two-second socket/connect timeouts;
new sign-in fails closed when it is unavailable. Signed random verification
challenges and accepted TOTP timesteps are claimed once in that shared cache,
including for counterless security keys. This does **not** yet prove replay/attempt
state survives Redis recreation or restoration: the current lab Redis has no
durable volume. Resolve and test that boundary with #53/#54 before ingress.

Six pinned Apache/core files integrate the policy. Their exact original/result
hashes are checked before image construction and again inside the build;
modified files carry notices. The policy itself is original Unlicense code.
Source acquisition, patch preparation and package tests execute no upstream app
code. Real Django request/session/form/PostgreSQL/Redis tests remain required.

Remaining acceptance includes first enrollment and malformed/changed seed,
valid and invalid factor login, stale/cross-user/password-reset/deactivated
sessions, challenge expiry/budgets/replay, simultaneous last-factor removal,
human-token rejection, constrained service-token access, password-age bootstrap,
and unchanged Santa device sync. Lost-all-factor recovery must become one
separately authorized, audited management command which invalidates prior
sessions/tokens and requires secure password recovery; email password reset
alone must never reset MFA. That command and the customer bootstrap experience
are not implemented by this first policy layer.

## Actual private request acceptance, 2026-11-06

The 137-test offline suite passed. The real image
`sha256:0f606eabc9a1a4103b6b8b97aced72d0ea160fa6ac5ee98b5e7ae854452fed60`
built, its non-root application user read the exact policy bytes, and its image
upgrade preserved the existing healthy synthetic Santa fixture. Policy SHA-256:
`e17fb7b380dab96bb593faf89ee9d33a4318c16d1f98a216c086640f409ece4a`.

All **14 actual Django/PostgreSQL/Redis request cases passed**, with zero skipped,
zero errors and zero failures. These cover the behaviors listed above except
lost-factor recovery, which remains separate. Both
ordinary and superuser operators were tested without staff status. Real forms,
CSRF checks, password hashing, TOTP verification, session persistence and user-row
locks ran against the actual core image. Human tokens were rejected while a
dedicated service token retained constrained access and PBAC denial elsewhere.

The security-key replay case used genuine ES256/COSE signatures with a zero
signature counter. Two requests loaded the same pre-authentication session before
continuing; exactly one authenticated. The factor-change case added a method at
hour seven without renewing the original proof and required sign-in after hour
eight. Neither case mocked a successful cryptographic verifier.

The accepted harness SHA-256 is
`54fe5999fd674865ff6979e4226ed903a69368ca71f42fa4d22efdb73ba25787`;
Compose SHA-256 is
`6883424b17ac84658261db0139b8328b9f42b60501989f4d009e27def0f28293`.
The guest receipt is in
`runtime-fixed/operator-mfa-requests-run3/receipt.json` under the private
qualification root. Detailed process output, passwords and seeds stay private.
The outer runner validates exact source hashes, fourteen tests, zero skipped and
a strict export schema before accepting or printing a receipt.

Earlier failed runs remain retained. The disposable request container initially
skipped the normal entrypoint's static-file collection; the harness now performs
the real collection instead of replacing the static renderer. A later assertion
was corrected to permit Django's safe local login URL with a `next` query after
password-session invalidation, while still requiring an empty scheme/host and
the exact login path. The policy was not weakened for either harness fix.

An actual loopback HTTP login page also rendered successfully. The request
acceptance uses Django's request client and a virtual authenticator, not a real
browser, TLS transport or physical security key. No native-Mac behavior or
restoration durability follows from this result. Recovery/customer bootstrap,
Redis recreation/restoration state and the final deployment flow remain open;
#51 is not closed and public ingress remains disabled.

The same original two-device synthetic fixture then passed full real HTTP Santa
sync under the MFA-enabled image, including cross-device rejection, Monitor
preflight, six exact rules paged 5+1, event upload and committed postflight without
re-enrollment. A separate Elasticsearch query found exactly six Santa events for
that fixture (four retained plus two new). A subsequent seven-service memory
sample totaled approximately 1.5 GiB; this is not a fleet-load or peak guarantee.

Successful-login audit ordering is tracked separately in #57: the upstream login
signal currently precedes the added replay-policy check. Access is denied on a
reused assertion, but final policy acceptance should precede a success audit.
That source finding needs its own signal-count regression before ingress.
