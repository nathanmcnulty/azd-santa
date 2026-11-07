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
state survives Redis recreation or restoration: the previously qualified lab
Redis has no durable volume. The [durability candidate](security-store-durability.md)
adds AOF and explicit store admission; its actual crash/recreation tests and #54
current-authority restoration gate remain required before ingress.

Six pinned Apache/core files integrate the policy. Their exact original/result
hashes are checked before image construction and again inside the build;
modified files carry notices. The policy itself is original Unlicense code.
Source acquisition, patch preparation and package tests execute no upstream app
code. Actual Django request/session/form/PostgreSQL/Redis acceptance is recorded
separately below.

The private request suite covers enrollment, malformed/changed seeds, factor
login, stale/password-reset/deactivated sessions, challenge expiry/budgets/replay,
simultaneous last-factor removal, human-token rejection, constrained service-token
access and password-age bootstrap. Device sync is qualified separately.
Lost-all-factor recovery uses a separate privileged management command which
invalidates prior sessions/tokens and requires secure password setup; email
password reset alone never resets MFA. Its later private acceptance is recorded
in [operator recovery](operator-recovery.md). The customer `azd` bootstrap and
private setup-link delivery flow remain separate implementation work.

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

Successful-login audit ordering in this first image was tracked separately in
#57: the upstream login signal preceded the added replay-policy check. Access
was denied on a reused assertion, but the success audit could misrepresent it.
The following regression qualifies the correction in a later image.

## Successful-login audit regression, 2026-11-06

The original image above reproduced both signal-count failures: a reused TOTP
step and two concurrent, genuinely signed counterless WebAuthn assertions each
emitted two successful-login signals while only one session obtained operator
access. The baseline ran all fourteen cases with exactly these two failures,
zero errors and zero skipped. Its private receipt is
`runtime-fixed/operator-audit-baseline-2/receipt.json`.

The integration now validates the fresh local user, password hash, factor and
signed challenge and atomically claims challenge/TOTP authority **before**
Django login. Login uses the accepted fresh user and explicit local backend;
the proof is attached after session rotation. A rejected assertion records the
existing failed-verification event, without adding credentials to its payload.
Restricted password-only enrollment retains its existing login event; that event
must not be interpreted as completed operator MFA.

The corrected image
`sha256:11d237a75da25179c5e4b6241a47abced0990c086f923b6bf34de3c3d3dfa3ad`
passed all **14 real request cases**, zero failures/errors/skipped. Both replay
cases now require exactly one actual `user_logged_in` signal, with the MFA marker
set, across the accepted/rejected pair. Exact bindings:

- Policy SHA-256: `df1a0b3b62919414fba6715e9e924f344d40ff17052da7c1b493a19b4cc2ad84`.
- Harness SHA-256: `ac2774bdef29f92c4bdbbb83a985f4dd9b815258b3c1f264121a5190aee67db8`.
- Compose SHA-256: `3930e33a57eaa071fa3fb6fac0db999174a40bfabd0c1229a947ca9dc7514219`.
- Private receipt: `runtime-fixed/operator-audit-events-requests/receipt.json`.

The image-only transition preserved the original healthy fixture. Both devices
then passed full loopback HTTP sync, including Monitor preflight, exact paged
rules, event upload, credential isolation and committed postflight without
re-enrollment. Its receipt is
`runtime-fixed/synthetic-fixture-operator-audit-events.receipt-192a852050354ac4a3fda62b2f948e31.json`.
The 137-test offline suite passed on PowerShell 7.6.9/Pester 6.2.0; independent
review verified all six transformed core-file hashes. This signal regression
does not additionally prove indexed audit delivery, real-browser/TLS behavior,
native Mac sync, Redis restoration or lost-factor recovery.

An earlier qualification attempt could not read the source-only bind-mounted
harness as the non-root app user. That failure remains retained in
`runtime-fixed/operator-audit-baseline/private-process-output.json`; only that
source file's read permission was corrected. Private credentials and logs
remained restricted, and the accepted run used new evidence paths.

The later combined image recorded in [operator recovery](operator-recovery.md)
also passed all fourteen MFA cases with the same policy-module hash. Its form
integration now locks the user before factor verification (forms output SHA-256
`ef4adc2ea64d7f92bb9b1683082baa4f946ab1d21867c5e0ac10496db192bc6a`),
matching recovery/factor-management ordering. The separate real recovery suite
confirmed both login/recovery ordering cases through PostgreSQL's actual wait
graph. This does not add Redis durability, customer transport or native-browser
acceptance to the original MFA result.
