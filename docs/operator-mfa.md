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
eight hours; password/factor changes invalidate other sessions. All local human
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
new sign-in fails closed when it is unavailable. Accepted TOTP timesteps are
claimed once in that shared cache. This does **not** yet prove replay/attempt
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

The 136-test offline suite and pinned-source preparation are separate from
these runtime gates. Public ingress remains disabled.
