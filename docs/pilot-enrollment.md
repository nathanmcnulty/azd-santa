# One-device backend enrollment worker

`experiments/server/pilot_enrollment.py` prepares a separate Monitor configuration
and one enrollment for the selected Mac. It is an internal Django worker, not a
deployment command. Its caller must first verify the selected Azure account,
immutable VM instance, installation binding, application image and running
container generation. It does not change networking, publish a profile, run a
Mac command, or establish native-device success.

The worker verifies the pinned backend source, HTTPS origin, admission/security
store and an active administrator with a prior login and enrolled MFA factor.
The request binds a fresh nonce, deployment digest, exact serial and hardware
UUID, administrator name and recipient public key. The enrollment permits that
serial and UUID with quota one. These client-reported identifiers restrict
enrollment; they are not hardware attestation or protection against a stolen
bearer with spoofed identifiers. Intune administrators with profile-read access
and the managed device can access the delivered bearer.

The configuration starts with Monitor mode, no path overrides, no rules and no
client-certificate requirement. Existing configurations, enrollments and
synthetic fixtures are retained. Pinned Zentral normalizes sync URL UUIDs to
lowercase before checking its enrollment restrictions, so the stored UDID uses
that spelling; Graph's uppercase hardware UUID remains in the request. The
Entra device object ID and Intune managed-device ID must never be substituted
for this hardware UUID.

An exclusive private checkpoint directory is reserved before database mutation.
The worker creates the configuration, business unit and enrollment in one
transaction, persisting recipient ciphertext before commit. An unknown outcome
must be observed using the same request. Observe verifies the exact database
projection and returns the original ciphertext; it never creates another
credential or repairs partial state. A retained attempt whose transaction rolled
back requires diagnosis, not automatic retry. The worker cannot recover a lost
recipient private key.

Only RSA3072 OAEP-SHA256 ciphertext and nonsecret binding/record IDs leave the
worker. Plaintext credentials are never written to checkpoints. Caller-side
decryption must verify the context and record IDs before composing the existing
Monitor baseline with the sync URL and `Zentral-Authorization` bearer header.
The full profile must use owner-private local storage and remain out of console
output, issues, Git and deployment-plan JSON. It must replace the existing owned
configuration object, retaining its profile identities and pilot-only assignment.

Before opening device sync, retain the exact prior configuration privately and
record the new enrollment ID. If first enrollment is unexpected or the quota is
consumed without the expected machine, close the pilot listener, inspect the
exact enrollment and revoke that credential before a separately reviewed
reissue. Do not automatically rotate or raise the quota. Restoring the baseline
profile does not prove previously downloaded rules were removed; rollback needs
native endpoint evidence as well as Intune payload readback.

Offline tests exercise actual recipient crypto, request/algorithm rejection,
durable attempt/readback boundaries on Linux, and Django UUID projection
handling. They do not prove real ORM creation, live encrypted transport, Intune
delivery, native sync or revocation. Existing permission inventory remains
unchanged for this worker: it authenticates to no API and grants no authority.
