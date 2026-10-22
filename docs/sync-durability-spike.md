# Restart-safe synthetic sync state

This is a local continuation of the [public-protocol spike](azure-sync-spike.md),
not an Azure deployment, selected production backend, or native Santa proof.
It adds no listener, cloud SDK, enrollment service or publication API. The
Intune-only baseline and generated profiles remain unchanged. Evaluate this
reference against a maintained server before committing to custom operations.

`tools/sync_spike/durable.py` stores bounded synthetic snapshots, per-device
reported revision high-water marks and irreversible fixture revocation tombstones
in a local SQLite file. Snapshot history is capped at 100 entries, each at most
64 KiB. Only the existing two synthetic devices are accepted. All writes use
explicit `BEGIN IMMEDIATE` transactions and FULL synchronous rollback journaling.
See SQLite's [transaction semantics](https://www.sqlite.org/lang_transaction.html)
and [synchronous setting](https://www.sqlite.org/pragma.html#pragma_synchronous).
These settings do not prove storage hardware, filesystem, or Azure durability.

Publication requires increasing revisions and nonempty fixture rules. Duplicate
revision attempts fail; they cannot replace prior bytes. Snapshot hashes detect
accidental payload damage, not an attacker with database write access. Fixture
approval labels are not verified signatures, administrator authorization or real
approval receipts. A rollback must become a new increasing fixture revision.

`DurableModel` reuses the existing synthetic protocol state machine. A successful
postflight response requires its report to commit first. Failed persistence drops
the session and returns 503. Reports still have the public-v1 stale-count ambiguity
documented in the original spike: durable storage does not make them trustworthy
proof of client receipt or enforcement. Revocation is checked from storage on
every stage and survives restart; creating fresh fake process tokens does not
reactivate a revoked device. Credential rotation is deliberately unsupported.

Sessions, cursors, signing keys, fake tokens and telemetry remain process-local.
Restart requires fresh synthetic authentication and preflight rather than guessing
that an interrupted transfer completed. Reopening a missing database fails rather
than silently creating an empty replacement; creation is explicit and incompatible
schema versions are rejected. Database errors fail closed without a success reply.

## Evidence and remaining gates

Run from repository root:

```sh
python tools/sync_spike/test_durable.py
python tools/sync_spike/test_conformance.py
```

The durability suite is also registered in Pester. It tests reopen/restart, device
isolation, revocation, stale revisions, competing connections, transaction rollback,
abrupt subprocess exit before commit, damaged/missing state and persistence errors.
The HTTP model drains only bounded rejected transport bodies before closing to
avoid Windows unread-body connection resets. This reads at most 64 KiB + one
oversize-test byte with a two-second timeout, never decodes unauthenticated JSON,
and does not increase the accepted JSON size limit. Larger/ambiguous rejected
bodies are not drained and may reset the connection. This single-threaded local
harness is not a production denial-of-service control or server.

There is no trusted external restore anchor. Restoring an old *valid* database
can restore older rules, reports and revocation state; hashes cannot detect that.
Do not reconnect a restored service until a separately protected publication and
revocation high-water ledger is reconciled. Backup/restore, deletion tombstones,
physical power loss, durable telemetry, concurrent distributed sessions, real
credentials, TLS and native behavior remain unproven. This is not a deployable
server and SQLite on an ephemeral Container Apps filesystem is not a production
persistence recommendation. Production storage, identity, cost and resource
selection still require the exact-target design/validation packet.

This offline feature adds no Azure, Graph, provider or connector permission;
`azd-permissions.json` retains the unresolved production data-access gaps. No
grant, profile assignment, endpoint change or rule publication is performed.
