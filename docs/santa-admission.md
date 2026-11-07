# Shared Santa admission candidate

This is an offline candidate for #58, based on `99165c7`; public ingress remains
held. It adds no Azure/Graph grant, service or secret. HMAC keys derive from the
existing Django secret with separate source/credential domains. Real Lua, load,
Redis-failure, memory, broker-pressure and native retry behavior are unqualified.

The first Django middleware gates both `/public/santa/sync/` and the preserved
legacy mount before session lookup, authentication, SQL or body parsing. A
hash-bound `BaseSyncView.dispatch` backstop denies calls missing its request-local
permit. The pinned header transport and its precedence over deprecated path
credentials remain unchanged. Doctor probes and invalid/missing credentials also
consume admission. Operator budgets remain separate.

The pinned profile generator uses `SyncExtraHeaders` with
`Zentral-Authorization`; the deployment-only baseline still has no SyncBaseURL.
No profile delivery or native behavior is established by this middleware.

A static Lua operation reuses the existing guarded security Redis, validating its
marker/configuration and bounded state before mutation. Defaults are provisional:
one concurrent Santa request, 120 global attempts / 60 seconds, 60/source and
30/credential. The global counter saturates first; requests above it allocate no
identity keys. Identity counters expire within the same 60-second bound and never
extend on rejection. At most two global windows overlap one identity retention
period, so there are at most `4 * global_max` identity keys plus fixed marker,
global and state keys. The state hash has only two metadata fields and one fixed
permit slot. Limits/trust are selected before fresh initialization; changing their fingerprint
requires a future deliberate configuration migration. Reconciliation does not
overwrite a mismatched configuration. Counter corruption, missing state, transport errors or unsafe
persistence settings return bounded 503 without downstream work. Budgets return
429 with bounded Retry-After. No transparent application retry/refund occurs.

Permits have no expiry. Normal synchronous completion or an unwound exception
releases only the exact random owner token. A proxy deadline does not release an
executing request. Uncertain release, process death or unsupported streaming
retains capacity. Gunicorn's current one-worker/two-thread timeout is not a hard
request deadline. Defaults require actual CPU/RSS/backlog qualification before
public use; encoded/expanded byte limits alone do not establish safe JSON object
memory amplification. Existing operator username-budget cardinality is unchanged.

Privileged `operator_security_store fresh` initializes the marker and admission
hash atomically only for an empty authority database. Existing marker/store
initialization does not silently create admission state. Normal runtime startup
requires valid empty admission state before opening its listener, and never
initializes or clears it. Held slots block startup until explicit reconciliation.

For a deliberately stopped, selected runtime, the explicit host command is:

```text
python3 -I runtime_service.py admission-reconcile --manifest <exact manifest> --sha256 <exact SHA>
```

The optional `--initialize-missing` is for deliberate quiesced feature migration,
not corrupt-state repair or backup restoration. The host acquires the existing
supervisor lock, verifies the exact bound old app container IDs all have
Running/Paused/Restarting false and PID zero, revalidates its manifest and actual
helper bytes, then launches a job touching only this admission hash. A mismatched,
missing/replaced or live old process prevents the job. Valid-slot reconciliation
changes its generation and removes only fixed permit fields; it preserves rate
budgets. Corrupt state stays closed. This action never stops processes on behalf
of a caller, never starts the listener, and is never called by worker boot or
normal supervisor startup. Explicit receipts retain selected app IDs and manifest
hash. ACA parity requires equivalent termination proof; TTL reclamation is not a
substitute.

Direct private mode ignores untrusted forwarding/certificate headers and derives
source identity from REMOTE_ADDR. Proxy mode requires an explicit bounded peer
allowlist and one single-address `X-Azd-Santa-Client-IP` value. It does not accept
comma-separated forwarding chains. Both modes strip arbitrary forwarding and
certificate identity headers, then set the upstream audit IP to the canonical
address. mTLS identity is not enabled by this candidate. Runtime generation
currently remains direct/private; proxy configuration and trusted TLS require
separate reviewed deployment contracts and actual gates. Credential-bearing sync
paths and authorization-header errors are suppressed from Django/Gunicorn request
logs. Proxy logs remain disabled by the existing held Caddy configuration.

Runtime manifests now require an admission helper hash; startup checks actual
installed bytes. Operator setup bindings add `AdmissionSha256`; the host checks
those bytes and live admission state. The finalizer's strict readiness schema adds
`sync_admission` without changing the eleven nonsecret installation output facts.
Source/schema changes require new receipts rather than acceptance of older ones.

Integration with the separately owned private installer must add
`santa_admission.py` to BOTH source FILES lists and add
`'admission': 'santa_admission.py'` to its runtime policy-hash map. Do not deploy the
old fixed source inventory with the new compiler.

Offline tests use a deliberate Python store double; they do not execute Lua or
prove Redis semantics. Remaining actual gates include concurrent global-first
key cardinality, invalid and valid credential overload, retained capacity while
work outlives a proxy deadline, worker death/reconciliation, Redis outage/corrupt
state/AOF behavior and worst-case memory/broker backlog. Existing 89 decoder
requests may now receive intentional 429s: qualification must honor bounded
Retry-After and separately verify decoder results, never disable admission or
count a rate denial as decoder acceptance. Real native-Mac retry/profile behavior
and the public-TLS/proxy gate remain required. This does not close #58.

## Original container generation follow-up

The explicit fresh machine producer is `runtime_service.py admission-bind-fresh`
with the exact `--manifest` and `--sha256`. It runs after fresh create/prepare and
before unit installation. It never accepts a caller-provided CID JSON map.
All seven actual containers must pass the existing image/config/env/mount
inspection and backing-data checks; all three apps must still be created, never
started, with PID zero, and dependencies must be running and initialized. A
second selection check precedes the exclusive private/fsynced anchor write.
An existing unit or anchor prevents binding.

The single machine-produced `runtime-service/container-generation.json` schema is
exactly `scope`, `manifest_sha256`, `project`, `image_id`, `generation`, and
`container_ids`. Scope is `private-runtime-container-generation-v1`; generation
is 32 lowercase hexadecimal characters. The map has exactly db/redis/rabbitmq/
elastic/web/workers/celery, seven distinct full 64-character lowercase Docker IDs.
Manifest SHA and immutable app image bind the source/configuration selection.
This is the common anchor for admission and future native backup maintenance,
not a second independent backup generation store.

Startup and reconciliation require this persisted original map and reject a
consistently replaced container, even if current labels/image/config all match.
Missing anchors are never adopted from current Compose labels. Older contexts
without the trusted machine-produced anchor remain closed; deliberate migration
or replacement/upgrade needs separately reviewed generation evidence. The
installer must call the fresh producer between runtime prepare and install.

Readiness CHECK and EMPTY now also validate the fixed global counter's type,
canonical positive value, upper bound and finite window TTL without writing it.
Absent counters are valid; exhausted-but-valid counters remain ready and produce
normal 429 admission denials. Corrupt counters produce 503 and prevent readiness.
