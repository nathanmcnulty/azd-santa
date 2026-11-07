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
still requires valid empty admission state before opening its listener. It now
recovers valid abandoned permits automatically only after proving original-process
and downstream database quiescence under the existing supervisor lock. Missing or
corrupt state is never initialized or repaired automatically. This source candidate
needs separate actual Redis and killed-handler/reboot qualification.

For a deliberately stopped, selected runtime, the explicit host command is:

```text
python3 -I runtime_service.py admission-reconcile --manifest <exact manifest> --sha256 <exact SHA>
```

The optional `--initialize-missing` remains a deliberate quiesced feature
migration, not corrupt-state repair or backup restoration. It rejects an existing
hash. The ordinary explicit command and automatic startup use the same fenced
recovery implementation. The explicit wrapper acquires the supervisor flock once;
startup calls a private under-lock method without acquiring a second flock.

Before recovery, the controller verifies the persisted exact seven-container
anchor, current manifest/source/configuration and a process-local capability
bound to this supervisor PID and its existing lock descriptor/inode. All three
original apps must have Status created/exited, Running/Paused/Restarting false,
and a typed PID zero. App exit zero is not required: process death is sufficient
for this capacity proof, distinct from clean backup shutdown. Identity/source
or PID drift on reinspection blocks recovery. Pending/unknown backup maintenance
remains the first startup gate, before any app selection or reclamation.

Dead Python does not prove a dispatched SQL query ended. A bounded read-only
probe using the normal restricted runtime role verifies its own PostgreSQL
identity/visibility, excludes only its current backend PID, and waits up to 60
seconds for zero other same-role/current-database sessions, including idle ones.
It never cancels or terminates another backend. PostgreSQL documents
[same-role session visibility](https://www.postgresql.org/docs/18/monitoring-stats.html#MONITORING-STATS-VIEWS);
the actual selected-role probe still verifies visibility rather than assuming it.
Unknown visibility/authority or
a remaining session fails closed before permit mutation; no pg_monitor, owner
credential or new grant is required.

The controller reads only a valid existing Redis marker/configuration, persistent
hash and valid global counter, then fsyncs one private attempt intent containing
expected/target admission generations and original identities. Production Lua
atomically compares the expected fence, removes only fixed permit fields and
installs one fresh fence. It advances even an empty hash, preventing a delayed
older job from clearing newly admitted work. Re-observation of the same target
is a strict no-op, including when that generation already has a live permit;
an unrelated generation conflicts without writes. Global/source/credential
counters and TTLs, security-store identity, MFA replay claims, credentials and
application data are unchanged. Valid saturated counters still impose 429s.

A timed-out submission is observed read-only for its exact target, never submitted
again in that attempt. Admission remains closed until valid empty target-state
readback and repeated process/identity proof succeed. A later bounded systemd
attempt re-proves quiescence and uses a new fence; old queued recovery mutations
then conflict or no-op. This does not replay initialization, HTTP requests, data
jobs or credential changes. Private intent/completion evidence is retained; a
serialized boolean or elapsed timeout is not a quiescence capability.

The unit's 1,800-second start-limit interval covers three 420-second startup
attempts plus the unchanged 30-second restart gaps; Burst remains three. This
corrects the earlier 600-second window, which could let slow failures escape the
burst limit. The policy is bounded recovery, not a guarantee against host/kernel
failure. Actual systemd exhaustion/reboot faults remain separate qualification.

Automatic recovery assumes cooperating lifecycle operations honor this same
lock and original generation. It does not fence an arbitrary privileged Docker
writer, adopt replacement containers, restore old Redis authority or provide ACA
parity. Those need their own termination/continuity proof; TTL reclamation is
not a substitute.

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

The private installer includes `santa_admission.py` in both source inventories
and binds its actual bytes in the runtime policy-hash map. New source needs a
fresh reviewed image/manifest and installation; old contexts are not upgraded or
rebound automatically.

Offline recovery tests exercise production script selection/arguments, strict
readback and an explicit Python CAS transport double; they do not execute Lua or
prove Redis semantics. The earlier selected 27-observation Redis receipt applies
to admission source `937ef10433eeb3bf901aaf5b87aaddf37b73b9c4c135a927cb6f9f5e1a0c5235`,
not this new fence. Its harness pins/expectations require coordinated adaptation
and new actual Redis execution before accepting these operations. Remaining
actual gates include concurrent global-first
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

Supervisor cleanup has a separate immutable authorized-ID snapshot. Inspection
does not arm cleanup: only successful persisted-generation equality does. Thus
the supervisor finally path cannot stop missing-anchor or replacement selections.
Failures/cancellation after authorization still clean the exact authorized IDs;
independently ownership-checked startup-helper cleanup remains enabled.
