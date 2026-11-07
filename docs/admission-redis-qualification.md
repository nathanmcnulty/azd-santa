# Disposable Redis Lua qualification

`experiments/server/test_admission_redis_live.py` is a standalone stdlib Linux
qualification tool. Source preparation and offline guards do not prove that its
Lua cases pass on Redis. The coordinator creates and controls a disposable Redis
container using the exact installed dependency image; this tool never creates,
restarts, stops or removes containers and never discovers application Redis.

## Historical unfenced actual result

On 2026-11-07, harness SHA-256
`33a2fd00f8e2c7bee5fb7989325605499e3d181c198ed216c7571d73f55a233b`
passed all 27 observations with exit0 in26.25s on the selected private Ubuntu
host. The disposable Redis image was
`sha256:5b816bb37d9707a70f10ef5002ecf8ee431750d397010fc4314c93dca887962f`;
the exact container was
`61a2f00e649579a0bc138f9fb2f372da7b3156b7726d9c3e6d3749dad08d1ade`.
It had no network, published ports or persistent volumes, and used only a
bounded tmpfs for data. The source was transferred byte-for-byte and verified
before execution. Private evidence is retained at
`/var/lib/azd-santa-qualification/admission-lua-6063052/evidence-9482511`.
Application Redis and the original seven application containers were not targets
of this qualification. This is actual Lua/Redis acceptance for these cases;
the integration and failure boundaries below remain open. This receipt binds
the older admission source SHA-256
`937ef10433eeb3bf901aaf5b87aaddf37b73b9c4c135a927cb6f9f5e1a0c5235`;
it is not acceptance of the newer fenced protocol.

## Fenced follow-up: source prepared, actual Redis execution pending

The current harness binds admission SHA-256
`ebe2abef0cb9786f677a08dacf96b27acd944fcdd4e1465afa5c74701249629b`
from frozen product commit `f4324804c5aad6d58e70bc186850d78f3f1f6982`.
The operator guard remains SHA-256
`0d5eb3b850b58c4f6092206734114fdbf931e965cb6b448feb60a4068aee4b8d`.
Its new receipt scope is `disposable-redis-admission-fenced-lua-v2`, requiring a
new evidence directory and new actual run. The original historical27 receipt
must not be updated or represented as fenced acceptance.

All prior27 observation families remain, adapted to fenced reconciliation.
Ten additional observations cover readonly generation/occupancy, expected to
target CAS, same-target replay with a new live permit, stale transitions,
discarded-reply observation/idempotent retry, exact budget preservation, invalid
or equal fences, advancing an empty state, explicit missing initialization and
rejecting corrupt global budgets while admission state is missing.
Every rejected corrupt-state/counter/read/CAS attempt compares atomic snapshots
of all case-local keys, sorted field/value bytes and absolute `PEXPIRETIME`
timestamps. Successful CAS and retry must preserve counter values and exact
expiration timestamps. A simulated lost reply means the actual first Lua
response is deliberately not interpreted; no fake success is substituted.

This is source/offline harness preparation only. It does not establish actual
Lua execution, host PID/container/PostgreSQL quiescence, supervisor locking,
host timeout handling or safe production recovery. The coordinator must first
verify exact source bytes and the independently selected disposable target.

## Coordinator invocation

The selected container must have `--network none`, no published ports, label
`io.azd-santa.qualification=santa-admission-lua-v1` and no persistent or bind
mounts. Use `--tmpfs /data` if the image declares a `/data` volume. Only that
optional tmpfs mount is accepted. Supply its full container ID and actual
immutable image ID, not its mutable image tag. The caller owns any overall
timeout (suggested five minutes); each exact-ID Docker call is bounded to fifteen
seconds. Keep the container on failure for inspection; no automatic replay.

Copy the harness and the exact pinned `santa_admission.py` and `operator_mfa.py`
beside it in a root-owned source directory. Run as root using isolated Python:

```text
python3 -I /var/lib/azd-santa-qualification/<source>/test_admission_redis_live.py \
  --container-id <64-hex-disposable-container-id> \
  --expected-image sha256:<64-hex-actual-image-id> \
  --destination /var/lib/azd-santa-qualification/<absent-private-evidence>
```

Require exit0, `SANTA_ADMISSION_REDIS_LUA_OK` and the exclusive private
`receipt.json` with `passed:true`, matching harness/product/image/container
hashes. Every case uses an independently random namespace and calls the actual
production Lua, including the literal `STORE_GUARD` and actual fresh initializer.
No source edits, fake Lua interpreter, successful-outcome mock, `FLUSH` or shared
namespace cleanup is used. Receipt observations contain case names only, without
keys, tokens, credentials or script output. Keys remain until the coordinator
deliberately disposes of this container.

Cases cover missing/corrupt/held authority markers, admission hash shape/config,
global budget type/value/TTL, valid exhausted budgets, source/credential/global
rate caps, global-first bounded identity allocation, eight concurrent acquire
attempts sharing one nonexpiring slot, exact-token release and nonreclamation
after rate-window expiry. Explicit fenced reconciliation changes the generation
and invalidates the old release token. A repeated same-target transition must
leave any new live permit untouched. These cases exercise the Lua primitive only;
it does not prove the host controller's process-quiescence prerequisite.

This tool does not exercise Django's persistence/configuration client checks,
request parsing/HTTP dispatch, held work after a request timeout, server load,
Redis restart durability, native Santa or a real Mac. Those remain separate
acceptance gates for issue58. No cloud or tenant permission is added.

## Optional hosted Linux gate

`.github/workflows/qualify-redis-lua.yml` adds a non-required Ubuntu 24.04 job
for relevant pull requests, main pushes and explicit workflow dispatch. It does
not change a ruleset, catalog enforcement or required status checks. Workflow,
CI driver, harness, admission policy, operator policy and dependency-lock changes
trigger the gate. Checkout/upload actions reuse the repository's immutable pins;
the GitHub token has only `contents: read`, checkout does not persist credentials,
and no cloud login, tenant secret, deployment environment or role grant is used.

The CI-only stdlib driver `scripts/ci/qualify_redis.py` runs as root with isolated
Python and a scrubbed environment on the disposable hosted runner. It reads the
Redis digest reference from `dependency-images.lock.json`, pulls that digest for
Linux amd64, verifies the returned RepoDigest, and binds the actual image ID. It
creates exactly one labeled container with a separate random owner label. The
container runs as UID/GID999, has a read-only root filesystem, no network or
published ports, only a64MiB tmpfs at `/data`,64MiB memory with no extra swap,
half a CPU,32PIDs, all capabilities dropped, no-new-privileges, no restart policy
and no Docker log storage. Actual container metadata must match these bounds.

Exactly the harness and its two product sources are copied into an absent
root-owned0700 directory with0600 files. The original harness CLI receives only
the selected64-hex CID, actual image ID and absent private evidence destination.
Read-only PING startup checks are bounded to20seconds; the harness is invoked
once with an external240-second subprocess timeout, inside a10-minute job. No
test dependency installation, FLUSH, key cleanup or application Redis lookup
occurs. Normal exits and handled signals check the original CID/image/owner
labels and stop only that container. Unknown creation or cleanup cannot trigger
global name/label cleanup or replay; runner disposal is the final safety bound.
The container and private diagnostic files are never reused or copied elsewhere.

Only after successful harness completion, strict receipt/source validation and
confirmed owned-container stop does the driver emit one nonsecret JSON receipt.
The artifact step uploads that one exact file, only on success, with three-day
retention. Its whitelist includes the source commit, dependency digest, actual
image/CID, source hashes and validated case names. Private attempts, stdout/stderr,
Redis keys, tokens, arbitrary error/limitation text and source files are excluded.
Failure diagnostics remain private only until the ephemeral runner is discarded;
there is no failed-run private artifact. This differs intentionally from the
coordinator's retained private VM qualification above.

The exporter admits only the reviewed `disposable-redis-admission-lua-v1` scope
with27 unique observation families or `disposable-redis-admission-fenced-lua-v2`
with37 families. It retains that harness scope explicitly and rejects unknown
versions, incomplete/extra case inventories and unexpected receipt fields. The
new fenced harness is integrated separately; this workflow does not edit its
product/source pins or claim its cases passed from an older v1 receipt.

The driver/workflow have offline orchestration, target-isolation, once-only
failure cleanup and artifact-whitelist tests. No hosted run is established by
those mocks or YAML parsing. Actual hosted Docker/image/startup/Lua/cleanup and
artifact delivery still need the first reviewed run. A pass qualifies only the
disposable Redis Lua cases for those exact sources; Django/HTTP, durable app
Redis, native clients, public HTTPS and Azure cold installation remain separate.
