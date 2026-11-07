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
