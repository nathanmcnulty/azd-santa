# Private operator security-store durability

Candidate source/configuration work only. Actual Redis crash/recreation and
end-to-end MFA acceptance remain separate qualification gates. This adds no
Azure service, permission grant, public listener or device assignment.

The seven-service generator adds project-local `redis_data:/data` with AOF
enabled, `appendfsync always`, `aof-load-truncated no`, `maxmemory-policy
noeviction`, no fsync suspension during rewrite, and no standalone RDB snapshot
schedule. Redis 7 uses a multipart AOF directory: retain the full `/data` volume,
not one presumed AOF file. Per-command fsync trades latency for acknowledged-write
durability. The 128 MiB container cap is unchanged, not newly qualified for rewrite
or load; memory, disk exhaustion and rewrite tests remain required. Never clear
security data to make a failed readiness check pass.

Each new private `runtime.env` receives a random `AZD_SANTA_SECURITY_STORE_ID`.
This expected identity stays outside the Redis volume and is never written into
public provenance or receipts. Missing configuration prevents Django startup.
The Redis marker contains that identity and a server-clock admission time.
Normal startup and request handling never create or replace it.

The original policy checks the actual persistence settings and AOF write health,
then validates the marker in the same atomic Lua operation as each nonce/TOTP
claim or attempt-budget change. A missing/wrong/malformed marker, migration hold,
configuration drift or Redis error rejects the operation. Authenticated operator
requests (except logout) and MFA pages also require an admitted store; the anonymous login form
can still render, but password submission fails closed. Device/service API
authority remains a separate boundary.

## Explicit privileged initialization

The image installs `server/manage.py operator_security_store` automatically.
After migrations and before human/device fixture creation, a genuinely fresh
private deployment may run `operator_security_store fresh`. It requires no user
accounts or enrollment secrets. A second initialization never overwrites a
marker, including a wrong marker. Diagnose and correct the selected private
configuration/store rather than treating a mismatched store as fresh.

For a deliberate cache-loss/legacy migration, stop the old application processes,
prepare the reviewed durable Redis/configuration, and explicitly run
`operator_security_store migrate --confirm-quiesced`. This is an operator
assertion of quiescence, not automated proof; an azd migration flow must enforce
that stop itself. Migration admits no operator authentication for six minutes,
allowing the old five-minute password/MFA/challenge windows and TOTP claims to
expire. It does not bypass or repair a preexisting marker. Keep the current
security prefix so retained claims are not silently forgotten.

`operator_security_store check` validates readiness without mutation. The intended
azd startup flow must require it before admitting traffic. Existing image-only
upgrade tooling cannot silently turn an old nonpersistent Compose/private-env
binding into this one: use a separately reviewed migration plan or a fresh
isolated deployment. No automatic initialization was added to resume/startup.

## Separate evidence gates

Offline tests cover generated volume/configuration bindings, private identity,
guarded operation arguments, error propagation and fresh/migration boundaries.
They do not execute a Redis interpreter. `test_security_store_live.py` requires
an explicit `--allow-redis-restart`, exact policy hash and one selected private
durable Compose. It binds the actual container/project/volume before interruption,
uses a unique test prefix, then probes real installed claim/budget helpers after
SIGKILL/restart and forced container recreation. Missing/wrong-marker tests affect
only that prefix; cleanup removes only its exact keys. It never flushes shared
Redis, deletes volumes or enrolls devices. Full cryptographic HTTP MFA, host power
loss, AOF corruption/rewrite, load and worker/event-pipeline recovery are separate
tests. The existing isolated recovery-request harness explicitly provisions and
cleans its own per-test marker; it cannot initialize the product namespace.

This marker detects an absent or incorrectly selected security store. **It is
not an anti-rollback anchor:** an old matching database/configuration/Redis backup
can restore old operator/device authority. #54 still requires isolated denied
ingress, current-authority reconciliation or conservative credential reissue and
policy reapproval before admission. AOF does not close that gate.
