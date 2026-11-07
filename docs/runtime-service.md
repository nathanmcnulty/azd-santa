# Initialized runtime startup service candidate

This implements a private Linux/systemd lifecycle controller toward #53. It is
not wired to an azd hook and has not yet passed an actual Docker, systemd or VM
reboot gate. The final deployment must install it automatically; these low-level
qualification commands are not tasks intended for a customer administrator.

`runtime_service.py prepare` records an existing, initialized runtime's exact
Compose, configuration and service-env file hashes, project name, controller and
validation-helper hashes, source revision and installed security-module hashes.
Files remain private and no secret value is copied into the manifest. Repeating
preparation with identical inputs reuses the exact artifact; changed inputs or
partial/conflicting artifacts require deliberate inspection/upgrade. Preparation
neither contacts Docker nor initializes a database or security store.
Controller and imported validation helpers must themselves be regular,
root-owned, non-writable-by-others files below the trusted qualification root;
the same restrictions apply to their ancestry before unit installation. The
unit renderer refuses executable/manifest paths outside that root.

The `unit` command renders the selected hash-bound unit. `install` exclusively
writes that unit, reloads systemd and optionally enables/starts it with
`--enable-now`. Existing different units are never overwritten. The final azd
orchestrator must generate/pass the binding; an admin must not construct its JSON.

Startup requires all seven prior containers and all existing project volumes.
It verifies actual image IDs, source labels, commands, privileges, env values,
mounts, network and loopback port binding, then closes application admission.
It starts only the original inspected container IDs. A disappeared container
fails without creating a replacement by service name. Before starting backing
services it checks their local volume identities and real initialized-data
sentinels: PostgreSQL's image-selected `PGDATA/PG_VERSION` and control/config
files, Redis's multipart AOF manifest and referenced files, broker cookie/node
data and existing search-node metadata. These are empty/missing-data gates,
not complete integrity or anti-rollback verification. The PostgreSQL sentinel
matches the [official image entrypoint](https://github.com/docker-library/postgres/blob/master/docker-entrypoint.sh).
No image is pulled and no container is recreated. Before
workers or web, it requires an available database, installed module hashes,
already-applied migrations, the configured Store row, the existing admitted Redis
security state, actual Elasticsearch readiness and the required queue consumers.
It checks real loopback HTTP readiness before notifying systemd that startup
completed. No public ingress or new Azure service is added.
Cancellation is checked before and after each bounded step and before readiness
notification. An in-flight Docker command may already have taken effect; cleanup
still stops the inspected IDs. Named, ownership-checked startup helper containers
are also stopped on timeout/cancellation, without selecting another project.

The controller never calls migrations, provisioning, marker initialization,
bootstrap or credential recovery. Normal upstream application entrypoints still
perform their own migration/provisioning checks when app containers start;
database ownership/runtime-role separation remains open in #61. Missing data or
an unadmitted security store blocks the listener; the controller does not repair
or replace them. This is not backup restoration or external current-authority
reconciliation (#54).

The selected containers use `restart: no`: Docker must not independently start a
listener before admission. systemd owns startup/restart. The supervisor checks
the pinned files and original container identities/running states every five
seconds, stops its inspected container IDs on termination/failure and retries
through systemd's bounded restart policy. It does not detect every application
hang or prove continuous database/search/queue health. A future upgrade must
coordinate service stop and deliberate new manifest/container admission.
Docker restart propagation and all cleanup/readiness behavior still need their
actual systemd qualification; offline mocks do not establish them.

Subprocess output is retained in exclusive private startup-attempt files. Healthy
supervision does not continually persist container environments or image dumps.
Readiness/failure messages expose no raw Docker/Django diagnostics. The selected
runtime and its control directories must be trusted, root-owned and inaccessible
for unprivileged modification; these checks do not sandbox a malicious root user.

Required live gates remain: exact selected private runtime adoption, failure
before admission, clean stop/resume, recovery from a selected process failure,
cold VM reboot with changed boot ID, unchanged device/rule/credential state,
unchanged event count and fail-closed missing-state behavior. Preserve failed
attempts and all prior stack volumes. Do not reinterpret offline guard tests as
those receipts, as production availability, or as native Mac evidence.
