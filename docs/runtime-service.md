# Initialized runtime startup service candidate

This implements a private Linux/systemd lifecycle controller toward #53. It is
not wired to an azd hook. Selected actual Docker, systemd and VM reboot gates
passed the private qualification below. The final deployment must install it
automatically; these low-level
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
Privileged CLI and generated unit execution require Python's `-I` isolated mode.
Executable validation helpers are imported by exact path only after the trust
checks; an unsafe sibling helper must not execute before rejection.
The controller compiles the checked source bytes directly, so a matching
timestamp/size bytecode cache cannot substitute executable helper code.

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
The selected clean restart, web-container failure, VM reboot and empty-data
rejection passed actual qualification. Docker-daemon restart propagation and
cancellation during startup still require separate live qualification.

Subprocess output is retained in exclusive private startup-attempt files. Healthy
supervision does not continually persist container environments or image dumps.
Readiness/failure messages expose no raw Docker/Django diagnostics. The selected
runtime and its control directories must be trusted, root-owned and inaccessible
for unprivileged modification; these checks do not sandbox a malicious root user.

Preserve failed attempts and all prior stack volumes. The remaining lifecycle
gates include startup cancellation, Docker-daemon restart propagation and the
final automatic installer. These selected results do not establish general
corrupt-data recovery, backup restoration, runtime-role separation, native Mac
sync, public TLS or final azd deployment acceptance.

## Actual private qualification, 2026-11-06

The initialized `runtime-santa-host-setup` namespace passed first adoption, clean
stop/start, supervisor recovery after killing its web container, and a VM reboot
with a changed boot ID. Each completed readiness gate was followed by independent
database and event-store readback. All seven original container IDs, two
synthetic Monitor devices, six rules, enrollment-secret bindings and two indexed
Santa events were preserved. The sole synthetic human's privilege flags and
password fingerprint were unchanged. The web-failure case also verified an
increased systemd restart counter and the controller's recorded failure.

Controller SHA-256:
`24bb73b6415835e4fc19786c8a1157fdbf51242d26f9cadae7029f03278a69df`;
Compose SHA-256:
`092f05fac6aca2f262887556e7a9bf4910f849ef6be2f7eac94408a93a1f0769`;
application image:
`sha256:4533b2fdb0922ab50a8fa78d423b0613c1b5b2a843cb33244d1c8887a8804fec`.
The unit executes the versioned controller under `lifecycle-controller-v2/`.
Private evidence includes `lifecycle-first-start-final-receipt.json`,
`lifecycle-clean-stop-receipt.json`, `lifecycle-clean-restart-receipt.json`,
`lifecycle-process-failure-receipt.json` and `lifecycle-reboot-receipt.json`.
The boot ID changed from `dcc7c943-47c1-4857-9b90-1e001fe89495` to
`0eb53542-dc0d-4d75-b0e3-dab0819d0359`.

A separate freshly generated `runtime-empty-data-negative` namespace had seven
containers created without starting them. The real controller rejected missing
initialized PostgreSQL data before starting dependencies or admission. Actual
Docker inspection confirmed that all seven negative containers had never
started, while the initialized runtime remained active. Its private
`missing-data-receipt.json` and failed attempt were retained; no legitimate
volume or data sentinel was removed to simulate the failure.

The first adoption attempt exposed Docker's null image-user versus empty
container-user representation. The controller now accepts that default-user
normalization while rejecting explicit overrides. Its failed manifest, unit and
attempts remain under `runtime-service-failed-default-user/`. Source execution
also has a timestamp-valid bytecode-cache regression. All 21 focused lifecycle
guards passed independently; offline evidence is separate from the live gates
above. The normal upstream application entrypoints in this image still perform
their earlier migration/provisioning checks; the separate database-role
candidate has not been accepted by these results.

Final readback after the negative case again preserved the initialized state.
The controller then cleanly stopped all seven original containers; an independent
Docker inventory found no running containers. The unit remains enabled for the
next VM boot. `lifecycle-after-negative-receipt.json` and
`lifecycle-cost-stop-receipt.json` retain those results.
