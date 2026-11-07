# Pinned worker shutdown overlay

This original helper and source overlay are a bounded prerequisite for reliable
shutdown/backup qualification. They change no running service, controller,
generator, backup path, Docker image or tenant resource. Core-image composition
and real Linux TERM/Kombu behavior remain coordinator gates.

Pinned Zentral command
`server/base/management/commands/runworkers.py` at commit
`88e67b3ce49033aab028029937a6e14f7c489073` has no graceful TERM path. Its parent
supervises daemon child processes and restarts exits with a 10–20 second delay.
`prepare_worker_lifecycle.docker_program(source_root)` verifies exact input bytes,
compiles the derived command and returns a source/hash-bound installation program.
The future core builder must compose this stage explicitly; nothing is installed
by importing the preparation tool. Existing source mismatch or helper overwrite
fails closed. The Apache/core derivative carries a modification notice; the
original helper uses the Unlicense. No enterprise module is copied or bypassed.

The overlay uses the command's exact forkserver context for both Event and
Process primitives. The original worker selection, list output and metrics
configuration stay intact. Outside shutdown, failed children still restart with
the original jitter/delay; the restart clock is monotonic. TERM/INT only marks
parent shutdown and starts one nonrenewable 20-second deadline. Signal handlers
never acquire multiprocessing locks. A small parent thread fans the flag into
the shared Event even during main-thread initialization I/O, and joins before
the clean marker. Normal supervision observes the flag,
sets the shared stop Event and stops starting/restarting workers. An in-flight
spawn remains tracked and cannot accept work after observing that Event.

Each child stops new callbacks cooperatively, requeues late deliveries, and lets
an already-running synchronous callback and its ack/requeue calls finish. A
swallowed callback failure during shutdown cannot become clean proof. On return,
tracked consumer clones, producer and connection factory are closed and checked
locally disconnected. Child acknowledgment is set only after that cleanup.
The parent joins all current children and checks zero exits plus individual
acknowledgments before publishing clean proof. A pending restart/crash, cleanup
error, missed acknowledgment or deadline is nonclean. Held children are killed
and joined within an additional bounded cleanup interval; forced paths never
publish a clean marker or accept exit143. The 20+3-second budget fits inside the
current 30-second Docker stop allowance (plus at most one second for the parent
fanout thread join), subject to actual Linux qualification.

These are local callback/connection/process claims, **not broker-confirmed
durability**. The pinned [Kombu ConsumerMixin](https://github.com/celery/kombu/blob/v5.6.2/kombu/mixins.py)
(also inspected at 5.5.4) checks `should_stop` around its synchronous consume
loop and uses context-managed cancellation/close. ConsumerProducerMixin closes
its producer connection on consume end. Connecting/retrying can still block;
such a case must fail the deadline, rather than be called clean. Requirements
allow Kombu<6, so the actual built dependency version/mixin bytes must be recorded
and qualified with the selected immutable image before enabling this capability.
Upstream worker logging is unchanged; the new helper logs no messages, bodies,
credentials, connection URLs or caught exception details.

## Exact source/proof contract

Installed helper: `/zentral/server/azd_santa_worker_lifecycle.py`.
Installed command: `/zentral/server/base/management/commands/runworkers.py`.
The compiler returns `module_sha256`, `command_sha256`, `upstream_sha256` and
`source_commit` for the image/controller binding. Before stop, a future controller
must verify installed bytes against that reviewed source and bind the original
worker container ID, its StartedAt and current startup nonce. Source preparation
alone is insufficient.

`SANTA_WORKERS_START_JSON:` has exactly `scope`, `nonce`, `parent_pid`,
`grace_seconds`, `module_sha256`, `command_sha256`, with scope
`azd-santa-workers-start-v1`, nonce32hex, grace20 and positive integer PID.
`SANTA_WORKERS_CLEAN_STOP_JSON:` uses scope
`azd-santa-workers-clean-stop-v1`, the same identity/budget/hash fields and
`children`, sorted by PID. Each child has exactly `pid`, `exit_code`, `clean`;
clean success requires positive PID, integer exit0 and true acknowledgment.
The clean marker follows worker joins and handle closes. Forkserver/resource
tracker auxiliaries are CPython infrastructure, not broker worker proofs.

Backup integration remains separate: bound `docker logs --since <StartedAt>`
from the exact original container, require one matching startup and clean marker,
verify hashes/nonce/PID/child schema and actual container exit0/PID0, and recheck
all known queues after publishers and workers are gone. Historical log success,
proxy timeout, generic connection release or exit143 is not a bypass. No controller
or backup code is changed by this candidate.

Offline tests include actual local Windows spawn processes with held synthetic
callbacks, acknowledgment/late-delivery ordering, connection closure and forced
nonzero termination. Other process/deadline/restart/compiler cases are mocks or
pure source checks. They prove no Linux signals, actual AMQP acknowledgments,
queue drain, metrics/thread teardown, forkserver behavior or core-image wiring.
The exact pinned upstream command was transformed and compiled locally without
executing it. Later qualification must exercise TERM during idle/held callback,
broker disconnect/reconnect, crash restart, deadline/force, and the complete
original-CID controller stop/drain/snapshot boundary.
