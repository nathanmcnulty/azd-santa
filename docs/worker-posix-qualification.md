# Standalone Linux worker signal qualification

This developer probe executes disposable synthetic processes only. It does not
connect to Kombu/RabbitMQ or change services, containers, images or deployments.
Its results do not establish application, broker durability or backup acceptance.

Stage the exact reviewed `qualify_worker_posix.py` and frozen
`worker_lifecycle.py` in a trusted owner-controlled directory. Verify the probe
SHA against its reviewed commit before execution. The probe itself requires the
helper SHA `e86d20287324eca25ef24c4c405e7d923feafb2d2760c1f22b799f0a02d0a50f`
before importing it. Linux with stdlib Python 3.12+ and forkserver is required;
there are no package installation steps. The destination must be absent with an
existing canonical owner-controlled parent that is not group/world-writable.

```sh
python3 -I /absolute/trusted/qualify_worker_posix.py \
  --module /absolute/trusted/worker_lifecycle.py \
  --destination /absolute/private/absent-worker-posix-attempt
```

Each case runs the frozen Lifecycle/run_command in a new subprocess session with
an actual forkserver child. The outer driver sends SIGTERM to its own parent
Popen handle only after the child's readiness. Cases cover idle close/join,
held callback acknowledgement after TERM followed by late delivery requeue, and
the actual 20-second deadline forcing a nonzero exit without a clean marker.
The driver checks current nonce, hashes, parent/child identity, join evidence and
child disappearance. The marker command hash identifies this probe, not the
derived product management command. Its fallback SIGKILL targets only the newly
owned subprocess session if its parent remains live or its synthetic descendants
still retain inherited output pipes, with a bounded wait. It never selects a
process by global name.

The destination retains exclusive private attempt, per-case stdout/stderr and
final receipt files, including failure output. Public stdout is one nonsecret
success JSON receipt; failure is a fixed message. Do not replay a failed
destination. Preserve it and inspect the private output before authorizing a
fresh attempt. Each case has a 45-second outer bound and a 32-second post-TERM
bound. Expected total runtime is about 22 seconds, plus process startup.

Offline guard tests do not prove Linux signals. Actual execution of all three
cases is a separate coordinator-owned gate. Subsequent core-image qualification
must additionally exercise real synchronous callback/ack failure and swallowed
connection errors, ConsumerProducerMixin publish/ack ordering, late prefetched
delivery requeue, reconnect/dead-broker deadline, normal crash/restart behavior,
and final broker queue counts after all publishers/workers exit.
