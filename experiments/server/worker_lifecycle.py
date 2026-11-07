"""Original Unlicense graceful supervision for pinned synchronous Kombu workers.

Signals set flags only; no callback is interrupted to manufacture a clean exit.
Broker durability/drain remains a separate controller-owned qualification gate.
"""
import hashlib
import json
import os
from pathlib import Path
import random
import secrets
import signal
import sys
import threading
import time

GRACE_SECONDS = 20
START = 'SANTA_WORKERS_START_JSON:'
CLEAN = 'SANTA_WORKERS_CLEAN_STOP_JSON:'


class ShutdownDeadline(BaseException):
    pass


class Lifecycle:
    def __init__(self, context):
        self.context = context
        self.event = context.Event()
        self.proofs = {}
        self.requested = False
        self.deadline = None

    @property
    def stopping(self):
        if self.requested:
            self.event.set()  # Never acquire a multiprocessing lock in a signal handler.
        return self.requested

    def request(self, *_):
        if not self.requested:
            self.requested = True
            self.deadline = time.monotonic() + GRACE_SECONDS
            signal.setitimer(signal.ITIMER_REAL, GRACE_SECONDS)

    def new_child(self, index):
        proof = self.context.Event(); self.proofs[index] = proof
        return proof

    def wait(self, seconds):
        end = time.monotonic() + seconds
        while not self.stopping and time.monotonic() < end:
            time.sleep(min(0.1, max(0, end-time.monotonic())))


def run_worker(worker, stop, proof, **kwargs):
    """Forkserver target. Current synchronous callback/ack runs to completion."""
    local_stop = False; connections = []; clean = False; callback_clean = True
    previous = {}
    def stopping(): return local_stop or stop.is_set()
    def request(*_):
        nonlocal local_stop
        local_stop = True; worker.should_stop = True
    try:
        for sig in (signal.SIGTERM, signal.SIGINT):
            previous[sig] = signal.signal(sig, request)
        original_create = worker.create_connection
        def create():
            connection = original_create(); connections.append(connection)
            return connection
        worker.create_connection = create
        original_iteration = worker.on_iteration
        def iteration():
            if stopping(): worker.should_stop = True
            else: original_iteration()
        worker.on_iteration = iteration
        original_consumers = worker.get_consumers
        def consumers(*args, **options):
            selected = original_consumers(*args, **options)
            for consumer in selected:
                callbacks = consumer.callbacks
                if not isinstance(callbacks, (list, tuple)) or not callbacks or not all(callable(c) for c in callbacks):
                    raise RuntimeError('Unsupported worker callbacks')
                def guard(callback):
                    def invoke(body, message):
                        nonlocal callback_clean
                        try:
                            if stopping():
                                worker.should_stop = True
                                message.requeue()
                            else:
                                callback(body, message)
                                callback_clean = True
                        except BaseException:
                            callback_clean = False
                            raise
                    return invoke
                consumer.callbacks = [guard(callback) for callback in callbacks]
            return selected
        worker.get_consumers = consumers
        if stopping(): worker.should_stop = True
        else: worker.run(**kwargs)
        clean = stopping() and callback_clean
    except BaseException:
        clean = False  # Never export exception args/message bodies/credentials.
    finally:
        # Kombu's consumer context normally closes its cloned connection and
        # ProducerMixin closes its producer on_consume_end. Explicitly close
        # tracked/factory/producer connections after callbacks have returned.
        for connection in [*connections, getattr(worker, '_producer_connection', None), getattr(worker, 'connection', None)]:
            if connection is None: continue
            try:
                connection.close()
                if connection.connected is not False: clean = False
            except BaseException: clean = False
        for sig, handler in previous.items(): signal.signal(sig, handler)
    if clean:
        proof.set()  # Parent still requires successful full process join/exit.
    else:
        raise SystemExit(1)


def watch_workers(command):
    lifecycle = command.lifecycle
    while not lifecycle.stopping:
        lifecycle.wait(random.uniform(1, 3))
        if lifecycle.stopping: break
        for index, (worker, process) in command.processes.items():
            if index in command.processes_to_restart: continue
            if not process.is_alive():
                process.join(timeout=0)
                process.close()
                command.processes_to_restart[index] = (time.monotonic() + random.uniform(*command.RESTART_DELAY), worker)
        for index, (deadline, worker) in list(command.processes_to_restart.items()):
            if lifecycle.stopping: break
            if deadline < time.monotonic():
                previous = command.processes[index][1]
                command.start_worker(index, worker)
                if command.processes[index][1] is not previous:
                    command.processes_to_restart.pop(index)
                elif not lifecycle.stopping:
                    raise RuntimeError('Worker restart did not start')


def finish(command, deadline):
    """Join current children; any pending crash, timeout or force is nonclean."""
    command.lifecycle.event.set()
    clean = bool(command.processes) and not command.processes_to_restart
    current = []
    for index, (_, process) in command.processes.items():
        if index in command.processes_to_restart: continue
        try: process.is_alive()
        except ValueError:
            clean = False
            continue
        current.append((index, process))
    while any(process.is_alive() for _, process in current) and time.monotonic() < deadline:
        for _, process in current:
            process.join(timeout=min(0.1, max(0, deadline-time.monotonic())))
    survivors = [process for _, process in current if process.is_alive()]
    if survivors:
        clean = False
        for process in survivors:
            try: process.kill()
            except BaseException: pass
        kill_deadline = time.monotonic() + 3
        for process in survivors:
            process.join(timeout=max(0, kill_deadline-time.monotonic()))
    children = []; unjoined = False
    for index, process in current:
        alive = process.is_alive()
        unjoined = unjoined or alive
        acknowledged = command.lifecycle.proofs[index].is_set()
        clean = clean and not alive and type(process.exitcode) is int and process.exitcode == 0 and acknowledged
        if not alive:
            process.join(timeout=0)
            children.append(dict(pid=process.pid, exit_code=process.exitcode, clean=acknowledged))
            process.close()
    if unjoined:
        # In a container PID1 exit tears down its namespace. Never enter Python's
        # unbounded daemon auto-join with an unkillable child or emit clean proof.
        os._exit(1)
    return clean, sorted(children, key=lambda item: item['pid'])


def run_command(command, command_file, *args, **options):
    if options.get('list_workers'): return command._azd_handle(*args, **options)
    if sys.platform != 'linux' or signal.getitimer(signal.ITIMER_REAL) != (0.0, 0.0):
        raise SystemExit('Worker lifecycle requires an unowned Linux deadline timer')
    lifecycle = command.lifecycle; handlers = {}; failed = False; children = []
    pump_stop = threading.Event(); pump = None
    identity = dict(nonce=secrets.token_hex(16), parent_pid=os.getpid(), grace_seconds=GRACE_SECONDS,
                    module_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                    command_sha256=hashlib.sha256(Path(command_file).read_bytes()).hexdigest())
    def expired(*_): raise ShutdownDeadline()
    def fanout():
        while not pump_stop.wait(0.05):
            if lifecycle.requested:
                lifecycle.event.set()
                return
    try:
        for sig, handler in ((signal.SIGTERM, lifecycle.request), (signal.SIGINT, lifecycle.request), (signal.SIGALRM, expired)):
            handlers[sig] = signal.signal(sig, handler)
        # Signal handlers use only flags; this thread propagates cancellation
        # even if main-thread initialization is waiting on I/O.
        pump = threading.Thread(target=fanout, daemon=True); pump.start()
        print(START + json.dumps(dict(scope='azd-santa-workers-start-v1', **identity), separators=(',', ':')), flush=True)
        command._azd_handle(*args, **options)
        failed = not lifecycle.requested
    except BaseException:
        failed = True
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        lifecycle.event.set()
        try:
            clean, children = finish(command, lifecycle.deadline if lifecycle.deadline is not None else time.monotonic() + GRACE_SECONDS)
            failed = failed or not clean
        except BaseException:
            failed = True
        pump_stop.set()
        if pump is not None:
            pump.join(timeout=1)
            failed = failed or pump.is_alive()
        signal.setitimer(signal.ITIMER_REAL, 0)
        for sig, handler in handlers.items(): signal.signal(sig, handler)
    if failed:
        raise SystemExit('Worker shutdown was not proven clean')
    print(CLEAN + json.dumps(dict(scope='azd-santa-workers-clean-stop-v1', **identity, children=children), separators=(',', ':')), flush=True)
