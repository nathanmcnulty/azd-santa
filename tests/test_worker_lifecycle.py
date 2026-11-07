"""Synthetic local processes only; no broker, Linux-signal or image acceptance."""
import contextlib
import hashlib
import io
import json
import multiprocessing
from pathlib import Path
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'experiments/server'))
import worker_lifecycle as life
import prepare_worker_lifecycle as overlay


class Connection:
    def __init__(self, closed, connected=False): self.closed=closed; self.connected=connected
    def close(self): self.connected=False; self.closed.set()


class SyntheticWorker:
    def __init__(self, entered, release, ack, rejected, closed):
        self.entered=entered; self.release=release; self.ack=ack; self.rejected=rejected
        self.closed=closed; self.connection=Connection(closed); self.should_stop=False
    def create_connection(self): return Connection(self.closed, True)
    def on_iteration(self): pass
    def callback(self, body, message):
        self.entered.set()
        if not self.release.wait(5): raise RuntimeError('synthetic held work did not finish')
        message.ack()
    def get_consumers(self, *_): return [SimpleNamespace(callbacks=[self.callback])]
    def run(self, **_):
        self.create_connection()
        consumer=self.get_consumers()[0]
        message=SimpleNamespace(ack=self.ack.set,requeue=self.rejected.set)
        consumer.callbacks[0]('synthetic-private-body', message)
        consumer.callbacks[0]('must-be-requeued', message)
        while not self.should_stop:
            self.on_iteration();time.sleep(0.01)


class Process:
    def __init__(self, alive=False, code=0): self.alive=alive;self.exitcode=code;self.pid=123;self.closed=False;self.killed=False
    def is_alive(self):
        if self.closed: raise ValueError('closed')
        return self.alive
    def join(self, timeout=0): pass
    def close(self): self.closed=True
    def kill(self): self.killed=True;self.alive=False;self.exitcode=-9


class Workers(unittest.TestCase):
    def test_signal_request_never_locks_event_or_renews_deadline(self):
        lifecycle=life.Lifecycle(SimpleNamespace(Event=threading.Event))
        with patch.object(life.time,'monotonic',side_effect=[10.,99.]),\
             patch.object(life.signal,'ITIMER_REAL',0,create=True),patch.object(life.signal,'setitimer',create=True) as timer:
            lifecycle.request();self.assertEqual(lifecycle.deadline,30.)
            lifecycle.request();self.assertEqual(lifecycle.deadline,30.)
            timer.assert_called_once_with(0,20)
        self.assertFalse(lifecycle.event.is_set())
        self.assertTrue(lifecycle.stopping);self.assertTrue(lifecycle.event.is_set())

    def process_fixture(self):
        ctx=multiprocessing.get_context('spawn')
        events=[ctx.Event() for _ in range(7)]
        entered,release,ack,rejected,closed,stop,proof=events
        worker=SyntheticWorker(entered,release,ack,rejected,closed)
        process=ctx.Process(target=life.run_worker,args=(worker,stop,proof))
        process.start()
        self.addCleanup(self.cleanup_process,process)
        self.assertTrue(entered.wait(4))
        return process,events
    @staticmethod
    def cleanup_process(process):
        if process._closed:return
        if process.is_alive():process.kill();process.join(3)
        process.close()
    def test_held_callback_finishes_ack_before_clean_join_and_late_work_is_requeued(self):
        process,events=self.process_fixture()
        entered,release,ack,rejected,closed,stop,proof=events
        stop.set();time.sleep(0.1)
        self.assertTrue(process.is_alive());self.assertFalse(ack.is_set());self.assertFalse(proof.is_set())
        release.set();process.join(4)
        self.assertFalse(process.is_alive());self.assertEqual(process.exitcode,0)
        self.assertTrue(ack.is_set() and rejected.is_set() and closed.is_set() and proof.is_set())
    def test_deadline_forces_held_process_nonzero_and_never_proves_clean(self):
        process,events=self.process_fixture();stop,proof=events[-2:]
        lifecycle=SimpleNamespace(event=stop,proofs={0:proof})
        command=SimpleNamespace(lifecycle=lifecycle,processes={0:(None,process)},processes_to_restart={})
        clean,children=life.finish(command,time.monotonic()+0.05)
        self.assertFalse(clean);self.assertNotEqual(children[0]['exit_code'],0)
        self.assertFalse(children[0]['clean']);self.assertFalse(proof.is_set())
    def test_unexpected_return_or_exception_cannot_emit_child_clean_ack(self):
        for crash in (False,True):
            closed=threading.Event();stop=threading.Event();proof=threading.Event()
            worker=SimpleNamespace(create_connection=lambda:Connection(closed),on_iteration=lambda:None,
                                   get_consumers=lambda:[],connection=Connection(closed))
            def run(**_):
                if crash:raise ValueError('private-credential-canary')
            worker.run=run
            output=io.StringIO()
            with self.subTest(crash=crash),contextlib.redirect_stdout(output),contextlib.redirect_stderr(output):
                with self.assertRaises(SystemExit):life.run_worker(worker,stop,proof)
            self.assertFalse(proof.is_set());self.assertTrue(closed.is_set())
            self.assertNotIn('private-credential',output.getvalue())
    def test_shutdown_before_child_begins_accepts_no_callback(self):
        events=[threading.Event() for _ in range(7)]
        worker=SyntheticWorker(*events[:5]);stop,proof=events[-2:];stop.set()
        life.run_worker(worker,stop,proof)
        self.assertFalse(events[0].is_set());self.assertFalse(events[2].is_set());self.assertTrue(proof.is_set())
    def test_connection_close_failure_prevents_clean_ack(self):
        stop=threading.Event();stop.set();proof=threading.Event()
        connection=SimpleNamespace(connected=True,close=lambda:None)
        worker=SimpleNamespace(create_connection=lambda:connection,on_iteration=lambda:None,get_consumers=lambda:[],connection=connection)
        with self.assertRaises(SystemExit):life.run_worker(worker,stop,proof)
        self.assertFalse(proof.is_set())
    def test_mixin_swallowing_a_callback_failure_during_stop_cannot_prove_clean(self):
        stop=threading.Event();proof=threading.Event();closed=threading.Event()
        def callback(*_):stop.set();raise OSError('private-broker-canary')
        worker=SimpleNamespace(create_connection=lambda:Connection(closed),on_iteration=lambda:None,
            get_consumers=lambda:[SimpleNamespace(callbacks=[callback])],connection=Connection(closed))
        def run(**_):
            consumer=worker.get_consumers()[0]
            try:consumer.callbacks[0]('body',SimpleNamespace(requeue=lambda:None))
            except OSError:pass  # ConsumerMixin reconnect path can swallow this.
            consumer.callbacks[0]('late-body',SimpleNamespace(requeue=lambda:None))
        worker.run=run
        with self.assertRaises(SystemExit):life.run_worker(worker,stop,proof)
        self.assertFalse(proof.is_set());self.assertTrue(closed.is_set())
    def test_crash_restarts_remain_enabled_outside_shutdown(self):
        now=[0];lifecycle=SimpleNamespace(stopping=False)
        def wait(_):now[0]+=20
        lifecycle.wait=wait
        command=SimpleNamespace(lifecycle=lifecycle,processes={0:(None,Process(code=1))},processes_to_restart={},RESTART_DELAY=(10,20))
        starts=[]
        def start(index,worker):
            starts.append(index);command.processes[index]=(worker,Process(alive=True));lifecycle.stopping=True
        command.start_worker=start
        with patch.object(life.time,'monotonic',side_effect=lambda:now[0]),patch.object(life.random,'uniform',return_value=10):
            life.watch_workers(command)
        self.assertEqual(starts,[0]);self.assertEqual(command.processes_to_restart,{})
    def test_clean_marker_follows_join_close_and_has_only_fixed_identity_fields(self):
        ctx=SimpleNamespace(Event=threading.Event)
        lifecycle=life.Lifecycle(ctx);proof=lifecycle.new_child(0);proof.set()
        process=Process();command=SimpleNamespace(lifecycle=lifecycle,processes={0:(None,process)},processes_to_restart={})
        def handle(**_):
            lifecycle.requested=True;lifecycle.deadline=time.monotonic()+1
            # Main never calls lifecycle.stopping here: the independent pump
            # must still fan cancellation out while initialization is blocked.
            self.assertTrue(lifecycle.event.wait(0.5))
        command._azd_handle=handle
        with tempfile.TemporaryDirectory() as folder:
            file=Path(folder)/'command.py';file.write_text('# synthetic command\n')
            output=io.StringIO()
            with patch.object(life.sys,'platform','linux'),patch.object(life.signal,'getitimer',return_value=(0.,0.),create=True),\
                 patch.object(life.signal,'signal',return_value=None),patch.object(life.signal,'setitimer',create=True),\
                 patch.object(life.signal,'ITIMER_REAL',0,create=True),patch.object(life.signal,'SIGALRM',14,create=True),\
                 contextlib.redirect_stdout(output):life.run_command(command,file)
            lines=output.getvalue().splitlines();self.assertEqual(len(lines),2);self.assertTrue(process.closed)
            start=json.loads(lines[0][len(life.START):]);clean=json.loads(lines[1][len(life.CLEAN):])
            self.assertEqual(set(start),{'scope','nonce','parent_pid','grace_seconds','module_sha256','command_sha256'})
            self.assertEqual(set(clean),set(start)|{'children'})
            self.assertEqual(start['nonce'],clean['nonce']);self.assertEqual(clean['children'],[dict(pid=123,exit_code=0,clean=True)])
    def test_pending_crash_or_missing_child_ack_cannot_be_clean(self):
        for pending in (True,False):
            lifecycle=SimpleNamespace(event=threading.Event(),proofs={0:threading.Event()})
            command=SimpleNamespace(lifecycle=lifecycle,processes={0:(None,Process())},processes_to_restart={0:(0,None)} if pending else {})
            clean,_=life.finish(command,time.monotonic())
            self.assertFalse(clean)


class Compiler(unittest.TestCase):
    def test_hash_mismatch_rejected_and_overlay_preserves_original_entry_logic(self):
        raw=b'''from zentral.core.queues.workers import get_workers
class Command:
    def __init__(self):
        multiprocessing.set_forkserver_preload(["server.multiprocessing_preload"])
    def start_worker(self, idx, worker):
        p = Process(target=worker.run,
                    kwargs={})
    def watch_workers(self):
        while True:
            pass
    def handle(self, *args, **options):
        return options['list_workers']
'''
        with self.assertRaises(ValueError):overlay.transform(raw)
        with patch.object(overlay,'INPUT_SHA256',hashlib.sha256(raw).hexdigest()):
            output=overlay.transform(raw).decode()
        self.assertIn("return options['list_workers']",output)
        self.assertIn('self.lifecycle.context.Process(target=run_worker',output)
        self.assertIn('Lifecycle(multiprocessing.get_context("forkserver"))',output)
        self.assertIn('return run_command(self, __file__',output)
        self.assertTrue(output.startswith(overlay.NOTICE))


if __name__=='__main__':unittest.main()
