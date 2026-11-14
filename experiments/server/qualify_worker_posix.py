"""Original Unlicense standalone Linux TERM/forkserver qualification, no broker.

Runs only disposable subprocesses in newly owned sessions. Requires the frozen
worker helper bytes; never starts/stops a service, image, container or deployment.
"""
import argparse
import hashlib
import importlib.util
import json
import multiprocessing
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import sys
import threading
import time
from types import SimpleNamespace

MODULE_SHA256 = 'e86d20287324eca25ef24c4c405e7d923feafb2d2760c1f22b799f0a02d0a50f'
READY = 'SANTA_POSIX_READY'
CASE = 'SANTA_POSIX_CASE_JSON:'
CASES = ('idle', 'held', 'deadline')


def need(value):
    if not value: raise ValueError('Standalone POSIX worker qualification failed')


def source(path):
    path = Path(path)
    need(path == path.resolve(strict=True) and path.is_file() and not path.is_symlink())
    need(hashlib.sha256(path.read_bytes()).hexdigest() == MODULE_SHA256)
    if os.name != 'nt':
        need(path.stat().st_uid == os.geteuid() and not path.stat().st_mode & 0o022)
    return path


def load(path):
    path = source(path)
    spec = importlib.util.spec_from_file_location('qualified_worker_lifecycle', path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def write(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as output:
        json.dump(value, output, sort_keys=True); output.flush(); os.fsync(output.fileno())


class Connection:
    def __init__(self, closed, connected=False): self.closed=closed; self.connected=connected
    def close(self): self.connected=False; self.closed.set()


class SyntheticConsumer:
    def __init__(self, case, events):
        self.case=case; self.ready,self.release,self.ack,self.requeued,self.closed=events
        self.connection=Connection(self.closed);self.should_stop=False
    def create_connection(self): return Connection(self.closed,True)
    def on_iteration(self): pass
    def callback(self, body, message):
        self.ready.set()
        if not self.release.wait(60): raise RuntimeError('Synthetic callback wait exceeded its bound')
        message.ack()
    def get_consumers(self,*_):return [SimpleNamespace(callbacks=[self.callback])]
    def run(self,**_):
        self.create_connection()
        if self.case=='idle':self.ready.set()
        else:
            callback=self.get_consumers()[0].callbacks[0]
            message=SimpleNamespace(ack=self.ack.set,requeue=self.requeued.set)
            callback('synthetic-only',message)
            callback('late-synthetic-only',message)
        while not self.should_stop:
            self.on_iteration();time.sleep(0.01)


def worker_target(module_path, worker, stop, proof):
    load(module_path).run_worker(worker,stop,proof)


def child(case, module_path):
    """A real parent and forkserver child; outer driver sends actual TERM."""
    need(sys.platform=='linux' and case in CASES)
    lifecycle_module=load(module_path);context=multiprocessing.get_context('forkserver')
    class Command:
        RESTART_DELAY=(10,20)
        def __init__(self):
            self.lifecycle=lifecycle_module.Lifecycle(context)
            self.processes={};self.processes_to_restart={};self.child_pid=None
            self.events=[context.Event() for _ in range(5)]
        def start_worker(self,index,worker):
            if self.lifecycle.stopping:return
            proof=self.lifecycle.new_child(index)
            process=context.Process(target=worker_target,args=(str(module_path),worker,self.lifecycle.event,proof))
            process.daemon=True;process.start();self.child_pid=process.pid
            self.processes[index]=(worker,process)
        def _azd_handle(self,**_):
            self.start_worker(0,SyntheticConsumer(case,self.events))
            need(self.events[0].wait(8))
            if case=='held':
                def release_after_term():
                    if self.lifecycle.event.wait(10):
                        time.sleep(0.25);self.events[1].set()
                threading.Thread(target=release_after_term,daemon=True).start()
            print(READY,flush=True)
            lifecycle_module.watch_workers(self)
    command=Command();passed=False
    try:
        lifecycle_module.run_command(command,__file__)
        passed=True
    except BaseException:
        passed=False
    print(CASE+json.dumps(dict(case=case,child_pid=command.child_pid,ack=command.events[2].is_set(),
        requeued=command.events[3].is_set(),closed=command.events[4].is_set(),
        acknowledged=command.lifecycle.proofs.get(0).is_set() if 0 in command.lifecycle.proofs else False),separators=(',',':')),flush=True)
    raise SystemExit(0 if passed else 1)


def record(lines,prefix):
    values=[json.loads(line[len(prefix):]) for line in lines if line.startswith(prefix)]
    need(len(values)==1)
    return values[0]


def validate_observation(lines,case,parent_pid,elapsed,returncode,probe_sha256):
    start=record(lines,'SANTA_WORKERS_START_JSON:');result=record(lines,CASE)
    expected={'scope','nonce','parent_pid','grace_seconds','module_sha256','command_sha256'}
    need(set(start)==expected and start['scope']=='azd-santa-workers-start-v1'
         and isinstance(start['nonce'],str) and re.fullmatch('[a-f0-9]{32}',start['nonce'])
         and type(start['parent_pid']) is int and start['parent_pid']==parent_pid
         and start['grace_seconds']==20 and start['module_sha256']==MODULE_SHA256
         and start['command_sha256']==probe_sha256)
    need(set(result)=={'case','child_pid','ack','requeued','closed','acknowledged'}
         and result['case']==case and type(result['child_pid']) is int and result['child_pid']>0
         and all(type(result[key]) is bool for key in ('ack','requeued','closed','acknowledged')))
    clean_lines=[line for line in lines if line.startswith('SANTA_WORKERS_CLEAN_STOP_JSON:')]
    if case=='deadline':
        need(returncode!=0 and not clean_lines and 19<=elapsed<30
             and not result['ack'] and not result['acknowledged'])
    else:
        clean=record(lines,'SANTA_WORKERS_CLEAN_STOP_JSON:')
        need(returncode==0 and set(clean)==expected|{'children'} and clean['scope']=='azd-santa-workers-clean-stop-v1')
        need(all(clean[key]==start[key] for key in expected-{'scope'}))
        need(clean['children']==[dict(pid=result['child_pid'],exit_code=0,clean=True)])
        need(result['acknowledged'] is True and result['closed'] is True)
        need(result['ack']==result['requeued']==(case=='held'))
    return result,bool(clean_lines)


def run_case(case,module_path,directory):
    need(sys.platform=='linux' and case in CASES)
    environment={key:value for key,value in os.environ.items() if not key.startswith(('PYTHON','DOCKER_','COMPOSE_'))}
    process=subprocess.Popen([sys.executable,'-I',str(Path(__file__).resolve()),'--child',case,'--module',str(module_path)],
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=environment,start_new_session=True)
    buffers={process.stdout:bytearray(),process.stderr:bytearray()};started=time.monotonic();term_at=None
    streams_drained=False
    try:
        write(directory/(case+'-attempt.json'),dict(case=case,parent_pid=process.pid,owned_session=process.pid))
        with selectors.DefaultSelector() as selector:
            for pipe in buffers:selector.register(pipe,selectors.EVENT_READ)
            while selector.get_map():
                now=time.monotonic();need(now-started<45)
                if term_at is None:need(now-started<10)
                else:need(now-term_at<32)
                for key,_ in selector.select(0.1):
                    raw=os.read(key.fileobj.fileno(),65536)
                    if not raw:selector.unregister(key.fileobj)
                    else:
                        buffers[key.fileobj].extend(raw)
                        need(sum(map(len,buffers.values()))<=65536)
                lines=buffers[process.stdout].decode('utf-8',errors='strict').splitlines()
                if term_at is None and READY in lines:
                    need(lines.count(READY)==1 and process.poll() is None)
                    term_at=time.monotonic();process.send_signal(signal.SIGTERM)
            streams_drained=True
            returncode=process.wait(timeout=2)
        elapsed=time.monotonic()-term_at if term_at is not None else 0
        need(term_at is not None)
        lines=buffers[process.stdout].decode().splitlines()
        result,clean_marker=validate_observation(lines,case,process.pid,elapsed,returncode,
                                               hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
        try:os.kill(result['child_pid'],0)
        except ProcessLookupError:pass
        else:raise ValueError('Owned synthetic worker did not exit')
        return dict(case=case,passed=True,signal='SIGTERM',start_method='forkserver',returncode=returncode,
                    clean_marker=clean_marker,elapsed_after_term_seconds=round(elapsed,3),
                    held_callback_ack=result['ack'],late_requeued=result['requeued'])
    finally:
        try:
            if process.poll() is None or not streams_drained:
                # Synthetic descendants never leave this newly owned session.
                # Undrained inherited pipes retain its ownership even if the
                # parent already exited. Never select a global process name.
                try:os.killpg(process.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                process.wait(timeout=3)
        finally:
            for pipe in buffers:pipe.close()
            # Retain bounded diagnostics on failure too. No raw output goes to
            # the public receipt; a failed attempt is never retried in place.
            write(directory/(case+'-private-output.json'),dict(
                stdout=bytes(buffers[process.stdout][:65536]).decode('utf-8',errors='replace'),
                stderr=bytes(buffers[process.stderr][:65536]).decode('utf-8',errors='replace'),
                returncode=process.poll(),term_sent=term_at is not None))


def run(module_path,destination):
    need(sys.platform=='linux')
    module_path=source(module_path);destination=Path(destination)
    need(destination.is_absolute() and destination.parent==destination.parent.resolve(strict=True)
         and not destination.exists() and not destination.is_symlink())
    parent=destination.parent.stat();need(parent.st_uid==os.geteuid() and not parent.st_mode&0o022)
    destination.mkdir(mode=0o700)
    identity=dict(scope='azd-santa-posix-worker-lifecycle-v1',module_sha256=MODULE_SHA256,
        probe_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),python_version=sys.version.split()[0],
        limitation='Standalone synthetic Linux processes only; no Kombu/broker/image/controller/backup acceptance')
    write(destination/'attempt.json',identity)
    observations=[]
    try:
        for case in CASES:observations.append(run_case(case,module_path,destination))
        receipt=dict(**identity,passed=True,cases=observations)
        write(destination/'receipt.json',receipt);return receipt
    except BaseException:
        write(destination/'failed.json',dict(**identity,passed=False,cases=observations,
            action='Preserve this attempt; inspect owned subprocess evidence before a fresh qualification'))
        raise


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--module',required=True);parser.add_argument('--destination')
    parser.add_argument('--child',choices=CASES)
    args=parser.parse_args()
    if args.child:child(args.child,source(args.module))
    try:
        need(args.destination is not None)
        print(json.dumps(run(args.module,args.destination),sort_keys=True))
    except BaseException:
        raise SystemExit('Standalone POSIX qualification failed; preserve private attempt evidence') from None
