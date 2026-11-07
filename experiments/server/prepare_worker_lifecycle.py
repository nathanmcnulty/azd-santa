"""Original Unlicense hash-bound overlay for pinned Apache/core runworkers.

No build/start action. Caller composes the returned stage after existing core
derivations and separately qualifies the installed process/Kombu behavior.
"""
import ast
import base64
import hashlib
from pathlib import Path

COMMIT = '88e67b3ce49033aab028029937a6e14f7c489073'
SOURCE = 'server/base/management/commands/runworkers.py'
INPUT_SHA256 = '000e35e8630ecacbc0dd4f6582ac20bcc4b5417f416b1e1fd513ad6b2161819a'
NOTICE = '# Modified by azd-santa: cooperative callback completion and bounded joined worker shutdown.\n'


def sha(raw): return hashlib.sha256(raw).hexdigest()


def transform(raw):
    if sha(raw) != INPUT_SHA256: raise ValueError('Pinned worker command differs')
    text = raw.decode('utf-8')
    patches = (
        ('from zentral.core.queues.workers import get_workers',
         'from zentral.core.queues.workers import get_workers\nfrom azd_santa_worker_lifecycle import Lifecycle, run_worker, watch_workers, run_command'),
        ('        multiprocessing.set_forkserver_preload(["server.multiprocessing_preload"])',
         '        multiprocessing.set_forkserver_preload(["server.multiprocessing_preload"])\n        self.lifecycle = Lifecycle(multiprocessing.get_context("forkserver"))'),
        ('    def start_worker(self, idx, worker):',
         '    def start_worker(self, idx, worker):\n        if self.lifecycle.stopping:\n            return'),
        ('        p = Process(target=worker.run,',
         '        proof = self.lifecycle.new_child(idx)\n        p = self.lifecycle.context.Process(target=run_worker,\n                    args=(worker, self.lifecycle.event, proof),'),
        ('    def handle(self, *args, **options):', '    def _azd_handle(self, *args, **options):'),
    )
    for old, new in patches:
        if text.count(old) != 1: raise ValueError('Pinned worker overlay anchor differs')
        text = text.replace(old, new, 1)
    tree = ast.parse(text)
    command = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'Command')
    watch = next(node for node in command.body if isinstance(node, ast.FunctionDef) and node.name == 'watch_workers')
    segment = ast.get_source_segment(text, watch)
    if text.count(segment) != 1: raise ValueError('Ambiguous worker supervision method')
    text = text.replace(segment, 'def watch_workers(self):\n        watch_workers(self)', 1)
    text += '\n    def handle(self, *args, **options):\n        return run_command(self, __file__, *args, **options)\n'
    result = (NOTICE + text).encode()
    compile(result, SOURCE, 'exec')
    return result


def docker_program(source_root, module_path=None):
    root = Path(source_root).resolve(strict=True)
    path = root / SOURCE
    if path.is_symlink() or path.resolve(strict=True) != path: raise ValueError('Canonical pinned worker source required')
    output = transform(path.read_bytes())
    helper = Path(module_path) if module_path else Path(__file__).with_name('worker_lifecycle.py')
    body = helper.read_bytes().replace(b'\r\n', b'\n')
    compile(body, 'azd_santa_worker_lifecycle.py', 'exec')
    program = ('from pathlib import Path\nfrom hashlib import sha256\nfrom base64 import b64decode\n'
        "p=Path('/zentral/" + SOURCE + "')\n"
        f"assert sha256(p.read_bytes()).hexdigest()=={INPUT_SHA256!r}\n"
        "helper=Path('/zentral/server/azd_santa_worker_lifecycle.py')\n"
        "assert not helper.exists() and not helper.is_symlink()\n"
        f"body=b64decode({base64.b64encode(body).decode()!r})\n"
        f"command=b64decode({base64.b64encode(output).decode()!r})\n"
        f"assert sha256(body).hexdigest()=={sha(body)!r}\n"
        f"assert sha256(command).hexdigest()=={sha(output)!r}\n"
        "compile(body,str(helper),'exec');compile(command,str(p),'exec')\n"
        "with helper.open('xb') as stream: stream.write(body)\n"
        "helper.chmod(0o644)\np.write_bytes(command)\np.chmod(0o644)\n")
    compile(program, '<worker-overlay>', 'exec')
    return dict(program=program, module_sha256=sha(body), command_sha256=sha(output),
                upstream_sha256=INPUT_SHA256, source_commit=COMMIT)
