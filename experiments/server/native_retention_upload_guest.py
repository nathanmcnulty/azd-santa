"""Original Unlicense. Run a single reviewed source upload relay on the guest."""

import io
import json
import os
from pathlib import Path
import re
import subprocess
import zipfile
from contextlib import ExitStack

import blob_capability_relay as relay
import blob_retention as blob

SCOPE = 'azd-santa-native-upload-command-v1'
RECORD_SCOPE = 'azd-santa-native-capture-record-v1'
PROGRAMS = ('blob_retention.py', 'blob_capability_relay.py')
MAX_PACKET = 2048


def checked_pins(pins):
    hashes = {'request_sha256', 'ciphertext_sha256', 'source_bundle_sha256'}
    blob.need(set(pins) == hashes | {'ciphertext_bytes', 'image_id'}
              and all(re.fullmatch(blob.HEX, pins[key]) for key in hashes)
              and re.fullmatch('sha256:' + blob.HEX, pins['image_id'])
              and type(pins['ciphertext_bytes']) is int
              and len(blob.MAGIC) + 32 < pins['ciphertext_bytes'] <= blob.MAXIMUM)


def check_record(record, target, selected, pins):
    blob.checked_record(record)
    complete = record['complete']
    blob.need(record['blob_uri'] == selected.uri and record['operation_id'] == selected.operation
              and record['source_vm_id'] == target.vm_id and record['source_instance_id'] == target.instance_id
              and record['image_id'] == pins['image_id'] and record['source_bundle_sha256'] == pins['source_bundle_sha256']
              and complete['maintenance_sha256'] == pins['request_sha256']
              and complete['ciphertext_sha256'] == pins['ciphertext_sha256']
              and complete['ciphertext_bytes'] == pins['ciphertext_bytes'])


def collect(config, target):
    selected = blob.Blob(**config['blob'])
    pins = config['pins']
    checked_pins(pins)
    match = re.fullmatch(r'rg-azd-santa-vm-([a-z0-9-]{2,32})', target.vm_id.split('/')[4])
    blob.need(match is not None)
    environment = match[1]
    runtime = relay.ROOT / ('private-runtime-' + environment) / 'runtime-service'
    request = relay.read_file(runtime / 'backup-request.json', 65536, private=True)
    blob.need(relay.sha(request) == pins['request_sha256'])
    request_info = relay.parsed(request)
    blob.need(request_info['operation_id'] == selected.operation)
    destination = Path(request_info['destination'])
    blob.need(destination.parent == relay.ROOT and re.fullmatch(r'ciphertext-[a-z0-9-]{2,64}', destination.name))
    complete = relay.parsed(relay.read_file(destination / 'complete.json', 16384, private=True))
    record = blob.capture_record(selected, complete, target, maintenance_request=request,
                                 image_id=pins['image_id'], source_bundle_sha256=pins['source_bundle_sha256'])
    check_record(record, target, selected, pins)
    relay.capture(environment, target, record)
    return record


def checked_document(raw, maximum):
    blob.need(0 < len(raw) <= maximum)
    value = json.loads(raw, object_pairs_hook=blob.unique)
    blob.need(type(value) is dict and blob.encoded(value) == raw)
    return value


def stage_program(folder, name, data, create):
    if create:
        descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=folder)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(folder)
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=folder)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        relay.State.file(before)
        blob.need(before.st_size == len(data) and stream.read(len(data) + 1) == data
                  and blob.identity(before) == blob.identity(os.fstat(stream.fileno())))


BRIDGE = """import sys
sys.path.insert(0, sys.argv[1])
import blob_capability_relay as relay

config, request = relay.parsed(sys.stdin.buffer.read(32769))
target = relay.blob.SelectedTarget(**config['source'])
record = config['record']
selected = relay.blob.Blob(**config['blob'])
environment = target.vm_id.split('/')[4].removeprefix('rg-azd-santa-vm-')
operation = relay.selection(environment, target, record)
action = request['action']
if request == {'action': 'offer'}:
    offer = relay.create_offer(environment, target, record, selected, apply=True)
    result = {'state': 'offered', 'offer': offer}
elif action == 'submit' and set(request) == {'action', 'packet', 'offer_sha256'}:
    result = relay.submit(operation, request['offer_sha256'], request['packet'], apply=True)
elif request == {'action': 'observe'}:
    result = relay.observe(operation, read_guest=True)
else:
    raise ValueError()
print(relay.encoded(result).decode('ascii'))
"""


def dispatch(raw, request_raw):
    """Stage only the reviewed relay scripts. The systemd job outlives Run Command."""
    request = checked_document(request_raw, MAX_PACKET + 512)
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entries = archive.infolist()
        blob.need(tuple(entry.filename for entry in entries) ==
                  (*PROGRAMS, 'native_retention_upload_guest.py', 'selection.json')
                  and all(0 < entry.file_size <= 262144 for entry in entries)
                  and entries[-1].file_size <= 8192)
        files = {name: archive.read(name) for name in PROGRAMS}
        config_raw = archive.read('selection.json')
    config = checked_document(config_raw, 8192)
    target = blob.SelectedTarget(**config['source'])
    blob.host_identity(target)
    if request == {'action': 'read-record'}:
        blob.need(set(config) == {'source', 'blob', 'pins'})
        record = collect(config, target)
        return {'scope': RECORD_SCOPE, 'batch_sha256': relay.sha(request_raw),
                'record': record, 'record_sha256': relay.sha(blob.encoded(record))}
    blob.need(set(config) == {'source', 'blob', 'record'})
    digest = relay.sha(blob.encoded({name: relay.sha(data) for name, data in files.items()}))
    folder = relay.ROOT / ('native-upload-' + digest)
    with ExitStack() as stack:
        parent, leaf = blob.parent(folder, stack)
        created = False
        if request == {'action': 'offer'}:
            try:
                os.mkdir(leaf, 0o700, dir_fd=parent)
                os.fsync(parent)
                created = True
            except FileExistsError:
                pass
        fd = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        stack.callback(os.close, fd)
        relay.State.directory(os.fstat(fd))
        for name, data in files.items():
            stage_program(fd, name, data, created)
    result = subprocess.run(['/usr/bin/python3', '-I', '-B', '-c', BRIDGE, str(folder)],
                            input=blob.encoded([config, request]), capture_output=True, timeout=160)
    blob.need(result.returncode == 0 and not result.stderr and 0 < len(result.stdout) <= 2900)
    reply = json.loads(result.stdout, object_pairs_hook=blob.unique)
    return {'scope': SCOPE, 'batch_sha256': relay.sha(request_raw),
            'record_sha256': relay.sha(blob.encoded(config['record'])), 'reply': reply}
