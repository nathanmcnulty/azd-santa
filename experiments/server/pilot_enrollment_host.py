"""Bound read-only host attestation followed by one separate enrollment worker."""
import base64
import gzip
import hashlib
import io
import json
import os
import types


def unpack(value, digest):
    with gzip.GzipFile(fileobj=io.BytesIO(base64.b64decode(value, validate=True))) as stream:
        raw = stream.read(65537)
    assert len(raw) <= 65536 and hashlib.sha256(raw).hexdigest() == digest
    return raw


def run(context):
    assert context['operation'] in ('create', 'observe')
    source = unpack(context['attestor'], context['attestor_sha256'])
    host = types.ModuleType('pilot_readonly_attestor')
    exec(compile(source, 'operator_setup_host.py', 'exec'), host.__dict__)
    os.environ['AZD_SANTA_SETUP_REQUEST_B64'] = context['setup_request']
    request, _ = host.request_from_environment()
    assert request['context']['binding']['RemoteProgramSha256'] == context['attestor_sha256']
    host.attest_metadata(request['context']['binding'])
    web = host.attest_runtime(request)['web']
    enrollment = context['enrollment']
    digest = hashlib.sha256(json.dumps(request['context']['binding'], sort_keys=True,
        separators=(',', ':'), ensure_ascii=True).encode('ascii')).hexdigest()
    assert enrollment['deployment_sha256'] == digest
    assert enrollment['operator_username'] == request['username']
    assert enrollment['origin'] == request['context']['binding']['Origin']
    assert enrollment['recipient_public_key'] == request['recipient_public_key']
    unpack(context['worker'], context['worker_sha256'])
    payload = json.dumps(dict(source=context['worker'], sha256=context['worker_sha256'],
        request=enrollment, operator_email=request['email'], operation=context['operation'])).encode('ascii')
    program = """import sys,json,base64,gzip,hashlib,io,types,os
from pathlib import Path
try:
 p=json.loads(sys.stdin.buffer.read(65537));assert len(json.dumps(p))<=65536
 with gzip.GzipFile(fileobj=io.BytesIO(base64.b64decode(p['source'],validate=True))) as f: raw=f.read(65537)
 assert len(raw)<=65536 and hashlib.sha256(raw).hexdigest()==p['sha256']
 worker=types.ModuleType('selected_pilot_worker');exec(compile(raw,'pilot_enrollment.py','exec'),worker.__dict__)
 from accounts.models import User
 assert User.objects.filter(username=p['request']['operator_username'],email=p['operator_email'],is_active=True,is_superuser=True).exists()
 root=Path('/var/zentral/azd-santa-pilot-enrollment')
 if p['operation']=='create':
  root.mkdir(mode=0o700,exist_ok=True)
  parent=os.open(root.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
  try:os.fsync(parent)
  finally:os.close(parent)
 result=worker.run(p['request'],root,p['operation'])
 print('SANTA_PILOT_ENVELOPE:'+json.dumps(result,separators=(',',':')))
except BaseException:
 sys.stderr.write('Pilot operation failed or unknown; never replay create.\\n');sys.exit(1)
"""
    output = host.docker(['exec', '-i', web, 'python', 'server/manage.py', 'shell',
        '--no-imports', '-c', program], timeout=180, input=payload)
    records = [line for line in output.decode('ascii').splitlines() if line.startswith('SANTA_PILOT_ENVELOPE:')]
    assert len(records) == 1 and len(records[0]) <= 4096
    envelope = host.loads(records[0][len('SANTA_PILOT_ENVELOPE:'):])
    digest = hashlib.sha256(json.dumps(enrollment, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')).hexdigest()
    assert set(envelope) == {'scope', 'context_sha256', 'recipient_sha256', 'configuration_id', 'enrollment_id', 'ciphertext_base64'}
    assert envelope['scope'] == 'azd-santa-pilot-enrollment-v1' and envelope['context_sha256'] == digest
    print(records[0])
    print('SANTA_PILOT_DONE:' + digest)
