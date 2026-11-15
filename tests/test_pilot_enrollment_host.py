"""Controlled host composer only; no Docker, ORM, identity or network invocation."""
import base64
import builtins
from contextlib import redirect_stdout
import copy
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('pilot_host',ROOT/'experiments/server/pilot_enrollment_host.py')
host=importlib.util.module_from_spec(spec);spec.loader.exec_module(host)
SOURCE=b"""import base64,json,os,builtins
loads=json.loads
def request_from_environment():
 builtins._pilot_calls.append('parse');return loads(base64.b64decode(os.environ['AZD_SANTA_SETUP_REQUEST_B64'])),None
def attest_metadata(binding):builtins._pilot_calls.append('metadata')
def attest_runtime(request):builtins._pilot_calls.append('runtime');return {'web':'a'*64}
def docker(arguments,**kwargs):
 builtins._pilot_calls.append('worker');compile(arguments[-1],'container_wrapper','exec')
 assert 'operator_access' not in arguments[-1] and 'os.fsync(parent)' in arguments[-1]
 assert arguments[:2]==['exec','-i'] and kwargs['timeout']==180
 payload=loads(kwargs['input']);assert payload['operation'] in ('create','observe')
 return ('SANTA_PILOT_ENVELOPE:'+json.dumps(builtins._pilot_envelope)).encode()
"""

def sha(value):return hashlib.sha256(value).hexdigest()
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')

class Composer(unittest.TestCase):
 def setUp(self):
  self.binding=dict(RemoteProgramSha256=sha(SOURCE),Origin='https://pilot.example.test')
  enrollment=dict(deployment_sha256=sha(canonical(self.binding)),operator_username='existing',origin=self.binding['Origin'],recipient_public_key='synthetic-public',nonce='a'*32)
  self.envelope=dict(scope='azd-santa-pilot-enrollment-v1',context_sha256=sha(canonical(enrollment)),recipient_sha256='b'*64,configuration_id=1,enrollment_id=2,ciphertext_base64=base64.b64encode(b'x'*384).decode())
  self.context=dict(operation='create',attestor=base64.b64encode(gzip.compress(SOURCE)).decode(),attestor_sha256=sha(SOURCE),worker=base64.b64encode(gzip.compress(b'# controlled worker')).decode(),worker_sha256=sha(b'# controlled worker'),setup_request=base64.b64encode(json.dumps(dict(context=dict(binding=self.binding),username='existing',email='existing@example.test',recipient_public_key='synthetic-public')).encode()).decode(),enrollment=enrollment)
  self.calls=[]
 def run_context(self,value):
  output=io.StringIO()
  with patch.object(builtins,'_pilot_calls',self.calls,create=True),patch.object(builtins,'_pilot_envelope',self.envelope,create=True),redirect_stdout(output):host.run(value)
  return output.getvalue()
 def test_exact_attestation_then_one_worker_only_and_context_marker(self):
  result=self.run_context(self.context)
  self.assertEqual(self.calls,['parse','metadata','runtime','worker'])
  self.assertIn('SANTA_PILOT_DONE:'+self.envelope['context_sha256'],result)
  self.assertNotIn('synthetic-public',result)
 def test_binding_origin_recipient_or_source_drift_reject_before_worker(self):
  for field,value in [('deployment_sha256','0'*64),('origin','https://other.example.test'),('recipient_public_key','other'),('operator_username','other')]:
   context=copy.deepcopy(self.context);context['enrollment'][field]=value;self.calls.clear()
   with self.subTest(field=field),self.assertRaises(AssertionError):self.run_context(context)
   self.assertNotIn('worker',self.calls)
  context=copy.deepcopy(self.context);context['worker_sha256']='0'*64
  with self.assertRaises(AssertionError):self.run_context(context)
 def test_unknown_operation_and_plaintext_extra_receipt_reject(self):
  context=copy.deepcopy(self.context);context['operation']='recover'
  with self.assertRaises(AssertionError):self.run_context(context)
  self.assertEqual(self.calls,[])
  self.envelope['secret']='plaintext-canary'
  with self.assertRaises(AssertionError):self.run_context(self.context)

if __name__=='__main__':unittest.main()
