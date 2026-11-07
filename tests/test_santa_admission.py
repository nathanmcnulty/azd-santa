"""Offline admission boundaries. Fake store exercises request flow, NOT Lua/Redis proof."""
import contextlib
import hashlib
import hmac
import importlib.util
import io
import json
import logging
from pathlib import Path
import sys
import threading
import time
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'experiments/server'))
import santa_admission as admission
import runtime_service as lifecycle


class Response(dict):
    streaming = False
    def __init__(self, data=None, status=200): super().__init__(); self.status_code = status


class Request:
    def __init__(self, path='/public/santa/sync/eventupload/device', header='Bearer PRIVATE-TOKEN'):
        self.path_info = path
        self.META = {'REMOTE_ADDR': '127.0.0.1'}
        if header is not None: self.META['HTTP_ZENTRAL_AUTHORIZATION'] = header
    @property
    def user(self): raise AssertionError('No pre-admission session SQL')
    @property
    def POST(self): raise AssertionError('No pre-admission form parsing')
    def read(self, *args): raise AssertionError('No denied request body read')


class Store:
    """Deliberate Python test double; live gate must execute the actual Lua."""
    def __init__(self): self.owner=None; self.lock=threading.Lock(); self.calls=[]; self.fail=False
    def __call__(self, script, extra_keys=(), arguments=()):
        with self.lock:
            self.calls.append((script,extra_keys,arguments))
            if self.fail: raise RuntimeError('PRIVATE-REDIS-ERROR')
            if script == admission.ACQUIRE:
                if self.owner: return [0,1]
                self.owner=arguments[-1]; return [1,b'0']
            if script == admission.RELEASE:
                if self.owner != arguments[-1]: return 0
                self.owner=None; return 1
            raise AssertionError('Unexpected state repair')


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        conf=ModuleType('django.conf'); conf.settings=SimpleNamespace(SECRET_KEY='PRIVATE-HMAC-KEY')
        http=ModuleType('django.http'); http.JsonResponse=Response
        self.modules=patch.dict(sys.modules, {'django.conf':conf,'django.http':http})
        self.modules.start(); self.addCleanup(self.modules.stop)

    def test_secret_paths_and_authorization_errors_are_not_logged(self):
        guard=admission.SecretPathFilter()
        for message in ('Forbidden: /public/santa/sync/PRIVATE/preflight/device',
                        'Invalid header: Zentral-Authorization: PRIVATE'):
            self.assertFalse(guard.filter(logging.LogRecord('gunicorn.error',40,'',1,message,(),None)))
        record=logging.LogRecord('django.request',40,'',1,'Request failure',(),None)
        record.request=Request('/public/santa/sync/PRIVATE/preflight/device')
        self.assertFalse(guard.filter(record))
        self.assertTrue(guard.filter(logging.LogRecord('gunicorn.error',40,'',1,'Worker exited',(),None)))

    def test_limits_are_bounded_and_proxy_requires_explicit_trust(self):
        for env in ({'AZD_SANTA_ADMISSION_GLOBAL_MAX':'1201'}, {'AZD_SANTA_ADMISSION_WINDOW':'0'},
                    {'AZD_SANTA_ADMISSION_MODE':'proxy'}, {'AZD_SANTA_ADMISSION_MODE':'proxy','AZD_SANTA_ADMISSION_PEERS':'0.0.0.0/0'}):
            with self.assertRaises(ValueError): admission.configured(env)
        self.assertEqual(admission.configured({}).capacity,1)

    def test_both_transports_preserve_header_precedence_and_doctor_scope(self):
        path='/public/santa/sync/LEGACY/preflight/santactl-doctor-test'
        self.assertEqual(admission.credential_from(Request(path,None)),'LEGACY')
        self.assertEqual(admission.credential_from(Request(path,'Bearer HEADER')),'HEADER')
        self.assertEqual(admission.credential_from(Request(path,'Basic HEADER')),'!invalid')
        for path in ('/public/santa/sync/postflight/device','/santa/sync/LEGACY/eventupload/device'):
            self.assertTrue(path.startswith(admission.PREFIXES))

    def test_hmac_domain_separation_and_untrusted_headers_removed(self):
        meta={'REMOTE_ADDR':'127.0.0.1','HTTP_X_REAL_IP':'198.51.100.7','HTTP_FORWARDED':'attacker','HTTP_X_SSL_CLIENT_S_DN':'forged'}
        source,credential=admission.identity(meta,'PRIVATE-TOKEN','PRIVATE-KEY')
        self.assertEqual(meta,{'REMOTE_ADDR':'127.0.0.1','HTTP_X_REAL_IP':'127.0.0.1'})
        self.assertNotIn('PRIVATE',source+credential); self.assertNotIn('127.0.0.1',source)
        self.assertEqual(credential,'sync-credential:'+hmac.new(b'PRIVATE-KEY',b'credential\0PRIVATE-TOKEN',hashlib.sha256).hexdigest())
        self.assertNotEqual(*admission.identity({'REMOTE_ADDR':'127.0.0.1'},'127.0.0.1','PRIVATE-KEY'))

    def test_proxy_rejects_wrong_peer_and_comma_chain(self):
        with patch.object(admission,'CONFIG',admission.Config(mode='proxy',peers=('127.0.0.1/32',))):
            for meta in ({'REMOTE_ADDR':'198.51.100.1','HTTP_X_AZD_SANTA_CLIENT_IP':'192.0.2.1'},
                         {'REMOTE_ADDR':'127.0.0.1','HTTP_X_AZD_SANTA_CLIENT_IP':'192.0.2.1,198.51.100.2'}):
                with self.assertRaises(ValueError): admission.identity(meta,'token','key')
            meta={'REMOTE_ADDR':'127.0.0.1','HTTP_X_AZD_SANTA_CLIENT_IP':'2001:db8::1'}
            admission.identity(meta,'token','key'); self.assertEqual(meta['HTTP_X_REAL_IP'],'2001:db8::1')

    def test_denial_and_store_corruption_touch_no_handler_sql_or_body(self):
        for effect in ([0,60],RuntimeError('malformed Redis state'),TimeoutError('unknown acquire')):
            downstream=Mock(side_effect=AssertionError('Denied work reached handler'))
            with patch.object(admission,'_eval',side_effect=effect if isinstance(effect,Exception) else None,return_value=effect):
                response=admission.Admission(downstream)(Request())
            self.assertEqual(response.status_code,429 if isinstance(effect,list) else 503)
            self.assertIn('Retry-After',response); downstream.assert_not_called()

    def test_normal_and_exception_release_only_exact_random_owner(self):
        for raises in (False,True):
            store=Store(); request=Request()
            def work(r):
                admission.require_admission(r)
                if raises: raise RuntimeError('handler failure')
                return Response()
            exceptions=ModuleType('django.core.exceptions'); exceptions.PermissionDenied=ValueError
            with patch.dict(sys.modules,{'django.core.exceptions':exceptions}),patch.object(admission,'_eval',side_effect=store):
                if raises:
                    with self.assertRaises(RuntimeError): admission.Admission(work)(request)
                else: self.assertEqual(admission.Admission(work)(request).status_code,200)
            self.assertIsNone(store.owner); self.assertFalse(hasattr(request,'_azd_santa_admission'))
            self.assertEqual(store.calls[0][2][-1],store.calls[-1][2][-1])

    def test_wall_time_and_caller_timeout_cannot_release_held_work(self):
        store=Store(); entered=threading.Event(); finish=threading.Event(); results=[]
        def work(request): entered.set(); self.assertTrue(finish.wait(3)); return Response()
        with patch.object(admission,'_eval',side_effect=store):
            thread=threading.Thread(target=lambda:results.append(admission.Admission(work)(Request())))
            thread.start()
            try:
                self.assertTrue(entered.wait(1)); token=store.owner
                thread.join(0.01)  # Caller/proxy deadline expires while thread continues.
                self.assertTrue(thread.is_alive()); self.assertEqual(store.owner,token)
                self.assertEqual(admission.Admission(lambda r:Response())(Request()).status_code,429)
                self.assertFalse(any(s==admission.RELEASE for s,_,_ in store.calls))
            finally: finish.set(); thread.join(2)
        self.assertEqual(results[0].status_code,200); self.assertIsNone(store.owner)

    def test_unsupported_streaming_retains_permit_and_fails_closed(self):
        store=Store(); response=Response(); response.streaming=True
        with patch.object(admission,'_eval',side_effect=store):
            self.assertEqual(admission.Admission(lambda r:response)(Request()).status_code,503)
        self.assertIsNotNone(store.owner)
        self.assertFalse(any(s==admission.RELEASE for s,_,_ in store.calls))

    def test_release_error_does_not_turn_unknown_capacity_into_success(self):
        calls=[]
        def evaluate(script,extra_keys=(),arguments=()):
            calls.append(script)
            if script==admission.ACQUIRE:return [1,'0']
            raise TimeoutError('uncertain release')
        with patch.object(admission,'_eval',side_effect=evaluate):
            self.assertEqual(admission.Admission(lambda r:Response())(Request()).status_code,503)
        self.assertEqual(calls,[admission.ACQUIRE,admission.RELEASE])

    def test_global_first_script_has_bounded_state_and_no_expiring_permit(self):
        script=admission.ACQUIRE
        self.assertLess(script.index('counts[3]>=limits[1]'),script.index("for i=4,5 do"))
        self.assertIn('HLEN',admission.VALIDATE); self.assertIn('ttl<0',script)
        self.assertIn("HSET',KEYS[2],slot,ARGV[8]",script)
        self.assertNotIn("EXPIRE',KEYS[2]",script)
        self.assertNotIn('SCAN',script); self.assertNotIn('KEYS *',script)
        self.assertIn("~= ARGV[5]",admission.RELEASE)
        self.assertNotIn('SET',admission.CHECK[len(admission.VALIDATE):])

    def test_backstop_and_existing_operator_isolation(self):
        exceptions=ModuleType('django.core.exceptions'); exceptions.PermissionDenied=ValueError
        with patch.dict(sys.modules,{'django.core.exceptions':exceptions}):
            with self.assertRaises(ValueError): admission.require_admission(Request())
        store=Mock(side_effect=AssertionError('Operator budgets must remain separate'))
        with patch.object(admission,'_eval',store):
            self.assertEqual(admission.Admission(lambda r:Response())(Request('/accounts/login/')).status_code,200)
        store.assert_not_called()

    def test_prelistener_readiness_requires_empty_state_without_reclaiming(self):
        with patch.object(admission, '_eval', return_value=1) as evaluate:
            admission.check(require_empty=True)
            self.assertEqual(evaluate.call_args.args[0], admission.EMPTY)
            self.assertNotIn('HDEL', admission.EMPTY)
        with patch.object(admission, '_eval', side_effect=RuntimeError('held permit')):
            with self.assertRaises(RuntimeError): admission.check(require_empty=True)

    def test_reconcile_is_never_called_by_middleware_or_normal_startup(self):
        text=(ROOT/'experiments/server/runtime_service.py').read_text()
        start=text[text.index('    def start(self):'):text.index('    def reconcile_admission(')]
        self.assertNotIn('reconcile(',start); self.assertIn("'sync-admission'",start)
        self.assertNotIn('reconcile(',admission.Admission.__call__.__code__.co_names)


    def test_explicit_reconcile_refuses_live_missing_or_replaced_app_processes(self):
        import tempfile
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            for change in ('running','paused','restarting','pid','replacement','missing'):
                runtime=lifecycle.Runtime.__new__(lifecycle.Runtime)
                runtime.manifest_path=root/'manifest.json'; runtime.digest='a'*64; runtime.evidence=root
                runtime.binding={'policy_hashes':{'admission':'b'*64}}
                ids={name:str(i)*64 for i,name in enumerate(lifecycle.APPS,1)}
                rows=[{'Id':cid,'State':{'Running':False,'Paused':False,'Restarting':False,'Pid':0}} for cid in ids.values()]
                if change=='replacement': rows[0]['Id']='f'*64
                elif change=='missing': rows.pop()
                else: rows[0]['State'][{'running':'Running','paused':'Paused','restarting':'Restarting','pid':'Pid'}[change]]=77 if change=='pid' else True
                runtime.inspect=Mock(return_value=ids); runtime.call=Mock(return_value=SimpleNamespace(stdout=json.dumps(rows)))
                runtime.python=Mock()
                fcntl=ModuleType('fcntl'); fcntl.LOCK_EX=1; fcntl.LOCK_NB=2; fcntl.flock=Mock()
                with patch.dict(sys.modules,{'fcntl':fcntl}),patch.object(lifecycle,'load_manifest') as load:
                    with self.assertRaises(ValueError):runtime.reconcile_admission()
                runtime.python.assert_not_called(); load.assert_not_called()
                self.assertEqual(runtime.call.call_args.args[1][-3:],list(ids.values()))

    def test_explicit_quiesced_reconcile_is_source_bound_and_records_exact_ids(self):
        import tempfile
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); runtime=lifecycle.Runtime.__new__(lifecycle.Runtime)
            runtime.manifest_path=root/'manifest.json'; runtime.digest='a'*64; runtime.evidence=root
            runtime.binding={'policy_hashes':{'admission':'b'*64}}
            ids={name:str(i)*64 for i,name in enumerate(lifecycle.APPS,1)}
            rows=[{'Id':cid,'State':{'Running':False,'Paused':False,'Restarting':False,'Pid':0}} for cid in ids.values()]
            runtime.inspect=Mock(return_value=ids); runtime.call=Mock(return_value=SimpleNamespace(stdout=json.dumps(rows)))
            runtime.python=Mock()
            fcntl=ModuleType('fcntl'); fcntl.LOCK_EX=1; fcntl.LOCK_NB=2; fcntl.flock=Mock()
            with patch.dict(sys.modules,{'fcntl':fcntl}),patch.object(lifecycle,'load_manifest'):
                runtime.reconcile_admission(initialize_missing=True)
            code=runtime.python.call_args.args[1]
            self.assertIn('b'*64,code);self.assertIn('initialize_missing=True',code)
            self.assertEqual(json.loads((root/'admission-reconciled.json').read_text())['app_ids'],list(ids.values()))


if __name__=='__main__':unittest.main()
