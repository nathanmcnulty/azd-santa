"""Fresh origin boundaries only; no Azure, package, Docker or network calls."""
import ast
from contextlib import ExitStack
import io
import tempfile
from types import SimpleNamespace
import test_private_install as installation
import copy
import json
import os
from pathlib import Path
import re
import unittest
from unittest.mock import patch
from test_private_install import installer
import test_zentral_eval as eval_tests
generator = eval_tests.generator

ORIGIN = 'https://santa-1111111111114111-synthetic-vm.westus2.cloudapp.azure.com'
TARGET = dict(TenantId='22222222-2222-4222-8222-222222222222',
    SubscriptionId='11111111-1111-4111-8111-111111111111', EnvironmentName='synthetic',
    ResourceGroup='rg-azd-santa-vm-synthetic', VmName='vm-santa-lab',
    VmId='/subscriptions/11111111-1111-4111-8111-111111111111/resourceGroups/rg-azd-santa-vm-synthetic/providers/Microsoft.Compute/virtualMachines/vm-santa-lab',
    VmInstanceId='33333333-3333-4333-8333-333333333333')

class FreshOrigin(unittest.TestCase):
    def test_guest_origin_is_bound_to_canonical_target_and_imds_region(self):
        context = dict(target=TARGET, https_origin=ORIGIN)
        self.assertEqual(installer.selected_origin(context, dict(location='westus2')), ORIGIN)
        self.assertEqual(installer.selected_origin(dict(target=TARGET), {}), 'https://localhost:8000')
        for origin in (ORIGIN+'/', ORIGIN+':443', ORIGIN+'?x=1', ORIGIN.replace('https:', 'http:'),
                       ORIGIN.replace('1111111111114111', 'aaaaaaaaaaaaaaaa'), ORIGIN.replace('synthetic-vm', 'other-vm'),
                       ORIGIN.replace('westus2', 'eastus'), 'https://user@'+ORIGIN[8:], None, False):
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                installer.selected_origin(dict(context, https_origin=origin), dict(location='westus2'))
        for metadata in ({}, dict(location='West US 2'), dict(location='westus2.evil')):
            with self.assertRaises(ValueError): installer.selected_origin(context, metadata)
        target = dict(TARGET, VmId=TARGET['VmId'].replace('synthetic', 'other'))
        with self.assertRaises(ValueError): installer.selected_origin(dict(context, target=target), dict(location='westus2'))

    def test_invalid_guest_origin_stops_before_package_or_filesystem_effects(self):
        from unittest.mock import MagicMock
        metadata = dict(subscriptionId=TARGET['SubscriptionId'], resourceId=TARGET['VmId'], vmId=TARGET['VmInstanceId'],
            location='eastus', tagsList=[dict(name=k,value=v) for k,v in {
                'azd-solution':'azd-santa','purpose':'synthetic-vm-lab','azd-env-name':'synthetic'}.items()])
        response = MagicMock(); response.__enter__.return_value = io.BytesIO(json.dumps(metadata).encode())
        opener = MagicMock(); opener.open.return_value = response
        with patch.object(installer.os,'geteuid',return_value=0,create=True), patch.object(installer.os,'umask'), \
             patch.object(installer.platform,'machine',return_value='x86_64'), \
             patch.object(installer,'verified',return_value=(dict(target=TARGET,https_origin=ORIGIN),Path('/unused'))), \
             patch.object(installer.urllib.request,'build_opener',return_value=opener), \
             patch.object(installer.subprocess,'run') as external, patch.object(Path,'mkdir') as mkdir:
            with self.assertRaises(ValueError): installer.install('/unused','a'*64)
            external.assert_not_called(); mkdir.assert_not_called()

    def test_stage_passes_origin_to_real_generator_boundary_before_initialization(self):
        stage = installer.load_stage(Path(installer.__file__).parent)
        image = 'sha256:'+'a'*64
        inspected = SimpleNamespace(returncode=0,stdout=json.dumps([dict(Id=image,Config=dict(Labels={
            'org.opencontainers.image.revision':stage.COMMIT,'io.azd-santa.variant':'core-experiment'}))]))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); lock=root/'lock.json'; lock.write_text('{}')
            with patch.object(stage,'require_host'), patch.object(stage,'private_directory'), \
                 patch.object(stage.subprocess,'run',return_value=inspected), \
                 patch.object(stage,'prepare',side_effect=ValueError('stop before fresh initialization')) as prepare:
                with self.assertRaisesRegex(ValueError,'stop before fresh initialization'):
                    stage.stage(root,lock,root/'absent',image,https_origin=ORIGIN)
                self.assertEqual(prepare.call_args.kwargs,dict(https_origin=ORIGIN))

    def test_context_reserves_origin_and_refuses_changed_origin_on_same_attempt(self):
        relay=installation.relay; harness=installation.Relay()
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            root=Path(directory); calls=[]
            def external(args):
                calls.append(args)
                if args[0]=='systemd-run': raise TimeoutError('unknown launch')
                return ''
            for guard in harness.harness(root,external): stack.enter_context(guard)
            digest,archive,data=installation.package()
            relay.run(dict(mode='chunk',bundle_sha256=digest,archive_sha256=archive,index=0,count=1,data=data))
            command=dict(mode='submit',bundle_sha256=digest,archive_sha256=archive,count=1,target=TARGET,https_origin=ORIGIN)
            with self.assertRaises(TimeoutError): relay.run(command)
            active=json.loads((root/'private-azd-install.json').read_bytes())
            self.assertEqual(active['https_origin'],ORIGIN)
            with self.assertRaises(ValueError): relay.run(dict(command,https_origin=ORIGIN.replace('westus2','eastus')))
            self.assertEqual(sum(args[0]=='systemd-run' for args in calls),1)

    def test_completion_cannot_report_a_different_bound_origin(self):
        relay=installation.relay; harness=installation.Relay()
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            root=Path(directory); digest='a'*64
            folder=harness.completed(root,digest)
            for guard in harness.harness(root,lambda _: self.fail('No external call')): stack.enter_context(guard)
            active=json.loads((root/'private-azd-install.json').read_bytes())
            active['https_origin']=ORIGIN
            complete=json.loads((folder/'complete.json').read_bytes())
            complete['outputs']['Origin']='https://localhost:8000'
            (folder/'complete.json').write_text(json.dumps(complete))
            with self.assertRaises(ValueError): relay.completion(folder,active)
            complete['outputs']['Origin']=ORIGIN
            (folder/'complete.json').write_text(json.dumps(complete))
            self.assertEqual(relay.completion(folder,active)[1]['outputs']['Origin'],ORIGIN)

    def test_real_settings_hook_consumes_profile_and_preserves_private_defaults(self):
        path = Path(installer.__file__).with_name('operator_mfa.py')
        tree = ast.parse(path.read_bytes())
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'install_policy')
        scope = dict(os=os, re=re, ImproperlyConfigured=ValueError)
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(path), 'exec'), scope)
        def settings():
            return dict(CACHES={'default': {'LOCATION': 'redis://redis:6379/1'}},
                MIDDLEWARE=['realms.middlewares.realm_session_middleware'])
        with patch.dict(os.environ, AZD_SANTA_SECURITY_STORE_ID='a'*64):
            private = settings(); scope['install_policy'](private)
            self.assertNotIn('SECURE_PROXY_SSL_HEADER', private)
            value = settings(); value.update(django_zentral_settings={'AZD_SANTA_HTTPS_ORIGIN': ORIGIN},
                ALLOWED_HOSTS=['localhost','127.0.0.1',ORIGIN[8:]], CSRF_TRUSTED_ORIGINS=[ORIGIN])
            scope['install_policy'](value)
            self.assertEqual(value['SECURE_PROXY_SSL_HEADER'], ('HTTP_X_FORWARDED_PROTO','https'))
            self.assertFalse(value['USE_X_FORWARDED_HOST'])
            self.assertTrue(value['CSRF_COOKIE_SECURE'] and value['SESSION_COOKIE_SECURE'])
            for key, changed in [('ALLOWED_HOSTS', ['*']), ('CSRF_TRUSTED_ORIGINS', ['https://evil.invalid'])]:
                broken = copy.deepcopy(value); broken[key] = changed
                with self.assertRaises(ValueError): scope['install_policy'](broken)

class RenderedOrigin(unittest.TestCase):
    setUp = eval_tests.ZentralEvaluation.setUp
    read = eval_tests.ZentralEvaluation.read
    environment = eval_tests.ZentralEvaluation.environment
    def test_https_profile_rendering(self):
        with patch.dict(generator.SOURCE_HASHES, self.hashes, clear=True):
            generator.prepare(self.source, self.image, self.lock, self.destination, 'core-experiment', https_origin=ORIGIN)
        config = self.read('conf/base.json')
        self.assertEqual(config['api']['fqdn'], ORIGIN[8:])
        self.assertEqual(config['django']['CSRF_TRUSTED_ORIGINS'], [ORIGIN])
        self.assertEqual(config['django']['ALLOWED_HOSTS'], ['localhost','127.0.0.1',ORIGIN[8:]])
        self.assertEqual(config['django']['AZD_SANTA_HTTPS_ORIGIN'], ORIGIN)
        self.assertNotIn('AZD_SANTA_ADMISSION_MODE', self.environment('runtime.env'))
        self.assertEqual(self.read('compose.json')['services']['web']['ports'], ['127.0.0.1:8000:8000'])

    def test_invalid_origin_rejects_before_destination_creation(self):
        for origin in ('https://evil.invalid', ORIGIN+'/', ORIGIN+'\nInjected: value', False):
            with self.assertRaises(ValueError):
                generator.prepare(self.source, self.image, self.lock, self.destination, https_origin=origin)
            self.assertFalse(self.destination.exists())

if __name__ == '__main__': unittest.main()
