"""Offline generator guards; mocks are not real proxy or overload proof."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('proxy', ROOT / 'experiments/server/prepare_https_proxy.py')
proxy = importlib.util.module_from_spec(spec); spec.loader.exec_module(proxy)


def facts():
    sub = '11111111-1111-4111-8111-111111111111'
    root = '/subscriptions/' + sub + '/resourceGroups/rg-azd-santa-vm-synthetic/providers/'
    return dict(scope='azd-santa-selected-arm-endpoint-v1', TenantId='22222222-2222-4222-8222-222222222222',
                SubscriptionId=sub, EnvironmentName='synthetic', VmId=root + 'Microsoft.Compute/virtualMachines/vm-santa-lab',
                VmInstanceId='33333333-3333-4333-8333-333333333333',
                NicId=root + 'Microsoft.Network/networkInterfaces/nic-santa-lab',
                IpConfigurationId=root + 'Microsoft.Network/networkInterfaces/nic-santa-lab/ipConfigurations/primary',
                PublicIpId=root + 'Microsoft.Network/publicIPAddresses/pip-santa-lab-egress',
                PublicIpAddress='8.8.8.8', Fqdn='santa-qualification.westus2.cloudapp.azure.com')


class Candidate(unittest.TestCase):
    def test_bound_hostname_and_selected_identity_reject_injection_without_writes(self):
        for key, value in [('Fqdn', '*.westus2.cloudapp.azure.com'), ('Fqdn', 'foo.example.com'),
                           ('Fqdn', 'foo.westus2.cloudapp.azure.com.'), ('Fqdn', 'https://foo.westus2.cloudapp.azure.com'),
                           ('Fqdn', 'foo.westus2.cloudapp.azure.com\n:80'), ('VmInstanceId', 'wrong'),
                           ('PublicIpId', facts()['PublicIpId'].replace('-egress', '-other')),
                           ('IpConfigurationId', facts()['IpConfigurationId'].replace('/primary', '/other')),
                           ('PublicIpAddress', '127.0.0.1')]:
            with self.subTest(key=key, value=value), tempfile.TemporaryDirectory() as folder:
                selected = facts(); selected[key] = value; dest = Path(folder).resolve() / 'absent'
                with self.assertRaises(ValueError): proxy.prepare(selected, dest)
                self.assertFalse(dest.exists())

    def test_https_only_tls_controls_and_admission_hold_cannot_be_enabled(self):
        data = proxy.configuration(facts(), Path('/private/state'))
        server = data['apps']['http']['servers']['https']
        self.assertEqual(server['listen'], [':443']); self.assertEqual(server['protocols'], ['h1'])
        self.assertEqual(server['automatic_https'], dict(disable_redirects=True))
        self.assertTrue(server['strict_sni_host']); self.assertNotIn('trusted_proxies', server)
        self.assertEqual(data['admin'], dict(disabled=True))
        policy = data['apps']['tls']['automation']['policies'][0]
        self.assertEqual(policy['subjects'], [facts()['Fqdn']]); self.assertFalse(policy['on_demand'])
        issuer = policy['issuers'][0]
        self.assertEqual(issuer['ca'], proxy.STAGING)
        self.assertTrue(issuer['challenges']['http']['disabled'])
        handlers = server['routes'][0]['handle']
        self.assertEqual(handlers[0]['max_size'], 1048576)
        self.assertEqual(handlers[1]['handler'], 'static_response'); self.assertEqual(handlers[1]['status_code'], 503)
        self.assertEqual(handlers[1]['headers']['Retry-After'], ['60'])
        upstream = handlers[2]
        self.assertEqual(upstream['upstreams'], [dict(dial='127.0.0.1:8000')])
        self.assertEqual(upstream['transport']['max_conns_per_host'], 4)
        self.assertIn('X-Forwarded-*', upstream['headers']['request']['delete'])
        self.assertEqual(upstream['headers']['request']['set']['X-Forwarded-For'], ['{http.request.remote.host}'])

    def test_absent_private_destination_and_truthful_unqualified_receipt(self):
        with tempfile.TemporaryDirectory() as folder:
            dest = Path(folder).resolve() / 'candidate'; path = proxy.prepare(facts(), dest)
            receipt = json.loads(path.with_name('candidate.json').read_bytes())
            self.assertEqual(receipt['admission'], 'held-closed')
            self.assertEqual(set(receipt['gates'].values()), {'not_run'})
            self.assertEqual(receipt['native_validation'], 'not_run')
            with self.assertRaises(ValueError): proxy.prepare(facts(), dest)
            if os.name != 'nt':
                self.assertEqual(dest.stat().st_mode & 0o777, 0o700)
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_validation_rejects_unpinned_binary_before_execution(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve(); path = proxy.prepare(facts(), root / 'candidate')
            binary = root / 'caddy'; binary.write_bytes(b'not reviewed')
            with patch.object(proxy.subprocess, 'run') as external:
                with self.assertRaises(ValueError): proxy.validate_windows(path, binary)
                external.assert_not_called()


if __name__ == '__main__': unittest.main()
