"""Edge rendering/kernel command tests; not actual Linux/firewall/TLS proof."""
import copy
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'experiments/server'))
import https_edge as edge
from test_https_proxy import facts


class Edge(unittest.TestCase):
    def test_private_profile_cannot_issue_certificates_or_listen_publicly(self):
        data = edge.configuration(facts(), Path('/private/state'), certificate='/private/cert.pem', key='/private/key.pem')
        server = data['apps']['http']['servers']['https']
        self.assertEqual(server['listen'], ['127.0.0.1:8443'])
        self.assertTrue(server['automatic_https']['disable_certificates'])
        self.assertNotIn('automation', data['apps']['tls'])
        self.assertEqual(server['protocols'], ['h1'])
        handlers = server['routes'][0]['handle']
        self.assertEqual([h['handler'] for h in handlers], ['request_body', 'reverse_proxy'])
        self.assertEqual(handlers[1]['headers']['request']['set']['Host'], ['localhost'])
        self.assertEqual(data['admin'], {'disabled': True})
        # The original unqualified candidate retains its unconditional hold.
        self.assertEqual(edge.candidate.configuration(facts(), Path('/private/state'))['apps']['http']['servers']['https']['routes'][0]['handle'][1]['status_code'], 503)

    def test_public_profiles_are_ipv4_only_exact_host_without_staging_fallback(self):
        for phase, ca in [('staging', edge.candidate.STAGING), ('production', 'https://acme-v02.api.letsencrypt.org/directory')]:
            data = edge.configuration(facts(), Path('/private/state'), phase=phase)
            self.assertEqual(data['apps']['http']['servers']['https']['listen'], ['0.0.0.0:443'])
            policy = data['apps']['tls']['automation']['policies'][0]
            self.assertEqual(policy['subjects'], [facts()['Fqdn']])
            self.assertFalse(policy['on_demand'])
            self.assertEqual(policy['issuers'][0]['ca'], ca)
            self.assertEqual(policy['issuers'][0]['test_ca'], ca)

    def test_header_trust_and_resource_bounds_are_explicit(self):
        data = edge.configuration(facts(), Path('/private/state'), phase='staging')
        proxy = data['apps']['http']['servers']['https']['routes'][0]['handle'][1]
        self.assertIn('X-Azd-Santa-Client-IP', proxy['headers']['request']['delete'])
        self.assertEqual(proxy['headers']['request']['set']['Host'], [facts()['Fqdn']])
        self.assertNotIn('X-Forwarded-For', proxy['headers']['request']['set'])
        self.assertEqual(proxy['transport']['network_proxy'], {'from': 'none'})
        self.assertEqual(proxy['transport']['max_conns_per_host'], 4)
        text = edge.unit_text('/opt/azd-santa-https/pinned/caddy', '/etc/azd-santa-https/pilot/caddy.json', '/var/lib/azd-santa-https/pilot')
        for line in ('User=azd-santa-https', 'MemoryMax=192M', 'MemorySwapMax=0', 'CPUQuota=50%', 'LimitNOFILE=256', 'TasksMax=64', 'ProtectSystem=strict', 'CapabilityBoundingSet=CAP_NET_BIND_SERVICE', 'Restart=no'):
            self.assertIn(line + '\n', text)

    def test_unreviewed_modes_paths_and_ports_are_rejected(self):
        for phase in ('', 'enabled', 'PRIVATE'):
            with self.assertRaises(ValueError): edge.configuration(facts(), Path('/private/state'), phase=phase)
        with self.assertRaises(ValueError): edge.configuration(facts(), Path('/private/state'))
        with self.assertRaises(ValueError): edge.unit_text('/bin/caddy', '/etc/azd-santa-https/x.json', '/var/lib/azd-santa-https/x')
        for port in (80, 0, True, 9443):
            with self.assertRaises(ValueError): edge.rules(port)


class Firewall(unittest.TestCase):
    def setUp(self):
        self.input = [['-P', 'INPUT', 'ACCEPT'], ['-A', 'INPUT', '-s', '192.0.2.1', '-j', 'DROP']]
        self.chain = None
        self.calls = []
        self.patch = patch.object(edge, 'command', side_effect=self.command)
        self.patch.start(); self.addCleanup(self.patch.stop)
        self.uid = patch.object(edge.os, 'geteuid', return_value=0, create=True)
        self.uid.start(); self.addCleanup(self.uid.stop)
        self.platform = patch.object(edge.os, 'name', 'posix')
        self.platform.start(); self.addCleanup(self.platform.stop)

    def command(self, args, required=True):
        self.calls.append(args)
        def result(rows=(), code=0):
            import shlex
            return SimpleNamespace(returncode=code, stdout=('\n'.join(shlex.join(row) for row in rows)).encode())
        if args == ['-S', 'INPUT']: return result(self.input)
        if args == ['-S', 'AZDSANTA_TLS8443']: return result(self.chain or (), 0 if self.chain is not None else 1)
        if args == ['-S']: return result(self.input + self.chain)
        if args[0] == '-N': self.chain = [args]; return result()
        if args[0] == '-A': self.chain.append(args); return result()
        if args[0] == '-I': self.input.insert(1, ['-A', 'INPUT', *args[3:]]); return result()
        if args[0] == '-C':
            rows = self.input if args[1] == 'INPUT' else self.chain
            if ['-A', *args[1:]] not in rows: raise ValueError('Missing exact rule')
            return result()
        raise AssertionError(args)

    def test_one_restrictive_chain_preserves_unrelated_rules_and_then_only_observes(self):
        before = copy.deepcopy(self.input)
        self.assertEqual(edge.ensure_firewall(8443)['maximum_connections'], 16)
        self.assertEqual(self.input[0], before[0]); self.assertEqual(self.input[2:], before[1:])
        self.assertIn('--syn', self.chain[1]); self.assertIn('--connlimit-mask', self.chain[1])
        self.calls.clear(); edge.ensure_firewall(8443)
        self.assertTrue(all(args[0] in ('-S', '-C') for args in self.calls))

    def test_partial_chain_is_never_reset_and_bypassing_input_rule_is_rejected(self):
        self.chain = [['-N', 'AZDSANTA_TLS8443']]
        with self.assertRaises(ValueError): edge.ensure_firewall(8443)
        self.assertFalse(any(args[0] in ('-F', '-X', '-D', '-A', '-I') for args in self.calls))
        self.chain = None; edge.ensure_firewall(8443)
        self.input.insert(1, ['-A', 'INPUT', '-j', 'ACCEPT'])
        with self.assertRaises(ValueError): edge.verify_firewall(8443)

    def test_return_before_limit_is_rejected_even_when_both_rules_exist(self):
        edge.ensure_firewall(8443)
        self.chain[1], self.chain[2] = self.chain[2], self.chain[1]
        with self.assertRaises(ValueError): edge.verify_firewall(8443)


if __name__ == '__main__': unittest.main()
