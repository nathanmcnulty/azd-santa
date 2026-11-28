"""Edge rendering/kernel command tests; not actual Linux/firewall/TLS proof."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'experiments/server'))
import https_edge as edge
import prepare_held_https as held
from test_https_proxy import facts


class HeldPackage(unittest.TestCase):
    def make_release(self, directory, *, binary_type=tarfile.REGTYPE):
        release = directory / 'release.tar.gz'
        assets = {'caddy': (b'fixture binary', binary_type),
                  'LICENSE': (b'fixture license', tarfile.REGTYPE),
                  'README.md': (b'fixture readme', tarfile.REGTYPE)}
        with tarfile.open(release, 'w:gz') as archive:
            for name, (data, kind) in assets.items():
                entry = tarfile.TarInfo(name)
                entry.type = kind
                entry.size = len(data) if entry.isfile() else 0
                archive.addfile(entry, io.BytesIO(data))
        lock = directory / 'caddy.lock.json'
        lock.write_text(json.dumps({'linuxAmd64': {'archiveUrl': 'https://fixture.invalid/caddy.tar.gz',
            'archiveSha256': hashlib.sha256(release.read_bytes()).hexdigest()}}), encoding='utf-8')
        return release, lock

    def test_package_only_contains_held_service_and_pinned_files(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            release, lock = self.make_release(directory)
            destination = directory / 'edge.tar'
            second = directory / 'edge-second.tar'
            with patch.object(edge.candidate, 'LOCK', lock):
                held.prepare(facts(), release, destination)
                held.prepare(facts(), release, second)
                with self.assertRaises(FileExistsError):
                    held.prepare(facts(), release, destination)
            self.assertEqual(destination.read_bytes(), second.read_bytes())
            with tarfile.open(destination) as package:
                entries = package.getmembers()
                self.assertEqual(len(entries), 11)
                for entry in entries:
                    self.assertTrue(entry.isfile())
                    self.assertEqual((entry.uid, entry.gid), (0, 0))
                    self.assertFalse(entry.name.startswith('/'))
                    self.assertEqual(entry.mode, 0o755 if entry.name.endswith('/caddy') else 0o644)
                self.assertEqual(package.extractfile('opt/azd-santa-https/pilot/caddy').read(), b'fixture binary')
                self.assertEqual(json.load(package.extractfile('etc/azd-santa-https/pilot/endpoint.json')), facts())
                config = package.extractfile('etc/azd-santa-https/pilot/held.json').read()
                self.assertNotIn(b'reverse_proxy', config)
                self.assertEqual(json.loads(config), edge.held_configuration(facts(), held.STATE, phase='production'))
                unit = package.extractfile('etc/systemd/system/azd-santa-pilot-https-held.service').read()
                self.assertIn(b'RuntimeMaxSec=300\n', unit)
                self.assertIn(b'Requires=azd-santa-https-firewall-443.service\n', unit)

    def test_rejects_unpinned_archive_and_nonregular_member_before_output(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            release, lock = self.make_release(directory, binary_type=tarfile.SYMTYPE)
            destination = directory / 'edge.tar'
            with self.assertRaisesRegex(ValueError, 'does not match the pinned'):
                held.prepare(facts(), release, destination)
            with patch.object(edge.candidate, 'LOCK', lock):
                with self.assertRaisesRegex(ValueError, 'Invalid file'):
                    held.prepare(facts(), release, destination)
            self.assertFalse(destination.exists())

    @unittest.skipUnless(os.name == 'posix', 'guest staging uses Linux file ownership and modes')
    def test_guest_stages_only_verified_files_and_never_starts_a_service(self):
        import pwd

        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            release, lock = self.make_release(directory)
            binary = directory / 'opt/azd-santa-https/pilot'
            config = directory / 'etc/azd-santa-https/pilot/held.json'
            state = directory / 'var/lib/azd-santa-https/pilot'
            units = directory / 'etc/systemd/system'
            for root in (binary.parent.parent, config.parent.parent.parent, state.parent.parent, units):
                root.mkdir(parents=True, exist_ok=True)
            # Use the real archive verifier and file writer. Map fixed paths into
            # the fixture while retaining the original rendered unit contents.
            files = held.package_files(facts(), release.read_bytes(), lock.read_bytes())
            mapped = {directory / path.relative_to('/'): value for path, value in files.items()}
            (directory / 'etc/tmpfiles.d').mkdir()
            commands = []
            def run(label, command):
                commands.append((label, command))
                return ''
            opener = SimpleNamespace(open=lambda *_args, **_kw: release.open('rb'))
            with patch.multiple(held, BINARY_DIR=binary, CONFIG=config, STATE=state), \
                 patch.object(edge.candidate, 'LOCK', lock), \
                 patch.object(held, 'package_files', return_value=mapped) as renderer, \
                 patch.object(held, 'secure_guest_parent'), \
                 patch.object(held.urllib.request, 'build_opener', return_value=opener), \
                 patch.object(os, 'chown') as owner, \
                 patch.object(pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=1234, pw_gid=1234)):
                receipt = held.stage_on_guest(facts(), run)
                renderer.assert_called_once_with(facts(), release.read_bytes(), lock.read_bytes())
                self.assertEqual(owner.call_count, 3)
                with self.assertRaises(FileExistsError):
                    held.stage_on_guest(facts(), run)
            self.assertEqual([command[0] for _, command in commands], ['/usr/bin/ss', '/usr/sbin/useradd', '/usr/bin/ss'])
            self.assertEqual(receipt['listener'], 'unbound')
            self.assertEqual(stat.S_IMODE((binary / 'caddy').stat().st_mode), 0o755)
            self.assertEqual(stat.S_IMODE(state.stat().st_mode), 0o700)
            self.assertNotIn('reverse_proxy', config.read_text())


class Edge(unittest.TestCase):
    def test_private_profile_cannot_issue_certificates_or_listen_publicly(self):
        data = edge.configuration(facts(), Path('/private/state'), certificate='/private/cert.pem', key='/private/key.pem')
        server = data['apps']['http']['servers']['https']
        self.assertEqual(server['listen'], ['127.0.0.1:8443'])
        self.assertTrue(server['automatic_https']['disable_certificates'])
        self.assertNotIn('automation', data['apps']['tls'])
        self.assertEqual(server['protocols'], ['h1'])
        handlers = server['routes'][0]['handle']
        self.assertEqual([h['handler'] for h in handlers], ['request_body', 'headers', 'reverse_proxy'])
        self.assertEqual(handlers[2]['headers']['request']['set']['Host'], ['localhost'])
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
        handlers = data['apps']['http']['servers']['https']['routes'][0]['handle']
        proxy = handlers[2]
        self.assertIn('X-Forwarded-*', handlers[1]['request']['delete'])
        self.assertNotIn('X-Forwarded-*', proxy['headers']['request']['delete'])
        self.assertIn('X-Forwarded-For', proxy['headers']['request']['delete'])
        self.assertEqual(proxy['headers']['request']['set']['X-Forwarded-Proto'], ['https'])
        self.assertIn('X-Azd-Santa-Client-IP', proxy['headers']['request']['delete'])
        self.assertEqual(proxy['headers']['request']['set']['Host'], [facts()['Fqdn']])
        self.assertNotIn('X-Forwarded-For', proxy['headers']['request']['set'])
        self.assertEqual(proxy['transport']['network_proxy'], {'from': 'none'})
        self.assertEqual(proxy['transport']['max_conns_per_host'], 4)
        text = edge.unit_text('/opt/azd-santa-https/pinned/caddy', '/etc/azd-santa-https/pilot/caddy.json', '/var/lib/azd-santa-https/pilot')
        for line in ('User=azd-santa-https', 'MemoryMax=192M', 'MemorySwapMax=0', 'CPUQuota=50%', 'LimitNOFILE=256', 'TasksMax=64', 'ProtectSystem=strict', 'CapabilityBoundingSet=CAP_NET_BIND_SERVICE', 'Restart=no'):
            self.assertIn(line + '\n', text)

    def test_certificate_qualification_has_no_application_proxy(self):
        import json
        for phase in ('staging', 'production'):
            data = edge.held_configuration(facts(), Path('/private/state'), phase=phase)
            self.assertNotIn('reverse_proxy', json.dumps(data))
            server = data['apps']['http']['servers']['https']
            self.assertEqual(server['listen'], ['0.0.0.0:443'])
            self.assertEqual(server['routes'][0]['handle'][0]['status_code'], 503)
            self.assertEqual(server['routes'][1]['handle'][0]['status_code'], 421)
            self.assertTrue(server['routes'][0]['handle'][0]['close'])
            issuer = data['apps']['tls']['automation']['policies'][0]['issuers'][0]
            self.assertEqual(issuer['test_ca'], issuer['ca'])
        with self.assertRaises(ValueError):
            edge.held_configuration(facts(), Path('/private/state'), phase='private')

    def test_firewall_lock_is_created_by_boot_tmpfiles_before_sandboxing(self):
        self.assertEqual(edge.lock_tmpfiles_text(), 'f /run/xtables.lock 0600 root root -\n')
        unit = edge.firewall_unit_text('/opt/azd-santa-https/pinned/https_edge.py')
        self.assertIn('Requires=systemd-tmpfiles-setup.service\n', unit)
        self.assertIn('After=systemd-tmpfiles-setup.service network-online.target docker.service\n', unit)
        self.assertIn('ReadWritePaths=/run/xtables.lock\n', unit)

    def test_certificate_network_candidate_is_conditional_and_one_device_only(self):
        selected = facts(); base = selected['VmId'].split('/providers/')[0] + '/providers/Microsoft.Network/'
        nsg_id = base + 'networkSecurityGroups/nsg-santa-lab'
        subnet_id = base + 'virtualNetworks/vnet-santa-lab/subnets/host'
        nsg = dict(id=nsg_id, etag='W/"44444444-4444-4444-8444-444444444444"', location='westus2', tags={
            'azd-solution': 'azd-santa', 'purpose': 'synthetic-vm-lab', 'azd-env-name': 'synthetic'},
            properties=dict(provisioningState='Succeeded', subnets=[{'id': subnet_id}], securityRules=[
                {'name': 'deny-all-inbound', 'properties': dict(priority=100, direction='Inbound',
                    access='Deny', protocol='*', sourcePortRange='*', destinationPortRange='*',
                    sourceAddressPrefix='*', destinationAddressPrefix='*')}]))
        subnet = dict(id=subnet_id, properties=dict(provisioningState='Succeeded',
            networkSecurityGroup={'id': nsg_id}, ipConfigurations=[{'id': selected['IpConfigurationId']}]))
        nsg['properties']['securityRules'][0]['properties']['destinationPortRanges'] = []
        original = copy.deepcopy((nsg, subnet))
        plan = edge.certificate_ingress_candidate(selected, nsg, subnet)
        self.assertEqual((nsg, subnet), original)
        self.assertEqual(plan['if_match'], nsg['etag'])
        for etag in ('*', ' W/"44444444-4444-4444-8444-444444444444"', '"one", "two"',
                     'W/"44444444-4444-4444-8444-444444444444"\r\n', 'unquoted'):
            wrong = copy.deepcopy(nsg); wrong['etag'] = etag
            with self.assertRaises(ValueError): edge.certificate_ingress_candidate(selected, wrong, subnet)
        rules = plan['body']['properties']['securityRules']
        self.assertEqual([(r['properties']['priority'], r['properties']['access'],
                           r['properties']['protocol'], r['properties']['destinationPortRange']) for r in rules],
                         [(100, 'Allow', 'Tcp', '443'), (110, 'Deny', '*', '*')])
        for changed in ('extra_device', 'foreign_assignment', 'extra_rule', 'wrong_owner', 'missing_etag'):
            other, network = copy.deepcopy(original)
            if changed == 'extra_device': network['properties']['ipConfigurations'].append({'id': 'other'})
            if changed == 'foreign_assignment': other['properties']['subnets'].append({'id': 'other'})
            if changed == 'extra_rule': other['properties']['securityRules'].append(rules[0])
            if changed == 'wrong_owner': other['tags']['purpose'] = 'other'
            if changed == 'missing_etag': other['etag'] = ''
            with self.assertRaises(ValueError): edge.certificate_ingress_candidate(selected, other, network)

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
