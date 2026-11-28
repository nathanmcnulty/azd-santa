"""Edge rendering/kernel command tests; not actual Linux/firewall/TLS proof."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'experiments/server'))
import https_edge as edge
import certificate_ingress as ingress
import held_https_readiness as readiness
import prepare_held_https as held
import probe_held_https as probe
import run_held_certificate_trial as trial
from test_https_proxy import facts


class CertificateWindow(unittest.TestCase):
    def setUp(self):
        selected = facts()
        base = selected['NicId'].rsplit('/', 2)[0]
        nsg_id = base + '/networkSecurityGroups/nsg-santa-lab'
        subnet_id = base + '/virtualNetworks/vnet-santa-lab/subnets/host'
        tags = {'azd-solution': 'azd-santa', 'purpose': 'synthetic-vm-lab', 'azd-env-name': 'synthetic'}
        deny = dict(priority=100, direction='Inbound', access='Deny', protocol='*', sourcePortRange='*',
                    destinationPortRange='*', sourceAddressPrefix='*', destinationAddressPrefix='*')
        self.version = '"44444444-4444-4444-8444-444444444444"'
        nsg = dict(id=nsg_id, etag=self.version, location='westus2', tags=tags,
                   properties=dict(provisioningState='Succeeded', subnets=[{'id': subnet_id}],
                       networkInterfaces=[], securityRules=[dict(name='deny-all-inbound', properties=deny)]))
        subnet = dict(id=subnet_id, properties=dict(provisioningState='Succeeded', addressPrefix='10.10.0.0/24',
                      networkSecurityGroup={'id': nsg_id}, ipConfigurations=[{'id': selected['IpConfigurationId']}]))
        config = dict(id=selected['IpConfigurationId'], properties=dict(subnet={'id': subnet_id},
                      publicIPAddress={'id': selected['PublicIpId']}, privateIPAddress='10.10.0.4'))
        nic = dict(id=selected['NicId'], properties=dict(provisioningState='Succeeded',
                   virtualMachine={'id': selected['VmId']}, ipConfigurations=[config]))
        self.intent = ingress.plan(selected, nsg, subnet, nic)
        self.view = nsg
        self.selected = selected
        self.arm_views = {nsg_id: nsg, subnet_id: subnet, selected['NicId']: nic,
                          selected['VmId']: {'properties': {'vmId': selected['VmInstanceId']}}}
        self.calls = []
        self.receipts = {}

    def read(self, resource):
        self.assertEqual(resource, self.intent['resource_id'])
        return copy.deepcopy(self.view)

    def put(self, resource, body, version):
        self.assertEqual((resource, version), (self.intent['resource_id'], self.view['etag']))
        self.calls.append((copy.deepcopy(body), version))
        self.view['properties']['securityRules'] = copy.deepcopy(body['properties']['securityRules'])
        self.view['etag'] = '"55555555-5555-4555-8555-555555555555"'
        return 202

    def record(self, name, receipt):
        self.assertNotIn(name, self.receipts)
        self.receipts[name] = receipt

    def test_window_targets_only_the_nic_and_restores_after_probe_failure(self):
        allow = self.intent['temporary']['properties']['securityRules'][0]['properties']
        self.assertEqual((allow['destinationAddressPrefix'], allow['destinationPortRange']), ('10.10.0.4', '443'))
        def probe():
            self.assertIn('ingress-intent', self.receipts)
            raise LookupError('fixture TLS failed')
        with patch.object(ingress.time, 'sleep'), self.assertRaisesRegex(LookupError, 'fixture TLS failed'):
            ingress.run(self.intent, self.read, self.put, probe, self.record)
        self.assertEqual(self.calls, [(self.intent['temporary'], self.version),
                                     (self.intent['original'], self.view['etag'])])
        self.assertTrue(self.receipts['ingress-outcome']['verified_closed'])

    def test_unknown_opening_does_not_claim_recovery_from_an_unchanged_policy(self):
        def put(*_):
            self.calls.append('submitted once')
            raise TimeoutError('fixture timeout')
        with self.assertRaisesRegex(ValueError, 'Opening outcome is uncertain'):
            ingress.run(self.intent, self.read, put, lambda: self.fail('No probe'), self.record)
        self.assertEqual(self.calls, ['submitted once'])
        self.assertFalse(self.receipts['ingress-outcome']['verified_closed'])

    def test_unrelated_policy_changes_are_never_overwritten(self):
        def probe():
            self.view['tags']['changed'] = 'outside trial'
        with self.assertRaisesRegex(ValueError, 'changed outside'):
            ingress.run(self.intent, self.read, self.put, probe, self.record)
        self.assertEqual(len(self.calls), 1)

    def test_controller_starts_probes_restores_and_stops_the_held_unit(self):
        self.exercise_controller('issue')

    def test_controller_compares_renewal_against_the_stored_certificate(self):
        self.exercise_controller('renew')

    def exercise_controller(self, mode):
        history = []
        selected = self.selected
        previous = {'certificate_sha256': 'a' * 64, 'certificate_expires_utc': '2030-01-02T00:00:00+00:00'}
        renewed = {'certificate_sha256': 'b' * 64, 'certificate_expires_utc': '2030-01-03T00:00:00+00:00'}
        def read(_method, url, *args):
            path = url.removeprefix('https://management.azure.com').split('?')[0]
            return copy.deepcopy(self.arm_views[path])
        def guest(command, *args, **kwargs):
            file = Path(command[-1][1:])
            action = file.name.split('-')[0]
            history.append(action)
            nonce = re.search('SANTA_CERTIFICATE_GUEST_DONE:[a-f0-9]{32}', file.read_text()).group()
            evidence = dict(action=action, vm_instance_id=selected['VmInstanceId'])
            if mode == 'renew' and action == 'start':
                evidence['previous_certificate'] = previous
            proof = json.dumps(evidence)
            return dict(value=[dict(code='ComponentStatus/StdOut/succeeded', message=f'SANTA_HELD_READY:{proof}\n{nonce}')])
        def write(request, **kwargs):
            body = json.loads(request.data)
            history.append('open' if body == self.intent['temporary'] else 'restore')
            self.put(self.intent['resource_id'], body, request.get_header('If-match'))
            return unittest.mock.MagicMock(**{'__enter__.return_value.status': 202})
        def observe(*args):
            history.append('probe')
            return {'http_status': 503} if mode == 'issue' else {'http_status': 503, **renewed}
        credentials = dict(tenant=selected['TenantId'], subscription=selected['SubscriptionId'], accessToken='fixture')
        with tempfile.TemporaryDirectory() as folder, patch.object(trial.arm, 'resolve_cli'), \
             patch.object(trial.arm, 'cached_cli', return_value=credentials), patch.object(trial.arm, 'https', side_effect=read), \
             patch.object(trial.arm, 'bounded_cli', side_effect=guest), patch.object(trial.probe, 'observe', side_effect=observe), \
             patch.object(ingress.time, 'sleep'), patch.object(trial.urllib.request, 'build_opener', return_value=SimpleNamespace(open=write)):
            result = trial.run(selected, Path(folder), mode)
            expected = {'http_status': 503}
            if mode == 'renew':
                expected.update(renewed, renewal_observed=True, previous_certificate=previous)
            self.assertEqual(result, expected)
            outcome = json.loads((Path(folder) / 'ingress-outcome.json').read_bytes())
            self.assertTrue(outcome['verified_closed'])
        self.assertEqual(history, ['start', 'open', 'probe', 'restore', 'stop'])

    def test_renewal_requires_a_changed_fingerprint_and_later_expiration(self):
        prior = dict(certificate_sha256='a' * 64, certificate_expires_utc='2030-01-02T00:00:00+00:00')
        self.assertFalse(trial.renewal_observed(prior, prior))
        with self.assertRaisesRegex(ValueError, 'does not extend'):
            trial.renewal_observed(prior, dict(prior, certificate_sha256='b' * 64))


class HeldObservation(unittest.TestCase):
    def test_dns_sample_binds_direct_tls_target_and_receipt(self):
        selected = dict(facts(), Fqdn='santa-1111111111114111-synthetic-vm.westus2.cloudapp.azure.com')
        address = selected['PublicIpAddress']
        expected = dict(certificate_sha256='b' * 64, http_status=503)
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / 'endpoint.json'
            source.write_bytes(json.dumps(selected).encode())
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            with patch.object(probe.socket, 'getaddrinfo', return_value=[(None, None, None, '', (address, 443))]) as dns, \
                 patch.object(probe, 'probe', return_value=expected) as direct:
                receipt = probe.observe(source, digest)
                self.assertEqual(receipt['facts_sha256'], digest)
                self.assertEqual(receipt['vm_instance_id'], selected['VmInstanceId'])
                self.assertEqual(receipt['certificate_sha256'], expected['certificate_sha256'])
                self.assertEqual(dns.call_args.args[0], selected['Fqdn'] + '.')
                self.assertEqual(direct.call_args.args[:3], (selected['Fqdn'], address, 443))
                context = direct.call_args.args[3]
                self.assertTrue(context.check_hostname)
                self.assertEqual(context.verify_mode, probe.ssl.CERT_REQUIRED)
                with self.assertRaisesRegex(ValueError, 'captured SHA-256'):
                    probe.observe(source, 'a' * 64)
                dns.return_value.append((None, None, None, '', ('1.1.1.1', 443)))
                with self.assertRaisesRegex(ValueError, 'recorded IPv4 address'):
                    probe.observe(source, digest)
                self.assertEqual(direct.call_count, 1)


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

    def test_readiness_expected_bytes_match_the_held_package(self):
        with tempfile.TemporaryDirectory() as folder:
            release, lock = self.make_release(Path(folder))
            files = held.package_files(facts(), release.read_bytes(), lock.read_bytes())
        request = readiness.render_request(facts())
        self.assertEqual(request['files'][request['binary']], readiness.LINUX_CADDY_SHA256)
        for path, (data, _) in files.items():
            expected = request['files'].get(str(path))
            if expected and str(path) != request['binary']:
                if path.suffix == '.py':
                    data = data.replace(b'\r\n', b'\n')
                self.assertEqual(expected, hashlib.sha256(data).hexdigest())

    def test_readiness_rejects_systemd_overrides_and_pending_reload(self):
        unit = readiness.HELD_UNIT
        props = dict(LoadState='loaded', FragmentPath='/etc/systemd/system/' + unit,
                     DropInPaths='', NeedDaemonReload='no')
        def properties(overrides):
            return '\n'.join(f'{key}={value}' for key, value in dict(props, **overrides).items())
        with patch.object(readiness, 'command', return_value=properties({})) as query:
            self.assertEqual(readiness.unit_properties(unit), props)
            self.assertIn('--all', query.call_args.args)
            for override in (dict(DropInPaths='/run/override.conf'), dict(NeedDaemonReload='yes')):
                query.return_value = properties(override)
                with self.assertRaisesRegex(ValueError, 'override, or pending reload'):
                    readiness.unit_properties(unit)

    @unittest.skipUnless(os.name == 'posix', 'certificate state permissions are POSIX')
    def test_prior_certificate_observation_checks_companion_files_without_reading_the_key(self):
        selected = facts()
        host = selected['Fqdn']
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder).resolve()
            asset = state / 'acme/certificates/acme-v02.api.letsencrypt.org-directory' / host / (host + '.crt')
            asset.parent.mkdir(parents=True)
            for path in (asset, asset.with_suffix('.key'), asset.with_suffix('.json')):
                path.write_bytes(b'fixture')
                path.chmod(0o600)
            pwd = SimpleNamespace(getpwnam=lambda _name: SimpleNamespace(pw_uid=asset.stat().st_uid))
            output = 'sha256 Fingerprint=' + ':'.join(['AB'] * 32) + '\nnotAfter=Jan  2 00:00:00 2030 GMT'
            request = dict(facts=selected, state=str(state))
            with patch.dict(sys.modules, pwd=pwd), patch.object(readiness, 'command', return_value=output) as openssl:
                observed = readiness.stored_certificate(request)
                self.assertEqual(observed, dict(certificate_sha256='ab' * 32, certificate_expires_utc='2030-01-02T00:00:00+00:00'))
                openssl.assert_called_once_with('/usr/bin/openssl', 'x509', '-in', str(asset), '-noout', '-fingerprint', '-sha256', '-enddate')
                asset.with_suffix('.key').unlink()
                with self.assertRaises(FileNotFoundError):
                    readiness.stored_certificate(request)

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
            self.assertEqual(data['apps']['tls']['automation']['renew_interval'], '30s')
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
