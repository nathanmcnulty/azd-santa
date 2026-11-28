"""Optional local Pebble TLS-ALPN and Caddy certificate renewal qualification."""
from contextlib import ExitStack
from datetime import datetime
import hashlib
import http.client
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import time
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'experiments/server'))
from test_https_proxy import facts
import https_edge as edge
import probe_held_https as probe


def choose_ports(stack):
    ports = []
    for _ in range(5):
        sock = stack.enter_context(socket.socket())
        sock.bind(('127.0.0.1', 0))
        ports.append(sock.getsockname()[1])
    return ports


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def start(stack, directory, name, arguments, environment=None):
    log = stack.enter_context((directory / f'{name}.log').open('wb'))
    process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, env=environment)
    stack.callback(stop, process)
    return process


def wait_for(seconds, description, action):
    deadline = time.monotonic() + seconds
    error = None
    while time.monotonic() < deadline:
        try:
            result = action()
            if result:
                return result
        except (OSError, http.client.HTTPException) as exc:
            error = exc
        time.sleep(.7)
    raise RuntimeError(f'{description} was not observed') from error


def fetch_root(port, context):
    connection = http.client.HTTPSConnection('localhost', port, context=context, timeout=3)
    try:
        connection.request('GET', '/roots/0')
        response = connection.getresponse()
        return response.read(65536) if response.status == 200 else None
    finally:
        connection.close()


def qualify(caddy, source, tools, directory):
    lock = json.loads((ROOT / 'experiments/server/caddy.lock.json').read_bytes())
    from held_https_readiness import LINUX_CADDY_SHA256
    expected = lock['windowsAmd64Validation']['binarySha256'] if os.name == 'nt' else LINUX_CADDY_SHA256
    if hashlib.sha256(caddy.read_bytes()).hexdigest() != expected:
        raise ValueError('Expected the pinned Caddy binary for this host.')
    suffix = '.exe' if os.name == 'nt' else ''
    pem_root = source / 'test/certs/pebble.minica.pem'
    server_certs = source / 'test/certs/localhost'
    state = directory / 'caddy-state'
    state.mkdir()
    with ExitStack() as sockets:
        ca, management, listener, dns, dns_mgmt = choose_ports(sockets)
    settings = dict(pebble=dict(listenAddress=f'127.0.0.1:{ca}', managementListenAddress=f'127.0.0.1:{management}',
        certificate=str(server_certs / 'cert.pem'), privateKey=str(server_certs / 'key.pem'),
        httpPort=listener, tlsPort=listener, profiles={'default': {'description': 'Loopback proof', 'validityPeriod': 90}}))
    ca_config = directory / 'pebble.json'
    ca_config.write_text(json.dumps(settings), encoding='utf-8')
    host = facts()['Fqdn']
    endpoint = f'https://localhost:{ca}/dir'
    config = edge.held_configuration(facts(), '/private-state', phase='staging')
    config['storage']['root'] = str(state)
    config['logging'] = {'logs': {'default': {'writer': {'output': 'stderr'}, 'level': 'INFO'}}}
    config['apps']['http']['servers']['https']['listen'] = [f'127.0.0.1:{listener}']
    automation = config['apps']['tls']['automation']
    automation['renew_interval'] = '2s'
    policy = automation['policies'][0]
    policy['renewal_window_ratio'] = 0.6
    issuer = policy['issuers'][0]
    issuer.update(ca=endpoint, test_ca=endpoint, trusted_roots_pem_files=[str(pem_root)], network_proxy={'from': 'none'})
    issuer['challenges']['tls-alpn']['alternate_port'] = listener
    caddy_config = directory / 'caddy.json'
    caddy_config.write_text(json.dumps(config), encoding='utf-8')

    env = dict(os.environ, PEBBLE_VA_NOSLEEP='1', PEBBLE_WFE_NONCEREJECT='0', PEBBLE_AUTHZREUSE='0')
    env.pop('PEBBLE_VA_ALWAYS_VALID', None)
    with ExitStack() as children:
        start(children, directory, 'dns', [str(tools / ('pebble-challtestsrv' + suffix)), '-dnsserver', f'127.0.0.1:{dns}',
            '-management', f'127.0.0.1:{dns_mgmt}', '-http01', '', '-https01', '', '-tlsalpn01', '', '-defaultIPv6', ''])
        start(children, directory, 'pebble', [str(tools / ('pebble' + suffix)), '-config', str(ca_config), '-dnsserver', f'127.0.0.1:{dns}'], env)
        management_tls = ssl.create_default_context(cafile=str(pem_root))
        serving_root = wait_for(20, 'Pebble root', lambda: fetch_root(management, management_tls))
        trust = ssl.create_default_context(cadata=serving_root.decode('ascii'))
        server = start(children, directory, 'caddy', [str(caddy), 'run', '--config', str(caddy_config)])
        first = wait_for(40, 'first trusted held response', lambda: probe.probe(host, '127.0.0.1', listener, trust))
        print('First held certificate verified.', flush=True)

        def later():
            assert server.poll() is None
            result = probe.probe(host, '127.0.0.1', listener, trust)
            return result if result['certificate_sha256'] != first['certificate_sha256'] else None

        renewed = wait_for(150, 'renewed trusted held response', later)
        assert datetime.fromisoformat(renewed['certificate_expires_utc']) > datetime.fromisoformat(first['certificate_expires_utc'])
        logs = [json.loads(line) for line in (directory / 'caddy.log').read_text(encoding='utf-8').splitlines()
                if line.startswith('{')]
        assert any(event.get('logger') == 'tls.renew' and event.get('msg') == 'certificate renewed successfully'
                   and event.get('identifier') == host for event in logs)
        challenges = [event for event in logs if event.get('msg') == 'trying to solve challenge']
        assert len(challenges) >= 2 and all(event.get('challenge_type') == 'tls-alpn-01'
                   and event.get('ca') == endpoint and event.get('identifier') == host for event in challenges)
        pebble_log = (directory / 'pebble.log').read_text(encoding='utf-8')
        assert pebble_log.count('set VALID by completed challenge') >= 2


VARIABLES = ('SANTA_CADDY_EXE', 'SANTA_PEBBLE_ROOT', 'SANTA_PEBBLE_BIN')


@unittest.skipUnless(all(os.environ.get(name) for name in VARIABLES), 'Select pinned Caddy and Pebble test tools')
class LocalRenewal(unittest.TestCase):
    def test_held_service_renews_without_restart(self):
        caddy, source, tools = (Path(os.environ[name]).resolve(strict=True) for name in VARIABLES)
        with tempfile.TemporaryDirectory() as folder:
            qualify(caddy, source, tools, Path(folder))


if __name__ == '__main__':
    unittest.main()
