"""Opt-in pinned Caddy loopback test; no Azure, ACME or native-device claim."""
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone

from test_https_edge import edge, facts


@unittest.skipUnless(os.environ.get('SANTA_CADDY_EXE'), 'Set SANTA_CADDY_EXE for pinned binary proof')
class ActualHeaders(unittest.TestCase):
    def test_spoofed_headers_removed_and_fixed_https_metadata_survives(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID
        binary = Path(os.environ['SANTA_CADDY_EXE'])
        lock = json.loads(edge.candidate.LOCK.read_bytes())
        expected = (lock['windowsAmd64Validation']['binarySha256'] if os.name == 'nt'
                    else 'a563843e11cbce39c557bd429ebb787d56f49d51d9bbb3292cd9b36b37a60cdf')
        self.assertEqual(hashlib.sha256(binary.read_bytes()).hexdigest(), expected)

        calls = []
        class Echo(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                calls.append(1)
                body = json.dumps(dict(self.headers)).encode()
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        server = http.server.HTTPServer(('127.0.0.1', 0), Echo)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            key = ec.generate_private_key(ec.SECP256R1())
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Santa loopback test')])
            now = datetime.now(timezone.utc)
            host = facts()['Fqdn']
            cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                    .public_key(key.public_key()).serial_number(x509.random_serial_number())
                    .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(minutes=5))
                    .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), False)
                    .sign(key, hashes.SHA256()))
            (state / 'cert.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            (state / 'key.pem').write_bytes(key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            config = edge.configuration(facts(), '/private', certificate='/private/cert.pem', key='/private/key.pem')
            config['storage']['root'] = str(state / 'storage')
            config['logging'] = {'logs': {'default': {'writer': {'output': 'discard'}}}}
            config['apps']['tls']['certificates']['load_files'][0] = {
                'certificate': str(state / 'cert.pem'), 'key': str(state / 'key.pem')}
            with socket.socket() as reservation:
                reservation.bind(('127.0.0.1', 0))
                port = reservation.getsockname()[1]
            listener = config['apps']['http']['servers']['https']
            listener['listen'] = ['127.0.0.1:' + str(port)]
            listener['routes'][0]['handle'][-1]['upstreams'][0]['dial'] = '127.0.0.1:' + str(server.server_port)
            path = state / 'config.json'
            path.write_text(json.dumps(config))
            process = subprocess.Popen([str(binary), 'run', '--config', str(path)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                ctx = ssl.create_default_context(cafile=str(state / 'cert.pem'))
                ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                deadline = time.monotonic() + 10
                while True:
                    try:
                        raw = socket.create_connection(('127.0.0.1', port), timeout=2)
                        break
                    except OSError:
                        if process.poll() is not None or time.monotonic() > deadline:
                            self.fail('Pinned loopback Caddy failed to start')
                        time.sleep(.05)
                with ctx.wrap_socket(raw, server_hostname=host) as connection:
                    connection.sendall(('GET / HTTP/1.1\r\nHost: ' + host + '\r\nConnection: close\r\n'
                        'X-Forwarded-Proto: http\r\nX-Forwarded-Host: attacker\r\n'
                        'X-Forwarded-For: attacker\r\nX-Forwarded-Unknown: attacker\r\n'
                        'Forwarded: for=attacker\r\nX-Azd-Santa-Client-IP: attacker\r\nX-Auth-User: attacker\r\n\r\n').encode())
                    response = http.client.HTTPResponse(connection)
                    response.begin()
                    self.assertEqual(response.status, 200)
                    headers = {k.lower(): v for k, v in json.loads(response.read(65536)).items()}
                self.assertEqual(headers['host'], 'localhost')
                self.assertEqual(headers['x-forwarded-host'], host)
                self.assertEqual(headers['x-forwarded-proto'], 'https')
                for header in ('x-forwarded-for', 'x-forwarded-unknown', 'forwarded', 'x-azd-santa-client-ip', 'x-auth-user'):
                    self.assertNotIn(header, headers)
                self.assertEqual(len(calls), 1)
                process.terminate()
                process.wait(timeout=10)
                # Actual handler proof uses a synthetic certificate on loopback;
                # it neither contacts ACME nor qualifies public certificate trust.
                held = edge.held_configuration(facts(), '/private', phase='staging')
                held['storage'] = config['storage']
                held['logging'] = config['logging']
                held['apps']['tls'] = config['apps']['tls']
                held_server = held['apps']['http']['servers']['https']
                held_server['listen'] = ['127.0.0.1:' + str(port)]
                held_server['automatic_https']['disable_certificates'] = True
                path.write_text(json.dumps(held))
                process = subprocess.Popen([str(binary), 'run', '--config', str(path)],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                deadline = time.monotonic() + 10
                while True:
                    try:
                        raw = socket.create_connection(('127.0.0.1', port), timeout=2)
                        break
                    except OSError:
                        if process.poll() is not None or time.monotonic() > deadline:
                            self.fail('Held loopback Caddy failed to start')
                        time.sleep(.05)
                with ctx.wrap_socket(raw, server_hostname=host) as connection:
                    connection.sendall(('GET / HTTP/1.1\r\nHost: ' + host + '\r\nConnection: close\r\n\r\n').encode())
                    response = http.client.HTTPResponse(connection)
                    response.begin()
                    self.assertEqual(response.status, 503)
                    self.assertEqual(response.getheader('Retry-After'), '60')
                    self.assertEqual(response.read(1024), b'Application admission held closed.\n')
                self.assertEqual(len(calls), 1)
            finally:
                if process.poll() is None:
                    process.terminate()
                process.wait(timeout=10)


if __name__ == '__main__':
    unittest.main()
