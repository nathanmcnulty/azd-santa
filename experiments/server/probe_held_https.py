"""Original Unlicense. Observe the held TLS endpoint from an external client."""
import argparse
from datetime import datetime, timezone
import hashlib
import http.client
import json
from pathlib import Path
import re
import socket
import ssl
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import https_edge as edge


def probe(host, address, port, context):
    """Connect to the selected address and use only the selected SNI and Host."""
    with socket.create_connection((address, port), timeout=6) as raw:
        with context.wrap_socket(raw, server_hostname=host) as connection:
            certificate = connection.getpeercert()
            fingerprint = hashlib.sha256(connection.getpeercert(binary_form=True)).hexdigest()
            connection.sendall(f'GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n'.encode('ascii'))
            with http.client.HTTPResponse(connection, method='GET') as response:
                response.begin()
                expected_body = edge.HELD_BODY.encode()
                if (response.status != 503 or response.headers.get_all('Retry-After') != ['60']
                        or response.headers.get_all('Cache-Control') != ['no-store']
                        or response.read(len(expected_body) + 1) != expected_body):
                    raise ValueError('The selected endpoint did not return the held HTTPS response.')
    expiry = datetime.fromtimestamp(ssl.cert_time_to_seconds(certificate['notAfter']), timezone.utc)
    return dict(certificate_sha256=fingerprint, certificate_expires_utc=expiry.isoformat(), http_status=503)


def observe(facts_path, expected_facts_sha256):
    with Path(facts_path).open('rb') as source:
        data = source.read(4097)
    if len(data) > 4096 or hashlib.sha256(data).hexdigest() != expected_facts_sha256:
        raise ValueError('The supplied ARM facts do not match the captured SHA-256.')
    facts = json.loads(data)
    edge.candidate.validate_facts(facts)
    address = facts['PublicIpAddress']
    host = facts['Fqdn']
    subscription = facts['SubscriptionId'].replace('-', '')[:16]
    prefix = f"santa-{subscription}-{facts['EnvironmentName']}-vm"
    if not re.fullmatch(re.escape(prefix) + r'\.[a-z0-9]{2,32}\.cloudapp\.azure\.com', host):
        raise ValueError('The hostname does not match the selected Azure deployment.')
    resolved = {row[4][0] for row in socket.getaddrinfo(host + '.', 443, socket.AF_INET, socket.SOCK_STREAM)}
    if resolved != {address}:
        raise ValueError('The selected Azure hostname did not resolve only to its recorded IPv4 address.')

    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    proof = probe(host, address, 443, context)
    return dict(scope='santa-held-https-client-observation-v1', facts_sha256=expected_facts_sha256,
                vm_instance_id=facts['VmInstanceId'], fqdn=host, address=address,
                observed_at_utc=datetime.now(timezone.utc).isoformat(), **proof)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--facts', type=Path, required=True)
    parser.add_argument('--expected-facts-sha256', required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(observe(args.facts, args.expected_facts_sha256), sort_keys=True))
    except (OSError, ValueError, http.client.HTTPException) as error:
        parser.exit(1, f'Held HTTPS observation failed: {error}\n')
