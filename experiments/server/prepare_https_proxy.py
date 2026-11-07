"""Original Unlicense: offline Caddy candidate; admission deliberately held closed.

No downloader, DNS client, Azure client, server startup or ingress integration.
Future installer owns authoritative ARM facts; this does not manufacture them.
"""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess

LOCK = Path(__file__).with_name('caddy.lock.json')
STAGING = 'https://acme-staging-v02.api.letsencrypt.org/directory'
GAPS = ('shared_fail_closed_budget', 'credential_hmac_and_key_cardinality',
        'inbound_connection_limit', 'strict_upstream_concurrency', 'overload_and_redis_recovery',
        'native_retry', 'trusted_certificate', 'renewal_restart', 'azure_fqdn_readback')


def need(value):
    if not value: raise ValueError('HTTPS candidate boundary failed')


def validate_facts(facts):
    need(set(facts) == {'scope', 'TenantId', 'SubscriptionId', 'EnvironmentName', 'VmId', 'VmInstanceId',
                        'NicId', 'IpConfigurationId', 'PublicIpId', 'PublicIpAddress', 'Fqdn'})
    need(facts['scope'] == 'azd-santa-selected-arm-endpoint-v1')
    guid = r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}'
    need(all(isinstance(facts[k], str) and re.fullmatch(guid, facts[k])
             for k in ('TenantId', 'SubscriptionId', 'VmInstanceId')))
    need(re.fullmatch('[a-z0-9-]{2,32}', facts['EnvironmentName']))
    root = '/subscriptions/' + facts['SubscriptionId'] + '/resourceGroups/rg-azd-santa-vm-' + facts['EnvironmentName'] + '/providers/'
    need(facts['VmId'] == root + 'Microsoft.Compute/virtualMachines/vm-santa-lab')
    need(facts['NicId'] == root + 'Microsoft.Network/networkInterfaces/nic-santa-lab')
    need(facts['IpConfigurationId'] == facts['NicId'] + '/ipConfigurations/primary')
    need(facts['PublicIpId'] == root + 'Microsoft.Network/publicIPAddresses/pip-santa-lab-egress')
    label = r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?'
    need(re.fullmatch(label + r'\.' + label + r'\.cloudapp\.azure\.com', facts['Fqdn']))
    need(ipaddress.IPv4Address(facts['PublicIpAddress']).is_global)


def configuration(facts, state):
    validate_facts(facts)
    host = facts['Fqdn']
    # A literal, unconditional response. There is intentionally no enable switch.
    # The following transport is provisioned/validated but cannot receive traffic.
    hold = {'handler': 'static_response', 'status_code': 503, 'body': 'Admission qualification pending.\n',
            'headers': {'Retry-After': ['60'], 'Cache-Control': ['no-store']}, 'close': True}
    upstream = {'handler': 'reverse_proxy', 'upstreams': [{'dial': '127.0.0.1:8000'}],
        'transport': {'protocol': 'http', 'versions': ['1.1'], 'max_conns_per_host': 4,
                      'dial_timeout': '2s', 'response_header_timeout': '10s',
                      'read_timeout': '15s', 'write_timeout': '15s'},
        'headers': {'request': {'delete': ['Forwarded', 'X-Forwarded-*', 'X-Real-IP', 'X-Client-Cert',
                                         'X-SSL-*', 'SSL-Client-*', 'X-Forwarded-Client-Cert',
                                         'Remote-User', 'X-Remote-User', 'X-Auth-*', 'X-Authenticated-*'],
                               'set': {'Host': [host], 'X-Forwarded-Host': [host],
                                       'X-Forwarded-Proto': ['https'], 'X-Forwarded-For': ['{http.request.remote.host}']}}}}
    return {'admin': {'disabled': True}, 'storage': {'module': 'file_system', 'root': str(state / 'acme')},
        'logging': {'logs': {'default': {'writer': {'output': 'file', 'filename': str(state / 'logs/caddy.json'),
                    'roll_size_mb': 5, 'roll_keep': 2, 'roll_keep_days': 1}, 'level': 'INFO',
                    'exclude': ['http.log.access', 'http.log.error']}}},
        'apps': {'tls': {'automation': {'policies': [{'subjects': [host], 'on_demand': False, 'issuers': [
            {'module': 'acme', 'ca': STAGING, 'test_ca': STAGING, 'acme_timeout': '30s',
             'challenges': {'http': {'disabled': True}, 'tls-alpn': {'disabled': False}}}]}]}},
            'http': {'servers': {'https': {'listen': [':443'], 'protocols': ['h1'],
                'automatic_https': {'disable_redirects': True}, 'strict_sni_host': True,
                'max_header_bytes': 16384, 'read_header_timeout': '5s', 'read_timeout': '10s',
                'write_timeout': '15s', 'idle_timeout': '30s',
                'tls_connection_policies': [{'match': {'sni': [host]}, 'protocol_min': 'tls1.2'}],
                'routes': [{'match': [{'host': [host]}], 'handle': [
                    {'handler': 'request_body', 'max_size': 1048576}, hold, upstream], 'terminal': True},
                    {'handle': [{'handler': 'static_response', 'status_code': 421, 'close': True}]}]}}}}}


def private_write(path, raw):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'wb') as stream: stream.write(raw)


def prepare(facts, destination):
    validate_facts(facts)
    destination = Path(destination)
    need(destination.is_absolute() and destination.parent == destination.parent.resolve(strict=True)
         and not destination.exists() and not destination.is_symlink())
    if os.name != 'nt':
        parent = destination.parent.stat()
        need(parent.st_uid == os.geteuid() and not parent.st_mode & 0o022)
    # Unix permissions are enforced. On Windows this is nonsecret offline
    # preparation only, never storage for actual ACME private keys.
    destination.mkdir(mode=0o700)
    state = destination / 'state'; state.mkdir(mode=0o700)
    for name in ('acme', 'logs'): (state / name).mkdir(mode=0o700)
    config = json.dumps(configuration(facts, state), indent=2).encode()
    private_write(destination / 'caddy.json', config)
    receipt = dict(scope='azd-santa-https-candidate-v1', admission='held-closed', facts=facts,
                   config_sha256=hashlib.sha256(config).hexdigest(),
                   lock_sha256=hashlib.sha256(LOCK.read_bytes()).hexdigest(),
                   gates={key: 'not_run' for key in GAPS}, native_validation='not_run')
    private_write(destination / 'candidate.json', json.dumps(receipt, indent=2).encode())
    return destination / 'caddy.json'


def validate_windows(config, binary):
    """Explicit local validator, never starts server or sends ACME requests.

    Caddy Validate provisions but does not start applications. Fresh empty
    storage, fixed ACME issuer and no DNS plugins are required by our renderer.
    This validates syntax/provisioning only; Linux/resource/ACME gates stay open.
    """
    need(os.name == 'nt')
    lock = json.loads(LOCK.read_bytes())
    need(hashlib.sha256(Path(binary).read_bytes()).hexdigest() == lock['windowsAmd64Validation']['binarySha256'])
    config = Path(config); receipt_path = config.with_name('candidate.json')
    receipt = json.loads(receipt_path.read_bytes())
    need(hashlib.sha256(config.read_bytes()).hexdigest() == receipt['config_sha256'] and
         receipt['lock_sha256'] == hashlib.sha256(LOCK.read_bytes()).hexdigest())
    expected = configuration(receipt['facts'], config.parent / 'state')
    need(json.loads(config.read_bytes()) == expected and not any((config.parent / 'state/acme').iterdir()))
    result = subprocess.run([str(binary), 'validate', '--config', str(config)],
                            capture_output=True, timeout=30, check=False)
    private_write(config.with_name('validation-diagnostics.json'), json.dumps(dict(
        returncode=result.returncode, stdout=result.stdout.decode(errors='replace'),
        stderr=result.stderr.decode(errors='replace'))).encode())
    need(result.returncode == 0)
    proof = dict(scope='caddy-windows-provision-validation-only', config_sha256=receipt['config_sha256'],
                 binary_sha256=lock['windowsAmd64Validation']['binarySha256'],
                 no_server_started=True, admission='held-closed', linux_and_admission_gates='not_run')
    private_write(config.with_name('validation.json'), json.dumps(proof).encode())
    return proof
