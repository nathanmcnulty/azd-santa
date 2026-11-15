"""Original Unlicense. Bounded stock-Caddy edge configuration and host TCP cap.

Rendering never starts a service, obtains a certificate or changes Azure. The
explicit root-only firewall entry installs only a dedicated restrictive chain.
Public admission remains a separate operator action after private qualification.
"""
import copy
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import prepare_https_proxy as candidate

LIMIT = 16
COMMENT = 'azd-santa-https-edge-v1'
IPTABLES = '/usr/sbin/iptables'


def need(value):
    if not value:
        raise ValueError('HTTPS edge configuration or firewall state rejected')


def configuration(facts, state, *, phase='private', certificate=None, key=None):
    need(phase in ('private', 'staging', 'production'))
    state = PurePosixPath(state)
    need(state.is_absolute())
    data = copy.deepcopy(candidate.configuration(facts, state))
    server = data['apps']['http']['servers']['https']
    server['listen'] = ['127.0.0.1:8443' if phase == 'private' else '0.0.0.0:443']
    handlers = server['routes'][0]['handle']
    need(handlers[1]['handler'] == 'static_response' and handlers[1]['status_code'] == 503)
    del handlers[1]
    upstream = handlers[1]
    # The existing backend is direct mode: budgets use its transport peer,
    # conservatively shared across this one-Mac pilot, never caller identity.
    headers = upstream['headers']['request']
    headers['delete'].append('X-Azd-Santa-Client-IP')
    headers['set'].pop('X-Forwarded-For', None)
    headers['set']['Host'] = ['localhost' if phase == 'private' else facts['Fqdn']]
    upstream['transport']['network_proxy'] = {'from': 'none'}
    upstream['transport']['keep_alive'] = {'max_idle_conns': 4, 'max_idle_conns_per_host': 4, 'idle_timeout': '10s'}
    if phase == 'private':
        need(certificate is not None and key is not None)
        certificate, key = PurePosixPath(certificate), PurePosixPath(key)
        need(certificate.is_absolute() and key.is_absolute() and certificate != key)
        data['apps']['tls'] = {'certificates': {'load_files': [
            {'certificate': str(certificate), 'key': str(key)}]}}
        server['automatic_https']['disable_certificates'] = True
    else:
        need(certificate is None and key is None)
        issuer = data['apps']['tls']['automation']['policies'][0]['issuers'][0]
        if phase == 'production':
            issuer['ca'] = 'https://acme-v02.api.letsencrypt.org/directory'
        # A failed production issuance must never fall back to an untrusted CA.
        issuer['test_ca'] = issuer['ca']
    return data


def unit_text(binary, config, state, *, port=8443):
    rules(port)
    paths = [str(PurePosixPath(value)) for value in (binary, config, state)]
    for path, prefix in zip(paths, ('/opt/azd-santa-https/', '/etc/azd-santa-https/', '/var/lib/azd-santa-https/')):
        need(re.fullmatch(re.escape(prefix) + r'[A-Za-z0-9/_.-]+', path) and '..' not in PurePosixPath(path).parts)
    return '\n'.join((
        '[Unit]', 'Description=Santa bounded HTTPS edge',
        'Requires=azd-santa-https-firewall-' + str(port) + '.service',
        'After=network-online.target azd-santa-https-firewall-' + str(port) + '.service',
        '[Service]', 'Type=exec', 'User=azd-santa-https', 'Group=azd-santa-https',
        'ExecStart=' + paths[0] + ' run --config ' + paths[1],
        'Restart=no', 'TimeoutStopSec=15', 'KillMode=control-group', 'UMask=0077',
        'NoNewPrivileges=yes', 'PrivateTmp=yes', 'PrivateDevices=yes', 'ProtectHome=yes',
        'ProtectSystem=strict', 'ReadWritePaths=' + paths[2],
        'ProtectKernelTunables=yes', 'ProtectKernelModules=yes', 'ProtectControlGroups=yes',
        'RestrictSUIDSGID=yes', 'LockPersonality=yes',
        'CapabilityBoundingSet=CAP_NET_BIND_SERVICE', 'AmbientCapabilities=CAP_NET_BIND_SERVICE',
        'MemoryMax=192M', 'MemorySwapMax=0', 'CPUQuota=50%', 'TasksMax=64',
        'LimitNOFILE=256', 'StandardOutput=null', 'StandardError=journal',
        '[Install]', 'WantedBy=multi-user.target', ''))


def firewall_unit_text(script, *, port=8443):
    rules(port)
    need(re.fullmatch(r'/opt/azd-santa-https/[A-Za-z0-9/_.-]+/https_edge.py', str(script))
         and '..' not in PurePosixPath(script).parts)
    return '\n'.join(('[Unit]', 'Description=Santa restrictive TLS connection cap',
        'After=network-online.target docker.service',
        '[Service]', 'Type=oneshot', 'RemainAfterExit=yes',
        'ExecStart=/usr/bin/python3 -I -B ' + str(script) + ' --ensure-firewall ' + str(port),
        'TimeoutStartSec=60', 'NoNewPrivileges=yes', 'ProtectSystem=strict',
        'ReadWritePaths=/run/xtables.lock',
        'ProtectHome=yes', 'PrivateTmp=yes', 'CapabilityBoundingSet=CAP_NET_ADMIN', ''))


def rules(port):
    need(type(port) is int and port in (443, 8443))
    chain = 'AZDSANTA_TLS' + str(port)
    reject = ['-p', 'tcp', '-m', 'tcp', '--syn', '--dport', str(port), '-m', 'connlimit',
              '--connlimit-above', str(LIMIT), '--connlimit-mask', '0',
              '--connlimit-saddr', '-j', 'REJECT', '--reject-with', 'tcp-reset']
    jump = ['-p', 'tcp', '-m', 'tcp', '--dport', str(port), '-m', 'comment', '--comment', COMMENT, '-j', chain]
    return chain, reject, jump


def command(arguments, *, required=True):
    result = subprocess.run([IPTABLES, '--wait', '5', *arguments], stdin=subprocess.DEVNULL,
                            capture_output=True, timeout=10, check=False)
    need(len(result.stdout) <= 262144 and len(result.stderr) <= 4096)
    if required:
        need(result.returncode == 0)
    return result


def lines(result):
    return [shlex.split(line) for line in result.stdout.decode('ascii').splitlines()]


def verify_firewall(port):
    chain, reject, jump = rules(port)
    chain_lines = lines(command(['-S', chain]))
    need(len(chain_lines) == 3 and chain_lines[0] == ['-N', chain])
    command(['-C', chain, *reject]); command(['-C', chain, '-j', 'RETURN'])
    input_lines = lines(command(['-S', 'INPUT']))
    entries = [row for row in input_lines if row[:2] == ['-A', 'INPUT']]
    need(entries and entries[0] == ['-A', 'INPUT', *jump])
    references = [row for row in lines(command(['-S']))
                  if any(flag in row and row[row.index(flag) + 1] == chain for flag in ('-j', '-g'))]
    need(references == [entries[0]])
    return dict(scope='santa-host-tcp-cap-v1', port=port, maximum_connections=LIMIT,
                ipv4_only=True, active_configuration_observed=True, public_ingress_opened=False)


def ensure_firewall(port):
    """Restrict only this port. No flush/delete or adoption of partial chains."""
    need(os.name == 'posix' and os.geteuid() == 0)
    chain, reject, jump = rules(port)
    before = lines(command(['-S', 'INPUT']))
    existing = command(['-S', chain], required=False)
    if existing.returncode == 0:
        return verify_firewall(port)
    # Recheck all INPUT entries after reservation. A partial failure is retained
    # and rejected next time; it never becomes an automatic delete/reset.
    command(['-N', chain])
    need(lines(command(['-S', 'INPUT'])) == before)
    command(['-A', chain, *reject]); command(['-A', chain, '-j', 'RETURN'])
    command(['-I', 'INPUT', '1', *jump])
    after = lines(command(['-S', 'INPUT']))
    need([row for row in after if row != ['-A', 'INPUT', *jump]] == before)
    return verify_firewall(port)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--ensure-firewall', type=int, choices=(443, 8443), required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(ensure_firewall(args.ensure_firewall)))
    except Exception:
        raise SystemExit('HTTPS edge firewall failed; preserve partial state, do not reset it') from None
