"""Original Unlicense. Run one held certificate window on the selected Azure VM."""
from datetime import datetime
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import sys
import time
import urllib.error
import urllib.request
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
import certificate_ingress as ingress
import held_https_readiness as guest
from https_edge import candidate
import private_arm_adapter as arm
import probe_held_https as probe


def validate_previous(proof):
    if (set(proof) != {'certificate_sha256', 'certificate_expires_utc'} or
            not re.fullmatch('[a-f0-9]{64}', proof['certificate_sha256']) or
            datetime.fromisoformat(proof['certificate_expires_utc']).utcoffset() is None):
        raise ValueError('Stored certificate proof is incomplete.')
    return proof


def renewal_observed(previous, current):
    if previous['certificate_sha256'] == current['certificate_sha256']:
        return False
    if datetime.fromisoformat(current['certificate_expires_utc']) <= datetime.fromisoformat(previous['certificate_expires_utc']):
        raise ValueError('The new certificate does not extend the stored certificate lifetime.')
    return True


def run(facts, directory, mode='issue'):
    ingress.require(mode in ('issue', 'renew'), 'Unsupported certificate trial mode.')
    candidate.validate_facts(facts)
    subscription = facts['SubscriptionId']
    group = 'rg-azd-santa-vm-' + facts['EnvironmentName']
    instance = facts['VmInstanceId']
    base = facts['VmId'].split('/providers/')[0] + '/providers/Microsoft.Network/'
    nsg = base + 'networkSecurityGroups/nsg-santa-lab'
    subnet = base + 'virtualNetworks/vnet-santa-lab/subnets/host'
    selected_paths = {nsg, subnet, facts['NicId'], facts['VmId']}
    cli = arm.resolve_cli()

    def record(name, value):
        with (directory / (name + '.json')).open('x', encoding='utf-8') as output:
            json.dump(value, output, sort_keys=True)
            output.flush()
            os.fsync(output.fileno())

    def token():
        result = arm.cached_cli(['account', 'get-access-token', '--subscription', subscription,
                                 '--resource', 'https://management.azure.com/'], 15, application=cli)
        ingress.require(result['tenant'] == facts['TenantId'] and result['subscription'] == subscription,
                        'Cached Azure authorization differs from the selected tenant or subscription.')
        return result['accessToken']

    def url(path):
        ingress.require(path in selected_paths, 'ARM read escaped the selected deployment.')
        version = '2024-11-01' if path == facts['VmId'] else '2024-05-01'
        return f'https://management.azure.com{path}?api-version={version}'

    def read(path):
        return arm.https('GET', url(path), None, token(), time.monotonic() + 15)

    def put(path, body, version):
        ingress.require(path == nsg, 'ARM write escaped the selected NSG.')
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), guest.NoRedirect())
        request = urllib.request.Request(url(path), method='PUT', data=json.dumps(body).encode(), headers={
            'Authorization': 'Bearer ' + token(), 'If-Match': version, 'Content-Type': 'application/json'})
        try:
            with opener.open(request, timeout=12) as response:
                return response.status
        except urllib.error.HTTPError as error:
            error.close()
            return error.code

    def invoke_guest(action):
        script = guest.render_script(facts, action, mode)
        nonce = 'SANTA_CERTIFICATE_GUEST_DONE:' + uuid.uuid4().hex
        script += f"printf '%s\\n' '{nonce}'\n"
        path = directory / f'{action}-held.sh'
        with path.open('x', encoding='utf-8', newline='\n') as output:
            output.write(script)
        response = arm.bounded_cli(['vm', 'run-command', 'invoke', '--subscription', subscription, '--resource-group', group,
            '--name', 'vm-santa-lab', '--command-id', 'RunShellScript', '--scripts', '@' + path.as_posix()], 120, application=cli)
        rows = response['value']
        ingress.require(rows and all(row['code'].endswith('/succeeded') for row in rows), 'Guest trial action did not complete.')
        lines = [line for row in rows for line in row['message'].splitlines()]
        markers = [line for line in lines if line.startswith('SANTA_HELD_READY:')]
        ingress.require(len(markers) == 1 and lines.count(nonce) == 1 and lines.index(markers[0]) < lines.index(nonce),
                        'Guest trial action did not produce terminal evidence.')
        proof = json.loads(markers[0].split(':', 1)[1])
        expected = dict(action=action, vm_instance_id=instance)
        if action == 'start' and mode == 'renew':
            expected['previous_certificate'] = validate_previous(proof['previous_certificate'])
        ingress.require(proof == expected, 'Guest trial evidence differs from the selection.')
        record('guest-' + action, proof)
        return proof

    record('endpoint', facts)
    endpoint = directory / 'endpoint.json'
    digest = hashlib.sha256(endpoint.read_bytes()).hexdigest()
    ingress.require(read(facts['VmId'])['properties']['vmId'].lower() == instance, 'The selected VM instance changed.')
    intent = ingress.plan(facts, read(nsg), read(subnet), read(facts['NicId']))

    def observe(previous):
        deadline = time.monotonic() + 150
        unchanged = None
        while time.monotonic() < deadline:
            try:
                result = probe.observe(endpoint, digest)
            except (OSError, http.client.RemoteDisconnected):
                time.sleep(3)
                continue
            if previous is None:
                record('certificate', result)
                return result
            observed = renewal_observed(previous, result)
            result.update(renewal_observed=observed, previous_certificate=previous)
            if observed:
                record('certificate', result)
                return result
            unchanged = result
            time.sleep(3)
        if unchanged is not None:
            record('certificate', unchanged)
            return unchanged
        raise TimeoutError('Trusted HTTPS did not return the held response during the certificate window.')

    try:
        started = invoke_guest('start')
        ingress.require(read(facts['VmId'])['properties']['vmId'].lower() == instance
                        and ingress.plan(facts, read(nsg), read(subnet), read(facts['NicId'])) == intent,
                        'Selected VM or network changed while preparing the held listener.')
        return ingress.run(intent, read, put, lambda: observe(started.get('previous_certificate')), record)
    finally:
        invoke_guest('stop')


if __name__ == '__main__':
    try:
        mode = sys.argv[2] if len(sys.argv) > 2 else 'issue'
        result = run(json.load(sys.stdin), Path(sys.argv[1]), mode)
        print(json.dumps(result, sort_keys=True))
    except Exception:
        raise SystemExit('Certificate trial failed or is uncertain. Inspect this attempt directory and the selected NSG before another action.') from None
