"""Read-only, secret-redacted diagnostics for the isolated synthetic event path."""
import argparse
import json
import re
import subprocess
from pathlib import Path
from urllib.parse import urlsplit

from test_live_zentral import load_fixture, validate_compose


def inspect(compose_path, fixture_path):
    compose, digest = validate_compose(compose_path)
    fixture = load_fixture(Path(fixture_path), digest)
    private_values = [device['secret'] for device in fixture['devices']]
    for line in (compose.parent / 'runtime.env').read_text().splitlines():
        key, value = line.split('=', 1)
        if any(part in key for part in ('PASS', 'SECRET', 'TOKEN', 'QUEUE_URL')):
            private_values.append(value)
        if key == 'ZENTRAL_QUEUE_URL':
            # The app-only environment no longer carries broker-bootstrap keys.
            # Keep redacting a password printed separately from its full URL.
            password = urlsplit(value).password
            if password:
                private_values.append(password)
    command = ['docker', '--host', 'unix:///var/run/docker.sock', 'compose', '-f', str(compose)]
    code = "import json; from zentral.core.stores.models import Store; print(json.dumps(list(Store.objects.values('backend','provisioning_uid'))))"
    rows = subprocess.run(command + ['exec', '-T', 'web', 'python', 'server/manage.py', 'shell', '--no-imports', '-c', code],
                          capture_output=True, text=True, timeout=30)
    print('STORE_RECORD_STATUS', rows.returncode)
    text = rows.stdout + rows.stderr
    logs = subprocess.run(command + ['logs', '--no-color', '--tail', '70', 'workers'],
                          capture_output=True, text=True, timeout=30)
    selected = [line for line in (logs.stdout + logs.stderr).splitlines()
                if re.search(r'ERROR|Error|WARNING|Warning|Traceback|store|Index|index|dead', line)]
    text += '\n'.join(selected[-18:])
    for value in sorted(private_values, key=len, reverse=True):
        if value:
            text = text.replace(value, '[REDACTED]')
    print(text[-3200:])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose', required=True)
    parser.add_argument('--fixture', required=True)
    args = parser.parse_args()
    inspect(args.compose, args.fixture)
