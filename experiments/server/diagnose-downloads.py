"""Read-only bounded comparison of public Ubuntu package mirror responses."""
import json
import re
import subprocess
import time
import urllib.error
import urllib.request

metadata = subprocess.check_output(['apt-cache', 'show', 'runc'], text=True)
filename = next(line.split(': ', 1)[1] for line in metadata.splitlines() if line.startswith('Filename: '))
if ('..' in filename.split('/') or
        not re.fullmatch(r'pool/[a-z0-9/+.~-]+/runc_[a-zA-Z0-9.~+_-]+_amd64\.deb', filename)):
    raise ValueError('Unexpected Ubuntu package filename')
for mirror in ('http://azure.archive.ubuntu.com/ubuntu/',
               'https://azure.archive.ubuntu.com/ubuntu/',
               'https://archive.ubuntu.com/ubuntu/'):
    started = time.monotonic()
    try:
        with urllib.request.urlopen(mirror + filename, timeout=15) as response:
            prefix = response.read(65536)
            result = dict(mirror=mirror, status=response.status, bytes_read=len(prefix),
                          content_length=response.headers.get('Content-Length'))
    except (OSError, urllib.error.URLError) as error:
        result = dict(mirror=mirror, error=type(error).__name__)
    result['elapsed_seconds'] = round(time.monotonic() - started, 2)
    print(json.dumps(result), flush=True)
