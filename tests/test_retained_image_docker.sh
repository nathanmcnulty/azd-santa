#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
umask 077
ulimit -f 65536
fixture="$(mktemp -d "$HOME/.santa-image-XXXXXXXX")"
id=''
cleanup() {
  if [[ "$id" =~ ^sha256:[a-f0-9]{64}$ ]]; then docker image rm "$id" >/dev/null 2>&1 || :; fi
  rm -rf -- "$fixture"
}
trap cleanup EXIT
printf '%s\n' "$fixture" > "$fixture/synthetic"
tar -C "$fixture" -cf "$fixture/root.tar" synthetic
id="$(docker image import --platform linux/amd64 "$fixture/root.tar")"
[[ "$id" =~ ^sha256:[a-f0-9]{64}$ ]]
python - "$fixture" "$id" <<'PY'
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

sys.path.insert(0, 'experiments/server')
from retained_image_export import encoded, export_image
from retained_image_parts import assemble, plan

directory = Path(sys.argv[1]) / 'exported'
image = sys.argv[2]
key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
public = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
inventory = {'scope': 'azd-santa-retention-image-inventory-v1', 'platform': 'linux/amd64',
             'images': {'core': {'id': image}}}
maximum = 1024 * 1024
inventory_sha256 = hashlib.sha256(encoded(inventory)).hexdigest()
operation = uuid.uuid4().hex
result = export_image(directory, inventory, 'core', public, maximum=maximum,
                      inventory_sha256=inventory_sha256,
                      recipient_sha256=hashlib.sha256(public).hexdigest(), operation=operation)
completion = encoded(result)
completion_sha256 = hashlib.sha256(completion).hexdigest()
readback = directory.parent / 'readback'
readback.mkdir(mode=0o700)
copy = readback / 'image.sealed'
# Simulate object transfer only with the bounded disposable fixture. The
# maintained planner/assembler read binary streams and never stage part files.
objects = {}
with (directory / 'image.sealed').open('rb') as source:
    manifest = (directory / 'parts.json').read_bytes()
    assert manifest == plan(source, completion, completion_sha256=completion_sha256, operation=operation)
    for part in json.loads(manifest)['parts']:
        source.seek(part['offset'])
        objects[part['object']] = source.read(part['bytes'])
assembled = assemble(manifest, completion, copy, lambda name: io.BytesIO(objects[name]),
                    manifest_sha256=hashlib.sha256(manifest).hexdigest(), completion_sha256=completion_sha256,
                    operation=operation)
assert assembled['ciphertext_sha256'] == result['ciphertext_sha256']
subprocess.run(['docker', 'image', 'rm', image], timeout=20, check=True, stdout=subprocess.DEVNULL)
absent = subprocess.run(['docker', 'image', 'inspect', image], timeout=10, stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL)
assert absent.returncode != 0

private_key = readback / 'recipient.der'
private_key.write_bytes(key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
completion_path = readback / 'complete.json'
completion_path.write_bytes(completion)
args = ['--ciphertext', str(copy), '--completion', str(completion_path), '--completion-sha256', completion_sha256,
        '--recipient-key', str(private_key), '--inventory-sha256', inventory_sha256,
        '--image', 'core', '--image-id', image, '--staging', str(readback), '--maximum', str(maximum)]
command = [sys.executable, 'experiments/server/retained_image_load.py']
verified = json.loads(subprocess.check_output([*command, 'verify', *args], timeout=25))
assert verified['state'] == 'verified' and not verified['image_loaded'] and verified['image_id'] == image
assert subprocess.run(['docker', 'image', 'inspect', image], timeout=10, stdout=subprocess.DEVNULL,
                      stderr=subprocess.DEVNULL).returncode != 0
attempt = readback / 'attempt'
load_args = ['load', *args, '--docker-socket', str(Path('/var/run/docker.sock').resolve(strict=True)),
             '--attempt', str(attempt)]
loaded = json.loads(subprocess.check_output([*command, *load_args], timeout=25))
assert loaded['state'] == 'loaded' and loaded['image_loaded'] and loaded['image_id'] == image
assert not loaded['container_started'] and not loaded['restore_accepted']
assert json.loads((attempt / 'outcome.json').read_bytes()) == loaded
intent = (attempt / 'intent.json').read_bytes()
assert json.loads(intent)['state'] == 'load-uncertain'
assert subprocess.run([*command, *load_args], timeout=20, capture_output=True).returncode != 0
assert (attempt / 'intent.json').read_bytes() == intent
assert set(readback.iterdir()) == {copy, private_key, completion_path, attempt}
PY
[[ "$(docker image inspect --format '{{.Id}} {{.Os}}/{{.Architecture}}' "$id")" == "$id linux/amd64" ]]
echo 'Authenticated encrypted export loaded with the exact Linux amd64 image ID; no container was started.'
