#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
umask 077
ulimit -f 65536
fixture="$(mktemp -d)"
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
import traceback
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

sys.path.insert(0, 'experiments/server')
from retained_image_export import encoded, export_image
from retained_image_parts import assemble, plan
from retained_image_readback import ReadbackRejected, open_verified_image

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

try:
    with open_verified_image(copy, completion, key, readback,
                             completion_sha256=completion_sha256,
                             inventory_sha256=inventory_sha256, image_name='core', image_id=image,
                             maximum=maximum) as (archive, verified):
        assert verified['image_id'] == image and not verified['image_loaded']
        subprocess.run(['docker', 'image', 'load', '--quiet'], stdin=archive, timeout=25, check=True)
except ReadbackRejected as error:
    traceback.print_exception(error.__context__)
    raise
assert set(readback.iterdir()) == {copy}
PY
[[ "$(docker image inspect --format '{{.Id}} {{.Os}}/{{.Architecture}}' "$id")" == "$id linux/amd64" ]]
echo 'Authenticated encrypted export loaded with the exact Linux amd64 image ID; no container was started.'
