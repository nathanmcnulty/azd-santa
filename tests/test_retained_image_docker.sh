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
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import time
import traceback

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

sys.path.insert(0, 'experiments/server')
from restore_cipher import authenticate
from restore_quarantine import decrypt_staging
from retained_image_archive import ArchiveRejected, verify_archive
from retained_image_export import IMAGE_MAGIC, encoded, export_image

directory = Path(sys.argv[1]) / 'exported'
image = sys.argv[2]
key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
public = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
inventory = {'scope': 'azd-santa-retention-image-inventory-v1', 'platform': 'linux/amd64',
             'images': {'core': {'id': image}}}
maximum = 1024 * 1024
result = export_image(directory, inventory, 'core', public, maximum=maximum,
                      inventory_sha256=hashlib.sha256(encoded(inventory)).hexdigest(),
                      recipient_sha256=hashlib.sha256(public).hexdigest())
subprocess.run(['docker', 'image', 'rm', image], timeout=20, check=True, stdout=subprocess.DEVNULL)
absent = subprocess.run(['docker', 'image', 'inspect', image], timeout=10, stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL)
assert absent.returncode != 0

# Test-only verifier with the independent recipient key and a bounded anonymous
# staging file. Authenticate the complete ciphertext before accessing plaintext.
with (directory / 'image.sealed').open('rb') as source, tempfile.TemporaryFile() as plaintext:
    authenticate(source, result['ciphertext_bytes'], result['ciphertext_sha256'], key, maximum=maximum + 4096)
    decrypt_staging(source, result['ciphertext_bytes'], result['ciphertext_sha256'], key, plaintext,
                    time.monotonic() + 10)
    assert plaintext.read(len(IMAGE_MAGIC)) == IMAGE_MAGIC
    length = struct.unpack('>I', plaintext.read(4))[0]
    assert 0 < length <= 4096
    metadata = plaintext.read(length)
    assert hashlib.sha256(metadata).hexdigest() == result['intent_sha256']
    assert metadata == (directory / 'intent.json').read_bytes()
    tar = plaintext.read(maximum + 1)
    assert len(tar) <= maximum
try:
    verify_archive(io.BytesIO(tar), archive_sha256=result['archive_sha256'], archive_bytes=result['archive_bytes'],
                   image_id=image, maximum=maximum)
except ArchiveRejected as error:
    traceback.print_exception(error.__context__)
    raise
subprocess.run(['docker', 'image', 'load', '--quiet'], input=tar, timeout=25, check=True)
PY
[[ "$(docker image inspect --format '{{.Id}} {{.Os}}/{{.Architecture}}' "$id")" == "$id linux/amd64" ]]
echo 'Authenticated encrypted export loaded with the exact Linux amd64 image ID; no container was started.'
