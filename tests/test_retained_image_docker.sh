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
from blob_retention import SelectedTarget, RetentionRejected
from retained_image_key_handoff import Handoff
from retained_image_parts import assemble, plan
from restore_recipient_key import pack

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
portable = readback / 'recipient.encrypted.der'
password = b'synthetic fixture passphrase only'
receipt = pack(private_key, portable, hashlib.sha256(public).hexdigest(), password)
private_key.unlink()
args[args.index('--recipient-key') + 1] = str(portable)
args += ['--encrypted-key-sha256', receipt['encrypted_key_sha256']]
# A hosted runner has no interactive terminal. Substitute the prompt only.
command = [sys.executable, '-c',
           'import runpy, sys; sys.path.insert(0, "experiments/server"); '
           'import restore_recipient_key as keys; '
           'keys.passphrase = lambda prompt: b"synthetic fixture passphrase only"; '
           'runpy.run_path("experiments/server/retained_image_load.py", run_name="__main__")']
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
assert set(readback.iterdir()) == {copy, portable, completion_path, attempt}

# Exercise delegation separately on the same authenticated fixture. The
# recovery side receives only the encrypted single-image data key.
subprocess.run(['docker', 'image', 'rm', image], timeout=20, check=True, stdout=subprocess.DEVNULL)
boot_id = '33333333-3333-4333-8333-333333333333'
host = SelectedTarget('/subscriptions/fixture/virtualMachines/receiver',
                      '44444444-4444-4444-8444-444444444444', '/fixture/socket', 'westus2')
handoff = Handoff(host, completion, completion_sha256=completion_sha256, inventory_sha256=inventory_sha256,
                  recipient_sha256=hashlib.sha256(public).hexdigest(), image_name='core', image_id=image,
                  boot_id=boot_id)
offers = readback / 'offers'
offers.mkdir(mode=0o700)
get_boot = lambda selected: boot_id
offer = handoff.offer(copy, offers, _boot=get_boot)
offer_sha = hashlib.sha256(offer).hexdigest()
envelope = handoff.seal(offer, offer_sha, key)
digest = hashlib.sha256(envelope).hexdigest()
delegated_attempt = readback / 'delegated-attempt'
pins = dict(socket=Path('/var/run/docker.sock').resolve(strict=True), staging=readback, attempt=delegated_attempt)
try:
    handoff.load(copy, offers, offer_sha, envelope, digest, **pins, _boot=lambda _: host.instance_id)
except RetentionRejected:
    pass
else:
    raise AssertionError('A different boot accepted the delegated image')
assert not delegated_attempt.exists()
delegated = handoff.load(copy, offers, offer_sha, envelope, digest, **pins, _boot=get_boot)
assert delegated['state'] == 'loaded' and delegated['image_id'] == image
assert not delegated['container_started'] and not delegated['restore_accepted']
try:
    handoff.load(copy, offers, offer_sha, envelope, digest, **pins, _boot=get_boot)
except RetentionRejected:
    pass
else:
    raise AssertionError('The consumed image offer was reused')
assert json.loads((delegated_attempt / 'outcome.json').read_bytes()) == delegated
bad_offers = readback / 'bad-offers'
bad_offers.mkdir(mode=0o700)
new_offer = handoff.offer(copy, bad_offers, _boot=get_boot)
new_sha = hashlib.sha256(new_offer).hexdigest()
try:
    handoff.seal(new_offer, new_sha, rsa.generate_private_key(public_exponent=65537, key_size=3072))
except RetentionRejected:
    pass
else:
    raise AssertionError('The wrong backup private key delegated the image')
bad_attempt = readback / 'bad-attempt'
try:
    handoff.load(copy, bad_offers, new_sha, envelope, digest,
                 **{**pins, 'attempt': bad_attempt}, _boot=get_boot)
except RetentionRejected:
    pass
else:
    raise AssertionError('An envelope for another offer reached Docker')
assert not bad_attempt.exists()
print('Delegated image key loaded the exact image and rejected wrong boots, keys, envelopes and replay.')
PY
[[ "$(docker image inspect --format '{{.Id}} {{.Os}}/{{.Architecture}}' "$id")" == "$id linux/amd64" ]]
echo 'Authenticated encrypted export loaded with the exact Linux amd64 image ID; no container was started.'
