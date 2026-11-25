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
docker image save "$id" > "$fixture/export.tar"
size="$(stat -c %s "$fixture/export.tar")"
read -r digest _ < <(sha256sum "$fixture/export.tar")
docker image rm "$id" >/dev/null
if docker image inspect "$id" >/dev/null 2>&1; then exit 1; fi

python - "$fixture/export.tar" "$digest" "$size" "$id" <<'PY'
import os
import subprocess
import sys
import traceback
sys.path.insert(0, 'experiments/server')
from restore_cipher import identity
from retained_image_archive import ArchiveRejected, verify_archive

path, digest, size, image = sys.argv[1:]
with open(path, 'rb') as archive:
    before = identity(os.fstat(archive.fileno()))
    try:
        verify_archive(archive, archive_sha256=digest, archive_bytes=int(size), image_id=image)
    except ArchiveRejected as error:
        # Only the disposable fixture is allowed to print internal verifier errors.
        traceback.print_exception(error.__context__)
        raise
    assert identity(os.fstat(archive.fileno())) == before
    archive.seek(0)
    subprocess.run(['docker', 'image', 'load', '--quiet'], stdin=archive, timeout=25, check=True)
    assert identity(os.fstat(archive.fileno())) == before
PY
[[ "$(docker image inspect --format '{{.Id}} {{.Os}}/{{.Architecture}}' "$id")" == "$id linux/amd64" ]]
echo 'Verified Docker archive loaded with the exact Linux amd64 image ID; no container was started.'
