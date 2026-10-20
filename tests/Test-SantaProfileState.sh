#!/bin/bash
# Offline regression; compatible with macOS Bash 3.2 and Linux Bash.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
inventory="$work/inventory"
# A start-of-stream match followed by enough data to force pipe buffering.
printf '%s\n' 'com.northpolesec.santa com.example.santa.configuration 6E70B113-0DD0-4A3D-8A8B-43BC077071ED 4D0DFE79-A7B0-4D0E-91AF-B9C7286DE299 PRIVATE-INVENTORY' > "$inventory"
awk 'BEGIN { for (i=0; i<100000; i++) print "unrelated.configuration.inventory.padding" }' >> "$inventory"
function /usr/bin/profiles() {
  cat "$inventory"
  return "$profiles_status"
}
profiles_status=0
output="$(source "$root/scripts/live-response/Get-SantaProfileState.sh")"
for key in santaRelatedText santaConfigurationPayload updatedInnerPayloadUuid santaConfigurationIdentifierXml outerPayloadUuidXml updatedInnerPayloadUuidXml; do
  grep -Fx "$key=present" <<< "$output" >/dev/null
done
if grep -F 'PRIVATE-INVENTORY' <<< "$output" >/dev/null; then echo 'Raw inventory leaked' >&2; exit 1; fi
printf '%s\n' 'unrelated.inventory' > "$inventory"
output="$(source "$root/scripts/live-response/Get-SantaProfileState.sh")"
for key in santaRelatedText santaConfigurationPayload updatedInnerPayloadUuid santaConfigurationIdentifierXml outerPayloadUuidXml updatedInnerPayloadUuidXml; do
  grep -Fx "$key=absent" <<< "$output" >/dev/null
done
profiles_status=1
output="$(source "$root/scripts/live-response/Get-SantaProfileState.sh")"
for key in santaRelatedText santaConfigurationPayload updatedInnerPayloadUuid santaConfigurationIdentifierXml outerPayloadUuidXml updatedInnerPayloadUuidXml result; do
  grep -Fx "$key=unknown" <<< "$output" >/dev/null
done
if grep -E '=absent|=passed' <<< "$output" >/dev/null; then echo 'Failure fabricated absence or success' >&2; exit 1; fi
printf 'Profile state regressions passed (%s).\n' "$(uname -s)"
