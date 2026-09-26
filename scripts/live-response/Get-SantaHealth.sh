#!/bin/bash
set -euo pipefail

expected_version="${1:-2026.8}"
captured_at="$(/bin/date -u +'%Y-%m-%dT%H:%M:%SZ')"
computer_name="$(/usr/sbin/scutil --get ComputerName 2>/dev/null || /bin/hostname)"

fail() {
  printf 'result=failed\nreason=%s\n' "$1" >&2
  exit 1
}

printf 'schemaVersion=1\n'
printf 'capturedAtUtc=%s\n' "$captured_at"
printf 'computerName=%s\n' "$computer_name"
printf 'expectedSantaVersion=%s\n' "$expected_version"

printf '\n== enrollment ==\n'
/usr/bin/profiles status -type enrollment 2>&1 || fail 'Unable to read MDM enrollment status.'

printf '\n== Santa version ==\n'
version_output="$(/usr/local/bin/santactl version 2>&1)" || {
  printf '%s\n' "$version_output" >&2
  fail 'santactl version failed.'
}
printf '%s\n' "$version_output"
printf '%s\n' "$version_output" | /usr/bin/grep -Fq -- "$expected_version" || fail 'Installed Santa version did not match the expected release.'

printf '\n== Santa status ==\n'
status_output="$(/usr/local/bin/santactl status 2>&1)" || {
  printf '%s\n' "$status_output" >&2
  fail 'santactl status failed.'
}
printf '%s\n' "$status_output"
printf '%s\n' "$status_output" | /usr/bin/grep -Eiq 'Mode[[:space:]]*\|[[:space:]]*Monitor' || fail 'Santa was not in Monitor mode.'

printf '\n== Santa doctor ==\n'
set +e
doctor_output="$(/usr/local/bin/santactl doctor 2>&1)"
doctor_exit=$?
set -e
printf '%s\n' "$doctor_output"
printf '%s\n' "$doctor_output" | /usr/bin/grep -Fq '[+] System Integrity Protection is enabled' || fail 'Santa doctor did not confirm System Integrity Protection.'
printf '%s\n' "$doctor_output" | /usr/bin/grep -Fq '[+] No configuration errors detected' || fail 'Santa doctor reported a configuration error.'
if [[ $doctor_exit -ne 0 ]]; then
  printf '%s\n' "$doctor_output" | /usr/bin/grep -Fq '[+] Sync is disabled' || fail 'santactl doctor reported an unexpected failure.'
fi

printf '\n== Endpoint Security extension ==\n'
extension_output="$(/usr/bin/systemextensionsctl list com.apple.system_extension.endpoint_security 2>&1)" || {
  printf '%s\n' "$extension_output" >&2
  fail 'Unable to read Endpoint Security extension state.'
}
printf '%s\n' "$extension_output"
santa_extension_line="$(printf '%s\n' "$extension_output" | /usr/bin/grep -F 'com.northpolesec.santa.daemon' || true)"
[[ -n "$santa_extension_line" ]] || fail 'Santa Endpoint Security extension was absent.'
[[ "$santa_extension_line" != *$'\n'* ]] || fail 'Multiple Santa Endpoint Security extension rows were found.'
[[ "$santa_extension_line" == *'ZMCG7MLDV9'* && "$santa_extension_line" == *'[activated enabled]'* ]] || fail 'Santa Endpoint Security extension did not have the expected Team ID and active state.'

printf '\nresult=passed\n'
printf 'evidenceBoundary=Local Santa health only; this does not prove Intune delivery, sync receipt, or controlled rule behavior.\n'
