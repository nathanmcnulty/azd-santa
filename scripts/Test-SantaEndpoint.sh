#!/bin/zsh
set -euo pipefail

expected_version="${1:-2026.8}"
evidence_root="${2:-.azure/azd-santa/endpoint-evidence}"
captured_at="$(/bin/date -u +'%Y-%m-%dT%H:%M:%SZ')"
directory_stamp="$(/bin/date -u +'%Y%m%dT%H%M%SZ')"
evidence_dir="${evidence_root}/${directory_stamp}"

umask 077
/bin/mkdir -p "$evidence_root"
/bin/mkdir "$evidence_dir"
/bin/chmod 700 "$evidence_dir"

finalize() {
  local exit_code=$?
  trap - EXIT
  set +e

  local result="failed"
  if [[ $exit_code -eq 0 ]]; then
    result="passed"
  fi

  {
    print -r -- "schemaVersion=1"
    print -r -- "capturedAtUtc=${captured_at}"
    print -r -- "computerName=${computer_name:-unknown}"
    print -r -- "expectedSantaVersion=${expected_version}"
    print -r -- "result=${result}"
    print -r -- "exitCode=${exit_code}"
  } > "${evidence_dir}/receipt.txt"

  (
    cd "$evidence_dir" || exit 1
    /usr/bin/shasum -a 256 ./*.txt > SHA256SUMS
  )

  print -r -- "Endpoint evidence: ${evidence_dir}"
  exit $exit_code
}
trap finalize EXIT

computer_name="$(/usr/sbin/scutil --get ComputerName 2>/dev/null || /bin/hostname)"

echo "== host =="
{
  print -r -- "computerName=${computer_name}"
  /usr/bin/sw_vers
} | /usr/bin/tee "${evidence_dir}/host.txt"

echo "== enrollment =="
/usr/bin/profiles status -type enrollment 2>&1 | /usr/bin/tee "${evidence_dir}/enrollment.txt"

echo "== installed profiles =="
/usr/bin/profiles show -type configuration 2>&1 | /usr/bin/tee "${evidence_dir}/profiles.txt"

echo "== version =="
/usr/local/bin/santactl version 2>&1 | /usr/bin/tee "${evidence_dir}/santactl-version.txt"
/usr/bin/grep -Fq -- "$expected_version" "${evidence_dir}/santactl-version.txt"

echo "== status =="
/usr/local/bin/santactl status 2>&1 | /usr/bin/tee "${evidence_dir}/santactl-status.txt"
/usr/bin/grep -Eiq 'Mode[[:space:]]*\|[[:space:]]*Monitor' "${evidence_dir}/santactl-status.txt"

echo "== doctor =="
/usr/bin/sudo /usr/local/bin/santactl doctor 2>&1 | /usr/bin/tee "${evidence_dir}/santactl-doctor.txt"

echo "== endpoint security extension =="
/usr/bin/systemextensionsctl list com.apple.system_extension.endpoint_security 2>&1 | /usr/bin/tee "${evidence_dir}/system-extension.txt"
/usr/bin/grep -q 'com.northpolesec.santa.daemon' "${evidence_dir}/system-extension.txt"
/usr/bin/grep -q 'activated enabled' "${evidence_dir}/system-extension.txt"

echo "Endpoint checks passed. This proves local health, not Intune delivery, sync receipt, or rule behavior."
