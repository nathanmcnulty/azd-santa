#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."

folder="$(mktemp -d)"
trap 'rm -rf -- "$folder"' EXIT
sed -e 's|/usr/sbin/scutil|fixture_scutil|g' \
    -e 's|/usr/bin/profiles|fixture_profiles|g' \
    -e 's|/usr/local/bin/santactl|fixture_santactl|g' \
    -e 's|/usr/bin/systemextensionsctl|fixture_extension|g' \
    scripts/live-response/Get-SantaHealth.sh > "$folder/health.sh"

fixture_scutil() { printf '%s\n' 'Fixture Mac'; }
fixture_profiles() { printf '%s\n' 'MDM enrollment: Yes'; }
fixture_santactl() {
  case "$1" in
    version) printf '%s\n' 'Santa version 2026.8' ;;
    status) printf '%s\n' 'Mode | Monitor' ;;
    doctor)
      printf '%s\n' '=> Validating processes...[+] No issues detected'
      printf '%s\n' '[+] System Integrity Protection is enabled[+] No configuration errors detected'
      # An early grep -q match must not close a printf pipeline under pipefail.
      awk 'BEGIN {for (i=0; i<20000; i++) print "fixture output padding"}'
      case "$fixture_sync" in
        disabled) printf '%s\n' '[+] Sync is disabled'; return 1 ;;
        timeout) printf '%s\n' '[-] Failed to retrieve preflight data: Request timed out'; return 1 ;;
        unknown) printf '%s\n' '[-] Unexpected doctor failure'; return 1 ;;
      esac
      ;;
  esac
}
fixture_extension() {
  if [[ "$fixture_extension_state" == active ]]; then
    printf '%s\n' 'ZMCG7MLDV9 com.northpolesec.santa.daemon [activated enabled]'
  fi
}
export -f fixture_scutil fixture_profiles fixture_santactl fixture_extension

run_health() {
  local status=0
  fixture_sync="$1" fixture_extension_state="$2" \
    /bin/bash "$folder/health.sh" > "$folder/stdout" 2> "$folder/stderr" || status=$?
  [[ "$status" -eq "$3" ]]
}

run_health connected active 0
grep -Fxq 'endpointSecurity=active' "$folder/stdout"
grep -Fxq 'result=passed' "$folder/stdout"

run_health disabled active 0
grep -Fxq 'result=passed' "$folder/stdout"

run_health timeout active 1
grep -Fxq 'endpointSecurity=active' "$folder/stdout"
grep -Fxq 'syncPreflight=timed-out' "$folder/stdout"
grep -Fxq 'result=failed' "$folder/stderr"
! grep -Fxq 'result=passed' "$folder/stdout"

run_health timeout absent 1
! grep -Fxq 'endpointSecurity=active' "$folder/stdout"
grep -Fxq 'syncPreflight=timed-out' "$folder/stdout"
grep -Fxq 'reason=Santa Endpoint Security extension was absent.' "$folder/stderr"

run_health unknown active 1
grep -Fxq 'endpointSecurity=active' "$folder/stdout"
! grep -Fxq 'syncPreflight=timed-out' "$folder/stdout"
grep -Fxq 'reason=santactl doctor reported an unexpected failure.' "$folder/stderr"
