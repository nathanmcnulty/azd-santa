#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."

folder="$(mktemp -d)"
trap 'rm -rf -- "$folder"' EXIT
sed 's|/usr/local/bin/santactl|fixture_santactl|g' scripts/live-response/Get-SantaRuleReceipt.sh > "$folder/receipt.sh"
hash="$(printf '%064d' 0)"
export hash

fixture_santactl() {
  case "$1" in
    status)
      printf '%s\n' "Mode | $fixture_mode" 'Last Successful Full Sync | Never' \
        'Last Successful Rule Sync | 2026/11/25 12:55:00 +0000'
      ;;
    rule)
      [[ $# -eq 4 && "$2" == --check && "$3" == --identifier && "$4" == "$hash" ]] || return 1
      printf '%s\n' "$fixture_rule"
      ;;
    *) return 1 ;;
  esac
}
export -f fixture_santactl

for state in blocked absent allowed; do
  case "$state" in
    blocked) rule='Blocked (Binary)' ;;
    absent) rule='No matching rule exists' ;;
    allowed) rule='Allowed (Binary)' ;;
  esac
  fixture_mode=Monitor fixture_rule="$rule" /bin/bash "$folder/receipt.sh" "$hash" > "$folder/output"
  grep -Fxq "ruleSha256=$hash" "$folder/output"
  grep -Fxq "ruleState=$state" "$folder/output"
  grep -Fxq 'lastSuccessfulFullSync=Never' "$folder/output"
  grep -Fxq 'lastSuccessfulRuleSync=2026/11/25 12:55:00 +0000' "$folder/output"
  grep -Fxq 'result=passed' "$folder/output"
done

if fixture_mode=Lockdown fixture_rule='Blocked (Binary)' /bin/bash "$folder/receipt.sh" "$hash"; then exit 1; fi
if fixture_mode=Monitor fixture_rule='Blocked (Certificate)' /bin/bash "$folder/receipt.sh" "$hash"; then exit 1; fi
if /bin/bash "$folder/receipt.sh" '--remove'; then exit 1; fi
