#!/bin/bash
set -euo pipefail
export LC_ALL=C

fail() {
  printf 'result=failed\nreason=%s\n' "$1" >&2
  exit 1
}

[[ $# -eq 1 && "$1" =~ ^[a-f0-9]{64}$ ]] || fail 'Provide one lowercase binary rule SHA-256.'
identifier="$1"
status="$(/usr/local/bin/santactl status 2>/dev/null)" || fail 'Unable to read Santa status.'
/usr/bin/grep -Eq '^[[:space:]]*Mode[[:space:]]*\|[[:space:]]*Monitor$' <<< "$status" || fail 'Santa is not in Monitor mode.'
full_sync="$(/usr/bin/sed -nE 's/^[[:space:]]*Last Successful Full Sync[[:space:]]*\|[[:space:]]*(.*)$/\1/p' <<< "$status")"
rule_sync="$(/usr/bin/sed -nE 's/^[[:space:]]*Last Successful Rule Sync[[:space:]]*\|[[:space:]]*(.*)$/\1/p' <<< "$status")"
sync_time='^(Never|[0-9]{4}/[0-9]{2}/[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} [+-][0-9]{4})$'
[[ "$full_sync" =~ $sync_time && "$rule_sync" =~ $sync_time ]] || fail 'Unable to read the Santa sync timestamps.'

rule="$(/usr/local/bin/santactl rule --check --identifier "$identifier" 2>/dev/null)" || fail 'Santa rule lookup failed.'
case "$rule" in
  'Blocked (Binary)') state=blocked ;;
  'Allowed (Binary)') state=allowed ;;
  'No matching rule exists') state=absent ;;
  *) fail 'Unexpected Santa rule lookup result.' ;;
esac

printf 'schemaVersion=1\ncapturedAtUtc=%s\nmode=Monitor\n' "$(/bin/date -u +'%Y-%m-%dT%H:%M:%SZ')"
printf 'lastSuccessfulFullSync=%s\nlastSuccessfulRuleSync=%s\n' "$full_sync" "$rule_sync"
printf 'ruleSha256=%s\nruleState=%s\nresult=passed\n' "$identifier" "$state"
