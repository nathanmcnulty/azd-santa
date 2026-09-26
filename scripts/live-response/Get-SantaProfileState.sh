#!/bin/bash
set -euo pipefail

printf 'schemaVersion=1\n'
printf 'capturedAtUtc=%s\n' "$(/bin/date -u +'%Y-%m-%dT%H:%M:%SZ')"
printf 'evidenceBoundary=Local macOS profile inventory only; this does not prove Intune delivery status.\n'

set +e
profiles_output="$(/usr/bin/profiles show -type configuration 2>&1)"
profiles_exit=$?
set -e
printf 'profilesShowExit=%s\n' "$profiles_exit"
printf 'profilesShowBytes=%s\n' "${#profiles_output}"

if [[ $profiles_exit -eq 0 ]]; then
  if printf '%s\n' "$profiles_output" | /usr/bin/grep -Eiq 'santa|northpole'; then
    printf 'santaRelatedText=present\n'
  else
    printf 'santaRelatedText=absent\n'
  fi
  if printf '%s\n' "$profiles_output" | /usr/bin/grep -Fq 'com.northpolesec.santa'; then
    printf 'santaConfigurationPayload=present\n'
  else
    printf 'santaConfigurationPayload=absent\n'
  fi
  if printf '%s\n' "$profiles_output" | /usr/bin/grep -Fq '6E70B113-0DD0-4A3D-8A8B-43BC077071ED'; then
    printf 'updatedInnerPayloadUuid=present\n'
  else
    printf 'updatedInnerPayloadUuid=absent\n'
  fi
else
  printf 'santaConfigurationPayload=unknown\n'
  printf 'updatedInnerPayloadUuid=unknown\n'
fi

set +e
xml_output="$(/usr/bin/profiles show -type configuration -output stdout-xml 2>&1)"
xml_exit=$?
set -e
printf 'profilesXmlExit=%s\n' "$xml_exit"
printf 'profilesXmlBytes=%s\n' "${#xml_output}"
if [[ $xml_exit -eq 0 ]]; then
  if printf '%s\n' "$xml_output" | /usr/bin/grep -Eq 'com\.[[:alnum:].-]+\.santa\.configuration'; then
    printf 'santaConfigurationIdentifierXml=present\n'
  else
    printf 'santaConfigurationIdentifierXml=absent\n'
  fi
  if printf '%s\n' "$xml_output" | /usr/bin/grep -Fq '4D0DFE79-A7B0-4D0E-91AF-B9C7286DE299'; then
    printf 'outerPayloadUuidXml=present\n'
  else
    printf 'outerPayloadUuidXml=absent\n'
  fi
  if printf '%s\n' "$xml_output" | /usr/bin/grep -Fq '6E70B113-0DD0-4A3D-8A8B-43BC077071ED'; then
    printf 'updatedInnerPayloadUuidXml=present\n'
  else
    printf 'updatedInnerPayloadUuidXml=absent\n'
  fi
fi

printf 'result=passed\n'
