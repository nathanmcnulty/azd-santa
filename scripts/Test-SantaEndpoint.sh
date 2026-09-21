#!/bin/zsh
set -euo pipefail

expected_version="${1:-2026.8}"
echo "== enrollment =="
/usr/bin/profiles status -type enrollment
echo "== installed profiles =="
/usr/bin/profiles show -type configuration
echo "== version =="
/usr/local/bin/santactl version | /usr/bin/tee /tmp/azd-santa-version.txt
/usr/bin/grep -q "$expected_version" /tmp/azd-santa-version.txt
echo "== status =="
/usr/local/bin/santactl status | /usr/bin/tee /tmp/azd-santa-status.txt
/usr/bin/grep -Eiq 'Mode[[:space:]]*\|[[:space:]]*Monitor' /tmp/azd-santa-status.txt
echo "== doctor =="
/usr/local/bin/santactl doctor
echo "== endpoint security extension =="
/usr/bin/systemextensionsctl list com.apple.system_extension.endpoint_security | /usr/bin/tee /tmp/azd-santa-system-extension.txt
/usr/bin/grep -q 'com.northpolesec.santa.daemon' /tmp/azd-santa-system-extension.txt
/usr/bin/grep -q 'activated enabled' /tmp/azd-santa-system-extension.txt
echo "Endpoint checks passed. This proves local health, not Intune delivery, sync receipt, or rule behavior."
