#!/bin/bash
# Developer qualification: named immutable outputs, never overwrite a prior run.
set -euo pipefail
label=${1:?An explicit qualification label is required}
[[ "$label" =~ ^[a-z0-9-]{2,24}$ ]]
root=/var/lib/azd-santa-qualification
pin=88e67b3ce49033aab028029937a6e14f7c489073
source="$root/source-$pin/zentral-$pin"
unit="azd-santa-build-$label"
if systemctl show "$unit" --property=LoadState --value | grep -qv '^not-found$'; then
    echo 'Observe the existing build; another submission is refused.' >&2
    exit 1
fi
python3 "$(dirname "${BASH_SOURCE[0]}")/prepare_core_build.py" --source "$source" --output "$source/Dockerfile.core-$label"
systemd-run --unit="$unit" --property=RuntimeMaxSec=1800 --property=TimeoutStopSec=60 \
    docker build --memory=2500m --memory-swap=2500m --build-arg APP_ENV=core \
    --build-arg "APP_VERSION=$pin" --label "org.opencontainers.image.revision=$pin" \
    --label io.azd-santa.variant=core-experiment \
    --file "$source/Dockerfile.core-$label" --tag "azd-santa-zentral-core-eval:$pin" "$source"
echo SANTA_NAMED_CORE_BUILD_SUBMITTED
