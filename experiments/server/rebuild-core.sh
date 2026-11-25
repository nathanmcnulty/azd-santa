#!/bin/bash
# Private evaluation only. Keep the running stack pinned to its previous image.
set -euo pipefail
root=/var/lib/azd-santa-qualification
source="$root/source-88e67b3ce49033aab028029937a6e14f7c489073/zentral-88e67b3ce49033aab028029937a6e14f7c489073"
unit=azd-santa-core-stores-build
if systemctl show "$unit" --property=LoadState --value | grep -qv '^not-found$'; then
    echo 'Existing build unit requires observation; refusing another submission.' >&2
    exit 1
fi
printf '%s\n' 'vm.max_map_count=1048576' > /etc/sysctl.d/90-azd-santa-qualification.conf
sysctl -w vm.max_map_count=1048576
python3 "$root/prepare_core_build-stores.py" --source "$source" --output "$source/Dockerfile.core-stores"
systemd-run --unit="$unit" --property=RuntimeMaxSec=1800 --property=TimeoutStopSec=60 \
    docker build --memory=2500m --memory-swap=2500m --build-arg APP_ENV=core \
    --label org.opencontainers.image.revision=88e67b3ce49033aab028029937a6e14f7c489073 \
    --label io.azd-santa.variant=core-experiment \
    --file "$source/Dockerfile.core-stores" \
    --tag azd-santa-zentral-core-eval:88e67b3ce49033aab028029937a6e14f7c489073 "$source"
echo SANTA_CORE_STORES_BUILD_SUBMITTED
