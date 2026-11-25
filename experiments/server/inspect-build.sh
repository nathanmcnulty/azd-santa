#!/bin/bash
# Read-only observation. A failed or missing unit is not an instruction to retry.
set -u
echo SANTA_BUILD_LOG_TAIL
journalctl -u azd-santa-zentral-build -n 12 --no-pager -o cat 2>&1 | tail -c 2000
echo SANTA_CORE_IMAGE_STATE
docker image inspect azd-santa-zentral-core-eval:88e67b3ce49033aab028029937a6e14f7c489073 --format '{{json .Id}} {{json .Config.Labels}}' 2>&1 || true
echo SANTA_HOST_STATE
free -m
df -h /var/lib/docker
echo SANTA_DEPENDENCY_LOCK_STATE
systemctl show azd-santa-dependency-pull --property=ActiveState,SubState,Result,ExecMainStatus,MainPID 2>&1 || true
if test -f /var/lib/azd-santa-qualification/dependency-images.json; then
    cat /var/lib/azd-santa-qualification/dependency-images.json
else
    journalctl -u azd-santa-dependency-pull -n 3 --no-pager -o cat 2>&1
fi
echo SANTA_BUILD_UNIT_STATE
systemctl show azd-santa-zentral-build --property=ActiveState,SubState,Result,ExecMainStatus,MainPID 2>&1 || true
echo SANTA_BUILD_OBSERVATION_COMPLETE
