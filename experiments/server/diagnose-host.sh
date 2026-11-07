#!/bin/bash
# Read-only diagnosis of the one synthetic qualification host.
set -u
echo 'QUALIFICATION_PROCESS_STATE'
ps -eo pid,ppid,etime,args | awk '/[a]pt-get|[d]pkg|[d]ocker|[t]imeout/'
echo 'QUALIFICATION_PACKAGE_STATE'
dpkg-query -W docker.io docker-compose-v2 containerd runc ca-certificates 2>&1 || true
dpkg --audit
echo 'QUALIFICATION_STORAGE_STATE'
df -h /
free -m
echo 'QUALIFICATION_DOCKER_STATE'
command -v docker >/dev/null && docker version --format '{{.Server.Version}}' 2>&1 || true
echo SANTA_HOST_DIAGNOSIS_COMPLETE
