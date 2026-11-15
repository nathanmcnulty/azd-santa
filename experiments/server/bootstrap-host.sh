#!/bin/bash
# Isolated, inbound-denied qualification host only; not a production installer.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
umask 077
install -d -m 0700 /var/lib/azd-santa-qualification
# The Azure mirror stalled on package bodies in the actual lab. Use Canonical's
# HTTPS archive for this invocation only, preserving Signed-By and global config.
source_file=/var/lib/azd-santa-qualification/ubuntu.sources
sed -E 's|https?://azure.archive.ubuntu.com/ubuntu|https://archive.ubuntu.com/ubuntu|g' /etc/apt/sources.list.d/ubuntu.sources > "$source_file"
apt_options=(-o "Dir::Etc::sourcelist=$source_file" -o Dir::Etc::sourceparts=- -o Acquire::Retries=1 -o Acquire::ForceIPv4=true -o Acquire::http::Pipeline-Depth=0 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 -o DPkg::Lock::Timeout=120)
timeout 300 apt-get "${apt_options[@]}" update -q
compose_package=docker-compose-v2
docker_package=docker.io
if [ -n "${SANTA_COMPOSE_PACKAGE_VERSION:-}" ]; then
  compose_package="docker-compose-v2=${SANTA_COMPOSE_PACKAGE_VERSION}"
fi
if [ -n "${SANTA_DOCKER_PACKAGE_VERSION:-}" ]; then
  docker_package="docker.io=${SANTA_DOCKER_PACKAGE_VERSION}"
fi
timeout 600 apt-get "${apt_options[@]}" install -y --no-install-recommends "$docker_package" "$compose_package" ca-certificates
systemctl enable --now docker
# The distribution's daemon uses a local Unix socket, never an unauthenticated TCP API.
docker version --format '{{.Server.Version}}'
docker compose version
dpkg-query -W docker.io docker-compose-v2 ca-certificates
free -b
df -B1 /var/lib/docker
echo SANTA_QUALIFICATION_HOST_READY
