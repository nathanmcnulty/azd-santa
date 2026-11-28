set -euo pipefail

map_count=$(cat "${1:-/proc/sys/vm/max_map_count}")
if [[ ! "$map_count" =~ ^[1-9][0-9]*$ || "${#map_count}" -gt 10 ]]; then
    echo 'Cannot interpret vm.max_map_count as a positive kernel integer.' >&2
    exit 2
fi

printf 'vm.max_map_count=%s\n' "$map_count"
if (( map_count < 1048576 )); then
    echo 'Elasticsearch probe requires vm.max_map_count >= 1048576.' >&2
    exit 1
fi
