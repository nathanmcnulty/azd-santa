#!/bin/bash
# Explicit manual resume for this one private experiment, not product recovery.
set -euo pipefail
root=/var/lib/azd-santa-qualification/runtime-fixed
compose=(docker --host unix:///var/run/docker.sock compose -f "$root/compose-stores.json")
test "$(sysctl -n vm.max_map_count)" = 1048576
"${compose[@]}" config --quiet
timeout 120 "${compose[@]}" up --detach db redis rabbitmq elastic
ready=false
for attempt in {1..60}; do
    if "${compose[@]}" exec -T db pg_isready -U zentral -d zentral >/dev/null 2>&1; then
        ready=true
        break
    fi
    sleep 2
done
test "$ready" = true
"${compose[@]}" run --rm --no-deps --entrypoint python web server/manage.py shell --no-imports -c \
    "import importlib; importlib.import_module('zentral.core.stores.provisioning'); from zentral.core.stores.models import Store; assert Store.objects.count()==1; s=Store.objects.get(provisioning_uid='elasticsearch'); assert s.backend=='ELASTICSEARCH' and s.admin_console"
timeout 120 "${compose[@]}" up --detach --no-deps workers celery
ready=false
for attempt in {1..60}; do
    if "${compose[@]}" exec -T rabbitmq rabbitmqctl list_queues name consumers --formatter json > "$root/resume-queues.json" 2> "$root/resume-queues.stderr" &&
        python3 -c "import json,pathlib; q=json.loads(pathlib.Path('$root/resume-queues.json').read_text()); assert all(any(row['name']==name and row['consumers']>0 for row in q) for name in ('store_events_Elasticsearch','enrich_events','process_events'))"; then
        ready=true
        break
    fi
    sleep 2
done
test "$ready" = true
timeout 120 "${compose[@]}" up --detach --no-deps web
echo SANTA_PRIVATE_MANUAL_RESUME_STARTED
