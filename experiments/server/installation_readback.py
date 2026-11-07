"""Original Unlicense read-only installer finalization, never a setup mutation.

Called inline with the exact hash-bound host attestor. No imports from mutable
host checkout files, no schema provisioning, account creation or marker repair.
"""
import json
import os
import re
import signal

MARKER = 'SANTA_INSTALLATION_JSON:'
READY = {'database_authority', 'migrations', 'store', 'security_store', 'sync_admission', 'event_consumers', 'search'}
PROBE = '''
import json,urllib.request
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from zentral.core.stores.models import Store
from azd_santa_database_roles import check_runtime
check_runtime()
executor=MigrationExecutor(connection)
assert not executor.migration_plan(executor.loader.graph.leaf_nodes())
assert Store.objects.count()==1
store=Store.objects.get(provisioning_uid='elasticsearch')
assert store.backend=='ELASTICSEARCH' and store.admin_console
assert store.backend_kwargs.get('hosts')==['http://elastic:9200']
queue=('store_events_'+store.name).replace(' ','_')
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs): return None
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
with opener.open('http://elastic:9200/_cluster/health?wait_for_status=yellow&timeout=5s',timeout=8) as r:
 data=r.read(65537)
assert len(data)<=65536
health=json.loads(data)
assert health['timed_out'] is False and health['status'] in ('yellow','green') and type(health['number_of_nodes']) is int and health['number_of_nodes']==1
print('SANTA_INSTALL_READY:'+json.dumps({'queue':queue,'database_authority':True,'migrations':True,'store':True,'search':True}))
'''


def produce_installation(host, deployment_id, attestor_sha256, producer_sha256):
    host.need(os.geteuid() == 0)
    def deadline(*args):
        raise TimeoutError('Read-only installation verification exceeded its budget')
    signal.signal(signal.SIGALRM, deadline); signal.alarm(150)
    request, _ = host.request_from_environment()
    binding = request['context']['binding']
    prefix = '/subscriptions/' + binding['SubscriptionId'] + '/'
    suffix = 'providers/Microsoft.Resources/deployments/[A-Za-z0-9_.()-]{1,64}'
    host.need(re.fullmatch(re.escape(prefix) + '(?:resourceGroups/' + re.escape(binding['ResourceGroup']) + '/)?' + suffix, deployment_id))
    host.need(all(host.HEX.fullmatch(v) for v in (attestor_sha256, producer_sha256)))
    host.attest_metadata(binding)
    services = host.attest_runtime(request)
    host.need(set(services) == {'web', 'workers', 'celery', 'db', 'redis', 'rabbitmq', 'elastic'}
              and all(re.fullmatch('[a-f0-9]{64}', v) for v in services.values()))
    # Reuse exact already-inspected container IDs; never re-resolve a service
    # between attestation and readiness, and never start/restart a container.
    raw = host.docker(['exec', services['web'], 'python', 'server/manage.py', 'shell', '--no-imports', '-c', PROBE], timeout=35)
    records = [line[len('SANTA_INSTALL_READY:'):] for line in raw.decode().splitlines() if line.startswith('SANTA_INSTALL_READY:')]
    host.need(len(records) == 1)
    projection = host.loads(records[0])
    host.need(set(projection) == {'queue', 'database_authority', 'migrations', 'store', 'search'}
              and all(projection[k] is True for k in ('database_authority', 'migrations', 'store', 'search'))
              and re.fullmatch('[A-Za-z0-9_.-]{1,128}', projection['queue']))
    queues = host.loads(host.docker(['exec', services['rabbitmq'], 'rabbitmqctl', 'list_queues', 'name', 'consumers', '--formatter', 'json'], timeout=20))
    host.need(type(queues) is list and len(queues) <= 1024)
    names = {}
    for row in queues:
        host.need(type(row) is dict and set(row) == {'name', 'consumers'} and type(row['name']) is str
                  and type(row['consumers']) is int and row['consumers'] >= 0 and row['name'] not in names)
        names[row['name']] = row['consumers']
    host.need(all(names.get(name, 0) > 0 for name in (projection['queue'], 'enrich_events', 'process_events')))
    outputs = {k: v for k, v in binding.items() if k not in ('SourceCommit', 'AdmissionSha256', 'RecoverySha256', 'SealedSha256', 'RemoteProgramSha256')}
    receipt = dict(schemaVersion=1, scope='azd-santa-backend-installation', state='installed', deploymentId=deployment_id, outputs=outputs)
    result = dict(scope='azd-santa-installation-readback', context_sha256=request['context_sha256'],
                  attestor_sha256=attestor_sha256, producer_sha256=producer_sha256,
                  readiness={k: True for k in sorted(READY)}, installation=receipt)
    raw = host.encoded(result)
    host.need(len(raw) <= 3200)
    print(MARKER + raw.decode('ascii'))
    return result
