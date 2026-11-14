"""Prepare a fresh Santa-only developer qualification, never switch deployments.

Preparation has no Docker/network side effects. The explicit check-runtime mode
only reads the selected new runtime; neither mode starts/stops/recreates services.
Original Unlicense tooling; not a customer migration or deployment flow.
"""
import argparse
import hashlib
import json
from pathlib import Path

from prepare_zentral_eval import COMMIT, prepare, write_new, json_text
from resume_runtime import validate_selection
from test_live_zentral import MARKER, orm, require, validate_compose

APPS = ('accounts', 'realms', 'zentral.core.compliance_checks',
        'zentral.core.incidents', 'zentral.core.probes', 'zentral.core.stores',
        'zentral.core.terraform', 'zentral.contrib.inventory', 'zentral.contrib.santa')
SERVICES = {'postgres': 'db', 'redis': 'redis', 'rabbitmq': 'rabbitmq', 'elasticsearch': 'elastic'}
VOLUMES = {'postgres_data', 'rabbitmq_data', 'elasticsearch_data', 'media_data'}
OPTIONAL_VOLUMES = {'redis_data', 'elasticsearch_snapshots'}
GATES = ('image_and_source_binding', 'new_docker_namespace_absent_before_start',
         'old_database_receipt_before_authorized_pause', 'migration_provision_and_profile_readback',
         'required_queue_consumers_and_stable_workers', 'operator_mfa_requests',
         'security_cache_durability_and_explicit_initialization',
         'recovery_and_authenticated_empty_santa_ui', 'full_loopback_sync_database_receipts',
         'indexed_events_and_admin_search', 'bounded_request_http', 'resource_measurement')


def local_volumes(data):
    volumes = data.get('volumes')
    require(isinstance(volumes, dict) and VOLUMES <= set(volumes) <= VOLUMES | OPTIONAL_VOLUMES
            and all(value == {} for value in volumes.values()), 'Only project-local generated volumes are supported')
    return set(volumes)


def prepare_fresh(source, previous_compose, previous_fixture, previous_project, image, destination):
    old, old_hash = validate_selection(previous_compose, previous_fixture, image)
    old_data = json.loads(old.read_text(encoding='utf-8'))
    require(old_data['name'] == previous_project, 'Explicit previous project does not match its Compose binding')
    local_volumes(old_data)
    requested = Path(destination).absolute()
    if requested.exists() or requested.is_symlink():
        raise FileExistsError('Fresh destination must be absent; inspect retained evidence')
    destination = requested.resolve()
    require(not destination.is_relative_to(old.parent) and not old.parent.is_relative_to(destination),
            'New qualification must be a separate sibling directory, not replace/nest the selected runtime')
    lock = {key: old_data['services'][service]['image'] for key, service in SERVICES.items()}
    prepare(source, image, lock, destination, 'core-experiment', app_profile='santa')
    new, new_hash = validate_compose(destination / 'compose.json')
    new_data = json.loads(new.read_text())
    require(new_data['name'] != previous_project, 'Fresh project name collision; inspect retained preparation')
    volumes = local_volumes(new_data)
    require(all(new_data['services'][key]['image'] == old_data['services'][key]['image']
                for key in old_data['services']), 'Profile comparison must retain exact application/dependency images')
    fixture = Path(previous_fixture).resolve(strict=True)
    plan = dict(scope='fresh-santa-profile-qualification-plan', commit=COMMIT,
        previous=dict(compose=str(old), compose_sha256=old_hash, fixture=str(fixture),
                      fixture_sha256=hashlib.sha256(fixture.read_bytes()).hexdigest(), project=previous_project),
        candidate=dict(compose=str(new), compose_sha256=new_hash, project=new_data['name'], image=image,
                       config_sha256=hashlib.sha256((destination / 'conf/base.json').read_bytes()).hexdigest(),
                       docker_volumes=sorted(new_data['name'] + '_' + name for name in volumes)),
        expected_apps=list(APPS), runtime_gates={gate: 'not_run' for gate in GATES},
        transition_authorization='Not granted by preparation; separately authorize pausing the exact previous project',
        limitation='No runtime, resource savings, production migration, browser/TLS or native Mac proof')
    path = destination / 'fresh-profile-plan.json'
    write_new(path, json_text(plan))
    return path


def check_runtime(plan_path):
    path = Path(plan_path).resolve(strict=True)
    plan = json.loads(path.read_text(encoding='utf-8'))
    require(plan.get('scope') == 'fresh-santa-profile-qualification-plan' and plan.get('commit') == COMMIT,
            'Unrecognized qualification plan')
    candidate = plan['candidate']
    compose, digest = validate_compose(candidate['compose'])
    require(compose.parent == path.parent and digest == candidate['compose_sha256'], 'Candidate Compose binding changed')
    data = json.loads(compose.read_text())
    require(data['name'] == candidate['project'] and data['name'] != plan['previous']['project'], 'Candidate project binding changed')
    require(all(data['services'][key]['image'] == candidate['image'] for key in ('web', 'workers', 'celery')),
            'Candidate application image changed')
    require(hashlib.sha256((path.parent / 'conf/base.json').read_bytes()).hexdigest() == candidate['config_sha256'],
            'Candidate profile configuration changed')
    receipt = path.parent / 'fresh-profile-runtime.json'
    if receipt.exists() or receipt.is_symlink():
        raise FileExistsError('Existing profile readback requires inspection')
    code = '''
from django.apps import apps
from django.db.migrations.recorder import MigrationRecorder
from zentral.conf import settings as central
from zentral.core.stores.models import Store
from accounts.models import User
expected = ''' + repr(APPS) + '''
configured = sorted(central['apps'])
need(configured == sorted(expected))
need(all(apps.is_installed(name) for name in expected))
applied = set(MigrationRecorder.Migration.objects.values_list('app', flat=True))
need(set(name.rsplit('.', 1)[-1] for name in expected) <= applied)
need(not applied.intersection({'jamf', 'munki', 'osquery', 'turbo'}))
need(Configuration.objects.count() == 0 and EnrolledMachine.objects.count() == 0)
need(User.objects.filter(is_service_account=False).count() == 0)
need(Store.objects.count() == 1)
store = Store.objects.get(provisioning_uid='elasticsearch')
need(store.backend == 'ELASTICSEARCH' and store.admin_console)
print(''' + repr(MARKER) + ''' + json.dumps(dict(apps=configured, applied_migration_apps=sorted(applied),
    empty_human_configuration_device_projection=True, provisioned_admin_store='ELASTICSEARCH')))
'''
    result = orm(compose, code)
    applied = result.get('applied_migration_apps')
    require(result.get('apps') == sorted(APPS) and result.get('empty_human_configuration_device_projection') is True
            and result.get('provisioned_admin_store') == 'ELASTICSEARCH'
            and isinstance(applied, list) and all(isinstance(name, str) for name in applied)
            and {name.rsplit('.', 1)[-1] for name in APPS} <= set(applied)
            and not set(applied).intersection({'jamf', 'munki', 'osquery', 'turbo'}),
            'Incomplete fresh-profile runtime readback')
    write_new(receipt, json_text(dict(scope='fresh-santa-profile-runtime-readback', compose_sha256=digest,
        result=result, limitation='Selected app/migration/data/store projection only; consumers, UI, sync and index gates remain separate')))
    return receipt


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    fresh = commands.add_parser('prepare')
    for name in ('source', 'previous-compose', 'previous-fixture', 'previous-project', 'image', 'destination'):
        fresh.add_argument('--' + name, required=True)
    check = commands.add_parser('check-runtime')
    check.add_argument('--plan', required=True)
    args = parser.parse_args()
    if args.command == 'prepare':
        output = prepare_fresh(args.source, args.previous_compose, args.previous_fixture,
                               args.previous_project, args.image, args.destination)
        print('SANTA_FRESH_PROFILE_PREPARED_NOT_STARTED ' + str(output))
    else:
        output = check_runtime(args.plan)
        print('SANTA_FRESH_PROFILE_READBACK_ONLY ' + str(output))
