"""Original Unlicense. Select exact images for independent retention.

Inputs come from authenticated capture evidence, a reviewed dependency lock and
the selected Linux Docker daemon. No Docker, filesystem or network calls here.
"""
import hashlib
import json
import re

from restore_cipher import unique

CORE_SERVICES = frozenset(('web', 'workers', 'celery'))
DEPENDENCIES = {'db': 'postgres', 'redis': 'redis', 'rabbitmq': 'rabbitmq', 'elastic': 'elasticsearch'}
REPOSITORIES = {'postgres': 'postgres', 'redis': 'redis', 'rabbitmq': 'rabbitmq',
                'elasticsearch': 'docker.elastic.co/elasticsearch/elasticsearch'}
HEX = r'[a-f0-9]{64}'
IMAGE_ID = r'sha256:' + HEX


class InventoryRejected(ValueError):
    pass


def need(accepted):
    if not accepted:
        raise InventoryRejected('Santa retention image selection rejected')


def digest_document(raw, expected, maximum):
    need(type(expected) is str and re.fullmatch(HEX, expected))
    need(type(raw) is bytes and 0 < len(raw) <= maximum and hashlib.sha256(raw).hexdigest() == expected)
    parsed = json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: need(False))
    need(type(parsed) is dict)
    return parsed


def registry_reference(name, reference):
    repo = REPOSITORIES[name]
    aliases = (repo, 'docker.io/library/' + repo) if '/' not in repo else (repo,)
    need(type(reference) is str and len(reference) <= 256)
    repository, separator, digest = reference.partition('@')
    need(separator and repository in aliases and re.fullmatch(IMAGE_ID, digest))
    return repo + '@' + digest


def expected_images(compatibility_raw, dependency_lock_raw, *, compatibility_sha256,
                    dependency_lock_sha256, source=None):
    """Select immutable expectations from trusted independent pins."""
    try:
        compatibility = digest_document(compatibility_raw, compatibility_sha256, 1024 * 1024)
        lock = digest_document(dependency_lock_raw, dependency_lock_sha256, 4096)
        need(compatibility['scope'] == 'azd-santa-cold-backup-v1' and set(lock) == set(REPOSITORIES))
        if source is not None:
            target = {'VmId': source.vm_id, 'VmInstanceId': source.instance_id}
            need(compatibility['selection']['target'] == target and
                 all(compatibility['host'][key] == value for key, value in target.items()))
        generation = compatibility['selection']['generation_sha256']
        need(type(generation) is str and re.fullmatch(HEX, generation))
        runtime = compatibility['selection']['runtime_manifest']['sha256']
        commit = compatibility['source_commit']
        need(type(runtime) is str and re.fullmatch(HEX, runtime)
             and type(commit) is str and re.fullmatch(r'[a-f0-9]{40}', commit))
        services = compatibility['images']
        need(type(services) is dict and set(services) == CORE_SERVICES | DEPENDENCIES.keys())
        for item in services.values():
            need(type(item) is dict and set(item) == {'reference', 'id'}
                 and type(item['id']) is str and re.fullmatch(IMAGE_ID, item['id']))

        core = services['web']['id']
        need(all(services[name] == {'id': core, 'reference': core} for name in CORE_SERVICES))
        selection = {'core': {'id': core, 'reference': core, 'services': sorted(CORE_SERVICES)}}
        for service, name in DEPENDENCIES.items():
            image = services[service]
            reference = registry_reference(name, lock[name])
            need(registry_reference(name, image['reference']) == reference)
            selection[name] = {'id': image['id'], 'reference': reference, 'services': [service]}

        need(len({image['id'] for image in selection.values()}) == len(selection))
        return {'scope': 'azd-santa-retention-image-inventory-v1', 'platform': 'linux/amd64',
                'compatibility_sha256': compatibility_sha256, 'dependency_lock_sha256': dependency_lock_sha256,
                'generation_sha256': generation, 'runtime_manifest_sha256': runtime,
                'source_commit': commit, 'images': selection}
    except (ValueError, KeyError, TypeError, RecursionError):
        raise InventoryRejected('Santa retention image selection rejected') from None


def confirm(expected, inspected_by_id):
    """Compare the selected images with one daemon's exact-ID observations."""
    try:
        selection = expected['images']
        selected_ids = {image['id'] for image in selection.values()}
        need(type(inspected_by_id) is dict and set(inspected_by_id) == selected_ids)
        for name, image in selection.items():
            observed = inspected_by_id[image['id']]
            need(type(observed) is dict and observed['Id'] == image['id']
                 and observed['Os'] == 'linux' and observed['Architecture'] == 'amd64'
                 and observed.get('Variant', '') == '')
            if name != 'core':
                digests = observed['RepoDigests']
                reference = image['reference']
                approved = (reference, 'docker.io/library/' + reference) if '/' not in reference else (reference,)
                need(type(digests) is list and len(digests) <= 64 and any(item in approved for item in digests))
        return expected
    except (ValueError, KeyError, TypeError, RecursionError):
        raise InventoryRejected('Santa retention image selection rejected') from None


def select_images(compatibility_raw, dependency_lock_raw, inspected_by_id, *,
                  compatibility_sha256, dependency_lock_sha256):
    """Require all five unique images selected by the seven amd64 services."""
    expected = expected_images(compatibility_raw, dependency_lock_raw, compatibility_sha256=compatibility_sha256,
                               dependency_lock_sha256=dependency_lock_sha256)
    return confirm(expected, inspected_by_id)


def inspect_selected(request_bytes):
    """Read only the five pinned image IDs from the selected VM's local daemon."""
    from blob_retention import SelectedTarget, host_identity
    from cold_backup import command

    digest = hashlib.sha256(request_bytes).hexdigest()
    request = digest_document(request_bytes, digest, 4096)
    need(set(request) == {'source', 'expected'})
    source = SelectedTarget(**request['source'])
    expected = request['expected']
    images = expected['images']
    need(set(images) == {'core', *REPOSITORIES})
    image_ids = [images[name]['id'] for name in sorted(images)]
    need(len(set(image_ids)) == 5 and all(re.fullmatch(IMAGE_ID, value) for value in image_ids))
    host_identity(source)
    raw = command(['/usr/bin/docker', '--host', 'unix:///var/run/docker.sock', 'image', 'inspect', *image_ids],
                  {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}, timeout=25).stdout
    observed = json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: need(False))
    need(type(observed) is list and len(observed) == len(image_ids))
    inventory = confirm(expected, {item['Id']: item for item in observed})
    host_identity(source)
    return {'scope': 'azd-santa-image-inventory-readback-v1', 'batch_sha256': digest,
            'source_vm_instance_id': source.instance_id, 'inventory': inventory}
