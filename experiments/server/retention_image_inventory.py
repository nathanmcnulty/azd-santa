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


def select_images(compatibility_raw, dependency_lock_raw, inspected_by_id, *,
                  compatibility_sha256, dependency_lock_sha256):
    """Require all five unique images selected by the seven amd64 services.

    The caller supplies hashes obtained independently of these inputs. They
    are not self-attestation. Docker inspection values are trusted daemon
    observations, keyed by exact image ID and collected without a tag lookup.
    """
    try:
        compatibility = digest_document(compatibility_raw, compatibility_sha256, 1024 * 1024)
        lock = digest_document(dependency_lock_raw, dependency_lock_sha256, 4096)
        need(compatibility['scope'] == 'azd-santa-cold-backup-v1' and set(lock) == set(REPOSITORIES))
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

        selected_ids = {image['id'] for image in selection.values()}
        need(len(selected_ids) == len(selection) and type(inspected_by_id) is dict
             and set(inspected_by_id) == selected_ids)
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
        return {'scope': 'azd-santa-retention-image-inventory-v1', 'platform': 'linux/amd64',
                'compatibility_sha256': compatibility_sha256, 'dependency_lock_sha256': dependency_lock_sha256,
                'generation_sha256': generation, 'runtime_manifest_sha256': runtime,
                'source_commit': commit, 'images': selection}
    except (ValueError, KeyError, TypeError, RecursionError):
        raise InventoryRejected('Santa retention image selection rejected') from None
