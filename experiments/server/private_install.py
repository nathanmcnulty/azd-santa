"""Original Unlicense one-shot fresh private VM installer, owned by systemd.

Never retry this process against retained state. The controller observes its
same unit after timeout; initialization is not an idempotent resume operation.
"""
import sys
if __name__ == '__main__' and not sys.flags.isolated:
    raise SystemExit('Isolated Python required')
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import types
import urllib.request

ROOT = Path('/var/lib/azd-santa-qualification')
COMPOSE_VERSION = '2.40.3+ds1-0ubuntu1~24.04.1'
DOCKER_VERSION = '29.1.3-0ubuntu3~24.04.2'
COMPOSE_SHA = 'd87a11e944c990dc9f2186115b1136c1cbffffc870845caff0cbdcce0780f41d'
COMPOSE_PLUGIN = Path('/usr/libexec/docker/cli-plugins/docker-compose')
OVERRIDING_PLUGINS = ('/usr/local/lib/docker/cli-plugins/docker-compose',
    '/usr/local/libexec/docker/cli-plugins/docker-compose', '/usr/lib/docker/cli-plugins/docker-compose',
    '/root/.docker/cli-plugins/docker-compose')


def require(value):
    if not value: raise ValueError('Private installer boundary failed')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs): return None


def validate_target(target):
    require(set(target) == {'TenantId', 'SubscriptionId', 'EnvironmentName', 'ResourceGroup', 'VmName', 'VmId', 'VmInstanceId'})
    guid = r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}'
    require(all(re.fullmatch(guid, target[k]) for k in ('TenantId', 'SubscriptionId', 'VmInstanceId')))
    require(re.fullmatch('[a-z0-9-]{2,32}', target['EnvironmentName']) and
            target['ResourceGroup'] == 'rg-azd-santa-vm-' + target['EnvironmentName'] and target['VmName'] == 'vm-santa-lab')
    require(target['VmId'] == '/subscriptions/' + target['SubscriptionId'] + '/resourceGroups/' + target['ResourceGroup'] + '/providers/Microsoft.Compute/virtualMachines/vm-santa-lab')


def write(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as output:
        json.dump(value, output, sort_keys=True); output.flush(); os.fsync(output.fileno())


def verified(context_path, digest):
    path = Path(context_path)
    require(path.is_absolute() and path == path.resolve(strict=True) and path.is_relative_to(ROOT))
    raw = path.read_bytes(); require(hashlib.sha256(raw).hexdigest() == digest)
    context = json.loads(raw); bundle = path.parent
    require(context['scope'] == 'private-azd-install-v1' and bundle.name == context['bundle_sha256'])
    manifest = (bundle / 'bundle.json').read_bytes()
    require(hashlib.sha256(manifest).hexdigest() == context['bundle_sha256'])
    files = json.loads(manifest)['files']
    for name, metadata in files.items():
        require(re.fullmatch(r'[a-zA-Z0-9_-]+\.(?:py|sh|json)', name))
        selected = bundle / name; info = selected.lstat()
        require(selected == selected.resolve(strict=True) and info.st_uid == 0 and not info.st_mode & 0o022)
        require(hashlib.sha256(selected.read_bytes()).hexdigest() == metadata['sha256'])
    return context, bundle


def load(bundle, name):
    path = bundle / (name + '.py')
    module = types.ModuleType(name); module.__file__ = str(path); sys.modules[name] = module
    exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
    return module


def reject_plugin_overrides():
    # Must precede bootstrap: its diagnostics execute `docker compose version`.
    for value in OVERRIDING_PLUGINS:
        path = Path(value)
        require(not path.exists() and not path.is_symlink())
    if COMPOSE_PLUGIN.exists() or COMPOSE_PLUGIN.is_symlink():
        require(COMPOSE_PLUGIN == COMPOSE_PLUGIN.resolve(strict=True) and COMPOSE_PLUGIN.is_file()
                and hashlib.sha256(COMPOSE_PLUGIN.read_bytes()).hexdigest() == COMPOSE_SHA)


def install(context_path, digest):
    require(os.geteuid() == 0 and platform.machine() == 'x86_64')
    os.umask(0o077)
    context, bundle = verified(context_path, digest)
    validate_target(context['target'])
    # Exact immutable guest identity before any package or runtime mutation.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    request = urllib.request.Request('http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01', headers={'Metadata': 'true'})
    with opener.open(request, timeout=3) as response: raw = response.read(65537)
    require(len(raw) <= 65536); metadata = json.loads(raw)
    require(metadata['subscriptionId'].lower() == context['target']['SubscriptionId'] and
            metadata['resourceId'].lower() == context['target']['VmId'].lower() and metadata['vmId'].lower() == context['target']['VmInstanceId'])
    tags = {item['name']: item['value'] for item in metadata['tagsList']}
    require(tags.get('azd-solution') == 'azd-santa' and tags.get('purpose') == 'synthetic-vm-lab' and tags.get('azd-env-name') == context['target']['EnvironmentName'])
    work = ROOT / ('private-runtime-' + context['target']['EnvironmentName'])
    require(not work.exists() and not Path('/etc/systemd/system/azd-santa-runtime.service').exists())
    evidence = bundle / 'install-evidence'; evidence.mkdir(mode=0o700)
    sequence = 0
    environment = {k: v for k, v in os.environ.items() if not k.startswith(('DOCKER_', 'COMPOSE_'))}
    environment['DOCKER_BUILDKIT'] = '0'  # Actual qualified builder lane.
    environment['SANTA_COMPOSE_PACKAGE_VERSION'] = COMPOSE_VERSION
    environment['SANTA_DOCKER_PACKAGE_VERSION'] = DOCKER_VERSION
    docker_config = evidence / 'docker-config'; docker_config.mkdir(mode=0o700)
    environment['DOCKER_CONFIG'] = str(docker_config)  # No inherited extra plugin dirs.
    def run(label, args, timeout=120, cwd=None):
        nonlocal sequence
        sequence += 1
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, env=environment, cwd=cwd)
        write(evidence / f'{sequence:03d}-{label}.json', dict(returncode=result.returncode, stdout=result.stdout, stderr=result.stderr))
        require(result.returncode == 0)
        return result.stdout
    try:
        reject_plugin_overrides()
        run('docker-prerequisites', ['/bin/bash', str(bundle / 'bootstrap-host.sh')], 1000)
        plugin = COMPOSE_PLUGIN
        require(hashlib.sha256(plugin.read_bytes()).hexdigest() == COMPOSE_SHA)
        # Local/root plugins override the distro binary: reject hidden suppliers.
        reject_plugin_overrides()
        require(run('compose-package', ['dpkg-query', '-W', '-f=${Version}', 'docker-compose-v2']).strip() == COMPOSE_VERSION)
        require(run('docker-package', ['dpkg-query', '-W', '-f=${Version}', 'docker.io']).strip() == DOCKER_VERSION)
        plugins = json.loads(run('plugin-supplier', ['docker', 'info', '--format', '{{json .ClientInfo.Plugins}}']))
        selected = [entry for entry in plugins if entry['Name'] == 'compose']
        require(len(selected) == 1 and selected[0]['Path'] == str(plugin))
        run('compose-capability', ['docker', 'compose', 'run', '--help'])
        run('kernel', ['sysctl', '-w', 'vm.max_map_count=1048576'])
        sysctl = Path('/etc/sysctl.d/90-azd-santa-qualification.conf')
        if sysctl.exists(): require(sysctl.read_text() == 'vm.max_map_count=1048576\n')
        else: sysctl.write_text('vm.max_map_count=1048576\n')
        source_module = load(bundle, 'prepare_source')
        source = Path(source_module.prepare(bundle / 'upstream')['source'])
        compiler = load(bundle, 'prepare_core_build')
        compiler.derive_core_dockerfile(source, source / 'Dockerfile.core')
        tag = 'azd-santa-private:' + context['bundle_sha256']
        run('core-build', ['docker', '--host', 'unix:///var/run/docker.sock', 'build', '--file', 'Dockerfile.core',
            '--memory', '2500m', '--memory-swap', '2500m', '--build-arg', 'APP_ENV=core', '--build-arg', 'APP_VERSION=' + source_module.COMMIT,
            '--label', 'org.opencontainers.image.revision=' + source_module.COMMIT, '--label', 'io.azd-santa.variant=core-experiment', '--tag', tag, '.'], 2400, source)
        image = run('built-image-id', ['docker', '--host', 'unix:///var/run/docker.sock', 'image', 'inspect', '--format', '{{.Id}}', tag]).strip()
        require(re.fullmatch('sha256:[a-f0-9]{64}', image))
        locks = json.loads((bundle / 'dependency-images.lock.json').read_text())
        require(set(locks) == {'postgres', 'redis', 'rabbitmq', 'elasticsearch'})
        for name, ref in locks.items():
            require(re.fullmatch('[a-z0-9][a-z0-9./:_-]*@sha256:[a-f0-9]{64}', ref))
            run('pull-' + name, ['docker', '--host', 'unix:///var/run/docker.sock', 'pull', ref], 360)
        load(bundle, 'prepare_zentral_eval'); load(bundle, 'prepare_database_roles')
        stage = load(bundle, 'stage_runtime')
        stage.stage(source, bundle / 'dependency-images.lock.json', work, image)
        compose = work / 'compose.json'; data = json.loads(compose.read_text())
        command = ['docker', '--host', 'unix:///var/run/docker.sock', 'compose', '--project-name', data['name'], '-f', str(compose)]
        # Explicit fresh admission only after the fresh owner/runtime job passed.
        run('fresh-security-store', command + ['run', '--rm', '--no-deps', '--pull', 'never', '--entrypoint', 'python',
            'web', 'server/manage.py', 'operator_security_store', 'fresh'])
        # The supervisor admits existing initialized containers; create the
        # three stopped application containers without starting their listener.
        run('create-app-containers', command + ['create', '--no-build', '--no-recreate', '--pull', 'never', 'web', 'workers', 'celery'])
        load(bundle, 'test_live_zentral')
        runtime = load(bundle, 'runtime_service')
        policies = {name: hashlib.sha256((bundle / file).read_bytes().replace(b'\r\n', b'\n')).hexdigest()
                    for name, file in {'policy': 'operator_mfa.py', 'recovery': 'operator_recovery.py', 'sealed': 'sealed_setup.py'}.items()}
        manifest = runtime.prepare(compose, work / 'runtime-service', policies)
        runtime.install_unit(manifest, hashlib.sha256(manifest.read_bytes()).hexdigest(), enable_now=True)
        run('runtime-active', ['systemctl', 'is-active', 'azd-santa-runtime.service'])
        facts = {**context['target'], 'ImageId': image, 'ComposePath': str(compose),
                 'ComposeSha256': hashlib.sha256(compose.read_bytes()).hexdigest(), 'Origin': 'https://localhost:8000'}
        write(bundle / 'complete.json', dict(scope='private-azd-install-complete', bundle_sha256=context['bundle_sha256'],
              outputs=facts, limitation='Unit ready; client finalizer must verify initialized runtime before operator binding'))
    except BaseException:
        write(bundle / 'failed.json', dict(scope='private-azd-install-failed', step=sequence,
              action='Inspect retained private evidence and same unit; initialization is never replayed'))
        raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--context', required=True); parser.add_argument('--sha256', required=True)
    arguments = parser.parse_args()
    try: install(arguments.context, arguments.sha256)
    except BaseException: raise SystemExit('Private install failed; retained job/data require inspection. Never retry initialization.') from None
