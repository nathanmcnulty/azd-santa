"""Original Unlicense fresh isolated DB fixture + restricted Recovery13 requests.

Explicit qualification job, never normal startup. No retry after unknown setup,
request, or teardown outcome. No normal service receives migration.env.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import uuid

from stage_runtime import require_host, private_file, private_directory, write_private, DOCKER
from test_live_zentral import validate_compose
from database_roles import runtime_file, BOOTSTRAP, RUNTIME
from run_operator_mfa_tests import run as requests, test_count


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(compose_path, harness, destination, image, policy_sha256, recovery_sha256):
    require_host()
    compose, compose_sha = validate_compose(private_file(compose_path))
    data = json.loads(compose.read_text())
    if (not re.fullmatch(r'sha256:[a-f0-9]{64}', image)
            or any(data['services'][name]['image'] != image for name in ('web', 'workers', 'celery'))
            or any(not re.fullmatch(r'[a-f0-9]{64}', value) for value in (policy_sha256, recovery_sha256))):
        raise ValueError('Explicit immutable app image and source hashes required')
    # Exact fresh split contract, no legacy shared-secret environment accepted.
    if any(data['services'][name].get('env_file') != ['./runtime.env'] for name in ('web', 'workers', 'celery')):
        raise ValueError('Restricted runtime env declaration required')
    if any(data['services'][name].get('environment') != {'ZENTRAL_CONF_DIR': '/zentral-eval-conf'} for name in ('web', 'workers', 'celery')):
        raise ValueError('Unexpected app environment override')
    runtime = runtime_file(compose.parent / 'runtime.env')
    owner_path = private_file(compose.parent / 'migration.env')
    owner = dict(line.split('=', 1) for line in owner_path.read_text().splitlines())
    if (set(owner) != set(runtime) or owner.get('POSTGRES_USER') != BOOTSTRAP or owner.get('POSTGRES_PASSWORD') == runtime['POSTGRES_PASSWORD']
            or {k: v for k, v in owner.items() if k not in ('POSTGRES_USER', 'POSTGRES_PASSWORD')} !=
               {k: v for k, v in runtime.items() if k not in ('POSTGRES_USER', 'POSTGRES_PASSWORD')}):
        raise ValueError('Owner-only migration environment required')
    harness = Path(harness).resolve(strict=True)
    if test_count(harness.read_text()) != 13:
        raise ValueError('Expected complete Recovery13 harness')
    source = Path(__file__).with_name('recovery_database_fixture.py').resolve(strict=True)
    destination = Path(destination).absolute()
    private_directory(destination.parent)
    destination.mkdir(mode=0o700)
    job = destination / 'fixture'
    job.mkdir(mode=0o755)
    job.chmod(0o755)
    conf = json.loads((compose.parent / 'conf/base.json').read_text())
    if conf['django']['POSTGRES_NAME'] != 'zentral':
        raise ValueError('Expected selected main runtime configuration')
    name = 'azd_recovery_' + uuid.uuid4().hex[:24]
    conf['django']['POSTGRES_NAME'] = name
    # This copy is secret-free; credentials still resolve from each job's env.
    for path, raw in ((job / 'base.json', json.dumps(conf).encode()),
                      (job / source.name, source.read_bytes())):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        os.chmod(path, 0o644)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    binding = dict(scope='restricted-runtime-recovery-fixture', database=name, image=image,
        compose_sha256=compose_sha, config_sha256=digest(job / 'base.json'),
        runtime_env_sha256=digest(compose.parent / 'runtime.env'), owner_env_sha256=digest(owner_path),
        harness_sha256=digest(harness), fixture_sha256=digest(source),
        policy_sha256=policy_sha256, recovery_sha256=recovery_sha256)
    fd = os.open(job / 'binding.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    (job / 'binding.json').chmod(0o644)
    with os.fdopen(fd, 'w') as stream:
        json.dump(binding, stream); stream.flush(); os.fsync(stream.fileno())
    environment = {k: v for k, v in os.environ.items() if not k.startswith(('DOCKER_', 'COMPOSE_'))}
    environment['DOCKER_CONFIG'] = str(destination / 'docker-config')
    Path(environment['DOCKER_CONFIG']).mkdir(mode=0o700)
    command = DOCKER + ['compose', '--project-name', data['name'], '-f', str(compose)]
    def unchanged():
        paths = {'compose_sha256': compose, 'config_sha256': job / 'base.json',
                 'runtime_env_sha256': compose.parent / 'runtime.env', 'owner_env_sha256': owner_path,
                 'harness_sha256': harness, 'fixture_sha256': job / source.name}
        if any(digest(path) != binding[key] for key, path in paths.items()):
            raise RuntimeError('Selected source/config/environment changed; retain fixture')

    def owner_job(action):
        unchanged()
        # Reserve unknown-outcome evidence BEFORE each potential mutation.
        write_private(destination / (action + '-attempt.json'), dict(binding=binding, state='unknown-until-terminal'))
        code = ("import hashlib,types,sys; from pathlib import Path; "
            "p=Path('/run/azd-recovery-conf/recovery_database_fixture.py'); "
            f"assert hashlib.sha256(p.read_bytes()).hexdigest()=={binding['fixture_sha256']!r}; "
            f"assert hashlib.sha256(Path('/zentral/server/azd_santa_operator.py').read_bytes()).hexdigest()=={policy_sha256!r}; "
            f"assert hashlib.sha256(Path('/zentral/server/azd_santa_operator_recovery.py').read_bytes()).hexdigest()=={recovery_sha256!r}; "
            "m=types.ModuleType('azd_recovery_fixture'); m.__file__=str(p); sys.modules[m.__name__]=m; "
            "exec(compile(p.read_bytes(),str(p),'exec'),m.__dict__); "
            f"m.{action}('/run/azd-recovery-conf/" + ('binding.json' if action == 'initialize' else 'fixture.json') + "')")
        args = command + ['run', '--rm', '--no-deps', '--pull', 'never',
            '--name', 'santa-recovery-' + action + '-' + uuid.uuid4().hex,
            '--user', '0', '--env-from-file', str(owner_path),
            '--env', 'ZENTRAL_CONF_DIR=/run/azd-recovery-conf',
            '--volume', str(job) + ':/run/azd-recovery-conf:rw',
            '--entrypoint', 'python', 'web', 'server/manage.py', 'shell', '--no-imports', '-c', code]
        try:
            result = subprocess.run(args, capture_output=True, text=True, env=environment, timeout=600)
        except subprocess.TimeoutExpired as error:
            write_private(destination / (action + '-timeout.json'), dict(stdout=str(error.stdout), stderr=str(error.stderr)))
            raise RuntimeError('Unknown owner job outcome; preserve fixture and inspect privately') from None
        write_private(destination / (action + '-process.json'), dict(returncode=result.returncode, stdout=result.stdout, stderr=result.stderr))
        if result.returncode:
            raise RuntimeError('Owner fixture job failed; no retry or teardown; inspect private state')

    owner_job('initialize')
    fixture = json.loads((job / 'fixture.json').read_text())
    if fixture.get('binding') != binding or fixture.get('owner') != BOOTSTRAP or type(fixture.get('database_oid')) is not int or not 0 < fixture['database_oid'] < 2**32:
        raise RuntimeError('Owner fixture completion binding mismatch')
    # Runtime path has neither --env-from-file nor owner mounts. Even failed
    # known-terminal request runs are retained; teardown only follows acceptance.
    unchanged()
    result = requests(compose, harness, destination / 'requests', policy_sha256, recovery_sha256, job)
    if (digest(compose) != compose_sha or digest(owner_path) != binding['owner_env_sha256']
            or digest(compose.parent / 'runtime.env') != binding['runtime_env_sha256']):
        raise RuntimeError('Selected state changed; retain isolated fixture')
    owner_job('teardown')
    write_private(destination / 'receipt.json', dict(scope='restricted-runtime-recovery-fixture-complete',
        binding=binding, database_oid=fixture['database_oid'], requests=result, teardown='exact-name-oid-no-active-backends'))
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('compose', 'harness', 'destination', 'image', 'policy-sha256', 'recovery-sha256'):
        parser.add_argument('--' + key, required=True)
    args = parser.parse_args()
    run(args.compose, args.harness, args.destination, args.image, args.policy_sha256, args.recovery_sha256)
