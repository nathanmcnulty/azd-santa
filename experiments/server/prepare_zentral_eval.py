"""Prepare a private, synthetic Zentral evaluation; never enroll a real device.

No network calls or upstream code execution. Full archive provenance and the
source-to-built-image binding remain the caller's responsibility.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import secrets

COMMIT = '88e67b3ce49033aab028029937a6e14f7c489073'
SOURCE_URL = f'https://github.com/zentralopensource/zentral/tree/{COMMIT}'
SOURCE_HASHES = {
    'Dockerfile': 'dd06e76e0b325684c0c07734cfb1b951218678fb454b8af18e719f309c2e94e1',
    'LICENSE': '00f43b4775da6dcbe63d20b3b2c36e616f35af5595d02c590278e75d9d86793c',
    'conf/start/zentral/base.json': 'ffd5c071c63d15ca5c529d522855345de814e8473f493eb973d2487aa7c44c2a',
}
DEPENDENCIES = ('postgres', 'redis', 'rabbitmq', 'elasticsearch')
DIGEST_REF = re.compile(r'[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}')
IMAGE_ID = re.compile(r'sha256:[0-9a-f]{64}')


def write_new(path, value, mode=0o600):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(descriptor, 'w', encoding='utf-8', newline='\n') as stream:
        stream.write(value)


def json_text(value):
    return json.dumps(value, indent=2, sort_keys=True) + '\n'


def prepare(source, image, lock, destination):
    source = Path(source).resolve(strict=True)
    if not source.is_dir() or not IMAGE_ID.fullmatch(image):
        raise ValueError('A source directory and local sha256 image ID are required')
    if not isinstance(lock, dict) or set(lock) != set(DEPENDENCIES):
        raise ValueError('Image lock must contain exactly the four dependency names')
    if any(not isinstance(ref, str) or not DIGEST_REF.fullmatch(ref)
           for ref in lock.values()):
        raise ValueError('Every dependency must have a digest-pinned image reference')
    for name, expected in SOURCE_HASHES.items():
        path = source / name
        if path.is_symlink() or not path.resolve().is_relative_to(source):
            raise ValueError('Source input escapes its root')
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError('Pinned source input differs: ' + name)
    config = copy.deepcopy(json.loads((source / 'conf/start/zentral/base.json').read_text(encoding='utf-8')))
    config['api'] = {'fqdn': 'localhost:8000',
                     'metrics_bearer_token': '{{ env:ZENTRAL_METRICS_TOKEN }}'}
    config['extra_links'] = []
    config['django'].update({
        'DEBUG': False, 'STATIC_WHITENOISE': True,
        'ALLOWED_HOSTS': ['localhost', '127.0.0.1'],
        'SECRET_KEY': '{{ env:ZENTRAL_DJANGO_SECRET }}',
        'POSTGRES_HOST': 'db', 'POSTGRES_NAME': 'zentral',
        'POSTGRES_USER': 'zentral', 'POSTGRES_PASSWORD': '{{ env:POSTGRES_PASSWORD }}',
        'CELERY_BROKER_URL': '{{ env:ZENTRAL_QUEUE_URL }}',
    })
    config['queues'] = {'backend': 'zentral.core.queues.backends.kombu',
                        'backend_url': '{{ env:ZENTRAL_QUEUE_URL }}'}
    # Keep the upstream supported Redis cache, notifications and ES store. This
    # deliberately does not invent a DB-backed queue or silently drop telemetry.
    config['notifier'] = {'url': 'redis://redis:6379/15'}
    config['apps']['zentral.core.stores']['provisioning']['stores']['elasticsearch']['elasticsearch_kwargs']['hosts'] = ['http://elastic:9200']
    rabbit_password = secrets.token_urlsafe(36)
    runtime = {
        'POSTGRES_DB': 'zentral', 'POSTGRES_USER': 'zentral',
        'POSTGRES_PASSWORD': secrets.token_urlsafe(48),
        'POSTGRES_HOST': 'db', 'ZENTRAL_DJANGO_SECRET': secrets.token_urlsafe(64),
        'ZENTRAL_METRICS_TOKEN': secrets.token_urlsafe(48),
        'RABBITMQ_DEFAULT_USER': 'zentral', 'RABBITMQ_DEFAULT_PASS': rabbit_password,
        'ZENTRAL_QUEUE_URL': f'amqp://zentral:{rabbit_password}@rabbitmq:5672//',
    }
    logging = {'driver': 'json-file', 'options': {'max-size': '10m', 'max-file': '3'}}

    def service(ref, memory):
        return {'image': ref, 'pull_policy': 'never' if ref == image else 'missing',
                'restart': 'no', 'mem_limit': memory, 'logging': copy.deepcopy(logging),
                'security_opt': ['no-new-privileges:true']}

    services = {
        'db': {**service(lock['postgres'], '384m'), 'env_file': ['./runtime.env'],
               'volumes': ['postgres_data:/var/lib/postgresql']},
        'redis': service(lock['redis'], '128m'),
        'rabbitmq': {**service(lock['rabbitmq'], '320m'), 'hostname': 'rabbitmq',
                     'env_file': ['./runtime.env'],
                     'volumes': ['rabbitmq_data:/var/lib/rabbitmq']},
        'elastic': {**service(lock['elasticsearch'], '896m'),
                    'environment': {'ES_JAVA_OPTS': '-Xms256m -Xmx256m',
                                    'discovery.type': 'single-node',
                                    'xpack.security.enabled': 'false'},
                    'volumes': ['elasticsearch_data:/usr/share/elasticsearch/data']},
    }
    for name, command, memory in (
            ('web', ['gunicorn', '--bind', '0.0.0.0:8000', '--workers', '1', '--threads', '2'], '512m'),
            ('workers', ['runworkers'], '640m'),
            ('celery', ['celery', '--concurrency', '1'], '384m')):
        services[name] = {
            **service(image, memory), 'command': command,
            'env_file': ['./runtime.env'],
            'environment': {'ZENTRAL_CONF_DIR': '/zentral-eval-conf'},
            'volumes': ['./conf:/zentral-eval-conf:ro', 'media_data:/var/zentral'],
            'depends_on': ['db', 'redis', 'rabbitmq', 'elastic'],
        }
    services['web']['ports'] = ['127.0.0.1:8000:8000']
    compose = {'name': 'santa-zentral-eval-' + secrets.token_hex(6), 'services': services,
               'volumes': {name: {} for name in (
                   'postgres_data', 'rabbitmq_data', 'elasticsearch_data', 'media_data')}}
    # Atomic reservation before any output. Failed preparation leaves evidence;
    # callers must inspect it and choose a new destination rather than retry over it.
    destination = Path(destination).absolute()
    destination.mkdir(mode=0o700)
    (destination / 'conf').mkdir(mode=0o755)
    # Docker's non-root Zentral user must read this secret-free configuration,
    # even when the invoking root bootstrap uses umask 077.
    (destination / 'conf').chmod(0o755)
    write_new(destination / 'conf/base.json', json_text(config), 0o644)
    (destination / 'conf/base.json').chmod(0o644)
    write_new(destination / 'runtime.env', ''.join(f'{key}={value}\n' for key, value in runtime.items()))
    write_new(destination / 'compose.json', json_text(compose))
    write_new(destination / 'LICENSE.upstream', (source / 'LICENSE').read_text(encoding='utf-8'))
    write_new(destination / 'provenance.json', json_text({
        'scope': 'synthetic-loopback-evaluation-only', 'upstream_commit': COMMIT,
        'upstream_source': SOURCE_URL, 'checked_source_files': SOURCE_HASHES,
        'local_image_id': image, 'dependency_images': lock,
        'limitations': ['Not a core-only image or production license clearance',
                        'Caller must verify full source archive and build binding',
                        'Memory caps are test constraints, not proven sizing',
                        'No real device enrollment, public TLS or device authentication'],
    }))
    write_new(destination / 'EVALUATION-ONLY.txt',
              f'Private synthetic Zentral evaluation only. Source: {SOURCE_URL}\n'
              'The upstream image includes ee/ under its evaluation license.\n'
              'Do not publish this image or treat it as a core-only production package.\n'
              'No real devices, public ingress or production credentials.\n'
              'HTTP is loopback-only; generated payload HTTPS URLs are not qualified.\n'
              'Keep upstream license and notices; consult upstream terms before further use.\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True)
    parser.add_argument('--image', required=True)
    parser.add_argument('--lock', required=True)
    parser.add_argument('--destination', required=True)
    args = parser.parse_args()
    with open(args.lock, encoding='utf-8') as stream:
        lock = json.load(stream)
    prepare(args.source, args.image, lock, args.destination)
    print('Prepared private synthetic evaluation; no service started.')


if __name__ == '__main__':
    main()
