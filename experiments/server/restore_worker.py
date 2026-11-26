"""Run the signed recovery command in a disposable network-isolated Zentral worker."""

import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from tempfile import TemporaryDirectory
import uuid

import blob_retention as blob
import restore_database_command as database
from restore_guest_readback import SCOPE as GUEST_SCOPE
from restore_packet_operator import CARRIER_ROOT, delivery_binding
from restore_quarantine_journal import is_digest
from restore_sealed_inputs import RECIPIENT_ROOT, check_offer, operation, sha
from restore_tooling_bundle import MAX_BUNDLE, WORKER_SCOPES, stage
from retained_image_delivery import read_at, write_at
from retained_image_handoff import boot, decode
from retained_image_load import RecoveryDocker
from retained_image_parts import checked_document

DOCKER = ('/usr/bin/docker', '--host', 'unix:///var/run/docker.sock')
WORKER_SOCKET = '/probe-socket'
WORKER_JOURNAL = '/restore-journal'
TOOLS = '/restore-tools'
SERVER = TOOLS + '/experiments/server'
HOST_RECEIPT = TOOLS + '/host.json'
MAX_OUTPUT = 4096
TIMEOUT = 165


def private_directory(path):
    with ExitStack() as guards:
        fd, _ = blob.parent(path / 'check', guards)
        blob.need(stat.S_IMODE(os.fstat(fd).st_mode) == 0o700)
    return path


def mount(path, destination, *, readonly=True):
    source = str(path)
    blob.need(re.fullmatch(r'/[a-zA-Z0-9_./-]+', source) is not None)
    access = ',readonly' if readonly else ''
    return ['--mount', f'type=bind,source={source},target={destination}{access}']


def socket_group(path):
    folder = path.lstat()
    blob.need(stat.S_ISDIR(folder.st_mode) and stat.S_IMODE(folder.st_mode) == 0o750 and folder.st_gid > 0)
    endpoint = (path / '.s.PGSQL.5432').lstat()
    blob.need(stat.S_ISSOCK(endpoint.st_mode) and stat.S_IMODE(endpoint.st_mode) == 0o770
              and endpoint.st_gid == folder.st_gid)
    return str(folder.st_gid)


def arguments(name, image, tools, recipient, workspace, request, job, config_sha256, *, carrier_root, application):
    result = ['run', '--rm', '--interactive', '--name', name, '--network', 'none', '--pull', 'never',
              '--user', '0:0', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
              '--log-driver', 'none', '--memory', '512m', '--cpus', '1', '--pids-limit', '96',
              '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=48m']
    result.extend(mount(tools, TOOLS))
    action = request['action']
    if action != 'preview':
        result.extend(mount(recipient, str(RECIPIENT_ROOT), readonly=False))
    command = [SERVER + '/restore_database_command.py', '--host-receipt', HOST_RECEIPT]
    if action in ('apply', 'preview'):
        blob.need(job.target.socket_dir == WORKER_SOCKET and is_digest(config_sha256))
        result.extend(mount(application, '/zentral'))
        config = workspace / 'base.json'
        with ExitStack() as guards:
            folder, name = blob.parent(config, guards)
            blob.need(sha(read_at(folder, name, 65536)) == config_sha256)
        result.extend(mount(config, '/restore-conf/base.json'))
        socket = workspace / 'socket'
        result.extend(['--group-add', socket_group(socket)])
        result.extend(mount(socket, WORKER_SOCKET))
        result.extend(mount(private_directory(workspace / 'journal'), WORKER_JOURNAL, readonly=action == 'preview'))
        if action == 'apply':
            capsule, _, _ = delivery_binding(job, request['plan'], request['plan_sha256'], request['receipt'])
            result.extend(mount(private_directory(carrier_root / capsule), str(CARRIER_ROOT / capsule)))
        else:
            command.append('--local-preview')
        result.extend(['--env', 'ZENTRAL_CONF_DIR=/restore-conf',
                       '--env', 'DJANGO_SETTINGS_MODULE=restore_worker_settings',
                       '--env', 'PYTHONPATH=' + SERVER + ':/zentral:/zentral/server',
                       '--env', 'ZENTRAL_QUIET=1', '--env', 'AZD_SANTA_SECURITY_STORE_ID=' + config_sha256,
                       '--env', 'PGOPTIONS=-c session_preload_libraries= -c local_preload_libraries='])
        command += ['--journal-directory', WORKER_JOURNAL]
    else:
        blob.need(config_sha256 is None)
    return result + ['--entrypoint', 'python', image, '-B', *command]


def check_worker_image(raw, image):
    blob.need(0 < len(raw) <= 1024 * 1024)
    results = json.loads(raw, object_pairs_hook=blob.unique)
    blob.need(type(results) is list and len(results) == 1 and type(results[0]) is dict)
    inspected = results[0]
    config = inspected.get('Config')
    blob.need(inspected.get('Id') == image and inspected.get('Os') == 'linux'
              and inspected.get('Architecture') == 'amd64' and type(config) is dict
              and config.get('Volumes') in (None, {}))


def stage_application(call, image, container, application):
    """Copy the pinned app tree from an unstarted container into private staging."""
    application.mkdir(mode=0o700)
    created = False
    try:
        call(['create', '--name', container, '--network', 'none', '--pull', 'never', '--read-only',
              '--entrypoint', '/bin/false', image], stdout=subprocess.DEVNULL, check=True, timeout=15)
        created = True
        call(['cp', f'{container}:/zentral/.', str(application)],
             stdout=subprocess.DEVNULL, check=True, timeout=45)
    finally:
        call(['rm', '--force', '--volumes', container], stdout=subprocess.DEVNULL, check=created, timeout=15)
    private_directory(application)
    settings = application / 'server' / 'server' / 'settings.py'
    info = settings.lstat()
    blob.need(settings.resolve(strict=True) == settings and stat.S_ISREG(info.st_mode)
              and info.st_uid == os.geteuid() and not info.st_mode & 0o022)


def checked_reply(raw_reply, raw, request, job):
    blob.need(0 < len(raw_reply) <= MAX_OUTPUT and raw_reply.endswith(b'\n'))
    reply = checked_document(raw_reply[:-1], sha(raw_reply[:-1]), MAX_OUTPUT)
    step = request['step']
    common = {'scope', 'request_sha256', 'stage', 'state'}
    action = request['action']
    scope = database.PREVIEW_SCOPE if action == 'preview' else database.SCOPE
    blob.need(reply['scope'] == scope and reply['request_sha256'] == sha(raw) and reply['stage'] == step['stage'])
    if action == 'preview':
        blob.need(set(reply) == common | {'plan_sha256', 'activation_allowed', 'current_authority_established'}
                  and reply['state'] == 'previewed' and is_digest(reply['plan_sha256'])
                  and reply['activation_allowed'] is False and reply['current_authority_established'] is False)
    elif action == 'offer':
        blob.need(set(reply) == common | {'offer', 'offer_sha256'} and reply['state'] == 'offered')
        check_offer(decode(reply['offer'], 4096), reply['offer_sha256'], operation(job, **step))
    else:
        blob.need(set(reply) == common | {'plan_sha256', 'stages', 'database_changed',
                                        'activation_allowed', 'current_authority_established'}
                  and reply['state'] == 'committed' and reply['plan_sha256'] == step['plan_digest']
                  and set(reply['stages']) == database.COMMITTED.keys()
                  and all(state in ('pending', 'committed') for state in reply['stages'].values())
                  and reply['stages'][step['stage']] == 'committed'
                  and type(reply['database_changed']) is bool and reply['activation_allowed'] is False
                  and reply['current_authority_established'] is False)
    return reply


def launch(raw, *, workspace, tooling, commit, tooling_sha256, image, config_sha256=None, docker_socket=None,
           local_preview=False, _boot=boot, _docker=subprocess.run, _recipient_root=RECIPIENT_ROOT,
           _carrier_root=CARRIER_ROOT):
    if local_preview:
        request, job, host, _ = database.parse_preview(raw)
    else:
        request, job, host = database.parse_request(raw)
    blob.need(re.fullmatch(r'sha256:[a-f0-9]{64}', image) is not None)
    blob.need(checked_document(tooling, tooling_sha256, MAX_BUNDLE)['scope'] in WORKER_SCOPES)
    workspace = private_directory(Path(workspace))
    blob.need(_boot(host) == job.verified_boot_id
              and blob.resource_id(host.vm_id) == blob.resource_id(job.selection.vm_id)
              and host.instance_id == job.selection.vm_instance_id and host.region == job.selection.region)
    daemon = RecoveryDocker(docker_socket) if docker_socket is not None else None
    docker = (*DOCKER[:2], 'unix://' + daemon.path.as_posix()) if daemon else DOCKER
    name = 'azd-santa-recovery-' + uuid.uuid4().hex
    with TemporaryDirectory(prefix='worker-', dir=workspace) as temporary:
        tools = Path(temporary) / 'tools'
        stage(tooling, tools, commit=commit, bundle_sha256=tooling_sha256)
        receipt = dict(scope=GUEST_SCOPE, vm_id=host.vm_id, vm_instance_id=host.instance_id,
                       boot_id=job.verified_boot_id)
        with ExitStack() as guards:
            folder, basename = blob.parent(tools / 'host.json', guards)
            write_at(folder, basename, blob.encoded(receipt))
        recipient = None
        if not local_preview:
            _recipient_root.mkdir(mode=0o700, exist_ok=True)
            recipient = private_directory(_recipient_root)
        application = Path(temporary) / 'application'
        args = arguments(name, image, tools, recipient, workspace, request, job,
                         config_sha256, carrier_root=_carrier_root, application=application)
        environment = {'PATH': '/usr/bin:/bin', 'DOCKER_CONFIG': str(Path(temporary) / 'docker-config')}

        def call(command, **options):
            if daemon:
                daemon.assert_current()
            return _docker([*docker, *command], env=environment, stderr=subprocess.DEVNULL, **options)

        inspected = call(['image', 'inspect', image], stdout=subprocess.PIPE, check=True, timeout=15)
        check_worker_image(inspected.stdout, image)
        if request['action'] != 'offer':
            stage_application(call, image, name + '-source', application)
        try:
            completed = call(args, input=raw, stdout=subprocess.PIPE, check=True, timeout=TIMEOUT)
        except subprocess.TimeoutExpired:
            call(['rm', '--force', name], stdout=subprocess.DEVNULL, check=False, timeout=15)
            raise
        if daemon:
            daemon.assert_current()
    return checked_reply(completed.stdout, raw, request, job)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('workspace', 'tooling', 'commit', 'tooling-sha256', 'image'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--config-sha256')
    parser.add_argument('--docker-socket', type=Path)
    parser.add_argument('--local-preview', action='store_true')
    inputs = vars(parser.parse_args())
    try:
        with Path(inputs.pop('tooling')).open('rb') as stream:
            tooling = stream.read(MAX_BUNDLE + 1)
        maximum = database.MAX_PREVIEW if inputs['local_preview'] else database.MAX_REQUEST
        request = sys.stdin.buffer.read(maximum + 1)
        reply = launch(request, tooling=tooling, **inputs)
        sys.stdout.buffer.write(blob.encoded(reply) + b'\n')
    except Exception:
        parser.exit(1, 'Santa recovery worker rejected or interrupted. Preserve the private journal.\n')


if __name__ == '__main__':
    main()
