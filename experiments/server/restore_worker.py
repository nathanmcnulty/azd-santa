"""Run the signed recovery command in a disposable network-isolated Zentral worker."""

import argparse
from contextlib import ExitStack
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
from restore_tooling_bundle import DATABASE_WORKER_SCOPE, IMAGE_KEY_SCOPE, MAX_BUNDLE, stage
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


def arguments(name, image, tools, recipient, workspace, request, job, config_sha256, *, carrier_root):
    result = ['run', '--rm', '--interactive', '--name', name, '--network', 'none', '--pull', 'never',
              '--user', '0:0', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
              '--log-driver', 'none', '--memory', '512m', '--cpus', '1', '--pids-limit', '96',
              '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=48m']
    result.extend(mount(tools, TOOLS))
    result.extend(mount(recipient, str(RECIPIENT_ROOT), readonly=False))
    command = [SERVER + '/restore_database_command.py', '--host-receipt', HOST_RECEIPT]
    if request['action'] == 'apply':
        capsule, _, _ = delivery_binding(job, request['plan'], request['plan_sha256'], request['receipt'])
        blob.need(job.target.socket_dir == WORKER_SOCKET and is_digest(config_sha256))
        config = workspace / 'base.json'
        with ExitStack() as guards:
            folder, name = blob.parent(config, guards)
            blob.need(sha(read_at(folder, name, 65536)) == config_sha256)
        result.extend(mount(config, '/restore-conf/base.json'))
        socket = workspace / 'socket'
        result.extend(['--group-add', socket_group(socket)])
        result.extend(mount(socket, WORKER_SOCKET))
        result.extend(mount(private_directory(workspace / 'journal'), WORKER_JOURNAL, readonly=False))
        result.extend(mount(private_directory(carrier_root / capsule), str(CARRIER_ROOT / capsule)))
        result.extend(['--env', 'ZENTRAL_CONF_DIR=/restore-conf',
                       '--env', 'DJANGO_SETTINGS_MODULE=restore_worker_settings',
                       '--env', 'PYTHONPATH=' + SERVER + ':/zentral:/zentral/server',
                       '--env', 'ZENTRAL_QUIET=1', '--env', 'AZD_SANTA_SECURITY_STORE_ID=' + config_sha256,
                       '--env', 'PGOPTIONS=-c session_preload_libraries= -c local_preload_libraries='])
        command += ['--journal-directory', WORKER_JOURNAL]
    else:
        blob.need(config_sha256 is None)
    return result + ['--entrypoint', 'python', image, '-B', *command]


def checked_reply(raw_reply, raw, request, job):
    blob.need(0 < len(raw_reply) <= MAX_OUTPUT and raw_reply.endswith(b'\n'))
    reply = checked_document(raw_reply[:-1], sha(raw_reply[:-1]), MAX_OUTPUT)
    step = request['step']
    common = {'scope', 'request_sha256', 'stage', 'state'}
    blob.need(reply['scope'] == database.SCOPE and reply['request_sha256'] == sha(raw)
              and reply['stage'] == step['stage'])
    if request['action'] == 'offer':
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
           _boot=boot, _docker=subprocess.run, _recipient_root=RECIPIENT_ROOT, _carrier_root=CARRIER_ROOT):
    request, job, host = database.parse_request(raw)
    blob.need(re.fullmatch(r'sha256:[a-f0-9]{64}', image) is not None)
    blob.need(checked_document(tooling, tooling_sha256, MAX_BUNDLE)['scope']
              in (DATABASE_WORKER_SCOPE, IMAGE_KEY_SCOPE))
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
        _recipient_root.mkdir(mode=0o700, exist_ok=True)
        args = arguments(name, image, tools, private_directory(_recipient_root), workspace, request, job,
                         config_sha256, carrier_root=_carrier_root)
        environment = {'PATH': '/usr/bin:/bin', 'DOCKER_CONFIG': str(Path(temporary) / 'docker-config')}

        def call(command, **options):
            if daemon:
                daemon.assert_current()
            return _docker([*docker, *command], env=environment, stderr=subprocess.DEVNULL, **options)

        output_format = '{{.Id}} {{.Os}} {{.Architecture}} {{json .Config.Volumes}}'
        inspected = call(['image', 'inspect', '--format', output_format, image],
                         stdout=subprocess.PIPE, check=True, timeout=15)
        fields = inspected.stdout.decode('ascii').split()
        blob.need(fields in ([image, 'linux', 'amd64', 'null'], [image, 'linux', 'amd64', '{}']))
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
    inputs = vars(parser.parse_args())
    try:
        with Path(inputs.pop('tooling')).open('rb') as stream:
            tooling = stream.read(MAX_BUNDLE + 1)
        request = sys.stdin.buffer.read(database.MAX_REQUEST + 1)
        reply = launch(request, tooling=tooling, **inputs)
        sys.stdout.buffer.write(blob.encoded(reply) + b'\n')
    except Exception:
        parser.exit(1, 'Santa recovery worker rejected or interrupted. Preserve the private journal.\n')


if __name__ == '__main__':
    main()
