"""Verify a populated database rewrap and rollback on the sealed PostgreSQL fixture."""
import base64
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
from unittest.mock import patch
from urllib.parse import parse_qs, urlencode, urlsplit
import zlib

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'experiments/server'))
import restore_authority_transaction as recovery
import restore_census as census
import restore_census_review as review
import restore_database_command as database_command
import restore_guest_job as guest_job
import restore_guest_readback as guest
import restore_operator_approval as operator_approval
import restore_packet_operator as packet_operator
import restore_tooling_bundle as tooling
import restore_worker as worker
import restore_arm_authorization as arm
import restore_sealed_inputs as sealed
import blob_retention as blob
import private_arm_adapter as cached_arm
from restore_input_blob import PacketTransfer
from restore_input_handoff import Handoff
from retained_image_sas import IssuedBatch
import restore_quarantine_journal as journal
import restore_secret_transaction as transaction
import run_restore_authority_transaction as fixture
import secret_rewrap as secret

DATABASE = 'azd_recovery_' + 'b' * 24
KEY = b'synthetic rewrap census key.....'
STORE = '11111111-1111-4111-8111-111111111111'
ACTION = '22222222-2222-4222-8222-222222222222'
OLD = {'old': secret.Material('fernet', ('synthetic previous password',), 'synthetic previous signing salt'),
       'noop': secret.Material('noop')}
NEW = {'new': secret.Material('fernet', ('synthetic new password',), 'synthetic new signing salt'),
       'noop': secret.Material('noop')}
TARGETS = {'old': 'new', 'noop': 'noop'}
CONTEXTS = [
    {'model': 'stores.store', 'pk': STORE, 'field': 'headers.0.value'},
    {'model': 'stores.store', 'pk': STORE, 'field': 'password'},
    {'model': 'probes.action', 'pk': ACTION, 'field': 'url'},
    {'model': 'terraform.stateversion', 'pk': 1, 'field': 'encryption_key'},
]
MODELS = {
    'stores': '''
from django.db import models

class Store(models.Model):
    id = models.UUIDField(primary_key=True)
    name = models.TextField()
    description = models.TextField()
    created_at = models.DateTimeField()
    updated_at = models.DateTimeField()
    provisioning_uid = models.TextField()
    slug = models.TextField()
    admin_console = models.BooleanField()
    event_filters = models.JSONField()
    backend = models.TextField()
    backend_kwargs = models.JSONField()
''',
    'probes': '''
from django.db import models

class Action(models.Model):
    id = models.UUIDField(primary_key=True)
    name = models.TextField()
    description = models.TextField()
    created_at = models.DateTimeField()
    updated_at = models.DateTimeField()
    backend = models.TextField()
    backend_kwargs = models.JSONField()
''',
    'terraform': '''
from django.db import models

class StateVersion(models.Model):
    state_id = models.BigIntegerField()
    encryption_key = models.TextField()
    data = models.BinaryField()
    created_by_id = models.BigIntegerField()
    created_by_username = models.TextField()
    created_at = models.DateTimeField()
''',
}


def reject(call, error_type=transaction.TransactionRejected):
    try:
        call()
    except error_type as error:
        return error
    raise AssertionError('Expected rewrap to reject the attempt')


def receiver_target(job):
    selected = job.selection
    source_id = selected.vm_id.split('/providers/')[0]
    subnet = source_id + '/providers/Microsoft.Network/virtualNetworks/vnet-santa-lab/subnets/host'
    return blob.SelectedTarget(selected.vm_id, selected.vm_instance_id, subnet, selected.region)


def transfer_packet(root, job, packet, stage):
    selected = job.selection
    target = receiver_target(job)
    account = (f'/subscriptions/{selected.subscription}/resourceGroups/rg-fixture-store'
               '/providers/Microsoft.Storage/storageAccounts/santafixture')
    sender = blob.SelectedTarget(selected.vm_id.replace('-fixture/', '-sender/'),
        '44444444-4444-4444-8444-444444444444', target.subnet_id.replace('-fixture/', '-sender/'), selected.region)
    store = blob.Store(blob.Blob(account, 'e' * 32), selected.region, (sender.subnet_id, target.subnet_id), selected.tenant)
    transfer = PacketTransfer(job, store, target, sealed.sha(packet), len(packet))
    placement = cached_arm.Selection(selected.tenant, selected.subscription, store, sender, target)
    uploads = root / ('upload-' + stage)
    uploads.mkdir(mode=0o700)
    now = datetime.now(timezone.utc)
    sender_boot = '55555555-5555-4555-8555-555555555555'

    def token(permission):
        return urlencode(dict(sv='2023-11-03', sr='b', sp=permission, spr='https',
                              st=(now - timedelta(minutes=1)).strftime('%Y-%m-%dT%H:%M:%SZ'),
                              se=(now + timedelta(minutes=4)).strftime('%Y-%m-%dT%H:%M:%SZ'),
                              sig=base64.b64encode(b'x' * 32).decode()))

    class Connection:
        calls = []
        corrupt = False
        unknown = stage == 'rewrap'

        def request(self, method, path, body=None, headers=None):
            parsed = urlsplit(path)
            assert parsed.path == f'/native-captures/{store.blob.operation}/restore-inputs/{sealed.sha(packet)}.sealed'
            assert parse_qs(parsed.query)['sp'] == ['c' if method == 'PUT' else 'r']
            self.calls.append(method)
            self.method = method
            if method == 'PUT':
                handoff_root = uploads / (sealed.sha(packet) + '-sas-offer-c')
                assert (handoff_root / sealed.sha(packet) / 'intent.json').is_file()
                assert (handoff_root / 'consumed.json').is_file() and not (handoff_root / 'recipient.der').exists()
                assert headers['If-None-Match'] == '*'
                self.data = b''.join(iter(lambda: body.read(8192), b''))
                assert self.data == packet and int(headers['Content-Length']) == len(packet)
                assert headers['Content-MD5'] == base64.b64encode(
                    hashlib.md5(self.data, usedforsecurity=False).digest()).decode()
                if self.unknown:
                    raise TimeoutError('synthetic lost PUT reply')

        def getresponse(self):
            data = b'' if self.method == 'PUT' else self.data
            if self.corrupt:
                data = data[:-1] + bytes([data[-1] ^ 1])
            response = io.BytesIO(data)
            response.status = 201 if self.method == 'PUT' else 200
            response.getheader = lambda name: {'Content-Length': str(len(data)), 'ETag': '"fixture"'}[name]
            return response

        def close(self):
            pass

    connection = Connection()

    def observed_boot(observed):
        assert observed in (sender, target)
        return sender_boot if observed == sender else job.verified_boot_id

    def sealed_capability(permission, host, boot_id):
        courier = Handoff(placement, transfer, permission, boot_id=boot_id)
        offer = courier.offer(uploads, _boot=observed_boot)
        sas = token(permission)
        batch = IssuedBatch(host, permission, transfer.packet_sha256,
                            {transfer.object_metadata()['object']: sas}, account_id=store.blob.account_id)
        envelope = courier.seal(offer, sealed.sha(offer), batch)
        assert sas.encode() not in envelope
        reject(lambda: courier.seal(offer, sealed.sha(offer), batch), blob.RetentionRejected)
        return courier, envelope, sealed.sha(offer), sealed.sha(envelope)

    with patch.object(blob.BlobHttp, 'connection', return_value=connection):
        reject(lambda: transfer.upload(packet, token('r'), uploads), blob.RetentionRejected)
        assert not connection.calls
        send, *create = sealed_capability('c', sender, sender_boot)
        reject(lambda: send.use(uploads, create[0], create[1], '0' * 64, packet=packet, _boot=observed_boot),
               blob.RetentionRejected)
        reject(lambda: send.use(uploads, *create, packet=packet, _boot=lambda _: selected.subscription),
               blob.RetentionRejected)
        if connection.unknown:
            reject(lambda: send.use(uploads, *create, packet=packet, _boot=observed_boot), blob.RetentionRejected)
        else:
            assert send.use(uploads, *create, packet=packet, _boot=observed_boot)['uploaded']
        reject(lambda: send.use(uploads, *create, packet=packet, _boot=observed_boot), blob.RetentionRejected)
        reject(lambda: transfer.download(token('r'), _boot=lambda _: selected.subscription), blob.RetentionRejected)
        assert connection.calls == ['PUT']
        connection.corrupt = True
        reject(lambda: transfer.download(token('r'), _boot=observed_boot), blob.RetentionRejected)
        connection.corrupt = False
        receive, *read = sealed_capability('r', target, job.verified_boot_id)
        result = receive.use(uploads, *read, _boot=observed_boot)
        reject(lambda: receive.use(uploads, *read, _boot=observed_boot), blob.RetentionRejected)
        assert connection.calls == ['PUT', 'GET', 'GET']
        return result, placement, sender_boot


def run(root):
    fixture.DATABASE = DATABASE
    fixture.MODELS.update(MODELS)
    fixture.MODELS['accounts'] = fixture.MODELS['accounts'].replace('class User(AbstractUser):\n    pass',
        'class User(AbstractUser):\n    is_remote = models.BooleanField(default=False)\n'
        '    is_service_account = models.BooleanField(default=False)')
    fixture.configure(root)
    from django.apps import apps
    from django.conf import settings
    from django.core.management import call_command
    from django.db import connections

    writer, observer, peer = (connections[name] for name in ('default', 'observer', 'peer'))
    try:
        call_command('makemigrations', 'accounts', 'realms', 'inventory', *MODELS, verbosity=0, interactive=False)
        call_command('migrate', verbosity=0, interactive=False)
        previous = secret.Engine('old', OLD['old'])
        replacement = secret.Engine('new', NEW['new'])

        def token(value, context):
            return 'old$' + previous.encrypt(value, context)

        model = apps.get_model('stores', 'Store')
        recorded = datetime(2026, 1, 1)
        user = apps.get_model('accounts', 'User').objects.create_user(
            username='archived-operator', password='synthetic archived password', is_superuser=True)
        model.objects.create(id=STORE, name='retained store', description='description',
            created_at=recorded, updated_at=recorded, provisioning_uid='retained', slug='retained',
            admin_console=False, event_filters={'retain': True}, backend='HTTP', backend_kwargs={
                'headers': [{'name': 'legacy', 'value': 'noop$c3ludGhldGlj'}],
                'password': token(b'store-password-fixture', CONTEXTS[1]), 'request_timeout': 1})
        apps.get_model('probes', 'Action').objects.create(id=ACTION, name='retained action',
            description='description', created_at=recorded, updated_at=recorded,
            backend='SLACK_INCOMING_WEBHOOK', backend_kwargs={'url': token(b'webhook-fixture', CONTEXTS[2])})
        history_key = Fernet.generate_key()
        history = Fernet(history_key).encrypt(zlib.compress(b'{"retained":"Terraform history"}'))
        apps.get_model('terraform', 'StateVersion').objects.create(id=1, state_id=7,
            encryption_key=token(history_key, CONTEXTS[3]), data=history,
            created_by_id=4, created_by_username='retained creator', created_at=recorded)
        numeric = '123456789.123456789012345678901234567890'
        with writer.cursor() as cursor:
            cursor.execute("""UPDATE stores_store SET backend_kwargs=jsonb_set(
                backend_kwargs, '{request_timeout}', to_jsonb(%s::numeric), false) WHERE id=%s""", (numeric, STORE))
            # A write on the last table should roll back the previous two writes.
            cursor.execute("""ALTER TABLE terraform_stateversion ADD CONSTRAINT preserved_old_key
                               CHECK (left(encryption_key, 4) = 'old$')""")

        observer.ensure_connection()
        target = recovery.read_target(observer)
        cutoff = datetime.now(timezone.utc)
        directory = root / 'journal'
        directory.mkdir(mode=0o700)
        sub = '11111111-1111-4111-8111-111111111111'
        vm_id = (f'/subscriptions/{sub}/resourceGroups/rg-azd-santa-vm-fixture'
                 '/providers/Microsoft.Compute/virtualMachines/vm-santa-lab')
        selected = arm.Selection('22222222-2222-4222-8222-222222222222', sub, 'operator@example.com',
                                 vm_id, '33333333-3333-4333-8333-333333333333', 'westus2')
        guest_receipt = dict(scope=guest.SCOPE, vm_id=vm_id, vm_instance_id=selected.vm_instance_id,
                             boot_id=target.boot_id)
        receipt_path = root / 'recovery-host.json'
        receipt_path.write_bytes(blob.encoded(guest_receipt))
        receipt_path.chmod(0o600)
        worker_boot = database_command.host_receipt(receipt_path)
        bound = dict(archive_sha256='a' * 64, generation='b' * 64)
        secret_options = dict(expected_contexts=CONTEXTS, old_material=OLD, new_material=NEW, targets=TARGETS)
        repo = Path(__file__).resolve().parents[1]
        commit = subprocess.check_output(['git', '-C', str(repo), 'rev-parse', 'HEAD'], text=True).strip()
        bundle = tooling.build(repo, commit, version=21)
        carrier_root = root / 'carrier'
        carrier_root.mkdir(mode=0o700)
        recipient_root = root / 'recipients'
        workspace = root / 'signed-worker'
        workspace.mkdir(mode=0o700)
        config_path = workspace / 'base.json'
        # Test the guarded mount with a fixture-only socket and use the real
        # PostgreSQL socket for the simulated container's command.
        config_path.write_bytes(b'{}')
        config_path.chmod(0o600)
        socket_dir = workspace / 'socket'
        socket_dir.mkdir(mode=0o750)
        socket_path = socket_dir / '.s.PGSQL.5432'
        with socket.socket(socket.AF_UNIX) as endpoint:
            endpoint.bind(str(socket_path))
        socket_path.chmod(0o770)
        if os.getegid() == 0:
            os.chown(socket_dir, -1, 65534)
            os.chown(socket_path, -1, 65534)
        worker_journal = workspace / 'journal'
        worker_journal.mkdir(mode=0o700)
        recovery_socket = workspace / 'docker.sock'
        with socket.socket(socket.AF_UNIX) as endpoint:
            endpoint.bind(str(recovery_socket))

        def run_worker(request):
            local_preview = type(request) is bytes
            raw = request if local_preview else blob.encoded(request)
            if local_preview:
                request, _, _, _ = database_command.parse_preview(raw)
            is_apply = request['action'] == 'apply'
            image = 'sha256:' + 'f' * 64
            selected_socket = recovery_socket if request['step']['stage'] == 'quarantine' else None
            staged_commands = []

            def docker(args, **options):
                expected_docker = (*worker.DOCKER[:2], 'unix://' + str(selected_socket)) if selected_socket else worker.DOCKER
                assert tuple(args[:3]) == expected_docker
                if args[3:5] == ['image', 'inspect']:
                    assert args[5:] == [image]
                    inspected = [dict(Id=image, Os='linux', Architecture='amd64', Config={})]
                    return subprocess.CompletedProcess(args, 0, blob.encoded(inspected))
                if args[3] == 'create':
                    assert is_apply or local_preview
                    assert args[args.index('--network')+1] == 'none'
                    assert args[args.index('--pull')+1] == 'never'
                    assert '--read-only' in args and args[args.index('--entrypoint')+1] == '/bin/false'
                    assert args[-1] == image
                    staged_commands.append('create')
                    return subprocess.CompletedProcess(args, 0, b'')
                if args[3] == 'cp':
                    assert args[4].endswith('-source:/zentral/.')
                    app = Path(args[5])
                    settings = app / 'server' / 'server' / 'settings.py'
                    settings.parent.mkdir(parents=True)
                    settings.write_text('# fixture application settings')
                    staged_commands.append('cp')
                    return subprocess.CompletedProcess(args, 0, b'')
                if args[3] == 'rm':
                    assert args[4:6] == ['--force', '--volumes'] and args[-1].endswith('-source')
                    staged_commands.append('rm')
                    return subprocess.CompletedProcess(args, 0, b'')
                assert args[3] == 'run' and args[args.index('--network') + 1] == 'none'
                assert '--read-only' in args and args[args.index('--cap-drop') + 1] == 'ALL'
                assert '--privileged' not in args and options['input'] == raw
                mounts = [args[index + 1] for index, value in enumerate(args) if value == '--mount']
                needs_application = is_apply or local_preview
                assert staged_commands == (['create', 'cp', 'rm'] if needs_application else [])
                assert len(mounts) == (7 if is_apply else 5 if local_preview else 2)
                assert any(item.endswith('/application,target=/zentral,readonly') for item in mounts) == needs_application
                if local_preview:
                    assert '--local-preview' in args
                    assert mounts[-1] == f'type=bind,source={worker_journal},target={worker.WORKER_JOURNAL},readonly'
                    assert all(str(worker.RECIPIENT_ROOT) not in item and str(worker.CARRIER_ROOT) not in item
                               for item in mounts)
                assert all('/var/run/docker.sock' not in value for value in mounts)
                if is_apply:
                    assert f'type=bind,source={socket_dir},target={target.socket_dir},readonly' in mounts
                    picked = request['plan']['receiver_capsule']
                    assert any(f'/{picked},readonly' in value for value in mounts)
                    assert mounts[-2] == f'type=bind,source={worker_journal},target={worker.WORKER_JOURNAL}'
                tools = Path(mounts[0].split(',')[1].removeprefix('source='))
                read_boot = database_command.host_receipt(tools / 'host.json')
                if local_preview:
                    reply = database_command.preview(raw, directory=directory, _boot=read_boot)
                else:
                    reply = database_command.dispatch(raw, directory=directory if is_apply else None,
                        carrier_root=carrier_root, recipient_root=recipient_root, _boot=read_boot)
                return subprocess.CompletedProcess(args, 0, blob.encoded(reply) + b'\n')

            with patch.object(worker, 'WORKER_SOCKET', target.socket_dir):
                return worker.launch(raw, workspace=workspace, tooling=bundle, commit=commit,
                    tooling_sha256=sealed.sha(bundle), image=image,
                    config_sha256=sealed.sha(config_path.read_bytes()) if is_apply or local_preview else None,
                    local_preview=local_preview, docker_socket=selected_socket, _boot=worker_boot, _docker=docker,
                    _recipient_root=recipient_root, _carrier_root=carrier_root)

        def observe():
            return census.collect(observer, apps, fingerprint_key=KEY)

        def reviewed():
            initial = observe()
            assert initial.receipt['complete_supported_data']
            return dict(expected=initial, dispositions={item: 'preserve_inert'
                        for item in census.coverage_items(initial, fingerprint_key=KEY)})

        def invoke(baseline, **kwargs):
            options = dict(target=target, fingerprint_key=KEY, **secret_options)
            return transaction.run(writer, observer, apps, **{**options, **baseline, **kwargs})

        def job(context=bound, selection=selected, receipt=guest_receipt, db_target=target):
            return guest_job.Job.from_readback(selection, db_target, guest_receipt=receipt, **context)

        def published(stage, baseline, context=bound):
            raw = job(context).publish(**baseline, fingerprint_key=KEY, stage=stage)
            return dict(review_bytes=raw, review_sha256=hashlib.sha256(raw).hexdigest())

        def guided(stage, baseline, *, folder=directory, context=bound, **kwargs):
            options = secret_options if stage == 'rewrap' else dict(cutoff=cutoff)
            inputs = published(stage, baseline, context)
            return job(context).run(writer, observer, apps, directory=folder, stage=stage, fingerprint_key=KEY,
                                    **{**inputs, 'options': options, **kwargs})

        def deny(call):
            return reject(call, (journal.JournalRejected, review.ReviewRejected))

        def authorized(stage, baseline, preview, context, record):
            assert record == dict(scope=review.SCOPE, binding=job(context).binding(KEY), stage=stage,
                plan_digest=preview['plan_digest'], review_sha256=published(stage, baseline, context)['review_sha256'])
            return True

        def sealed_apply(stage, baseline, preview):
            selected_job = job()
            options = secret_options if stage == 'rewrap' else dict(cutoff=cutoff)
            inputs = published(stage, baseline)
            host = receiver_target(selected_job)
            preview_raw = database_command.preview_request(selected_job, host, stage=stage, fingerprint_key=KEY,
                                                            options=options, **inputs)
            reject(lambda: database_command.parse_request(preview_raw), ValueError)
            before = set(directory.iterdir())
            try:
                reviewed_plan = run_worker(preview_raw)
            finally:
                writer.ensure_connection()
                observer.ensure_connection()
            assert reviewed_plan['plan_sha256'] == preview['plan_digest']
            assert not reviewed_plan['activation_allowed'] and not reviewed_plan['current_authority_established']
            assert before == set(directory.iterdir())
            selection = dict(stage=stage, plan_digest=reviewed_plan['plan_sha256'], review_sha256=inputs['review_sha256'])
            signer = Ed25519PrivateKey.generate()
            public_key = signer.public_key().public_bytes_raw()
            public_pin = sealed.sha(public_key)
            reject(lambda: worker_boot(replace(host, instance_id='55555555-5555-4555-8555-555555555555')),
                   blob.RetentionRejected)
            bound_stage = dict(binding=selected_job.binding(KEY), **selection)
            state = dict(root=recipient_root, _boot=worker_boot)
            job_input = dict(selection=asdict(selected_job.selection), target=asdict(selected_job.target),
                             boot_id=selected_job.verified_boot_id, **bound)
            frame = dict(scope=database_command.SCOPE, job=job_input, host=asdict(host), step=bound_stage)
            offered = run_worker(dict(**frame, action='offer', public_key_sha256=public_pin))
            assert offered['state'] == 'offered'
            offer = base64.b64decode(offered['offer'], validate=True)
            pin = sealed.sha(offer)
            assert pin == offered['offer_sha256']
            recipient_key = recipient_root / pin / 'recipient.der'
            assert recipient_key.stat().st_mode & 0o777 == 0o600
            reject(lambda: sealed.BootRecipient(selected_job, host, pin, **bound_stage, root=recipient_root,
                           _boot=lambda _: '55555555-5555-4555-8555-555555555555'), sealed.InputRejected)
            reject(lambda: sealed.seal(selected_job, offer, pin, stage=stage, **inputs,
                                       plan_digest='0' * 64, fingerprint_key=KEY, options=options),
                   sealed.InputRejected)
            packet = sealed.seal(selected_job, offer, pin, **selection, review_bytes=inputs['review_bytes'],
                                 fingerprint_key=KEY, options=options)
            assert KEY not in packet and inputs['review_bytes'] not in packet
            if stage == 'rewrap':
                assert OLD['old'].passwords[0].encode() not in packet
            packet, placement, sender_boot = transfer_packet(root, selected_job, packet, stage)
            approve = lambda record: authorized(stage, baseline, preview, bound, record)

            def receive(current, data, digest):
                return current.run(data, digest, writer, observer, apps, directory=directory, authorize=approve)

            other = sealed.Recipient(selected_job, binding=selected_job.binding(KEY), **selection)
            reject(lambda: receive(other, packet, '0' * 64), sealed.InputRejected)
            reject(lambda: receive(other, packet, sealed.sha(packet)), sealed.InputRejected)
            if stage == 'rewrap':
                tamper = sealed.Recipient(selected_job, binding=selected_job.binding(KEY), **selection)
                separate = sealed.seal(selected_job, tamper.offer, sealed.sha(tamper.offer), **selection,
                                       review_bytes=inputs['review_bytes'], fingerprint_key=KEY, options=options)
                corrupt = separate[:-1] + bytes([separate[-1] ^ 1])
                reject(lambda: receive(tamper, corrupt, sealed.sha(corrupt)), sealed.InputRejected)
            transport = packet_operator.Operation(placement, selected_job, packet, bundle, commit=commit,
                                                  tooling_sha256=sealed.sha(bundle), sender_boot=sender_boot)
            plan = transport.preview()
            plan_sha = plan['plan_sha256']
            receipt = transport._summary(state='verified', upload_confirmed=(stage != 'rewrap'))
            if stage == 'quarantine':
                reject(lambda: packet_operator.stage_local(selected_job, host, packet, root=carrier_root,
                    _boot=lambda _: '55555555-5555-4555-8555-555555555555'), sealed.InputRejected)
                plan, receipt = packet_operator.stage_local(selected_job, host, packet, root=carrier_root,
                                                            _boot=worker_boot)
                plan_sha = plan['plan_sha256']
                carrier = carrier_root / plan['receiver_capsule']
                verified = carrier / 'verified.json'
                saved = verified.read_bytes()
                verified.write_bytes(blob.encoded({**receipt, 'state': 'interrupted'}))
                reject(lambda: packet_operator.received_packet(selected_job, plan, plan_sha, receipt,
                                                                root=carrier_root), blob.RetentionRejected)
                verified.write_bytes(saved)
                reject(lambda: packet_operator.stage_local(selected_job, host, packet, root=carrier_root,
                                                            _boot=worker_boot), FileExistsError)
                assert packet_operator.received_packet(selected_job, plan, plan_sha, receipt, root=carrier_root) == packet
                received = carrier / 'packet.sealed'
            else:
                guest = carrier_root / plan['receiver_capsule']
                guest.mkdir(mode=0o700)
                received = guest / 'packet.sealed'
                received.write_bytes(packet)
                received.chmod(0o600)

            def sign(digest, key=signer):
                return operator_approval.issue(key, selected_job, KEY, offer,
                                               plan, plan_sha, receipt, approved_plan_digest=digest)

            with patch.object(guest_job.Job, 'confirm', return_value=approve) as confirm:
                reject(lambda: sign('0' * 64), operator_approval.ApprovalRejected)
                confirm.assert_not_called()
                approval = sign(selection['plan_digest'])
                confirm.assert_called_once_with(fingerprint_key=KEY, **selection)
                other_signer = Ed25519PrivateKey.generate()
                other_approval = sign(selection['plan_digest'], other_signer)

            def apply_file(result, digest=plan_sha, key=public_key, signed=approval):
                request = dict(**frame, action='apply', offer_sha256=pin, plan=plan, plan_sha256=digest,
                               receipt=result, approval=base64.b64encode(signed).decode(),
                               public_key=base64.b64encode(key).decode())
                try:
                    return run_worker(request)
                finally:
                    writer.ensure_connection()
                    observer.ensure_connection()

            reject(lambda: apply_file(receipt, '0' * 64), blob.RetentionRejected)
            reject(lambda: apply_file(receipt, key=other_signer.public_key().public_bytes_raw(),
                                      signed=other_approval), operator_approval.ApprovalRejected)
            error = blob.RetentionRejected if stage == 'quarantine' else operator_approval.ApprovalRejected
            reject(lambda: apply_file({**receipt, 'upload_confirmed': not receipt['upload_confirmed']}), error)
            approval_body = json.loads(approval)['body']
            forged = review.encode(dict(body=approval_body,
                                        signature=base64.b64encode(bytes(64)).decode()))
            reject(lambda: apply_file(receipt, signed=forged), operator_approval.ApprovalRejected)
            with patch.dict(settings.DATABASES['observer'], {'HOST': 'unexpected.invalid'}):
                reject(lambda: apply_file(receipt), blob.RetentionRejected)
            verifier = operator_approval.Verify(public_key, public_pin, approval, selected_job,
                                               offer, plan, plan_sha, receipt)
            request = approval_body['request']
            with patch.object(operator_approval.time, 'time', return_value=approval_body['expires']):
                reject(lambda: verifier(request), operator_approval.ApprovalRejected)
            assert verifier(request)
            reject(lambda: verifier(request), operator_approval.ApprovalRejected)
            received.write_bytes(packet[:-1] + bytes([packet[-1] ^ 1]))
            reject(lambda: apply_file(receipt), sealed.InputRejected)
            assert recipient_key.exists()
            unchanged(baseline)
            received.write_bytes(packet)
            with patch.object(guest_job.Job, 'confirm', return_value=approve):
                raw = operator_approval.apply_request(selected_job, host, offer, plan, receipt, signing_key=signer,
                    fingerprint_key=KEY, offer_sha256=pin, plan_sha256=plan_sha,
                    approved_plan_digest=selection['plan_digest'], public_key_sha256=public_pin)
            try:
                result = run_worker(json.loads(raw))
            finally:
                writer.ensure_connection()
                observer.ensure_connection()
            assert result['plan_sha256'] == selection['plan_digest']
            assert not recipient_key.exists() and (recipient_key.parent / 'consumed.json').is_file()
            reject(lambda: apply_file(receipt), sealed.InputRejected)
            return result

        def unchanged(baseline):
            assert census.compare(observe(), fingerprint_key=KEY, **baseline)['exact_match']

        baseline = reviewed()
        preview = invoke(baseline)
        assert preview['inspected'] == 4 and preview['rewrapped'] == 3 and preview['noop_preserved'] == 1
        assert not preview['performs_mutation'] and not preview['rewrap_committed']
        assert invoke(baseline)['plan_digest'] == preview['plan_digest']
        failed = reject(lambda: invoke(baseline, apply=True, plan_digest=preview['plan_digest']))
        constraint_failure = failed.__context__.__cause__
        assert isinstance(constraint_failure, writer.Database.errors.CheckViolation)
        assert constraint_failure.diag.constraint_name == 'preserved_old_key'
        unchanged(baseline)
        failed_directory = root / 'journal-failed'
        failed_directory.mkdir(mode=0o700)
        failed_bound = {**bound, 'generation': 'f' * 64}
        interrupted = guided('rewrap', baseline, folder=failed_directory, context=failed_bound)
        deny(lambda: guided('rewrap', baseline, folder=failed_directory, context=failed_bound,
                            plan_digest=interrupted['plan_digest'], authorize=lambda record: authorized(
                                'rewrap', baseline, interrupted, failed_bound, record)))
        assert job(failed_bound).inspect(failed_directory, fingerprint_key=KEY)['stages'] == {
            'rewrap': 'inspect', 'quarantine': 'pending'}
        deny(lambda: guided('rewrap', baseline, folder=failed_directory, context=failed_bound))
        unchanged(baseline)

        with writer.cursor() as cursor:
            cursor.execute('ALTER TABLE terraform_stateversion DROP CONSTRAINT preserved_old_key')
        baseline = reviewed()
        preview = invoke(baseline)
        reject(lambda: invoke(baseline, apply=True, plan_digest='0' * 64))
        changed_key = {**NEW, 'new': secret.Material('fernet', ('another target password',), 'different salt')}
        reject(lambda: invoke(baseline, apply=True, plan_digest=preview['plan_digest'], new_material=changed_key))
        peer.ensure_connection()
        try:
            reject(lambda: invoke(baseline))
        finally:
            peer.close()
        unchanged(baseline)

        deny(lambda: guided('quarantine', baseline))
        deny(lambda: guided('rewrap', baseline, options={**secret_options, 'apply': True,
                                                          'plan_digest': preview['plan_digest']}))
        reviewed_plan = guided('rewrap', baseline)
        assert reviewed_plan['stages'] == {'rewrap': 'pending', 'quarantine': 'pending'}
        artifact = published('rewrap', baseline)
        deny(lambda: guided('rewrap', baseline, review_bytes=artifact['review_bytes'] + b' '))
        deny(lambda: job(receipt={**guest_receipt, 'boot_id': sub}))
        deny(lambda: job(receipt={**guest_receipt, 'vm_id': vm_id.replace('fixture', 'other')}))
        deny(lambda: job(receipt={**guest_receipt, 'vm_instance_id': sub}))
        other_operator = job(selection=replace(selected, account='other@example.com'))
        deny(lambda: other_operator.run(writer, observer, apps, directory=directory, stage='rewrap',
                                       fingerprint_key=KEY, options=secret_options, **artifact))
        other_database = job(db_target=replace(target, database_oid=target.database_oid + 1))
        raw = other_database.publish(**baseline, fingerprint_key=KEY, stage='rewrap')
        deny(lambda: other_database.run(writer, observer, apps, directory=directory, stage='rewrap',
                                       fingerprint_key=KEY, options=secret_options, review_bytes=raw,
                                       review_sha256=hashlib.sha256(raw).hexdigest()))
        deny(lambda: guided('quarantine', baseline, **artifact))
        deny(lambda: guided('rewrap', baseline, context={**bound, 'generation': '0' * 64}, **artifact))
        deny(lambda: guided('rewrap', baseline, plan_digest=reviewed_plan['plan_digest']))
        deny(lambda: guided('rewrap', baseline, plan_digest=reviewed_plan['plan_digest'], authorize=lambda _: False))
        calls = []
        deny(lambda: guided('rewrap', baseline, context={**bound, 'archive_sha256': 'c' * 64},
                            plan_digest=reviewed_plan['plan_digest'], authorize=calls.append))
        assert not calls
        with writer.cursor() as cursor:
            cursor.execute("UPDATE stores_store SET description='temporarily changed'")
        deny(lambda: guided('rewrap', baseline, **artifact))
        with writer.cursor() as cursor:
            cursor.execute("UPDATE stores_store SET description='description'")
        unchanged(baseline)
        assert not list(directory.iterdir())
        applied = sealed_apply('rewrap', baseline, reviewed_plan)
        assert applied['stages'] == {'rewrap': 'committed', 'quarantine': 'pending'}
        assert applied['state'] == 'committed' and applied['database_changed']
        assert not applied['activation_allowed'] and not applied['current_authority_established']
        with observer.cursor() as cursor:
            cursor.execute("SELECT backend_kwargs #>> '{request_timeout}' FROM stores_store WHERE id=%s", (STORE,))
            assert cursor.fetchone() == (numeric,)
            cursor.execute('SELECT name, backend_kwargs::text FROM stores_store WHERE id=%s', (STORE,))
            name, raw = cursor.fetchone()
            kwargs = census.parse(raw)
            assert name == 'retained store' and kwargs['headers'] == [{'name':'legacy','value':'noop$c3ludGhldGlj'}]
            cursor.execute('SELECT backend_kwargs->>%s FROM probes_action WHERE id=%s', ('url', ACTION))
            action, = cursor.fetchone()
            cursor.execute('SELECT data, encryption_key FROM terraform_stateversion WHERE id=1')
            persisted_history, state_key = cursor.fetchone()
        assert bytes(persisted_history) == history
        for value, index, decoded in ((kwargs['password'], 1, b'store-password-fixture'),
                                      (action, 2, b'webhook-fixture'), (state_key, 3, history_key)):
            engine, payload = value.split('$', 1)
            assert engine == 'new' and replacement.decrypt(payload, CONTEXTS[index]) == decoded
        reject(lambda: invoke(baseline, apply=True, plan_digest=preview['plan_digest']))
        deny(lambda: guided('rewrap', baseline, plan_digest=reviewed_plan['plan_digest'], authorize=calls.append))
        deny(lambda: guided('quarantine', baseline))
        deny(lambda: job({**bound, 'generation': '0' * 64}).inspect(directory, fingerprint_key=KEY))
        subsequent = reviewed()
        quarantine = guided('quarantine', subsequent)
        completed = sealed_apply('quarantine', subsequent, quarantine)
        assert completed['state'] == 'committed' and completed['database_changed']
        user.refresh_from_db()
        assert not user.is_active and not user.check_password('synthetic archived password')
        inspected = job().inspect(directory, fingerprint_key=KEY)
        assert inspected['stages'] == {'rewrap': 'committed', 'quarantine': 'committed'}
        assert not inspected['activation_allowed'] and not inspected['current_authority_established']
        reissue_options = dict(directory=directory, fingerprint_key=KEY, username='fresh-fixture-admin',
                               email='fresh-fixture-admin@example.invalid',
                               runtime_sha256='a' * 64, recipient_sha256='b' * 64,
                               setup_origin_sha256=hashlib.sha256(b'https://santa.example.invalid').hexdigest())
        reissue = job().reissue_admin(observer, apps, **reissue_options)
        assert reissue['state'] == 'previewed' and reissue['quarantine_plan_sha256'] == completed['plan_sha256']
        assert not reissue['activation_allowed']
        with writer.cursor() as cursor:
            cursor.execute("UPDATE stores_store SET description='changed after quarantine'")
        try:
            reject(lambda: job().reissue_admin(observer, apps, **reissue_options), journal.JournalRejected)
        finally:
            with writer.cursor() as cursor:
                cursor.execute("UPDATE stores_store SET description='description'")
        assert job().reissue_admin(observer, apps, **reissue_options) == reissue
        check_fresh_administrator(job(), writer, observer, apps, directory, reissue_options, user)
        deny(lambda: guided('quarantine', subsequent, plan_digest=quarantine['plan_digest'], authorize=calls.append))
        assert not calls
        with journal.locked(directory):
            deny(lambda: job().inspect(directory, fingerprint_key=KEY))
        (directory / 'quarantine-committed.json').write_text('{}')
        deny(lambda: job().inspect(directory, fingerprint_key=KEY))
        unchanged_failure = job(failed_bound).inspect(failed_directory, fingerprint_key=KEY)
        assert unchanged_failure['stages']['rewrap'] == 'inspect'
        print('Verified guided rewrap and authority handoff, durable intent, replay denial and closed activation')
        print('Verified private review handoff, stale census rejection and authorization before database intent')
        print('Verified the guest-bound job committed both steps and rejected a mismatched VM, boot, operator or database')
        print('Verified sealed input delivery to both database steps, including wrong recipient and replay rejection')
        print('Verified exact-object Blob transport to both database steps with ambiguous upload and tamper checks')
        print('Verified sealed SAS delivery to distinct sender and receiver boots before both database steps')
        print('Verified receiver files fed both PostgreSQL steps and changed files or plans failed before writes')
        print('Verified signed operator approval before both isolated PostgreSQL writes')
        print('Verified administrator reissue preview against the exact committed PostgreSQL census')
        print('Reopened and consumed boot-local recipients for both PostgreSQL writes')
        print('The guest command applied both signed stages through its local Django connections')
        print('Verified network-isolated worker arguments and both signed requests against PostgreSQL')
        print('Verified transactional rewrap, late rollback, unchanged Terraform bytes and exact JSONB numbers')
    finally:
        connections.close_all()


def check_fresh_administrator(job, writer, observer, apps, directory, options, archived):
    from types import ModuleType, SimpleNamespace
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from django.conf import settings
    from django.contrib.auth.tokens import default_token_generator
    import restore_admin_account as account
    import restore_admin_approval as approval
    import restore_admin_transport as transport
    import sealed_setup

    setup_origin = 'https://santa.example.invalid'
    artifact_directory = directory / 'setup'
    artifact_directory.mkdir(mode=0o700)
    recipient = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    der = recipient.public_key().public_bytes(serialization.Encoding.DER,
                                              serialization.PublicFormat.SubjectPublicKeyInfo)
    pin = hashlib.sha256(der).hexdigest()
    setup_options = {**options, 'recipient_sha256': pin}
    plan = job.reissue_admin(observer, apps, **setup_options)

    def url(user):
        pk = base64.urlsafe_b64encode(str(user.pk).encode()).decode().rstrip('=')
        return f'{setup_origin}/accounts/reset/{pk}/{default_token_generator.make_token(user)}/'

    reset = ModuleType('accounts.password_reset')
    reset.handler = SimpleNamespace(generate_password_reset_url=url)
    signer = Ed25519PrivateKey.generate()
    operator_public_key = signer.public_key().public_bytes_raw()
    operator_pin = hashlib.sha256(operator_public_key).hexdigest()
    snapshot = dict(scope='santa-restore-arm-readback-v1', vm_instance_id=job.selection.vm_instance_id,
                    account_verified=True, exact_vm_verified=True, cloud_write=False)
    with patch.object(approval.arm, 'observe', return_value=snapshot) as observe:
        signed = approval.issue(job, plan, fingerprint_key=KEY, approved_plan_sha256=plan['plan_sha256'],
                                signing_key=signer, operator_pin=operator_pin)
        observe.assert_called_once_with(job.selection)
    inputs = {name: value for name, value in setup_options.items() if name != 'setup_origin_sha256'}
    apply_options = dict(artifact_directory=artifact_directory, approved_plan_sha256=plan['plan_sha256'],
                         recipient_public_key=base64.b64encode(der).decode(), setup_origin=setup_origin,
                         approval=signed, operator_public_key=operator_public_key, operator_pin=operator_pin)
    with patch.dict(sys.modules, {'accounts.password_reset': reset}), patch.object(settings, 'PASSWORD_RESET_TIMEOUT', 600):
        reject(lambda: account.apply(job, writer, observer, apps, **{**inputs, 'recipient_sha256': '0' * 64},
                                     **apply_options), journal.JournalRejected)
        reject(lambda: account.apply(job, writer, observer, apps, **inputs,
                                     **{**apply_options, 'setup_origin': 'https://another.example.invalid'}),
               journal.JournalRejected)
        workspace = directory / ('9' * 32)
        workspace.mkdir(mode=0o700)
        transport.prepare(workspace, job, plan['plan_sha256'], operator_pin)
        vm = job.selection.vm_id
        subnet = vm.split('/providers/')[0] + '/providers/Microsoft.Network/virtualNetworks/vnet/subnets/host'
        host = blob.SelectedTarget(vm, job.selection.vm_instance_id, subnet, job.selection.region)
        frame = dict(scope=transport.SCOPE, workspace=workspace.name, tooling_commit='a' * 40,
                     tooling_sha256='b' * 64, host=asdict(host),
                     **transport.context(job, plan['plan_sha256'], operator_pin))
        readback = blob.encoded(dict(**frame, action='readback', approval_sha256=hashlib.sha256(signed).hexdigest()))
        submitted = blob.encoded(dict(**frame, action='submit', approval=base64.b64encode(signed).decode(),
                                      public_key=base64.b64encode(operator_public_key).decode()))

        def dispatch(raw):
            return transport.dispatch(raw, workspace, _boot=lambda _: job.verified_boot_id)

        assert dispatch(readback)['state'] == 'not-submitted'
        reject(lambda: transport.dispatch(submitted, workspace, _boot=lambda _: 'different-boot'),
               blob.RetentionRejected)
        assert dispatch(submitted)['state'] == 'submitted'
        reject(lambda: dispatch(submitted), FileExistsError)
        assert dispatch(readback)['state'] == 'pending'
        result = transport.consume(workspace, job, writer, observer, apps, **inputs,
                                   artifact_directory=artifact_directory, setup_origin=setup_origin,
                                   recipient_public_key=apply_options['recipient_public_key'],
                                   plan_sha256=plan['plan_sha256'])
        assert result['state'] == 'committed' and not result['activation_allowed']
        reject(lambda: account.apply(job, writer, observer, apps, **inputs, **apply_options),
               journal.JournalRejected)
        read_options = dict(directory=directory, artifact_directory=artifact_directory, fingerprint_key=KEY,
                            plan_sha256=plan['plan_sha256'])
        raw = account.read_artifact(job, **read_options)
        assert account.read_artifact(job, **read_options) == raw
        published = dispatch(readback)
        assert published['state'] == 'committed' and blob.encoded(published['artifact']) == raw
        assert hashlib.sha256(raw).hexdigest() == result['artifact_sha256'] and b'/accounts/reset/' not in raw
        envelope = json.loads(raw)
        wrapping = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        key = recipient.decrypt(base64.b64decode(envelope['wrapped_key_base64']), wrapping)
        aad = sealed_setup.aad('bootstrap', pin, plan['plan_sha256'],
                               sealed_setup.target_digest(options['username'], options['email']))
        payload = json.loads(AESGCM(key).decrypt(base64.b64decode(envelope['nonce_base64']),
                                                  base64.b64decode(envelope['ciphertext_base64']), aad))
        users = apps.get_model('accounts', 'User').objects
        new = users.get(pk=payload['target_pk'])
        assert new.pk != archived.pk and new.is_superuser and new.is_active
        assert new.username == options['username'] and new.email == options['email']
        assert not new.is_remote and not new.is_service_account and not new.is_staff
        assert list(users.filter(is_active=True).values_list('pk', flat=True)) == [new.pk]
        token = urlsplit(payload['setup_url']).path.rstrip('/').rsplit('/', 1)[-1]
        assert default_token_generator.check_token(new, token)
        assert not default_token_generator.check_token(archived, token)
        archived.refresh_from_db()
        assert not archived.is_active and not archived.has_usable_password()
        (artifact_directory / account.artifact_name(plan['plan_sha256'])).write_bytes(raw + b' ')
        reject(lambda: account.read_artifact(job, **read_options), journal.JournalRejected)
    print('Verified the administrator approval mailbox and sealed setup readback on restored PostgreSQL')


if __name__ == '__main__':
    run(Path(sys.argv[1]))
