"""Verify a populated database rewrap and rollback on the sealed PostgreSQL fixture."""
import base64
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
from pathlib import Path
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
        bundle = tooling.build(repo, commit, version=19)
        carrier_root = root / 'carrier'
        carrier_root.mkdir(mode=0o700)
        recipient_root = root / 'recipients'

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
            selection = dict(stage=stage, plan_digest=preview['plan_digest'], review_sha256=inputs['review_sha256'])
            signer = Ed25519PrivateKey.generate()
            public_key = signer.public_key().public_bytes_raw()
            public_pin = sealed.sha(public_key)
            host = receiver_target(selected_job)
            reject(lambda: worker_boot(replace(host, instance_id='55555555-5555-4555-8555-555555555555')),
                   blob.RetentionRejected)
            bound_stage = dict(binding=selected_job.binding(KEY), **selection)
            state = dict(root=recipient_root, _boot=worker_boot)
            job_input = dict(selection=asdict(selected_job.selection), target=asdict(selected_job.target),
                             boot_id=selected_job.verified_boot_id, **bound)
            frame = dict(scope=database_command.SCOPE, job=job_input, host=asdict(host), step=bound_stage)
            offered = database_command.dispatch(blob.encoded(dict(**frame, action='offer', public_key_sha256=public_pin)),
                                                recipient_root=state['root'], _boot=state['_boot'])
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
                    return database_command.dispatch(blob.encoded(request), carrier_root=carrier_root,
                        directory=directory, recipient_root=state['root'], _boot=state['_boot'])
                finally:
                    writer.ensure_connection()
                    observer.ensure_connection()

            reject(lambda: apply_file(receipt, '0' * 64), operator_approval.ApprovalRejected)
            reject(lambda: apply_file(receipt, key=other_signer.public_key().public_bytes_raw(),
                                      signed=other_approval), operator_approval.ApprovalRejected)
            reject(lambda: apply_file({**receipt, 'upload_confirmed': not receipt['upload_confirmed']}),
                   operator_approval.ApprovalRejected)
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
            result = apply_file(receipt)
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
        print('Reopened and consumed boot-local recipients for both PostgreSQL writes')
        print('The guest command applied both signed stages through its local Django connections')
        print('Verified transactional rewrap, late rollback, unchanged Terraform bytes and exact JSONB numbers')
    finally:
        connections.close_all()


if __name__ == '__main__':
    run(Path(sys.argv[1]))
