"""One-device Monitor enrollment worker for an explicitly bound private runtime.

Called inside Django only after the host/caller verifies deployment and image
identity. This module never authenticates, changes ingress or publishes to MDM.
Only recipient-encrypted credentials may leave the worker. Original Unlicense.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid
from urllib.parse import urlsplit

SCOPE = 'azd-santa-pilot-enrollment-v1'
SOURCE = '88e67b3ce49033aab028029937a6e14f7c489073'


def need(condition):
    if not condition:
        raise ValueError('Pilot enrollment binding/state check failed')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def validate(request):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    need(type(request) is dict and set(request) == {
        'scope', 'nonce', 'deployment_sha256', 'origin', 'serial', 'hardware_uuid',
        'operator_username', 'recipient_public_key', 'source_commit'})
    need(all(type(v) is str for v in request.values()) and request['scope'] == SCOPE)
    need(request['source_commit'] == SOURCE)
    need(re.fullmatch('[0-9a-f]{32}', request['nonce'])
         and re.fullmatch('[0-9a-f]{64}', request['deployment_sha256']))
    need(re.fullmatch('[A-Za-z0-9]{8,32}', request['serial']))
    need(str(uuid.UUID(request['hardware_uuid'])).upper() == request['hardware_uuid']
         and uuid.UUID(request['hardware_uuid']).int != 0)
    need(re.fullmatch('[A-Za-z0-9@.+_-]{1,150}', request['operator_username']))
    origin = request['origin']
    need(origin.isascii() and len(origin) <= 256)
    parsed = urlsplit(origin)
    need(parsed.scheme == 'https' and parsed.hostname and parsed.netloc == parsed.hostname
         and not parsed.path and not parsed.query and not parsed.fragment
         and re.fullmatch('[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', parsed.hostname))
    value = request['recipient_public_key']
    need(len(value) <= 768)
    raw = base64.b64decode(value, validate=True)
    need(base64.b64encode(raw).decode() == value)
    key = serialization.load_der_public_key(raw)
    need(isinstance(key, rsa.RSAPublicKey) and key.key_size == 3072
         and key.public_numbers().e == 65537
         and key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) == raw)
    return hashlib.sha256(canonical(request)).hexdigest(), key


def seal(request, secret, configuration_id, enrollment_id):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    digest, key = validate(request)
    need(type(secret) is str and re.fullmatch('[A-Za-z0-9_-]{16,128}', secret))
    need(type(configuration_id) is int and type(enrollment_id) is int
         and 0 < configuration_id < 2**63 and 0 < enrollment_id < 2**63)
    payload = canonical(dict(context_sha256=digest, secret=secret,
                             configuration_id=configuration_id, enrollment_id=enrollment_id))
    need(len(payload) <= 318)  # RSA3072 OAEP SHA256 maximum plaintext.
    ciphertext = key.encrypt(payload, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                                  algorithm=hashes.SHA256(), label=None))
    return dict(scope=SCOPE, context_sha256=digest,
                recipient_sha256=hashlib.sha256(base64.b64decode(request['recipient_public_key'])).hexdigest(),
                configuration_id=configuration_id, enrollment_id=enrollment_id,
                ciphertext_base64=base64.b64encode(ciphertext).decode('ascii'))


def private_directory(path):
    path = Path(path)
    need(path.is_absolute())
    for item in (path, *path.parents):
        info = item.lstat()
        need(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode)
             and info.st_uid in (0, os.getuid()) and not info.st_mode & 0o022)
    need(stat.S_IMODE(path.stat().st_mode) == 0o700 and path.stat().st_uid == os.getuid())
    return path


def write_new(path, value):
    raw = canonical(value)
    need(len(raw) <= 8192)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    directory = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def read_private(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        need(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
             and info.st_uid == os.getuid() and info.st_size <= 8192)
        return json.loads(stream.read(8193))


def models():
    from django.db import transaction
    from accounts.models import User, UserTOTP, UserWebAuthn
    from zentral.contrib.inventory.models import MetaBusinessUnit, EnrollmentSecret
    from zentral.contrib.santa.models import Configuration, Enrollment, EnrolledMachine, Rule
    return transaction, User, UserTOTP, UserWebAuthn, MetaBusinessUnit, EnrollmentSecret, Configuration, Enrollment, EnrolledMachine, Rule


def check_runtime(request):
    from django.conf import settings
    from base.deployment import version
    from zentral.conf import api_base_url
    import azd_santa_admission as admission
    import azd_santa_operator as policy
    need(not settings.DEBUG and version.strip() == SOURCE
         and api_base_url().rstrip('/') == request['origin'])
    admission.check()
    policy.check_security_store()
    _, User, TOTP, WebAuthn, *_ = models()
    user = User.objects.get(username=request['operator_username'], is_active=True, is_superuser=True)
    need(user.last_login is not None and (TOTP.objects.filter(user=user).exists()
                                        or WebAuthn.objects.filter(user=user).exists()))


def projection(request):
    _, _, _, _, MBU, Secret, Configuration, Enrollment, Machine, Rule = models()
    name = 'azd-santa-pilot-' + request['nonce']
    configuration = Configuration.objects.get(name=name)
    need(configuration.client_mode == Configuration.MONITOR_MODE
         and configuration.get_local_config() == {'ClientMode': 1}
         and not configuration.client_certificate_auth
         and configuration.allowed_path_regex == '' and configuration.blocked_path_regex == '')
    need(not Rule.objects.filter(configuration=configuration).exists())
    mbu = MBU.objects.get(name=name)
    enrollment = Enrollment.objects.get(configuration=configuration)
    secret = Secret.objects.get(pk=enrollment.secret_id)
    need(secret.meta_business_unit_id == mbu.pk and secret.serial_numbers == [request['serial']]
         and secret.udids == [request['hardware_uuid']] and secret.quota == 1
         and secret.revoked_at is None and secret.expired_at is None
         and secret.request_count in (0, 1))
    machines = list(Machine.objects.filter(enrollment=enrollment).values('serial_number', 'hardware_uuid'))
    need(len(machines) <= 1 and all(m['serial_number'] == request['serial']
         and str(m['hardware_uuid']).upper() == request['hardware_uuid'] for m in machines))
    return configuration, enrollment, secret


def run(request, checkpoint_root, operation):
    """create is once-only; observe never creates or reissues a credential."""
    digest, _ = validate(request)
    need(operation in ('create', 'observe'))
    root = private_directory(checkpoint_root)
    check_runtime(request)
    folder = root / digest
    if operation == 'create':
        folder.mkdir(mode=0o700)  # Exclusive durable attempt; do not replay.
        private_directory(folder)
        write_new(folder / 'request.json', request)
        transaction, _, _, _, MBU, Secret, Configuration, Enrollment, _, _ = models()
        name = 'azd-santa-pilot-' + request['nonce']
        with transaction.atomic():
            need(not Configuration.objects.filter(name=name).exists()
                 and not MBU.objects.filter(name=name).exists())
            configuration = Configuration.objects.create(name=name, client_mode=Configuration.MONITOR_MODE)
            configuration.full_clean()
            mbu = MBU.objects.create(name=name)
            mbu.create_enrollment_business_unit()
            secret = Secret.objects.create(meta_business_unit=mbu, serial_numbers=[request['serial']],
                                           udids=[request['hardware_uuid']], quota=1)
            secret.full_clean()
            enrollment = Enrollment.objects.create(configuration=configuration, secret=secret)
            # Ciphertext is persisted before commit; observe verifies the DB
            # projection before returning it if the commit response was lost.
            write_new(folder / 'sealed.json', seal(request, secret.secret, configuration.pk, enrollment.pk))
    else:
        private_directory(folder)
        need(read_private(folder / 'request.json') == request)
    configuration, enrollment, _ = projection(request)
    envelope = read_private(folder / 'sealed.json')
    need(envelope['scope'] == SCOPE and envelope['context_sha256'] == digest
         and envelope['configuration_id'] == configuration.pk and envelope['enrollment_id'] == enrollment.pk)
    return envelope
