"""Original Unlicense. Separate r-only independent ciphertext verifier relay.

Recipient confidentiality is not operator/capture/ARM authority. No backup key,
ARM token, source capture access, service restore, cleanup or automatic replay.
"""
import argparse
from contextlib import ExitStack
from dataclasses import asdict
import datetime as dt
import os
from pathlib import Path
import re
import secrets
import sys
import time
import urllib.parse
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
import blob_capability_relay as common
import blob_retention as blob

# Reuse reviewed private-files, RSA recipient, canonical encoding and systemd /
# kernel proof contracts. Source c-only executable and its scopes stay unchanged.
State = common.State
need, safe, sha, encoded, parsed = common.need, common.safe, common.sha, common.encoded, common.parsed
encode, decode, operation = common.encode, common.decode, common.operation
fresh, unit_state, absent_cgroup = common.fresh, common.unit_state, common.absent_cgroup
read_file, command = common.read_file, common.command
ROOT, MAX_PACKET, ALGORITHM = common.ROOT, common.MAX_PACKET, common.ALGORITHM
COMMON_SHA = 'eb6a5eee83ededf08e78c6203aeb7babc8e36129cf836f2af7ef80be0f6a9a1c'


def guest():
    need(sys.platform == 'linux' and os.geteuid() == 0)
    script = Path(__file__).absolute()
    need(script.is_relative_to(ROOT) and re.fullmatch(r'/[A-Za-z0-9/_.-]+', str(script)))
    read_file(script, 262144)
    need(sha(read_file(Path(common.__file__), 262144)) == COMMON_SHA
         and sha(read_file(Path(blob.__file__), 262144)) == common.RETENTION_SHA)


def selection(environment, target, record):
    blob.checked_record(record)
    need(type(environment) is str and re.fullmatch(r'[a-z0-9-]{2,32}', environment)
         and type(target) is blob.SelectedTarget
         and blob.resource_id(target.vm_id) != blob.resource_id(record['source_vm_id'])
         and target.instance_id != record['source_instance_id']
         and target.vm_id.split('/resourceGroups/')[1].split('/')[0] == 'rg-azd-santa-vm-' + environment
         and target.vm_id.split('/')[2] == record['source_vm_id'].split('/')[2])
    return operation(record['operation_id'])


def check_offer(value):
    need(type(value) is dict and value.get('scope') == 'blob-verifier-offer-v1')
    # Structural reuse only. Original offer bytes and verifier domain remain
    # bound by encryption; a source offer/packet cannot cross the role boundary.
    return common.check_offer(dict(value, scope='blob-relay-offer-v1'))


def current(offer, record, *, require_fresh=True):
    target, _ = check_offer(offer)
    selection(offer['environment'], target, record)
    now = int(time.time())
    need((not require_fresh or offer['created'] <= now < offer['expires'])
         and fresh(target) == offer['boot_id'] and offer['program_sha256'] == sha(Path(__file__).read_bytes())
         and offer['retention_sha256'] == common.RETENTION_SHA and offer['record_sha256'] == sha(encoded(record)))
    return target


@safe
def create_offer(environment, target, record, selected_blob, *, apply=False, lifetime=1800):
    need(type(apply) is bool)
    selected = selection(environment, target, record)
    need(type(selected_blob) is blob.Blob and selected_blob.uri == record['blob_uri']
         and selected_blob.operation == selected and type(lifetime) is int and 1 <= lifetime <= 1800)
    if not apply:
        return dict(scope='blob-verifier-offer-plan-v1', performs_mutation=False, operation=selected)
    guest()
    boot, now = fresh(target), int(time.time())
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    with State(selected, create=True) as state:
        state.write('offer-intent.json', encoded(dict(scope='one-verifier-offer-v1', record_sha256=sha(encoded(record)), boot_id=boot)))
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        public = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        private = key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        offer = dict(scope='blob-verifier-offer-v1', version=1, algorithm=ALGORITHM, offer_id=uuid.uuid4().hex,
            created=now, expires=now+lifetime, boot_id=boot, environment=environment, target=asdict(target),
            operation=selected, record_sha256=sha(encoded(record)), account_id=selected_blob.account_id, blob_uri=record['blob_uri'],
            ciphertext_sha256=record['complete']['ciphertext_sha256'], ciphertext_bytes=record['complete']['ciphertext_bytes'],
            public_key_base64=encode(public), kid_sha256=sha(public), program_sha256=sha(Path(__file__).read_bytes()),
            retention_sha256=common.RETENTION_SHA)
        check_offer(offer)
        current(offer, record)
        state.write('private-key.der', private)
        state.write('record.json', encoded(record))
        state.write('offer.json', encoded(offer))
        return offer


def token_fields(token, offer, now):
    need(type(token) is str and token.isascii() and 0 < len(token) <= 4096)
    values = blob.unique(urllib.parse.parse_qsl(token, keep_blank_values=True, strict_parsing=True))
    need(set(values) == {'sv', 'sr', 'sp', 'spr', 'st', 'se', 'sig'} and values['sp'] == 'r')
    # Reuse the exact existing SAS grammar/time/signature checks, after requiring
    # r on the original token. This local projection never leaves validation.
    values['sp'] = 'c'
    return common.token_fields(urllib.parse.urlencode(values), offer, now)


def aad(offer):
    return b'azd-santa/blob-verifier/v1\0' + encoded(offer)


def check_packet(packet, offer):
    need(type(packet) is dict and packet.get('scope') == 'sealed-blob-verifier-v1')
    return common.check_packet(dict(packet, scope='sealed-blob-relay-v1'), offer)


@safe
def seal_offer(offer, capability, record):
    target, public = check_offer(offer)
    selection(offer['environment'], target, record)
    blob.valid_capability(capability, record, 'r')
    need(capability.target == target and capability.blob.account_id == offer['account_id']
         and capability.blob.uri == offer['blob_uri'] == record['blob_uri'] and offer['record_sha256'] == sha(encoded(record))
         and capability.ciphertext_sha256 == offer['ciphertext_sha256'] == record['complete']['ciphertext_sha256']
         and offer['ciphertext_bytes'] == record['complete']['ciphertext_bytes']
         and capability.expires.utcoffset() == dt.timedelta(0))
    now = int(time.time())
    need(offer['created'] <= now < offer['expires'])
    expiry = token_fields(capability._token, offer, now)
    need(int(capability.expires.timestamp()) == expiry)
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key = serialization.load_der_public_key(public)
    need(isinstance(key, rsa.RSAPublicKey) and key.key_size == 3072 and key.public_numbers().e == 65537
         and key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) == public)
    secret, nonce = AESGCM.generate_key(bit_length=256), secrets.token_bytes(12)
    body = encoded(dict(scope='blob-verifier-capability-v1', offer_sha256=sha(encoded(offer)), token=capability._token, expires=expiry))
    ciphertext = AESGCM(secret).encrypt(nonce, body, aad(offer))
    wrapped = key.encrypt(secret, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    packet = dict(scope='sealed-blob-verifier-v1', version=1, algorithm=ALGORITHM, offer_sha256=sha(encoded(offer)),
        kid_sha256=offer['kid_sha256'], wrapped_key_base64=encode(wrapped), nonce_base64=encode(nonce), ciphertext_base64=encode(ciphertext))
    check_packet(packet, offer)
    return packet


def decrypt(state, packet, offer, record):
    wrapped, nonce, ciphertext = check_packet(packet, offer)
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key = common.private_recipient(state, offer)
    secret = key.decrypt(wrapped, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    need(len(secret) == 32)
    value = parsed(AESGCM(secret).decrypt(nonce, ciphertext, aad(offer)))
    need(set(value) == {'scope', 'offer_sha256', 'token', 'expires'} and value['scope'] == 'blob-verifier-capability-v1'
         and value['offer_sha256'] == sha(encoded(offer)) and type(value['expires']) is int)
    expiry = token_fields(value['token'], offer, int(time.time()))
    need(expiry == value['expires'])
    target, _ = check_offer(offer)
    selection(offer['environment'], target, record)
    return blob.Capability(blob.Blob(offer['account_id'], record['operation_id']), target, 'r', offer['ciphertext_sha256'],
                           dt.datetime.fromtimestamp(expiry, dt.timezone.utc), value['token'])


def context(state, expected=None):
    raw = state.read('offer.json')
    offer = parsed(raw)
    need(raw == encoded(offer) and offer['operation'] == state.operation and (expected is None or sha(raw) == expected))
    target, _ = check_offer(offer)
    record = parsed(state.read('record.json'))
    selection(offer['environment'], target, record)
    need(offer['record_sha256'] == sha(encoded(record)) and offer['blob_uri'] == record['blob_uri']
         and offer['ciphertext_sha256'] == record['complete']['ciphertext_sha256']
         and offer['ciphertext_bytes'] == record['complete']['ciphertext_bytes'])
    return offer, record


def load_intent(state, digest=None):
    raw = state.read('submit-intent.json')
    value = parsed(raw)
    need(raw == encoded(value) and set(value) == {'scope', 'operation', 'unit', 'offer_sha256', 'envelope_sha256', 'seconds', 'program_sha256'}
         and value['scope'] == 'one-verifier-blob-relay-v1' and value['operation'] == state.operation
         and type(value['seconds']) is int and 1 <= value['seconds'] <= 900
         and value['program_sha256'] == sha(Path(__file__).read_bytes()) and (digest is None or sha(raw) == digest))
    offer, _ = context(state, value['offer_sha256'])
    need(value['unit'] == 'azd-santa-blob-relay-' + offer['offer_id'] + '.service')
    return value, sha(raw)


def launch(intent, digest):
    script = Path(__file__).absolute()
    need(script.is_relative_to(ROOT) and re.fullmatch(r'/[A-Za-z0-9/_.-]+', str(script))
         and sha(read_file(script, 262144)) == intent['program_sha256'])
    command(['systemd-run', '--no-block', '--unit=' + intent['unit'].removesuffix('.service'), '--property=Type=oneshot',
        '--property=Restart=no', '--property=Slice=system.slice', '--property=KillMode=control-group', '--property=Delegate=no',
        '--property=NoNewPrivileges=yes', '--property=PrivateTmp=yes', '--property=ProtectHome=yes', '--property=UMask=0077',
        '--property=TimeoutStartSec=' + str(intent['seconds']+300), '--property=RuntimeMaxSec=' + str(intent['seconds']+300),
        '--property=ExecStopPost=/usr/bin/python3 -I ' + str(script) + ' --record-terminal ' + intent['operation'] + ' --sha256 ' + digest,
        '/usr/bin/python3', '-I', str(script), '--execute', intent['operation'], '--sha256', digest])


@safe
def get_offer(selected, *, read_guest=False):
    need(type(read_guest) is bool)
    operation(selected)
    if not read_guest:
        return dict(scope='blob-verifier-read-offer-plan-v1', performs_mutation=False, operation=selected)
    guest()
    with State(selected) as state:
        offer, record = context(state)
        current(offer, record)
        common.private_recipient(state, offer)
        need(not state.exists('submit-intent.json'))
        return offer


@safe
def submit(selected, expected_offer_sha256, packet, *, apply=False, seconds=900):
    need(type(apply) is bool)
    operation(selected)
    need(re.fullmatch(blob.HEX, expected_offer_sha256) and type(seconds) is int and 1 <= seconds <= 900
         and type(packet) is dict and set(packet) == common.PACKET_FIELDS and len(encoded(packet)) <= MAX_PACKET
         and packet['scope'] == 'sealed-blob-verifier-v1')
    if not apply:
        return dict(scope='blob-verifier-submit-plan-v1', performs_mutation=False, operation=selected, automatic_replay=False)
    guest()
    with State(selected) as state:
        offer, record = context(state, expected_offer_sha256)
        raw = encoded(packet)
        if state.exists('submit-intent.json'):
            intent, _ = load_intent(state)
            need(intent['envelope_sha256'] == sha(raw))
            return _observe(state)
        current(offer, record)
        decrypt(state, packet, offer, record)
        name = 'envelope-' + sha(raw) + '.json'
        if state.exists(name):
            need(state.read(name) == raw)
        else:
            state.write(name, raw)
        intent = dict(scope='one-verifier-blob-relay-v1', operation=selected,
            unit='azd-santa-blob-relay-' + offer['offer_id'] + '.service', offer_sha256=sha(encoded(offer)),
            envelope_sha256=sha(raw), seconds=seconds, program_sha256=offer['program_sha256'])
        state.write('submit-intent.json', encoded(intent))
        launch(intent, sha(encoded(intent)))
        return _observe(state)


def body(intent, digest, state, outcome=None):
    return dict(scope='blob-verifier-body-v1', state=state, intent_sha256=digest, offer_sha256=intent['offer_sha256'],
        envelope_sha256=intent['envelope_sha256'], download_outcome_sha256=sha(encoded(outcome)) if outcome is not None else None,
        automatic_replay=False, permission='r', independent_bytes_verified=state == 'verified',
        sealed_authenticated=False, restore_accepted=False, current_authority=False)


@safe
def execute(selected, digest, *, apply=False, transport=None):
    need(type(apply) is bool)
    operation(selected)
    need(re.fullmatch(blob.HEX, digest))
    if not apply:
        return dict(scope='blob-verifier-execute-plan-v1', performs_mutation=False, operation=selected)
    guest()
    with State(selected) as state:
        intent, actual = load_intent(state, digest)
        invocation = os.environ.get('INVOCATION_ID', '')
        need(re.fullmatch(r'[a-f0-9]{32}', invocation))
        manager = unit_state(intent['unit'])
        need(manager['LoadState'] == 'loaded' and manager['InvocationID'] == invocation
             and manager['MainPID'] == str(os.getpid()) and manager['ActiveState'] in ('activating', 'active')
             and not any(state.exists(name) for name in ('execution-intent.json', 'body.json', 'terminal.json')))
        state.write('execution-intent.json', encoded(dict(scope='one-download-execution-v1', intent_sha256=actual, invocation=invocation)))
        try:
            offer, record = context(state, intent['offer_sha256'])
            current(offer, record)
            raw = state.read('envelope-' + intent['envelope_sha256'] + '.json')
            need(sha(raw) == intent['envelope_sha256'])
            capability = decrypt(state, parsed(raw), offer, record)
            remaining = min(intent['seconds'], int(capability.expires.timestamp())-int(time.time()), offer['expires']-int(time.time()))
            need(remaining >= 1)
            os.mkdir('download', 0o700, dir_fd=state.fd)
            os.fsync(state.fd)
            result = blob.verify_download(state.path/'download/backup.sealed', record, capability,
                state.path/'get', apply=True, seconds=remaining, transport=transport)
            current(offer, record)
            need(result == download_result(state, offer, record))
            state.write('body.json', encoded(body(intent, actual, 'verified', result)))
            return body(intent, actual, 'verified', result)
        except BaseException:
            if not state.exists('body.json'):
                state.write('body.json', encoded(body(intent, actual, 'unknown')))
            raise


def private_output(state, record):
    with ExitStack() as stack:
        fd, name = blob.parent(state.path/'download/backup.sealed', stack)
        stream = stack.enter_context(os.fdopen(os.open(name, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK, dir_fd=fd), 'rb'))
        before = os.fstat(stream.fileno())
        State.file(before)
        blob.fingerprint(stream, record, time.monotonic()+60)
        need(blob.identity(before) == blob.identity(os.fstat(stream.fileno()))
             == blob.identity(os.stat(name, dir_fd=fd, follow_symlinks=False)))


def download_result(state, offer, record):
    observed = parsed(read_file(state.path/'get/verified.json', private=True))
    need(set(observed) == {'scope', 'blob_uri', 'ciphertext_sha256', 'ciphertext_bytes', 'etag', 'verifier_vm_id',
        'independent_bytes_verified', 'sealed_authenticated', 'exact_image_retained', 'restore_accepted', 'current_authority_established'}
        and observed['scope'] == 'independent-native-ciphertext-verification-v1'
        and observed['blob_uri'] == record['blob_uri'] and observed['ciphertext_sha256'] == offer['ciphertext_sha256']
        and observed['ciphertext_bytes'] == offer['ciphertext_bytes'] and observed['verifier_vm_id'] == offer['target']['vm_id']
        and re.fullmatch(r'"[A-Za-z0-9._-]{1,128}"', observed['etag']) and observed['independent_bytes_verified'] is True
        and all(observed[key] is False for key in ('sealed_authenticated', 'exact_image_retained', 'restore_accepted', 'current_authority_established')))
    private_output(state, record)
    return observed


def verified_body(state, intent, digest):
    raw = state.read('body.json')
    value = parsed(raw)
    need(type(value) is dict and value['state'] in ('verified', 'unknown'))
    if value['state'] == 'unknown':
        need(value == body(intent, digest, 'unknown'))
    else:
        offer, record = context(state, intent['offer_sha256'])
        need(value == body(intent, digest, 'verified', download_result(state, offer, record)))
    return raw, value


@safe
def record_terminal(selected, digest):
    guest()
    operation(selected)
    need(re.fullmatch(blob.HEX, digest))
    with State(selected) as state:
        intent, actual = load_intent(state, digest)
        invocation = os.environ.get('INVOCATION_ID', '')
        result, code, status = os.environ.get('SERVICE_RESULT'), os.environ.get('EXIT_CODE'), os.environ.get('EXIT_STATUS', '')
        need(re.fullmatch(r'[a-f0-9]{32}', invocation)
             and result in ('success', 'exit-code', 'signal', 'core-dump', 'watchdog', 'timeout', 'resources', 'protocol', 'start-limit-hit', 'oom-kill')
             and code in ('exited', 'killed', 'dumped') and (re.fullmatch(r'[0-9]{1,3}', status)
             or status in ('HUP', 'INT', 'QUIT', 'KILL', 'ABRT', 'SEGV', 'ALRM', 'TERM', 'PIPE', 'BUS', 'ILL', 'FPE')))
        need(parsed(state.read('execution-intent.json')) == dict(scope='one-download-execution-v1', intent_sha256=actual, invocation=invocation))
        raw, value = verified_body(state, intent, actual) if state.exists('body.json') else (None, None)
        if result == 'success':
            need(code == 'exited' and status == '0' and value is not None and value['state'] == 'verified')
        state.write('terminal.json', encoded(dict(scope='blob-verifier-terminal-v1', intent_sha256=actual, invocation=invocation,
            service_result=result, exit_code=code, exit_status=status, body_sha256=sha(raw) if raw is not None else None)))


def _observe(state):
    offer, record = context(state)
    current(offer, record, require_fresh=False)
    result = dict(scope='blob-verifier-observation-v1', operation=state.operation, offer_sha256=sha(encoded(offer)), state='offered',
        automatic_replay=False, independent_bytes_verified=False, restore_accepted=False, current_authority=False)
    if not state.exists('submit-intent.json'):
        return result
    intent, digest = load_intent(state)
    manager, phase = unit_state(intent['unit']), 'unknown'
    quiet = all(manager[key] == value for key, value in dict(ActiveState='inactive', SubState='dead', Result='success',
        MainPID='0', ExecMainStatus='0', Job='', ControlGroup='').items())
    terminal = parsed(state.read('terminal.json')) if state.exists('terminal.json') else None
    if terminal is not None:
        need(set(terminal) == {'scope', 'intent_sha256', 'invocation', 'service_result', 'exit_code', 'exit_status', 'body_sha256'}
             and terminal['scope'] == 'blob-verifier-terminal-v1' and terminal['intent_sha256'] == digest
             and re.fullmatch(r'[a-f0-9]{32}', terminal['invocation']))
        invocation = manager['InvocationID'] == ('' if manager['LoadState'] == 'not-found' else terminal['invocation'])
        if quiet and invocation and terminal['service_result'] == 'success' and terminal['exit_code'] == 'exited' and terminal['exit_status'] == '0':
            raw, value = verified_body(state, intent, digest)
            need(value['state'] == 'verified' and sha(raw) == terminal['body_sha256']
                 and parsed(state.read('execution-intent.json')) == dict(scope='one-download-execution-v1', intent_sha256=digest, invocation=terminal['invocation']))
            if absent_cgroup(intent['unit']):
                phase = 'independent-bytes-verified'
    elif manager['LoadState'] == 'loaded' and manager['Result'] == 'success' and manager['ActiveState'] in ('active', 'activating', 'deactivating'):
        phase = 'in-progress'
    result.update(state=phase, unit=intent['unit'], intent_sha256=digest, independent_bytes_verified=phase == 'independent-bytes-verified')
    return result


@safe
def observe(selected, *, read_guest=False):
    need(type(read_guest) is bool)
    operation(selected)
    if not read_guest:
        return dict(scope='blob-verifier-observe-plan-v1', performs_mutation=False, operation=selected)
    guest()
    with State(selected) as state:
        return _observe(state)


if __name__ == '__main__':
    try:
        need(sys.flags.isolated and sys.platform == 'linux' and os.geteuid() == 0)
        class NoRawParser(argparse.ArgumentParser):
            def error(self, message):
                raise common.RelayRejected('Invalid private verifier job arguments')
        parser = NoRawParser()
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument('--execute')
        group.add_argument('--record-terminal')
        parser.add_argument('--sha256', required=True)
        args = parser.parse_args()
        if args.execute:
            execute(args.execute, args.sha256, apply=True)
        else:
            record_terminal(args.record_terminal, args.sha256)
    except BaseException:
        sys.stderr.write('Verifier relay job requires same-handle observation; never replay.\n')
        sys.exit(1)
