"""Sign and verify the fresh-administrator plan for one selected recovery job."""

import hashlib
import hmac
import threading
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

import restore_admin_reissue as reissue
import restore_arm_authorization as arm
from restore_guest_job import Job
from restore_quarantine_journal import encode_record, is_digest
from retained_image_handoff import b64, decode
from retained_image_parts import checked_document

DOMAIN = b'azd-santa/restore-admin-approval/v1\0'
LIFETIME = 180
FIELDS = {'binding', 'quarantine_plan_sha256', 'quarantine_census_sha256', 'runtime_sha256',
          'recipient_sha256', 'setup_origin_sha256', 'identity_sha256'}


class ApprovalRejected(ValueError):
    pass


def require(condition):
    if not condition:
        raise ApprovalRejected('Administrator reissue approval rejected')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def check_request(request, job, fingerprint_key):
    require(type(job) is Job and type(request) is dict and set(request) == FIELDS | {'scope', 'plan_sha256'}
            and request['scope'] == reissue.SCOPE
            and all(is_digest(request[name]) for name in FIELDS | {'plan_sha256'}))
    plan = {name: value for name, value in request.items() if name != 'plan_sha256'}
    require(hmac.compare_digest(sha(encode_record(plan)), request['plan_sha256'])
            and hmac.compare_digest(job.binding(fingerprint_key), request['binding']))


def issue(job, reviewed, *, fingerprint_key, approved_plan_sha256, signing_key, operator_pin):
    """Sign one exact preview after fresh cached Azure operator and VM readback."""
    try:
        require(type(reviewed) is dict and reviewed.get('state') == 'previewed'
                and reviewed.get('activation_allowed') is False
                and isinstance(signing_key, Ed25519PrivateKey) and is_digest(operator_pin)
                and hmac.compare_digest(sha(signing_key.public_key().public_bytes_raw()), operator_pin))
        request = {name: value for name, value in reviewed.items() if name not in ('state', 'activation_allowed')}
        check_request(request, job, fingerprint_key)
        require(is_digest(approved_plan_sha256)
                and hmac.compare_digest(request['plan_sha256'], approved_plan_sha256))
        observed = arm.observe(job.selection)
        require(observed == dict(scope='santa-restore-arm-readback-v1', vm_instance_id=job.selection.vm_instance_id,
                                 account_verified=True, exact_vm_verified=True, cloud_write=False))
        issued = int(time.time())
        body = dict(request=request, issued=issued, expires=issued + LIFETIME)
        return encode_record(dict(body=body, signature=b64(signing_key.sign(DOMAIN + encode_record(body)))))
    except Exception:
        raise ApprovalRejected('Could not issue administrator reissue approval') from None


class Verify:
    """Accept only the independently pinned operator key and consume approval once."""

    def __init__(self, job, fingerprint_key, raw, *, public_key, operator_pin):
        try:
            require(type(public_key) is bytes and len(public_key) == 32 and is_digest(operator_pin)
                    and hmac.compare_digest(sha(public_key), operator_pin) and type(raw) is bytes)
            packet = checked_document(raw, sha(raw), 2048)
            require(set(packet) == {'body', 'signature'} and type(packet['body']) is dict)
            body = packet['body']
            require(set(body) == {'request', 'issued', 'expires'} and type(body['issued']) is int
                    and type(body['expires']) is int and body['issued'] <= int(time.time()) < body['expires']
                    and body['expires'] - body['issued'] == LIFETIME)
            check_request(body['request'], job, fingerprint_key)
            Ed25519PublicKey.from_public_bytes(public_key).verify(
                decode(packet['signature'], 64), DOMAIN + encode_record(body))
            self._request, self._expires = body['request'], body['expires']
            self._used = False
            self._lock = threading.Lock()
        except Exception:
            raise ApprovalRejected('Could not verify administrator reissue approval') from None

    def __call__(self, request):
        with self._lock:
            require(not self._used and type(request) is dict and request == self._request
                    and int(time.time()) < self._expires)
            self._used = True
            return True
