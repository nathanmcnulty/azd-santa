"""Issue and verify one signed operator approval for an isolated recovery step."""

import threading
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

import restore_census_review as review
from restore_packet_operator import delivery_binding
from restore_quarantine_journal import is_digest
import restore_sealed_inputs as sealed
from retained_image_handoff import b64, decode
from retained_image_parts import checked_document

SCOPE = 'santa-restore-operator-approval-v1'
DOMAIN = b'azd-santa/restore-operator-approval/v1\0'
LIFETIME = 180


class ApprovalRejected(ValueError):
    pass


def require(condition):
    if not condition:
        raise ApprovalRejected('Restore operator approval rejected')


def context(job, offer, plan, plan_sha256, receipt):
    capsule, packet_sha, _ = delivery_binding(job, plan, plan_sha256, receipt)
    digest = sealed.sha(offer)
    doc = checked_document(offer, digest, 4096)
    request = dict(scope=review.SCOPE, stage=doc['stage'], binding=doc['binding'],
                   review_sha256=doc['review_sha256'], plan_digest=doc['plan_digest'])
    expected = sealed.operation(job, request['stage'], request['binding'],
                                request['review_sha256'], request['plan_digest'])
    sealed.check_offer(offer, digest, expected)
    operation = dict(scope=SCOPE, request=request, offer_sha256=digest, delivery_plan_sha256=plan_sha256,
                     delivery_receipt_sha256=sealed.sha(review.encode(receipt)),
                     receiver_capsule=capsule, packet_sha256=packet_sha)
    return operation, doc['expires']


def issue(signing_key, job, fingerprint_key, offer, plan, plan_sha256, receipt, *, approved_plan_digest):
    """Sign only after explicit plan confirmation and a fresh selected ARM readback."""
    try:
        require(isinstance(signing_key, Ed25519PrivateKey))
        operation, expiry = context(job, offer, plan, plan_sha256, receipt)
        request = operation['request']
        require(is_digest(approved_plan_digest) and approved_plan_digest == request['plan_digest']
                and job.binding(fingerprint_key) == request['binding'])
        authorize = job.confirm(fingerprint_key=fingerprint_key, stage=request['stage'],
                                review_sha256=request['review_sha256'], plan_digest=approved_plan_digest)
        require(authorize(request) is True)
        now = int(time.time())
        require(now < expiry)
        body = dict(**operation, issued=now, expires=min(expiry, now + LIFETIME))
        signature = signing_key.sign(DOMAIN + review.encode(body))
        require(type(signature) is bytes and len(signature) == 64)
        return review.encode(dict(body=body, signature=b64(signature)))
    except Exception:
        raise ApprovalRejected('Could not issue restore operator approval') from None


class Verify:
    """Authenticate a pinned approval and consume it once under the restore journal lock."""

    def __init__(self, public_key, public_key_sha256, approval, job, offer, plan, plan_sha256, receipt):
        try:
            require(type(public_key) is bytes and len(public_key) == 32
                    and is_digest(public_key_sha256) and sealed.sha(public_key) == public_key_sha256)
            operation, offer_expiry = context(job, offer, plan, plan_sha256, receipt)
            packet = checked_document(approval, sealed.sha(approval), 4096)
            require(set(packet) == {'body', 'signature'} and type(packet['body']) is dict)
            body = packet['body']
            require(set(body) == set(operation) | {'issued', 'expires'}
                    and all(body[name] == value for name, value in operation.items())
                    and type(body['issued']) is int and type(body['expires']) is int
                    and body['issued'] <= int(time.time()) < body['expires'] <= offer_expiry
                    and body['expires'] - body['issued'] <= LIFETIME)
            Ed25519PublicKey.from_public_bytes(public_key).verify(
                decode(packet['signature'], 64), DOMAIN + review.encode(body))
            self._request = operation['request']
            self._expires = body['expires']
            self._used = False
            self._lock = threading.Lock()
        except Exception:
            raise ApprovalRejected('Could not verify restore operator approval') from None

    def __call__(self, request):
        with self._lock:
            require(not self._used and type(request) is dict and request == self._request
                    and int(time.time()) < self._expires)
            self._used = True
            return True
