"""Issue and verify one signed operator approval for an isolated recovery step."""

import argparse
from dataclasses import asdict
import sys
import threading
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

import blob_retention as blob
import restore_census_review as review
from restore_packet_operator import delivery_binding, selected_job
from restore_quarantine_journal import is_digest
import restore_sealed_inputs as sealed
from retained_image_archive import parse
from retained_image_handoff import b64, decode
from retained_image_operator import read_bytes
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


def apply_request(job, host, offer, plan, receipt, *, signing_key, fingerprint_key, offer_sha256,
                  plan_sha256, approved_plan_digest, public_key_sha256):
    """Build a canonical worker request after fresh ARM readback. Keep signing material local."""
    from restore_database_command import MAX_REQUEST, SCOPE, parse_request

    require(type(host) is blob.SelectedTarget and blob.resource_id(host.vm_id) == blob.resource_id(job.selection.vm_id)
            and host.instance_id == job.selection.vm_instance_id and host.region == job.selection.region)
    require(type(offer) is bytes and 0 < len(offer) <= 4096 and sealed.sha(offer) == offer_sha256)
    require(isinstance(signing_key, Ed25519PrivateKey) and is_digest(public_key_sha256))
    public_key = signing_key.public_key().public_bytes_raw()
    require(sealed.sha(public_key) == public_key_sha256)
    approval = issue(signing_key, job, fingerprint_key, offer, plan, plan_sha256, receipt,
                     approved_plan_digest=approved_plan_digest)
    signed = checked_document(approval, sealed.sha(approval), 4096)['body']['request']
    step = {key: value for key, value in signed.items() if key != 'scope'}
    selection = dict(selection=asdict(job.selection), target=asdict(job.target),
                     archive_sha256=job.archive_sha256, generation=job.generation, boot_id=job.verified_boot_id)
    raw = blob.encoded(dict(scope=SCOPE, action='apply', job=selection, host=asdict(host), step=step,
                            offer_sha256=offer_sha256, plan=plan, plan_sha256=plan_sha256, receipt=receipt,
                            approval=b64(approval), public_key=b64(public_key)))
    require(len(raw) <= MAX_REQUEST)
    parse_request(raw)
    return raw


def main():
    """Write just the signed request for the trusted guest transport on stdout."""
    from restore_database_command import SCOPE as WORKER_SCOPE

    parser = argparse.ArgumentParser(description=main.__doc__)
    for name in ('selection', 'job', 'operation', 'offer-reply', 'offer-sha256', 'plan', 'plan-sha256',
                 'receipt', 'approved-plan-digest', 'public-key-sha256'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    try:
        selection, job, sender_boot = selected_job(read_bytes(args.selection, 8192), read_bytes(args.job, 8192),
                                                  args.operation)
        plan = parse(read_bytes(args.plan, 8192))
        receipt = parse(read_bytes(args.receipt, 8192))
        require(plan['account_id'] == selection.store.blob.account_id and plan['operation'] == args.operation
                and plan['sender'] == selection.source.instance_id and plan['sender_boot'] == sender_boot)
        reply = parse(read_bytes(args.offer_reply, 8192))
        require(set(reply) == {'scope', 'state', 'stage', 'offer', 'offer_sha256', 'request_sha256'}
                and reply['scope'] == WORKER_SCOPE and reply['state'] == 'offered'
                and reply['offer_sha256'] == args.offer_sha256)
        offer = decode(reply['offer'], 4096)
        require(checked_document(offer, args.offer_sha256, 4096)['stage'] == reply['stage'])
        # The trusted operator launcher supplies the 32-byte Ed25519 seed followed by the 32-byte census key.
        private = sys.stdin.buffer.read(65)
        require(len(private) == 64)
        raw = apply_request(job, selection.verifier, offer, plan, receipt,
                            signing_key=Ed25519PrivateKey.from_private_bytes(private[:32]),
                            fingerprint_key=private[32:], offer_sha256=args.offer_sha256,
                            plan_sha256=args.plan_sha256, approved_plan_digest=args.approved_plan_digest,
                            public_key_sha256=args.public_key_sha256)
        sys.stdout.buffer.write(raw)
    except Exception:
        parser.exit(1, 'Santa could not build a signed recovery request. Keep the existing approval evidence.\n')


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


if __name__ == '__main__':
    main()
