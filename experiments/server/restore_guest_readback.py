"""Read the selected Santa recovery guest identity through Azure Action Run Command."""

import argparse
from base64 import b64encode
import hashlib
import json
import re
import uuid

import blob_retention as blob
import private_arm_adapter as arm
from retained_image_run_command import RECEIPT, build_script, submit_action
from restore_arm_authorization import Selection, VM_PATH, observe

SCOPE = 'santa-restore-guest-readback-v1'
IDENTITY = """import base64, hashlib, json, os, re
from pathlib import Path
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def unique(pairs):
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError()
    return result


def selected_boot(requested):
    request = urllib.request.Request(
        'http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01',
        headers={'Metadata': 'true'})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(request, timeout=3) as response:
        body = response.read(65537)
    if len(body) > 65536:
        raise ValueError()
    metadata = json.loads(body, object_pairs_hook=unique)
    if (metadata['resourceId'].casefold() != requested['vm_id'].casefold()
            or metadata['vmId'].lower() != requested['vm_instance_id']
            or metadata['location'] != requested['region']
            or metadata['osType'] != 'Linux'):
        raise ValueError()
    boot = Path('/proc/sys/kernel/random/boot_id').read_text(encoding='ascii').strip()
    if not re.fullmatch(GUID, boot):
        raise ValueError()
    return boot
"""
IDENTITY = f'GUID = {blob.GUID!r}\n' + IDENTITY
GUEST = IDENTITY + """

def main():
    raw = base64.b64decode(os.environ.pop('SANTA_GUEST_SELECTION'), validate=True)
    requested = json.loads(raw, object_pairs_hook=unique)
    boot = selected_boot(requested)
    result = dict(scope=SCOPE, batch_sha256=hashlib.sha256(raw).hexdigest(),
                  vm_instance_id=requested['vm_instance_id'], boot_id=boot)
    print(RECEIPT + json.dumps(result, sort_keys=True, separators=(',', ':')))


try:
    main()
except Exception:
    raise SystemExit(1) from None
"""
GUEST = f'SCOPE = {SCOPE!r}\nRECEIPT = {RECEIPT!r}\n' + GUEST


def operation(selection, nonce):
    arm.require(type(selection) is Selection and re.fullmatch(r'[a-f0-9]{32}', nonce))
    target = dict(vm_id=selection.vm_id, vm_instance_id=selection.vm_instance_id, region=selection.region)
    raw = blob.encoded(target)
    encoded = b64encode(raw).decode('ascii')
    script = build_script(f"export SANTA_GUEST_SELECTION='{encoded}'\n", GUEST, nonce)
    return script, hashlib.sha256(raw).hexdigest()


def readback(selection, *, _cli=None):
    """Exercise existing Run Command rights and verify a fresh host boot receipt."""
    try:
        nonce = uuid.uuid4().hex
        script, digest = operation(selection, nonce)
        application = arm.resolve_cli() if _cli is None else None

        def call(args, seconds):
            if _cli is not None:
                return _cli(args, seconds)
            return arm.bounded_cli(args, seconds, application=application)

        before = observe(selection, _cli=call)
        group = re.fullmatch(VM_PATH, selection.vm_id, re.IGNORECASE | re.ASCII)[2]
        args = ['--subscription', selection.subscription, '--resource-group', group, '--name', 'vm-santa-lab']
        receipt = submit_action(call, args, script, nonce, digest, 180, scope=SCOPE)
        arm.require(set(receipt) == {'scope', 'batch_sha256', 'vm_instance_id', 'boot_id'}
                    and receipt['vm_instance_id'] == selection.vm_instance_id
                    and re.fullmatch(blob.GUID, receipt['boot_id'])
                    and observe(selection, _cli=call) == before)
        return dict(scope=SCOPE, vm_id=selection.vm_id, vm_instance_id=receipt['vm_instance_id'],
                    boot_id=receipt['boot_id'])
    except Exception:
        raise arm.ArmRejected() from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('tenant', 'subscription', 'account', 'vm-id', 'vm-instance-id', 'region'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--live', action='store_true', help='Submit one read-only guest probe')
    args = vars(parser.parse_args())
    live = args.pop('live')
    try:
        selection = Selection(**args)
        if live:
            result = readback(selection)
        else:
            script, digest = operation(selection, '0' * 32)
            result = dict(scope=SCOPE, state='planned', vm_instance_id=selection.vm_instance_id,
                          selection_sha256=digest, script_bytes=len(script), submits_run_command=False)
        print(json.dumps(result, sort_keys=True))
    except arm.ArmRejected:
        parser.exit(1, 'Santa restore guest readback did not complete\n')


if __name__ == '__main__':
    main()
