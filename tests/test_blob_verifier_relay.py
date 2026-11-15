"""Offline real crypto, controlled IMDS/systemd/HTTP; actual Linux files separate."""
import base64
import copy
from dataclasses import replace
import io
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'experiments/server'))
import blob_verifier_relay as relay
import test_blob_retention as fixtures
from test_blob_capability_relay import MemoryState as SourceMemoryState
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


class MemoryState(SourceMemoryState):
    fd = 123

    def write(self, name, raw):
        if name == 'download/backup.sealed':
            relay.need(type(raw) is bytes and len(raw) <= relay.blob.MAXIMUM and name not in self.values)
            self.values[name] = raw
        else:
            super().write(name, raw)


class Verifier(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.Retention.setUpClass()

    def setUp(self):
        self.fixture = fixtures.Retention()
        self.fixture.setUp()
        self.target, self.record = self.fixture.verifier, self.fixture.record
        self.selected, self.raw = self.fixture.blob.operation, self.fixture.raw
        self.cap = self.fixture.cap('r')
        self.boot = '55555555-5555-4555-8555-555555555555'
        self.now = int(time.time())
        self.transport = fixtures.Transport(self.raw)
        self.downloads = 0
        MemoryState.stores = {}
        self.manager = dict(LoadState='loaded', ActiveState='activating', SubState='start', Result='success',
            MainPID=str(os.getpid()), InvocationID='e'*32, ExecMainStatus='0', Job='', ControlGroup='')
        self.patches = [patch.object(relay, 'guest'), patch.object(relay, 'State', MemoryState),
            patch.object(relay, 'fresh', side_effect=self.identity), patch.object(relay, 'launch'),
            patch.object(relay, 'unit_state', side_effect=lambda _: copy.deepcopy(self.manager)),
            patch.object(relay, 'absent_cgroup', return_value=True), patch.object(relay, 'private_output', side_effect=self.check_output),
            patch.object(relay, 'read_file', side_effect=self.read_file), patch.object(relay.blob, 'verify_download', side_effect=self.download),
            patch.object(relay.os, 'mkdir'), patch.object(relay.os, 'fsync'),
            patch.object(relay.time, 'time', side_effect=lambda: self.now), patch.dict(os.environ, INVOCATION_ID='e'*32)]
        for value in self.patches:
            value.start()
            self.addCleanup(value.stop)

    def identity(self, target):
        relay.need(target == self.target)
        return self.boot

    def read_file(self, path, *args, **kwargs):
        path = Path(path)
        return MemoryState(self.selected).read(path.relative_to(MemoryState(self.selected).path).as_posix())

    def check_output(self, state, record):
        stream = io.BytesIO(state.read('download/backup.sealed', relay.blob.MAXIMUM))
        relay.blob.fingerprint(stream, record, time.monotonic()+30)

    def download(self, destination, record, capability, attempt, **kwargs):
        self.downloads += 1
        state = MemoryState(self.selected)
        self.assertEqual(destination, state.path/'download/backup.sealed')
        self.assertEqual(attempt, state.path/'get')
        self.assertTrue(kwargs['apply'])
        self.assertEqual(capability.permission, 'r')
        self.assertEqual(capability.target, self.target)
        state.write('get/intent.json', relay.encoded(dict(record, attempt='independent-exact-blob-download')))
        _, response = self.transport.get(capability, kwargs['seconds'])
        output = io.BytesIO()
        total, digest = relay.blob.download_bytes(response, output, record, time.monotonic()+30)
        state.write('download/backup.sealed', output.getvalue())
        result = dict(scope='independent-native-ciphertext-verification-v1', blob_uri=record['blob_uri'],
            ciphertext_sha256=digest, ciphertext_bytes=total, etag=response.getheader('ETag'), verifier_vm_id=self.target.vm_id,
            independent_bytes_verified=True, sealed_authenticated=False, exact_image_retained=False,
            restore_accepted=False, current_authority_established=False)
        state.write('get/verified.json', relay.encoded(result))
        return result

    def offered(self):
        return relay.create_offer('restore', self.target, self.record, self.fixture.blob, apply=True)

    def reserved(self):
        offer = self.offered()
        packet = relay.seal_offer(offer, self.cap, self.record)
        result = relay.submit(self.selected, relay.sha(relay.encoded(offer)), packet, apply=True)
        return offer, packet, result['intent_sha256']

    def terminal(self, digest, result='success', status='0'):
        with patch.dict(os.environ, SERVICE_RESULT=result, EXIT_CODE='exited', EXIT_STATUS=status):
            relay.record_terminal(self.selected, digest)

    def finish(self):
        self.manager.update(ActiveState='inactive', SubState='dead', MainPID='0')

    def test_default_apis_are_offline_and_source_target_is_rejected(self):
        self.assertFalse(relay.create_offer('restore', self.target, self.record, self.fixture.blob)['performs_mutation'])
        self.assertFalse(relay.observe(self.selected)['performs_mutation'])
        self.assertFalse(relay.get_offer(self.selected)['performs_mutation'])
        self.assertFalse(relay.execute(self.selected, 'a'*64)['performs_mutation'])
        self.assertEqual(MemoryState.stores, {})
        relay.guest.assert_not_called()
        relay.fresh.assert_not_called()
        for target in (self.fixture.source, replace(self.fixture.source,
                       vm_id=self.fixture.source.vm_id.replace('rg-azd-santa-vm-source', 'RG-AZD-SANTA-VM-SOURCE')),
                       replace(self.target, instance_id=self.fixture.source.instance_id)):
            with self.assertRaises(relay.common.RelayRejected):
                relay.create_offer('restore', target, self.record, self.fixture.blob, apply=True)

    def test_real_crypto_seals_only_exact_r_capability_and_redacts_secrets(self):
        offer = self.offered()
        packet = relay.seal_offer(offer, self.cap, self.record)
        self.assertEqual(relay.decrypt(MemoryState(self.selected), packet, offer, self.record)._token, self.cap._token)
        private = MemoryState(self.selected).read('private-key.der')
        self.assertNotIn(self.cap._token.encode(), relay.encoded(packet)+relay.encoded(offer))
        self.assertNotIn(private, relay.encoded(packet))
        for cap in (self.fixture.cap(), replace(self.cap, target=self.fixture.source),
                    replace(self.cap, blob=relay.blob.Blob(self.cap.blob.account_id, 'b'*32)),
                    replace(self.cap, ciphertext_sha256='0'*64)):
            with self.assertRaises(relay.common.RelayRejected):
                relay.seal_offer(offer, cap, self.record)

    def test_source_scopes_and_aad_cannot_cross_roles(self):
        offer = self.offered()
        packet = relay.seal_offer(offer, self.cap, self.record)
        with self.assertRaises(relay.common.RelayRejected):
            relay.common.check_offer(offer)
        with self.assertRaises(relay.common.RelayRejected):
            relay.common.seal_offer(offer, self.cap, self.record)
        with self.assertRaises(relay.common.RelayRejected):
            relay.check_offer(dict(offer, scope='blob-relay-offer-v1'))
        with self.assertRaises(relay.common.RelayRejected):
            relay.check_packet(dict(packet, scope='sealed-blob-relay-v1'), offer)
        self.assertNotEqual(relay.aad(offer), relay.common.aad(offer))

    def test_tamper_wrong_key_unknown_fields_and_wrong_offer_reject_before_reservation(self):
        offer = self.offered()
        original = relay.seal_offer(offer, self.cap, self.record)
        for key in ('wrapped_key_base64', 'nonce_base64', 'ciphertext_base64', 'offer_sha256', 'extra'):
            packet = copy.deepcopy(original)
            if key == 'extra':
                packet[key] = 'secret-never-log'
            elif key.endswith('sha256'):
                packet[key] = '0'*64
            else:
                raw = bytearray(base64.b64decode(packet[key]))
                raw[-1] ^= 1
                packet[key] = relay.encode(bytes(raw))
            with self.subTest(key=key), self.assertRaises(relay.common.RelayRejected) as caught:
                relay.submit(self.selected, relay.sha(relay.encoded(offer)), packet, apply=True)
            self.assertNotIn('secret', str(caught.exception))
            self.assertFalse(MemoryState(self.selected).exists('submit-intent.json'))
        wrong = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        MemoryState.stores[self.selected]['private-key.der'] = wrong.private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        with self.assertRaises(relay.common.RelayRejected):
            relay.submit(self.selected, relay.sha(relay.encoded(offer)), original, apply=True)

    def test_cross_boot_expiry_record_and_expected_offer_drift_fail_closed(self):
        offer = self.offered()
        packet = relay.seal_offer(offer, self.cap, self.record)
        for change in ('boot', 'expiry', 'record', 'expected'):
            old_boot, old_now = self.boot, self.now
            original = copy.deepcopy(MemoryState.stores)
            expected = relay.sha(relay.encoded(offer))
            if change == 'boot':
                self.boot = '66666666-6666-4666-8666-666666666666'
            elif change == 'expiry':
                self.now = offer['expires']
            elif change == 'record':
                record = copy.deepcopy(self.record)
                record['complete']['ciphertext_sha256'] = '0'*64
                MemoryState.stores[self.selected]['record.json'] = relay.encoded(record)
            else:
                expected = '0'*64
            with self.subTest(change=change), self.assertRaises(relay.common.RelayRejected):
                relay.submit(self.selected, expected, packet, apply=True)
            self.boot, self.now, MemoryState.stores = old_boot, old_now, original
        self.assertEqual(self.downloads, 0)

    def test_arm_token_broad_sas_unknown_fields_and_expiry_are_never_delivered(self):
        offer = self.offered()
        for token in ('eyJhbGciOiJSUzI1NiJ9.private-arm-token', self.cap._token+'&sp=r',
                      self.cap._token+'&sip=192.0.2.1', self.cap._token.replace('sp=r', 'sp=rc')):
            with self.assertRaises(relay.common.RelayRejected) as caught:
                relay.seal_offer(offer, replace(self.cap, _token=token), self.record)
            self.assertNotIn(token, str(caught.exception))
        self.now = int(self.cap.expires.timestamp())
        with self.assertRaises(relay.common.RelayRejected):
            relay.seal_offer(offer, self.cap, self.record)

    def test_once_only_download_fixed_paths_and_terminal_independent_bytes(self):
        offer, packet, digest = self.reserved()
        result = relay.execute(self.selected, digest, apply=True)
        self.assertEqual(result['state'], 'verified')
        self.assertEqual(self.transport.gets, 1)
        self.assertEqual(MemoryState(self.selected).read('download/backup.sealed', len(self.raw)), self.raw)
        with self.assertRaises(relay.common.RelayRejected):
            relay.execute(self.selected, digest, apply=True)
        relay.submit(self.selected, relay.sha(relay.encoded(offer)), packet, apply=True)
        relay.launch.assert_called_once()
        self.assertNotEqual(relay.observe(self.selected, read_guest=True)['state'], 'independent-bytes-verified')
        self.terminal(digest)
        self.finish()
        outcome = relay.observe(self.selected, read_guest=True)
        self.assertEqual(outcome['state'], 'independent-bytes-verified')
        self.assertTrue(outcome['independent_bytes_verified'])
        self.assertFalse(outcome['restore_accepted'])
        self.assertFalse(outcome['current_authority'])
        persisted = b'\n'.join(raw for name, raw in MemoryState.stores[self.selected].items() if name != 'private-key.der')
        self.assertNotIn(self.cap._token.encode(), persisted)
        self.assertEqual(self.downloads, 1)

    def test_duplicate_offer_and_unknown_launch_preserve_same_handle_no_restart(self):
        offer = self.offered()
        before = copy.deepcopy(MemoryState.stores)
        with self.assertRaises(relay.common.RelayRejected):
            self.offered()
        self.assertEqual(before, MemoryState.stores)
        self.assertEqual(relay.get_offer(self.selected, read_guest=True), offer)
        packet = relay.seal_offer(offer, self.cap, self.record)
        relay.launch.side_effect = TimeoutError('sig=private')
        with self.assertRaises(relay.common.RelayRejected):
            relay.submit(self.selected, relay.sha(relay.encoded(offer)), packet, apply=True)
        relay.submit(self.selected, relay.sha(relay.encoded(offer)), packet, apply=True)
        relay.launch.assert_called_once()
        with self.assertRaises(relay.common.RelayRejected):
            relay.get_offer(self.selected, read_guest=True)

    def test_unknown_download_and_hard_interrupt_never_replay_or_overwrite(self):
        _, _, digest = self.reserved()
        relay.blob.verify_download.side_effect = TimeoutError('sig=private')
        with self.assertRaises(relay.common.RelayRejected) as caught:
            relay.execute(self.selected, digest, apply=True)
        self.assertNotIn('private', str(caught.exception))
        self.assertEqual(relay.parsed(MemoryState(self.selected).read('body.json'))['state'], 'unknown')
        with self.assertRaises(relay.common.RelayRejected):
            relay.execute(self.selected, digest, apply=True)
        relay.blob.verify_download.assert_called_once()
        self.terminal(digest, 'timeout', '1')
        self.finish()
        self.manager.update(Result='timeout', ExecMainStatus='1')
        self.assertEqual(relay.observe(self.selected, read_guest=True)['state'], 'unknown')

    def test_hard_interrupt_after_execution_marker_preserves_unknown_without_second_get(self):
        _, _, digest = self.reserved()
        relay.blob.verify_download.side_effect = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            relay.execute(self.selected, digest, apply=True)
        self.assertEqual(relay.parsed(MemoryState(self.selected).read('body.json'))['state'], 'unknown')
        with self.assertRaises(relay.common.RelayRejected):
            relay.execute(self.selected, digest, apply=True)
        relay.blob.verify_download.assert_called_once()

    def test_non_200_download_retains_intent_and_unknown_without_success_receipt(self):
        _, _, digest = self.reserved()
        self.transport.get = Mock(return_value=(Mock(), fixtures.Response(self.raw, status=404)))
        with self.assertRaises(relay.common.RelayRejected):
            relay.execute(self.selected, digest, apply=True)
        self.assertTrue(MemoryState(self.selected).exists('get/intent.json'))
        self.assertFalse(MemoryState(self.selected).exists('get/verified.json'))
        self.assertEqual(relay.parsed(MemoryState(self.selected).read('body.json'))['state'], 'unknown')

    def test_body_alone_hard_kill_and_wrong_loaded_invocation_never_finish(self):
        _, _, digest = self.reserved()
        relay.execute(self.selected, digest, apply=True)
        self.finish()
        self.assertEqual(relay.observe(self.selected, read_guest=True)['state'], 'unknown')
        self.terminal(digest)
        self.manager['InvocationID'] = 'f'*32
        self.assertEqual(relay.observe(self.selected, read_guest=True)['state'], 'unknown')
        self.manager.update(InvocationID='e'*32, Result='signal', ActiveState='failed', ExecMainStatus='9')
        self.assertEqual(relay.observe(self.selected, read_guest=True)['state'], 'unknown')

    def test_typed_opt_ins_reject_truthy_strings_without_guest_actions(self):
        for action in (lambda: relay.create_offer('restore', self.target, self.record, self.fixture.blob, apply='false'),
                       lambda: relay.get_offer(self.selected, read_guest='false'),
                       lambda: relay.execute(self.selected, 'a'*64, apply='false'),
                       lambda: relay.observe(self.selected, read_guest='false')):
            with self.assertRaises(relay.common.RelayRejected):
                action()
        relay.guest.assert_not_called()
        self.assertEqual(MemoryState.stores, {})

    def test_wrong_bytes_wrong_http_status_and_missing_terminal_do_not_prove_success(self):
        _, _, digest = self.reserved()
        self.transport.raw = b'wrong'
        with self.assertRaises(relay.common.RelayRejected):
            relay.execute(self.selected, digest, apply=True)
        self.assertFalse(MemoryState(self.selected).exists('get/verified.json'))
        self.finish()
        self.assertEqual(relay.observe(self.selected, read_guest=True)['state'], 'unknown')

    def test_negative_gc_manager_facts_wrong_invocation_and_present_cgroup_override_files(self):
        _, _, digest = self.reserved()
        relay.execute(self.selected, digest, apply=True)
        self.terminal(digest)
        self.finish()
        self.manager.update(LoadState='not-found', InvocationID='')
        baseline = self.manager.copy()
        for changes in ({'ActiveState':'failed'}, {'SubState':'failed'}, {'Result':'timeout'}, {'MainPID':'27'},
                        {'ExecMainStatus':'1'}, {'Job':'queued'}, {'ControlGroup':'/unexpected'}, {'InvocationID':'e'*32}):
            self.manager.clear()
            self.manager.update(baseline, **changes)
            relay.absent_cgroup.reset_mock()
            with self.subTest(changes=changes):
                self.assertEqual(relay.observe(self.selected, read_guest=True)['state'], 'unknown')
            relay.absent_cgroup.assert_not_called()
        self.manager.clear()
        self.manager.update(baseline)
        relay.absent_cgroup.return_value = False
        self.assertEqual(relay.observe(self.selected, read_guest=True)['state'], 'unknown')
        relay.absent_cgroup.return_value = True
        self.assertEqual(relay.observe(self.selected, read_guest=True)['state'], 'independent-bytes-verified')

    def test_local_output_or_receipt_drift_rejects_terminal_success(self):
        _, _, digest = self.reserved()
        relay.execute(self.selected, digest, apply=True)
        self.terminal(digest)
        self.finish()
        before = copy.deepcopy(MemoryState.stores)
        for name in ('download/backup.sealed', 'get/verified.json', 'execution-intent.json'):
            MemoryState.stores[self.selected][name] = b'changed'
            with self.subTest(name=name), self.assertRaises(relay.common.RelayRejected):
                relay.observe(self.selected, read_guest=True)
            MemoryState.stores = copy.deepcopy(before)
        self.now += 3600
        self.assertEqual(relay.observe(self.selected, read_guest=True)['state'], 'independent-bytes-verified')
        self.boot = '66666666-6666-4666-8666-666666666666'
        with self.assertRaises(relay.common.RelayRejected):
            relay.observe(self.selected, read_guest=True)


class LinuxPrivateFiles(unittest.TestCase):
    @unittest.skipUnless(sys.platform == 'linux', 'Actual Linux private output/descriptor proof required')
    def test_real_private_download_and_output_preservation_with_controlled_http_identity(self):
        fixtures.Retention.setUpClass()
        fixture = fixtures.Retention()
        fixture.setUp()
        capability = fixture.cap('r')
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root = Path(directory)
            root.chmod(0o700)
            with patch.object(relay.common, 'ROOT', root), patch.object(relay.blob, 'host_identity'):
                with relay.State(fixture.blob.operation, create=True) as state:
                    os.mkdir('download', 0o700, dir_fd=state.fd)
                    destination = state.path/'download/backup.sealed'
                    transport = fixtures.Transport(fixture.raw)
                    result = relay.blob.verify_download(destination, fixture.record, capability, state.path/'get', apply=True, transport=transport)
                    self.assertTrue(result['independent_bytes_verified'])
                    relay.private_output(state, fixture.record)
                    self.assertEqual(destination.read_bytes(), fixture.raw)
                    self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)
                    with self.assertRaises(relay.blob.RetentionRejected):
                        relay.blob.verify_download(destination, fixture.record, capability, state.path/'get', apply=True, transport=transport)
                    self.assertEqual(transport.gets, 1)
                    destination.chmod(0o644)
                    with self.assertRaises(relay.common.RelayRejected):
                        relay.private_output(state, fixture.record)
                    destination.chmod(0o600)
                    destination.rename(destination.with_name('retained.sealed'))
                    destination.symlink_to('retained.sealed')
                    with self.assertRaises(OSError):
                        relay.private_output(state, fixture.record)
                    self.assertEqual(destination.with_name('retained.sealed').read_bytes(), fixture.raw)

    @unittest.skipUnless(sys.platform == 'linux', 'Actual Linux partial download preservation required')
    def test_real_interrupted_download_keeps_partial_and_original_ciphertext(self):
        fixtures.Retention.setUpClass()
        fixture = fixtures.Retention()
        fixture.setUp()
        capability = fixture.cap('r')
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root = Path(directory)
            root.chmod(0o700)
            with patch.object(relay.common, 'ROOT', root), patch.object(relay.blob, 'host_identity'):
                with relay.State(fixture.blob.operation, create=True) as state:
                    os.mkdir('download', 0o700, dir_fd=state.fd)
                    destination = state.path/'download/backup.sealed'
                    response = fixtures.Response(fixture.raw)
                    response.read = Mock(side_effect=[fixture.raw[:100], TimeoutError('private-sig')])
                    transport = Mock()
                    transport.get.return_value = Mock(), response
                    with self.assertRaises(relay.blob.RetentionRejected):
                        relay.blob.verify_download(destination, fixture.record, capability, state.path/'get', apply=True, transport=transport)
                    self.assertEqual(destination.read_bytes(), fixture.raw[:100])
                    self.assertTrue((state.path/'get/intent.json').is_file())
                    self.assertFalse((state.path/'get/verified.json').exists())
                    with self.assertRaises(relay.blob.RetentionRejected):
                        relay.blob.verify_download(destination, fixture.record, capability, state.path/'get', apply=True, transport=transport)
                    self.assertEqual(transport.get.call_count, 1)
                    self.assertEqual(fixture.raw, fixtures.Retention.raw)


if __name__ == '__main__':
    unittest.main()
