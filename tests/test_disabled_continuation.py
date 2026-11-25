"""Synthetic continuation preserves the failed reservation and models real reload resets."""
import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import test_presnapshot_recovery as original
r=original.r


class DisableOnlyContinuation(unittest.TestCase):
    def setUp(self):
        self.f=original.Recovery(methodName='runTest');self.f.setUp();self.addCleanup(self.f.doCleanups)
        f=self.f
        old,self.previous,self.old_digest=f.prepared()
        self.old_intent=old
        (self.previous/'disable-intent.json').write_bytes(r.encoded({'scope':'persistent-boot-hold-v1'}))
        (self.previous/'failed.json').write_bytes(r.encoded({'automatic_replay':False,'error_type':'ValueError'}))
        f.enabled='disabled'
        # Both caller commands and the runtime command lost only their history
        # during systemctl disable's implicit daemon reload.
        for state in (f.caller,f.runtime_state):
            for key in ('ExecStart','ExecStopPost'):
                if key in state:state[key]+=' ; reload-cleared-history'
        self.predecessor_name=r.recovery_unit(self.previous)
        self.predecessor_fragment=b'original immutable failed recovery transient'
        self.predecessor_state={**f.caller,'InvocationID':r.PREDECESSOR_INVOCATION,
            'FragmentPath':'/run/systemd/transient/'+self.predecessor_name,
            'ExecStart':'predecessor executed with history','ExecStopPost':'predecessor failed recorder with history'}
        self.definitions={}
        for name in (r.CALLER,'azd-santa-runtime.service',self.predecessor_name):
            self.definitions[name]={'ExecStart':[['/usr/bin/python3',['/usr/bin/python3','-I',name+'-source'],False]],
                'ExecStopPost':[] if name=='azd-santa-runtime.service' else [['/usr/bin/python3',['/usr/bin/python3','-I',name+'-recorder'],False]]}
        self.history_metadata=47
        source=Path(r.__file__).read_bytes();program_sha=r.sha(source)
        program=f.root/'helper-upgrades/programs'/program_sha/'helper_upgrade.py';program.parent.mkdir(parents=True);program.write_bytes(source)
        pins={**r.CONTINUATION_PINS,
            'proof':r.sha((self.previous/'eligibility.json').read_bytes()),
            'disable':r.sha((self.previous/'disable-intent.json').read_bytes()),
            'failed':r.sha((self.previous/'failed.json').read_bytes()),
            'caller_profile':r.sha(r.encoded({k:f.caller[k] for k in r.PROFILE_FIELDS})),
            'runtime_profile':r.sha(r.encoded({k:f.runtime_state[k] for k in r.RUNTIME_FIELDS})),
            'predecessor_profile':r.sha(r.encoded({k:self.predecessor_state[k] for k in r.PROFILE_FIELDS})),
            'predecessor_fragment':r.sha(self.predecessor_fragment)}
        for key,name in [('caller',r.CALLER),('runtime','azd-santa-runtime.service'),('predecessor',self.predecessor_name)]:
            pins[key+'_definitions']=r.sha(r.encoded(self.definitions[name]))
        self.continuations=f.recoveries/'disable-only-continuations'
        patches=[patch.object(r,'CONTINUATIONS',self.continuations),patch.object(r,'CONTINUATION_ACTIVE',self.continuations/'active.json'),
            patch.object(r,'PREDECESSOR_OPERATION',self.previous.name.removeprefix('operation-')),
            patch.object(r,'PREDECESSOR_INTENT',self.old_digest),patch.object(r,'PREDECESSOR_PROGRAM',program_sha),
            patch.object(r,'CONTINUATION_PINS',pins),patch.object(f.h,'command',side_effect=self.command),
            patch.object(f.h,'read',side_effect=self.read)]
        for p in patches:p.start();self.addCleanup(p.stop)
        self.preserved={p.name:p.read_bytes() for p in self.previous.iterdir()}
        self.original_active=r.ACTIVE.read_bytes();f.actions.clear()

    def read(self,path,maximum=2*1024**2):
        if Path(path).name==self.predecessor_name:return self.predecessor_fragment
        return self.f.read(path,maximum)

    def command(self,args,timeout=30):
        if args[0]=='/usr/bin/busctl' and '--json=short' in args:
            def object_name(name):
                import re
                return re.sub(r'[^A-Za-z0-9]',lambda m:'_'+format(ord(m[0]),'02x'),name)
            name=next(n for n in self.definitions if args[-3].endswith('/'+object_name(n)))
            rows=[row+[self.history_metadata]*7 for row in self.definitions[name][args[-1]]]
            return json.dumps({'type':'a(sasbttttuii)','data':rows})
        if args[:3]==['systemctl','show',self.predecessor_name]:
            fields=next(v.split('=',1)[1].split(',') for v in args if v.startswith('--property='))
            return '\n'.join(k+'='+self.predecessor_state[k] for k in fields)
        if args[:2]==['systemctl','daemon-reload']:
            self.history_metadata=0
            self.predecessor_state['ExecStart']='same loaded predecessor source, cleared history'
            self.predecessor_state['ExecStopPost']='same loaded predecessor recorder, cleared history'
            # Runtime and caller were already reload-cleared before continuation;
            # their definitions and scalar failure/invocations remain unchanged.
        return self.f.command(args,timeout)

    def prepared(self):
        intent=r.prepare(self.f.h,self.f.target,self.f.folder,continuation=True)
        operation=Path(intent['operation']);return intent,operation,r.sha((operation/'intent.json').read_bytes())

    def assert_original_preserved(self):
        self.assertEqual(r.ACTIVE.read_bytes(),self.original_active)
        self.assertEqual({p.name:p.read_bytes() for p in self.previous.iterdir()},self.preserved)

    def test_explicit_new_reservation_skips_disable_and_starts_original_ids_once_after_reload(self):
        intent,op,digest=self.prepared();r.execute(op/'intent.json',digest)
        self.assertEqual(self.f.actions.count('start'),1);self.assertNotIn('disable',self.f.actions);self.assertNotIn('stop',self.f.actions)
        self.assertTrue((op/'retirement-receipt.json').exists());self.assertTrue((op/'complete.json').exists())
        self.assertEqual(json.loads((op/'complete.json').read_bytes())['predecessor_intent_sha256'],self.old_digest)
        self.assertEqual(self.history_metadata,0);self.assert_original_preserved()
        with self.assertRaises(ValueError):r.execute(op/'intent.json',digest)
        self.assertEqual(self.f.actions.count('start'),1)

    def test_original_failed_action_remains_nonreplayable_and_continuation_has_separate_active(self):
        self.prepared()
        self.assertNotEqual(r.ACTIVE,r.CONTINUATION_ACTIVE)
        with self.assertRaises(ValueError):r.execute(self.previous/'intent.json',self.old_digest)
        self.assertEqual(self.f.actions,[]);self.assert_original_preserved()

    def test_changed_loaded_command_or_hook_for_any_terminal_unit_blocks_before_retirement(self):
        for name in self.definitions:
            for prop in ('ExecStart','ExecStopPost'):
                old=copy.deepcopy(self.definitions[name][prop])
                self.definitions[name][prop]=[['/usr/bin/python3',['/usr/bin/python3','-I','different-command'],False]]
                with self.subTest(name=name,prop=prop),self.assertRaises(ValueError):r.predecessor(self.f.h,self.f.target)
                self.definitions[name][prop]=old
        self.assertTrue(self.f.request_path.exists());self.assertEqual(self.f.actions,[])

    def test_unknown_predecessor_or_continuation_markers_never_authorize_partial_replay(self):
        extra=self.previous/'retirement-intent.json';extra.write_bytes(b'unknown')
        with self.assertRaises(ValueError):self.prepared()
        extra.unlink();intent,op,digest=self.prepared();(op/'promote-manifest.json').write_bytes(b'unknown')
        with self.assertRaises(ValueError):r.execute(op/'intent.json',digest)
        self.assertTrue(self.f.request_path.exists());self.assertEqual(self.f.actions,[])

    def test_no_new_candidate_or_chunk_route_can_expand_the_explicit_continuation(self):
        with self.assertRaises(ValueError):r.prepare(self.f.h,self.f.target,self.f.folder.parent/('f'*64),continuation=True)
        with patch.object(r.sys,'platform','linux'),patch.object(r.os,'geteuid',return_value=0,create=True):
            with self.assertRaises(ValueError):r.run({'mode':'continue-request','target':self.f.target,'bundle_sha256':'f'*64})
            with self.assertRaises(ValueError):r.run({'mode':'continue-chunk','target':self.f.target,'bundle_sha256':self.f.folder.name})
        self.assertFalse(r.CONTINUATION_ACTIVE.exists());self.assertEqual(self.f.actions,[])

    def test_predecessor_descendant_and_wrong_terminal_invocation_reject(self):
        old=self.predecessor_state['InvocationID'];self.predecessor_state['InvocationID']='f'*32
        with self.assertRaises(ValueError):self.prepared()
        self.predecessor_state['InvocationID']=old
        group=self.f.cg/'system.slice'/self.predecessor_name;group.mkdir();(group/'cgroup.events').write_bytes(b'populated 1\n')
        self.predecessor_state['ControlGroup']='/system.slice/'+self.predecessor_name
        with self.assertRaises(ValueError):self.prepared()
        self.assertEqual(self.f.actions,[])

    def test_under_lock_predecessor_recheck_stops_new_effect_without_retirement(self):
        intent,op,digest=self.prepared()
        def locked(*args):
            self.f.actions.append('flock');(self.previous/'unexpected').write_bytes(b'unknown')
        with patch.object(sys.modules['fcntl'],'flock',side_effect=locked):
            with self.assertRaises(ValueError):r.execute(op/'intent.json',digest)
        self.assertTrue(self.f.request_path.exists());self.assertNotIn('start',self.f.actions)

    def test_unknown_retirement_after_rename_preserves_both_evidence_namespaces_without_promotion(self):
        intent,op,digest=self.prepared();rename=r.os.rename
        def unknown(source,destination):
            rename(source,destination);raise TimeoutError('unknown after rename')
        with patch.object(r.os,'rename',side_effect=unknown):
            with self.assertRaises(TimeoutError):r.execute(op/'intent.json',digest)
        self.assertFalse(self.f.request_path.exists());self.assertTrue((op/'retired-request.json').exists())
        self.assertFalse((op/'retirement-receipt.json').exists());self.assertFalse((op/'complete.json').exists())
        self.assertEqual(r.sha(self.f.manifest.read_bytes()),r.OLD_MANIFEST)
        self.assertNotIn('start',self.f.actions);self.assert_original_preserved()
        with self.assertRaises(ValueError):r.execute(op/'intent.json',digest)

    def test_unknown_start_or_retirement_outcome_never_replays_or_claims_completion(self):
        intent,op,digest=self.prepared();self.f.fail='start'
        with self.assertRaises(TimeoutError):r.execute(op/'intent.json',digest)
        self.assertFalse((op/'complete.json').exists());self.assert_original_preserved()
        with self.assertRaises(ValueError):r.execute(op/'intent.json',digest)
        self.assertEqual(self.f.actions.count('start'),1)

if __name__=='__main__':unittest.main()
