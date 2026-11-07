"""Offline receipt/ownership guards; these do not execute POSIX signal cases."""
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'experiments/server'))
import qualify_worker_posix as probe


class ProbeTests(unittest.TestCase):
    def lines(self,case='held'):
        start=dict(scope='azd-santa-workers-start-v1',nonce='1'*32,parent_pid=123,
                   grace_seconds=20,module_sha256=probe.MODULE_SHA256,command_sha256='2'*64)
        result=dict(case=case,child_pid=456,ack=case=='held',requeued=case=='held',
                    closed=case!='deadline',acknowledged=case!='deadline')
        lines=['SANTA_WORKERS_START_JSON:'+json.dumps(start),probe.CASE+json.dumps(result)]
        if case!='deadline':
            clean=dict(start,scope='azd-santa-workers-clean-stop-v1',
                       children=[dict(pid=456,exit_code=0,clean=True)])
            lines.append('SANTA_WORKERS_CLEAN_STOP_JSON:'+json.dumps(clean))
        return lines

    def check(self,lines,case='held',elapsed=1,code=0):
        return probe.validate_observation(lines,case,123,elapsed,code,'2'*64)

    def test_three_receipt_shapes(self):
        for case in probe.CASES:
            with self.subTest(case=case):
                result,clean=self.check(self.lines(case),case,20 if case=='deadline' else 1,
                                        1 if case=='deadline' else 0)
                self.assertEqual(clean,case!='deadline')
                self.assertEqual(result['case'],case)

    def test_duplicate_marker_rejected(self):
        lines=self.lines()
        with self.assertRaises(ValueError):self.check(lines+[lines[0]])

    def test_identity_and_source_mutation_rejected(self):
        for key,value in [('parent_pid',789),('nonce','invalid'),('module_sha256','3'*64),
                          ('command_sha256','4'*64),('grace_seconds',30)]:
            with self.subTest(key=key):
                lines=self.lines();start=json.loads(lines[0].split(':',1)[1]);start[key]=value
                lines[0]='SANTA_WORKERS_START_JSON:'+json.dumps(start)
                with self.assertRaises(ValueError):self.check(lines)

    def test_late_callback_or_unclosed_connection_rejected(self):
        for key in ('ack','requeued','closed','acknowledged'):
            with self.subTest(key=key):
                lines=self.lines();result=json.loads(lines[1][len(probe.CASE):]);result[key]=False
                lines[1]=probe.CASE+json.dumps(result)
                with self.assertRaises(ValueError):self.check(lines)

    def test_deadline_needs_nonzero_real_budget_without_clean(self):
        for elapsed,code,extra in [(1,1,[]),(20,0,[]),(31,1,[]),
                                    (20,1,[self.lines()[-1]])]:
            with self.subTest(elapsed=elapsed,code=code,extra=bool(extra)):
                with self.assertRaises(ValueError):self.check(self.lines('deadline')+extra,'deadline',elapsed,code)

    def test_source_bytes_rejected_before_import(self):
        with tempfile.TemporaryDirectory() as name:
            path=Path(name).resolve()/'wrong.py';path.write_text('raise AssertionError("executed")')
            with self.assertRaises(ValueError):probe.load(path)

    def test_exclusive_output_preserves_existing(self):
        with tempfile.TemporaryDirectory() as name:
            path=Path(name)/'receipt.json';probe.write(path,{'first':True})
            with self.assertRaises(FileExistsError):probe.write(path,{'second':True})
            self.assertEqual(json.loads(path.read_text()),{'first':True})

    def test_non_linux_does_not_spawn_or_create_destination(self):
        with patch.object(probe.sys,'platform','win32'),patch.object(probe.subprocess,'Popen') as spawn:
            with self.assertRaises(ValueError):probe.run('/absent','/absent')
            spawn.assert_not_called()

    def timeout_cleanup(self,parent_status):
        process=Mock(pid=123,stdout=io.BytesIO(),stderr=io.BytesIO())
        process.poll.side_effect=[parent_status,-9]
        with tempfile.TemporaryDirectory() as name,patch.object(probe.sys,'platform','linux'),\
             patch.object(probe.subprocess,'Popen',return_value=process) as spawn,\
             patch.object(probe.selectors,'DefaultSelector'),\
             patch.object(probe.time,'monotonic',side_effect=[0,11]),\
             patch.object(probe.signal,'SIGKILL',9,create=True),\
             patch.object(probe.os,'killpg',create=True) as kill:
            with self.assertRaises(ValueError):probe.run_case('idle',Path('/trusted/helper.py'),Path(name))
            kill.assert_called_once_with(123,probe.signal.SIGKILL)
            process.wait.assert_called_once_with(timeout=3)
            self.assertTrue(spawn.call_args.kwargs['start_new_session'])
            retained=json.loads((Path(name)/'idle-private-output.json').read_text())
            self.assertEqual(retained,dict(stdout='',stderr='',returncode=-9,term_sent=False))

    def test_startup_timeout_kills_only_owned_session_and_retains_output(self):
        self.timeout_cleanup(None)

    def test_exited_parent_with_inherited_pipes_still_cleans_owned_session(self):
        self.timeout_cleanup(-1)


if __name__=='__main__':unittest.main()
