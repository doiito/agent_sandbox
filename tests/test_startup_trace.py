import importlib.util
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
spec=importlib.util.spec_from_file_location('startup_trace',Path(__file__).resolve().parents[1]/'scripts/trace-startup.py')
trace=importlib.util.module_from_spec(spec);spec.loader.exec_module(trace)


class TraceTests(unittest.TestCase):
    def parse(self,text):
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'trace';path.write_text(text)
            return trace.parse_trace(path)

    def test_raw_buffers_and_exec_never_decode_private_data_real_strace(self):
        marker='TRACE_PRIVATE_SENTINEL_a85f004a64b38a65'
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);helper=root/'helper.py';output=root/'syscalls'
            helper.write_text('import os,sys\nr,w=os.pipe()\nos.write(w,'+repr(marker.encode())+')\nos.close(w)\nos.read(r,4096)\nos.close(r)\nos.getrandom(8)\npid=os.fork()\nif pid==0:os.execv(sys.executable,[sys.executable,"-c","import os;os.write(1,b\\\"CHILD_AFTER_EXEC_PAYLOAD\\\")"])\nos.waitpid(pid,0)\n')
            result=subprocess.run(['strace',*trace.trace_options(),'-o',str(output),sys.executable,str(helper)],
                                  capture_output=True,timeout=10,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(result.stdout,'CHILD_AFTER_EXEC_PAYLOAD')
            raw=output.read_text();self.assertNotIn(marker,raw);self.assertNotIn(marker.encode().hex(),raw)
            self.assertNotIn('CHILD_AFTER_EXEC_PAYLOAD',raw)
            calls,pending=trace.parse_trace(output)
            self.assertTrue(any(row['name']=='write' for row in calls))
            self.assertTrue(any(row['name']=='read' for row in calls))
            self.assertTrue(any(row['name']=='getrandom' for row in calls))
            self.assertGreaterEqual(raw.count('execve('),2)
            # Child exec detaches: subsequent child interpreter reads/writes
            # cannot be present, while the original interpreter stays traced.
            exec_tids=[int(match[1]) for line in raw.splitlines() if (match:=trace.LINE.match(line)) and match[3].startswith('execve(')]
            self.assertEqual(len(set(exec_tids)),2)
            for tid in set(exec_tids)-{exec_tids[0]}:
                self.assertFalse(any(row['tid']==tid and row['name'] in ('read','write') for row in calls))

    def test_unfinished_resumed_are_joined_by_thread_and_keep_entry_time(self):
        calls,pending=self.parse('11 100.100000 read(0x8, 0x100, 0x80 <unfinished ...>\n'
            '12 100.101000 write(0x9, 0x200, 0x10) = 0x10 <0.000100>\n'
            '11 100.120000 <... read resumed>) = 0x20 <0.020000>\n')
        self.assertEqual(pending,{})
        self.assertEqual([row['tid'] for row in calls],[11,12])
        self.assertEqual(calls[0]['at_ns'],100100000000)
        self.assertEqual(calls[0]['duration_ns'],20000000)
        self.assertEqual(calls[0]['returned'],32)

    def test_decoded_buffers_unknown_syscalls_and_unmatched_resume_fail(self):
        for line in ('11 100.0 read(8, "SECRET", 10) = 6 <0.001>\n',
                     '11 100.0 <... read resumed>) = 6 <0.001>\n',
                     '11 100.0 ioctl(8, 0, 0) = 0 <0.001>\n','unrecognized\n'):
            with self.assertRaises(ValueError):self.parse(line)
        _,pending=self.parse('11 100.0 read(0x8, 0x100, 0x80 <unfinished ...>\n')
        self.assertEqual(pending[11][1],'read')

    def test_trace_arguments_and_limits_cannot_enable_data_dump(self):
        args=trace.trace_options()
        self.assertIn('--detach-on=execve',args);self.assertIn('-f',args)
        self.assertNotIn('--kill-on-exit',args)
        self.assertEqual([x for x in args if x.startswith(('read=','write='))],[])
        self.assertTrue(set(trace.RAW)<=set(trace.TRACE))
        with patch.object(trace.os,'umask'),patch.object(trace.resource,'setrlimit') as limit:
            trace.tracer_limits()
        limit.assert_called_once_with(trace.resource.RLIMIT_FSIZE,(64<<20,64<<20))

    def test_verified_detach_tail_stays_unknown_and_default_rejects(self):
        text='11 100.0 read(0x8, 0x100, 0x80) = 0x20 <0.001>\n12 100.1 fcntl(9, F_SETFL, O_NONBL'
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'trace';path.write_text(text)
            with self.assertRaisesRegex(ValueError,'missing syscall duration'):trace.parse_trace(path)
            calls,pending=trace.parse_trace(path,allow_detach_tail=True)
            self.assertEqual(len(calls),1)
            self.assertEqual(pending,{12:(100100000000,'fcntl','fcntl(9, F_SETFL, O_NONBL')})

    def test_detach_tail_never_accepts_decoded_unknown_or_interior_missing_duration(self):
        for text in ('11 100.0 read(8, "SECRET", 10', '11 100.0 ioctl(8, 0',
                     '11 100.0 fcntl(9, F_SETFL, O_NONBL\n',
                     '11 100.0 fcntl(9, F_SETFL, O_NONBL\n12 100.1 close(9) = 0 <0.001>\n'):
            with tempfile.TemporaryDirectory() as temporary:
                path=Path(temporary)/'trace';path.write_text(text)
                with self.assertRaises(ValueError):trace.parse_trace(path,allow_detach_tail=True)

    def test_watchdog_stops_only_tracer_on_size_or_time_limit(self):
        for size,elapsed in ((trace.SOFT_BYTES,0),(0,trace.MAX_SECONDS+1)):
            with tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary)
                with (root/'launcher.trace').open('w') as output:output.truncate(size)
                observer=trace.LauncherTrace(os.getpid(),root)
                observer.process=Mock();observer.process.poll.return_value=None
                with patch.object(observer.requested_stop,'wait',return_value=False), \
                     patch.object(trace.time,'monotonic',return_value=observer.started+elapsed):
                    observer.watch()
                self.assertEqual(len(observer.errors),1)
                observer.process.send_signal.assert_called_once_with(signal.SIGINT)

    def test_guest_fd_routing_handles_interleaving_reuse_and_child_processes(self):
        a,b='job-'+'a'*24,'job-'+'b'*24
        directory=lambda vm:'/run/'+vm+'/jailer/firecracker/'+vm+'/root'
        bodies=[
            (11,'clone','clone(child_stack=NULL, flags=CLONE_VM|CLONE_THREAD) = 12'),
            (11,'clone','clone(child_stack=NULL, flags=CLONE_VM|CLONE_VFORK|SIGCHLD) = 13'),
            (12,'openat','openat(AT_FDCWD, "'+directory(a)+'", O_RDONLY) = 7'),
            (12,'socket','socket(AF_UNIX, SOCK_STREAM, 0) = 9'),
            (12,'connect','connect(9, {sa_family=AF_UNIX, sun_path="/proc/self/fd/7/agent.vsock"}, 40) = 0'),
            (12,'close','close(7) = 0'),
            (11,'openat','openat(AT_FDCWD, "'+directory(b)+'", O_RDONLY) = 7'),
            (13,'openat','openat(AT_FDCWD, "/unrelated-child", O_RDONLY) = 9'),
            (11,'read','read(0x9, 0x100, 0x80) = 0x10'),
            (11,'close','close(9) = 0'),
            (11,'socket','socket(AF_UNIX, SOCK_STREAM, 0) = 9'),
            (11,'connect','connect(9, {sa_family=AF_UNIX, sun_path="/proc/self/fd/7/agent.vsock"}, 40) = 0'),
            (12,'read','read(0x9, 0x200, 0x80) = 0x20')]
        text=''.join(str(tid)+' 100.'+str(i).zfill(6)+' '+body+' <0.000001>\n' for i,(tid,_,body) in enumerate(bodies))
        calls,_=self.parse(text)
        selected,threads=trace.guest_calls(calls,{11},{a,b})
        self.assertEqual(threads,{11,12})
        reads=[row for row in selected if row['name']=='read']
        self.assertEqual([(row['instance_id'],row['connection']) for row in reads],[(a,1),(b,2)])


if __name__=='__main__':unittest.main()
