import importlib.util
from pathlib import Path
import signal
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
spec=importlib.util.spec_from_file_location('cg_probe',Path(__file__).resolve().parents[1]/'scripts/probe-cgroup-membership.py')
probe=importlib.util.module_from_spec(spec);spec.loader.exec_module(probe)


class CgroupProbeTests(unittest.TestCase):
    def test_direct_domain_membership_rejects_foreign_threaded_malformed_and_truncated(self):
        for members in (b'123\n',b'123\n123\n'):
            probe.validate_membership(b'domain\n',members,123)
        for kind in (b'threaded\n',b'domain threaded\n',b'domain invalid\n',b'domain',b''):
            with self.assertRaises(ValueError):probe.validate_membership(kind,b'123\n',123)
        for members in (b'',b'123',b' 123\n',b'0123\n',b'+123\n',b'123\n456\n',b'0\n',b'123\n\n',b'123\n'*5000):
            with self.assertRaises(ValueError):probe.validate_membership(b'domain\n',members,123)
        for pid in (0,1,True,123.0):
            with self.assertRaises(ValueError):probe.validate_membership(b'domain\n',b'123\n',pid)

    def test_root_cannot_escape_or_reuse_existing_or_dangling_link(self):
        for root in ('/tmp/osv-offline-validation-20261030-cgprobe1','/var/lib/osv-sandbox',
                     '/var/lib/osv-offline-validation-20261030-cgprobe','/var/lib/../cgprobe1'):
            with self.assertRaises(ValueError):probe.validate_root(Path(root))
        with patch.object(Path,'exists',return_value=False),patch.object(Path,'is_symlink',return_value=True):
            with self.assertRaises(ValueError):probe.validate_root(Path('/var/lib/osv-offline-validation-20261030-cgprobe1'))
        with patch.object(Path,'exists',return_value=True):
            with self.assertRaises(ValueError):probe.validate_root(Path('/var/lib/osv-offline-validation-20261030-cgprobe1'))

    def test_pair_keeps_failure_if_expired_generation_changes_or_second_read_fails(self):
        leaf=Path('/sys/fs/cgroup/osv-offline-validation-20261030-cgprobe1/target')
        expected=b'0::/osv-offline-validation-20261030-cgprobe1/target\n'
        with patch.object(probe,'start_ticks',return_value=7) as ticks:
            result=probe.pair(leaf,123,7,'A1',0,0)
            self.assertFalse(result['success']);self.assertEqual(result['timing_us'],{});ticks.assert_not_called()
        for ticks,reads in [([7,8],[expected,b'domain\n',b'123\n']),([7],[expected,b'domain\n',OSError('I/O failure')])]:
            with patch.object(probe,'start_ticks',side_effect=ticks),patch.object(Path,'read_bytes',side_effect=reads):
                result=probe.pair(leaf,123,7,'B1',0,float('inf'))
            self.assertFalse(result['success']);self.assertIn('error',result)
            self.assertIn('proc',result['timing_us'])
            self.assertGreaterEqual(result['monotonic_end_ns'],result['monotonic_start_ns'])

    def test_pair_alternates_interface_order_and_validates_exact_path(self):
        leaf=Path('/sys/fs/cgroup/osv-offline-validation-20261030-cgprobe1/target')
        expected=b'0::/osv-offline-validation-20261030-cgprobe1/target\n'
        for index,reads in [(0,[expected,b'domain\n',b'123\n']),(1,[b'domain\n',b'123\n',expected])]:
            with patch.object(probe,'start_ticks',return_value=7),patch.object(Path,'read_bytes',side_effect=reads):
                result=probe.pair(leaf,123,7,'A1',index,float('inf'))
            self.assertTrue(result['success']);self.assertEqual(set(result['timing_us']),{'proc','members'})
            self.assertEqual(result['order'][0],'proc' if index==0 else 'members')
        with patch.object(probe,'start_ticks',return_value=7),patch.object(Path,'read_bytes',return_value=b'0::/foreign\n'):
            self.assertFalse(probe.pair(leaf,123,7,'A1',0,float('inf'))['success'])

    def test_cleanup_kills_only_owned_group_and_escalates_after_timeout(self):
        process=Mock(pid=123);process.poll.return_value=None
        process.wait.side_effect=[subprocess.TimeoutExpired('owned',3),0]
        with patch.object(probe.os,'killpg') as kill:
            probe.stop_owned(process)
        self.assertEqual([tuple(call.args) for call in kill.call_args_list],[(123,signal.SIGTERM),(123,signal.SIGKILL)])
        child=Mock(pid=456);child.poll.return_value=None
        with patch.object(probe.os,'killpg') as kill:
            probe.stop_owned(child,group=False)
        kill.assert_not_called();child.terminate.assert_called_once();child.wait.assert_called_once()


if __name__=='__main__':unittest.main()
