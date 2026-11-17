import importlib.util
from pathlib import Path
import sys
import unittest

SCRIPTS = Path(__file__).resolve().parents[1]/'scripts'
sys.path.insert(0, str(SCRIPTS))
spec = importlib.util.spec_from_file_location('osv_pipe_probe', SCRIPTS/'probe-osv-pipe-stat.py')
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


def serial(legacy=False):
    errors = probe.LEGACY_ERRORS if legacy else set()
    rows = [f'PIPE_STAT_CHECK name={name} passed={int(name not in errors)}' for name in sorted(probe.CHECKS)]
    rows.append(f'PIPE_STAT_PROBE_END checks={len(rows)} failed={len(errors)}')
    if legacy:
        rows.extend(f'PIPE_STAT_FD name={name} fd=3 result=-1 errno=9 flags=0' for name in ('read-end', 'write-end'))
    return '\n'.join(rows)+'\n'


class Classification(unittest.TestCase):
    def test_complete_success_only_accepts_fixed_phase(self):
        value = serial()
        self.assertTrue(probe.classify(value, 'fixed')['expected_observation'])
        self.assertFalse(probe.classify(value, 'baseline')['expected_observation'])

    def test_legacy_needs_io_success_and_valid_fd_ebadf(self):
        value = serial(True)
        self.assertTrue(probe.classify(value, 'baseline')['expected_observation'])
        self.assertFalse(probe.classify(value, 'fixed')['expected_observation'])
        for changed in (value.replace('name=pipe-roundtrip passed=1', 'name=pipe-roundtrip passed=0'),
                        value.replace('errno=9 flags=0', 'errno=9 flags=-1'),
                        value.replace('errno=9 flags=0', 'errno=5 flags=0')):
            self.assertFalse(probe.classify(changed, 'baseline')['expected_observation'])

    def test_missing_duplicate_and_contradictory_markers_rejected(self):
        value = serial()
        for changed in (value.replace('PIPE_STAT_CHECK name=pipe passed=1\n', ''),
                        value+'PIPE_STAT_CHECK name=pipe passed=1\n',
                        value.replace('failed=0', 'failed=1'),
                        value+'PIPE_STAT_PROBE_END checks=31 failed=0\n', ''):
            self.assertFalse(probe.classify(changed, 'fixed')['expected_observation'])

    def test_crlf_supported_without_dropping_checks(self):
        result = probe.classify(serial().replace('\n', '\r\n'), 'fixed')
        self.assertTrue(result['functional_probe_passed'])
        self.assertEqual(set(result['checks']), probe.CHECKS)

    def test_pinned_poweroff_shutdown_is_distinct_from_arbitrary_exit(self):
        value = serial()+'Unexpected exit reason on vcpu run: Shutdown\nError: RunWithoutApiError(Shutdown(GenericError))\n'
        self.assertTrue(probe.stopped_after_probe(value, 1))
        self.assertTrue(probe.stopped_after_probe(serial(), 0))
        self.assertFalse(probe.stopped_after_probe(serial(), 1))
        self.assertFalse(probe.stopped_after_probe(value, 2))

    def test_shutdown_without_probe_or_before_probe_cannot_pass(self):
        shutdown = 'Unexpected exit reason on vcpu run: Shutdown\nShutdown(GenericError)\n'
        self.assertFalse(probe.stopped_after_probe(shutdown, 1))
        self.assertFalse(probe.stopped_after_probe(shutdown+serial(), 1))

    def test_kernel_fault_does_not_pass_on_expected_shutdown(self):
        value = serial()+'Assertion failed\nUnexpected exit reason on vcpu run: Shutdown\nShutdown(GenericError)\n'
        self.assertFalse(probe.stopped_after_probe(value, 1))


if __name__ == '__main__':
    unittest.main()
