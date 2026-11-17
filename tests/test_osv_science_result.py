import copy
import importlib.util
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
spec = importlib.util.spec_from_file_location('science_result', Path(sys.path[0]) / 'e2e-osv-python-science.py')
science = importlib.util.module_from_spec(spec)
spec.loader.exec_module(science)


class ScienceResultTests(unittest.TestCase):
    def result(self, code=7):
        return {'id': '0123456789abcdef01234567', 'state': 'guest_error' if code else 'succeeded',
                'exit_code': code, 'protocol_ok': True, 'timed_out': False,
                'guest_result': {'job_id': '0123456789abcdef01234567', 'exit_code': code,
                                 'runner_status': 0, 'ok': code == 0, 'stdout': 'OUT\nCLEANUP\n', 'stderr': 'ERR\n'}}

    def test_completed_nonzero_is_guest_error(self):
        self.assertTrue(science.valid_result(200, self.result(), 7, ('OUT', 'CLEANUP'), 'ERR'))
        value = self.result()
        value['state'] = 'failed'
        self.assertFalse(science.valid_result(200, value, 7))

    def test_zero_is_success(self):
        self.assertTrue(science.valid_result(200, self.result(0), 0))
        self.assertFalse(science.valid_result(200, self.result(), 0))

    def test_exit_codes_must_agree(self):
        for field in ('host', 'guest'):
            value = self.result()
            (value if field == 'host' else value['guest_result'])['exit_code'] = 0
            self.assertFalse(science.valid_result(200, value, 7))

    def test_runner_and_guest_success_are_checked(self):
        for key, changed in (('runner_status', -5), ('ok', True)):
            value = self.result()
            value['guest_result'][key] = changed
            self.assertFalse(science.valid_result(200, value, 7))

    def test_identity_and_transport(self):
        for key, changed in (('id', 'different'), ('protocol_ok', False), ('timed_out', True)):
            value = self.result()
            value[key] = changed
            self.assertFalse(science.valid_result(200, value, 7))
        self.assertFalse(science.valid_result(500, self.result(), 7))

    def test_every_cleanup_and_output_marker_is_required(self):
        self.assertFalse(science.valid_result(200, self.result(), 7, ('OUT', 'MISSING'), 'ERR'))
        self.assertFalse(science.valid_result(200, self.result(), 7, 'OUT', 'MISSING'))

    def test_missing_or_malformed_capture(self):
        for changed in (None, {}, {'stdout': 42, 'stderr': ''}):
            value = copy.deepcopy(self.result())
            value['guest_result'] = changed
            self.assertFalse(science.valid_result(200, value, 7))


if __name__ == '__main__':
    unittest.main()
