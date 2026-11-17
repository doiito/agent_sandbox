"""Real interpreter regressions for idle progress and task-local rich output."""
import importlib.util
import os
from pathlib import Path
import signal
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('kernel_reference', ROOT / 'tests/reference-code-kernels.py')
REFERENCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REFERENCE)


def kernel():
    return REFERENCE.Kernel('python', argv=[sys.executable, '-u', '-B', str(ROOT / 'linux-guest/code-kernels/python.py')], cwd=str(ROOT))


class IdleKernelTest(unittest.TestCase):
    def test_user_contextvars_persist_between_cells(self):
        with kernel() as process:
            process.execute('import contextvars\nuser_value=contextvars.ContextVar("user-value")\nuser_value.set(42)\nNone')
            self.assertEqual(REFERENCE.main_result(process.execute('user_value.get()')[0]), '42')

    def test_partial_stdout_arrives_before_done_without_flush(self):
        with kernel() as process:
            process.begin('import asyncio,sys\nprint("live-print")\nsys.stdout.write("partial")\nawait asyncio.sleep(30)')
            deadline = time.monotonic() + 2
            while b'live-print\npartial' not in process.stdout and time.monotonic() < deadline:
                process.read_available(.01)
            self.assertEqual(bytes(process.stdout), b'live-print\npartial')
            self.assertFalse(any(event['type'] == 'done' for event in process.events))
            os.kill(process.process.pid, signal.SIGINT)
            self.assertTrue(any(event['type'] == 'error' for event in process.until('done', timeout=2)))

    def test_cancel_leaves_unrelated_background_task_alive(self):
        for body in ('await asyncio.sleep(30)', 'while True:\n    pass'):
            with self.subTest(body=body), tempfile.TemporaryDirectory(prefix='osv-idle-test-') as temporary, kernel() as process:
                marker = Path(temporary) / 'done'
                process.execute('import asyncio\nfrom pathlib import Path\ngate=asyncio.Event()\n'
                                'async def later():\n    await gate.wait()\n'
                                f'    Path({str(marker)!r}).write_text("survived-cancel")\n'
                                'background=asyncio.create_task(later())\nNone')
                process.interrupt('print("INTERRUPT_READY")\n' + body)
                process.execute('gate.set()')
                deadline = time.monotonic() + 2
                while not marker.exists() and time.monotonic() < deadline:
                    time.sleep(.01)
                self.assertTrue(marker.exists(), 'cancelling the cell also stopped its unrelated background task')
                self.assertEqual(marker.read_text(), 'survived-cancel')

    def test_background_task_finishes_without_another_cell(self):
        with tempfile.TemporaryDirectory(prefix='osv-idle-test-') as temporary, kernel() as process:
            marker = Path(temporary) / 'done'
            process.execute('import asyncio\nfrom pathlib import Path\n'
                            'async def later():\n    await asyncio.sleep(.05)\n'
                            f'    Path({str(marker)!r}).write_text("background-done")\n'
                            'background = asyncio.create_task(later())\nNone')
            deadline = time.monotonic() + 2
            while not marker.exists() and time.monotonic() < deadline:
                time.sleep(.01)
            self.assertTrue(marker.exists(), 'idle interpreter did not advance its background task')
            self.assertEqual(marker.read_text(), 'background-done')

    def test_saved_display_uses_the_calling_cell(self):
        with kernel() as process:
            process.execute('saved_display = display')
            events = process.execute('saved_display({"text/plain":"new-cell"},raw=True)')[0]
            output = next(event for event in events if event['type'] == 'result')
            self.assertEqual(output['execution_count'], 2)
            self.assertEqual(output['data']['text/plain'], 'new-cell')

    def test_idle_display_keeps_its_originating_cell(self):
        with kernel() as process:
            process.execute('import asyncio\nasync def later():\n    await asyncio.sleep(.05)\n'
                            '    display({"text/plain":"background"},raw=True)\n'
                            'background = asyncio.create_task(later())\nNone')
            deadline = time.monotonic() + 2
            while not process.events and time.monotonic() < deadline:
                process.read_available(.01)
            self.assertTrue(process.events, 'background display did not arrive while idle')
            self.assertEqual(process.events[0]['execution_count'], 1)
            self.assertEqual(process.events[0]['data']['text/plain'], 'background')


if __name__ == '__main__':
    unittest.main()
