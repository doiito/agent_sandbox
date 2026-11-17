"""SIGINT must wake a selector that has already entered an async wait."""
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]


class KernelInterruptTest(unittest.TestCase):
    def test_sigint_wakes_suspended_task_and_keeps_loop_usable(self):
        program = '''
import asyncio, importlib.util, signal, sys
spec = importlib.util.spec_from_file_location('kernel', sys.argv[1])
kernel = importlib.util.module_from_spec(spec)
spec.loader.exec_module(kernel)
signal.signal(signal.SIGINT, kernel.interrupt)
async def first():
    kernel.ACTIVE_TASK = asyncio.current_task()
    print('READY', flush=True)
    try:
        await asyncio.sleep(600)
    except asyncio.CancelledError:
        print('CANCELLED', flush=True)
    finally:
        kernel.ACTIVE_TASK = None
async def second():
    await asyncio.sleep(0)
    return 42
with asyncio.Runner() as runner:
    runner.run(first())
    print(runner.run(second()), flush=True)
'''
        child = subprocess.Popen(
            [sys.executable, '-u', '-c', program, str(ROOT / 'linux-guest/code-kernels/python.py')],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        try:
            self.assertEqual(child.stdout.readline(), 'READY\n')
            deadline = time.monotonic() + 5
            while True:
                wait = Path(f'/proc/{child.pid}/wchan').read_text()
                if 'epoll' in wait or 'ep_poll' in wait:
                    break
                self.assertIsNone(child.poll())
                self.assertLess(time.monotonic(), deadline, wait)
                time.sleep(.001)
            os.kill(child.pid, signal.SIGINT)
            stdout, stderr = child.communicate(timeout=3)
            self.assertEqual(child.returncode, 0, stderr)
            self.assertEqual(stdout, 'CANCELLED\n42\n')
        finally:
            if child.poll() is None:
                child.kill()
            child.communicate()


if __name__ == '__main__':
    unittest.main()
