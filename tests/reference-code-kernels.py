#!/opt/python/bin/python3.12
"""Exercise the real persistent kernel processes; this is not API acceptance."""
import fcntl
import json
import os
from pathlib import Path
import selectors
import signal
import struct
import subprocess
import time


class Kernel:
    def __init__(self, language, argv=None, cwd='/workspace'):
        self.language = language
        self.execution_count = 0
        to_child, self.input = os.pipe()
        self.output, from_child = os.pipe()
        child_input = fcntl.fcntl(to_child, fcntl.F_DUPFD_CLOEXEC, 20)
        child_output = fcntl.fcntl(from_child, fcntl.F_DUPFD_CLOEXEC, 20)
        os.close(to_child)
        os.close(from_child)
        argv = argv or (['/opt/python/bin/python3.12', '-u', '-B', '/validation/kernels/python.py']
                if language == 'python' else ['/opt/node/bin/node', '/validation/kernels/node.cjs', language])

        def prepare():
            os.dup2(child_input, 3, inheritable=True)
            os.dup2(child_output, 4, inheritable=True)
            os.setsid()

        self.process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, close_fds=False, preexec_fn=prepare,
                                        env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'), cwd=cwd)
        os.close(child_input)
        os.close(child_output)
        self.selector = selectors.DefaultSelector()
        for descriptor, name in [(self.output, 'control'), (self.process.stdout.fileno(), 'stdout'),
                                 (self.process.stderr.fileno(), 'stderr')]:
            os.set_blocking(descriptor, False)
            self.selector.register(descriptor, selectors.EVENT_READ, name)
        self.buffer = bytearray()
        self.events = []
        self.stdout = bytearray()
        self.stderr = bytearray()
        ready = self.until('ready')
        assert ready[-1]['language'] == language, ready

    def read_available(self, timeout):
        for key, _ in self.selector.select(timeout):
            data = os.read(key.fd, 16384)
            if not data:
                self.selector.unregister(key.fd)
                continue
            if key.data == 'stdout':
                self.stdout.extend(data)
            elif key.data == 'stderr':
                self.stderr.extend(data)
            else:
                self.buffer.extend(data)
                while len(self.buffer) >= 4:
                    size = struct.unpack('!I', self.buffer[:4])[0]
                    assert 0 < size <= 96 * 1024, size
                    if len(self.buffer) < size + 4:
                        break
                    self.events.append(json.loads(self.buffer[4:4+size]))
                    del self.buffer[:4+size]
        assert len(self.buffer) <= 96 * 1024 + 4
        assert len(self.stdout) + len(self.stderr) <= 256 * 1024

    def until(self, event, timeout=90):
        deadline = time.monotonic() + timeout
        while not any(item['type'] == event for item in self.events):
            self.read_available(min(0.05, max(0, deadline - time.monotonic())))
            if time.monotonic() >= deadline:
                raise AssertionError('kernel timeout: ' + repr((event, self.events, bytes(self.stderr))))
            if not self.selector.get_map():
                raise AssertionError('kernel closed before ' + event + ': exit=' + str(self.process.poll())
                                     + ' stderr=' + bytes(self.stderr).decode(errors='replace'))
        # A done frame follows flushed writes; collect already available output.
        for _ in range(8):
            self.read_available(0)
        events, self.events = self.events, []
        for item in events:
            if item['type'] == 'done':
                self.execution_count = item['execution_count']
        return events

    def begin(self, code, env=None):
        self.stdout.clear()
        self.stderr.clear()
        data = json.dumps({'code': code, 'env': env or {}}).encode()
        packet = memoryview(struct.pack('!I', len(data)) + data)
        while packet:
            packet = packet[os.write(self.input, packet):]

    def execute(self, code, env=None):
        self.begin(code, env)
        events = self.until('done')
        assert sum(item['type'] == 'done' for item in events) == 1, events
        return events, bytes(self.stdout).decode(errors='replace'), bytes(self.stderr).decode(errors='replace')

    def interrupt(self, code):
        self.begin(code)
        deadline = time.monotonic() + 30
        while b'INTERRUPT_READY\n' not in self.stdout:
            self.read_available(0.05)
            if time.monotonic() >= deadline:
                raise AssertionError('kernel did not enter the interrupt test')
        if self.language != 'python':
            data = json.dumps({'interrupt': self.execution_count + 1}).encode()
            os.write(self.input, struct.pack('!I', len(data)) + data)
            until = time.monotonic() + .025
            while time.monotonic() < until and not any(e['type'] == 'done' for e in self.events):
                self.read_available(.001)
        if not any(e['type'] in {'done', 'interrupt_ack'} for e in self.events):
            os.kill(self.process.pid, signal.SIGINT)
        events = self.until('done', timeout=30)
        assert any(item['type'] == 'error' for item in events), events
        return events

    def close(self):
        os.close(self.input)
        try:
            self.process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(self.process.pid, signal.SIGKILL)
            self.process.wait(timeout=3)
        self.selector.close()
        os.close(self.output)
        self.process.stdout.close()
        self.process.stderr.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def main_result(events):
    assert not any(item['type'] == 'error' for item in events), events
    return next(item['data']['text/plain'] for item in events
                if item['type'] == 'result' and item['is_main_result'])


def python():
    with Kernel('python') as first, Kernel('python') as second:
        first.execute('answer = 40\ndef add(value):\n    return answer + value')
        assert main_result(first.execute('add(2)')[0]) == '42'
        errors = second.execute('answer')[0]
        assert next(e for e in errors if e['type'] == 'error')['name'] == 'NameError'
        assert main_result(first.execute('answer')[0]) == '40'
        events, stdout, stderr = first.execute('import os,sys,subprocess\nos.write(1,b"raw stdout\\n")\n'
            'print("print stdout")\nprint("print stderr",file=sys.stderr)\n'
            'subprocess.run([sys.executable,"-c","print(123)"],check=True)\nanswer + 2')
        assert main_result(events) == '42', events
        assert 'raw stdout\n' in stdout and 'print stdout\n' in stdout and '123\n' in stdout, stdout
        assert stderr == 'print stderr\n', stderr
        events = first.execute('display({"text/html":"<b>offline</b>","application/json":{"value":42}},raw=True)\n'
                               'import pandas as pd\npd.DataFrame({"value":[42]})')[0]
        outputs = [e for e in events if e['type'] == 'result']
        assert len(outputs) == 2 and not outputs[0]['is_main_result'] and outputs[1]['is_main_result'], events
        assert outputs[0]['data']['application/json'] == {'value': 42}
        assert '<table' in outputs[1]['data']['text/html']
        assert main_result(first.execute('import asyncio\nawait asyncio.sleep(0)\nanswer + 3')[0]) == '43'
        assert main_result(first.execute('import os\nos.environ["CELL_ONLY"]', {'CELL_ONLY': 'temporary'})[0]) == "'temporary'"
        assert main_result(first.execute('os.environ.get("CELL_ONLY", "absent")')[0]) == "'absent'"
        for code, name in [('1/0', 'ZeroDivisionError'), ('def invalid(', 'SyntaxError'), ('raise SystemExit(5)', 'SystemExit')]:
            error = next(e for e in first.execute(code)[0] if e['type'] == 'error')
            assert error['name'] == name and isinstance(error['traceback'], str), error
        assert main_result(first.execute('answer + 4')[0]) == '44'
        assert any(e['type'] == 'error' for e in first.execute('display({"text/plain":"x"*40000},raw=True)')[0])
        assert main_result(first.execute('answer + 5')[0]) == '45'
        interrupted = first.interrupt('print("INTERRUPT_READY",flush=True)\nwhile True:\n    pass')
        assert any(e.get('name') == 'KeyboardInterrupt' for e in interrupted), interrupted
        assert main_result(first.execute('answer + 6')[0]) == '46'
        interrupted = first.interrupt('print("INTERRUPT_READY",flush=True)\nawait asyncio.sleep(600)')
        assert any(e.get('name') == 'KeyboardInterrupt' for e in interrupted), interrupted
        assert main_result(first.execute('answer + 7')[0]) == '47'
        assert first.execute('answer')[0][-1]['execution_count'] > 10
    with Kernel('python') as restarted:
        assert any(e.get('name') == 'NameError' for e in restarted.execute('answer')[0])
    print('PASS code-kernel-python-state-isolation-rich-async-errors-interrupt-restart', flush=True)


def node(language):
    with Kernel(language) as first, Kernel(language) as second:
        declaration = 'let answer: number = 40;' if language == 'typescript' else 'let answer = 40;'
        first.execute(declaration)
        assert main_result(first.execute('answer + 2')[0]) == '42'
        assert any(e.get('name') == 'ReferenceError' for e in second.execute('answer')[0])
        assert main_result(first.execute('await Promise.resolve(answer + 3)')[0]) == '43'
        events, stdout, stderr = first.execute('console.log("actual stdout"); console.error("actual stderr"); answer + 4')
        assert main_result(events) == '44' and stdout == 'actual stdout\n' and stderr == 'actual stderr\n', (events, stdout, stderr)
        events = first.execute('display({"text/html":"<b>offline</b>","application/json":{value:42}}); answer + 5')[0]
        assert len([e for e in events if e['type'] == 'result']) == 2, events
        assert main_result(first.execute('process.env.CELL_ONLY', {'CELL_ONLY': 'temporary'})[0]) == "'temporary'"
        assert main_result(first.execute('process.env.CELL_ONLY === undefined')[0]) == 'true'
        for code, name in [('throw new Error("actual error")', 'Error'),
                           ('await Promise.reject(new Error("await failure"))', 'Error'),
                           ('let broken = ;', 'SyntaxError')]:
            errors = [e for e in first.execute(code)[0] if e['type'] == 'error']
            assert len(errors) == 1 and errors[0]['name'] == name, errors
        assert main_result(first.execute('answer + 6')[0]) == '46'
        for _ in range(3):
            interrupted = first.interrupt('console.log("INTERRUPT_READY"); while (true) {}')
            assert any('interrupt' in e.get('value', '').lower() for e in interrupted), interrupted
            assert main_result(first.execute('answer + 7')[0]) == '47'
            interrupted = first.interrupt('await new Promise(resolve => setTimeout(resolve,10)); '
                                          'console.log("INTERRUPT_READY"); await new Promise(() => {})')
            assert any('interrupt' in e.get('value', '').lower() for e in interrupted), interrupted
            assert main_result(first.execute('answer + 8')[0]) == '48'
        assert first.execute('answer')[0][-1]['execution_count'] > 10
    with Kernel(language) as restarted:
        assert any(e.get('name') == 'ReferenceError' for e in restarted.execute('answer')[0])
    print('PASS code-kernel-' + language + '-state-isolation-async-errors-interrupt-restart', flush=True)


def main():
    assert os.geteuid() == 10000
    python()
    node('javascript')
    node('typescript')
    print('CODE_KERNEL_REFERENCE_PASS', flush=True)


if __name__ == '__main__':
    main()
