"""Real subprocess lifecycle checks and manager boundary failures for validation jobs."""
import concurrent.futures
import ctypes
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'scripts/validation_job.py'
spec = importlib.util.spec_from_file_location('validation_job', SOURCE)
job = importlib.util.module_from_spec(spec)
spec.loader.exec_module(job)
PYTHON = Path(sys.executable).resolve()
SCRATCH = Path(os.environ.get('OSV_VALIDATION_JOB_TEST_ROOT', str(ROOT / 'build/validation/durable-validation-jobs')))
MANAGED_TEMP = None


def setUpModule():
    global SCRATCH, MANAGED_TEMP
    if 'OSV_VALIDATION_JOB_TEST_ROOT' in os.environ:
        if not SCRATCH.resolve().is_relative_to(ROOT / 'build/validation/durable-validation-jobs'):
            raise ValueError('test scratch must stay in this project validation directory')
    else:
        # These are generated process fixtures, not runtime dependencies. Keep
        # project-disk fsync latency out of intentional overlap observations.
        MANAGED_TEMP = tempfile.TemporaryDirectory(prefix='osv-validation-job-tests-', dir='/tmp')
        SCRATCH = Path(MANAGED_TEMP.name)
    SCRATCH.mkdir(parents=True, exist_ok=True)
    # Adopt and explicitly reap only our known grandchildren when their worker
    # exits; PID 1 in the local namespace need not implement orphan reaping.
    if ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), 'cannot become child subreaper')


def tearDownModule():
    if MANAGED_TEMP is not None:
        MANAGED_TEMP.cleanup()


def wait_for(predicate, seconds=10):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.02)
    raise AssertionError('bounded process observation timed out')


class ValidationJobTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=str(SCRATCH), prefix='case-')
        self.root = Path(self.temporary.name)
        self.store = self.root / 'jobs'
        self.batch_lock = self.root / 'batch.lock'
        self.children = []
        self.adopted = []
        self.commands = []
        self.script = self.root / 'work.py'
        self.script.write_text('print("completed-once", flush=True)\n')
        self.manager = {'observed': True, 'LoadState': 'not-found', 'ActiveState': 'inactive', 'SubState': 'dead'}

    def tearDown(self):
        for process in self.children:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        for pid in self.adopted:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                os.waitpid(pid, 0)
            except ChildProcessError:
                pass
        self.temporary.cleanup()

    def plan(self, *, timeout=10, limit=65536, extra=None):
        inputs = {str(PYTHON): job.sha(PYTHON), str(self.script): job.sha(self.script)}
        inputs.update(extra or {})
        return {'protocol': job.PROTOCOL, 'argv': [str(PYTHON), str(self.script)],
                'cwd': str(self.root), 'inputs': inputs, 'timeout_seconds': timeout, 'log_limit_bytes': limit}

    def submit(self, identity='one', plan=None, response=None):
        def manager_call(command, **kwargs):
            self.commands.append(command)
            if isinstance(response, BaseException):
                raise response
            return subprocess.CompletedProcess(command, 0, b'', b'')
        with mock.patch.object(job, 'observe_manager', return_value=self.manager), mock.patch.object(job.subprocess, 'run', side_effect=manager_call):
            result = job.submit(self.store, identity, plan or self.plan(), self.batch_lock)
        return self.store / identity, result

    def launch(self, directory):
        output = (directory / 'worker-observer.log').open('wb')
        try:
            process = subprocess.Popen([str(PYTHON), str(directory / 'worker.py'), '_run', str(directory)],
                                       stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT, env=job.ENV)
        finally:
            output.close()
        self.children.append(process)
        return process

    def finish(self, process, directory, code):
        self.assertEqual(process.wait(timeout=12), code)
        return job.read_json(directory / 'result.json')

    def assert_reaped(self, pid):
        wait_for(lambda: not Path('/proc', str(pid)).exists() or Path('/proc', str(pid), 'stat').read_text().rsplit(')', 1)[1].split()[0] == 'Z')
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass
        self.assertFalse(Path('/proc', str(pid)).exists())

    def test_success_claim_once_and_private_files(self):
        directory, _ = self.submit()
        result = self.finish(self.launch(directory), directory, 0)
        self.assertTrue(result['passed'])
        self.assertTrue(result['inputs_unchanged'])
        self.assertEqual((directory / 'job.log').read_text(), 'completed-once\n')
        digest = job.sha(directory / 'result.json')
        self.assertEqual(self.launch(directory).wait(timeout=5), 75)
        self.assertEqual(job.sha(directory / 'result.json'), digest)
        self.assertFalse((directory / 'job.log').stat().st_mode & 0o077)
        with mock.patch.object(job, 'observe_manager', return_value=self.manager):
            self.assertTrue(job.status(directory)['passed'])

    def test_lost_submission_response_never_replays(self):
        plan = self.plan()
        directory, first = self.submit(plan=plan, response=subprocess.TimeoutExpired('systemd-run', 15))
        self.assertFalse(job.read_json(directory / 'submission.json')['response_received'])
        self.manager.update(LoadState='loaded', ActiveState='active', SubState='running')
        _, again = self.submit(plan=plan)
        self.assertEqual(len(self.commands), 1)
        self.assertEqual(again['state'], 'running')
        self.assertFalse(again['execution_replayed'])
        altered = dict(plan, timeout_seconds=11)
        with self.assertRaisesRegex(ValueError, 'different plan'):
            self.submit(plan=altered)
        self.assertEqual(len(self.commands), 1)
        command = self.commands[0]
        for flag in ['--service-type=exec', '--property=Restart=no', '--property=KillMode=control-group', '--property=UMask=0077']:
            self.assertIn(flag, command)

    def test_concurrent_same_id_submission_starts_once(self):
        plan = self.plan()
        calls = []
        def invoke(command, **kwargs):
            calls.append(command)
            time.sleep(0.05)
            return subprocess.CompletedProcess(command, 0, b'', b'')
        with mock.patch.object(job, 'observe_manager', return_value=self.manager), mock.patch.object(job.subprocess, 'run', side_effect=invoke):
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(job.submit, self.store, 'one', plan, self.batch_lock) for _ in range(2)]
                for future in futures:
                    future.result(timeout=5)
        self.assertEqual(len(calls), 1)

    def test_manager_query_failure_stays_unknown(self):
        directory, _ = self.submit()
        for error in [subprocess.TimeoutExpired('systemctl', 10), OSError('bus unavailable')]:
            with self.subTest(error=type(error).__name__), mock.patch.object(job.subprocess, 'run', side_effect=error):
                observed = job.status(directory)
                self.assertEqual(observed['state'], 'observation-failed')
                self.assertFalse(observed['terminal'])
        partial = subprocess.CompletedProcess([], 1, 'LoadState=not-found\n', '')
        with mock.patch.object(job.subprocess, 'run', return_value=partial):
            self.assertEqual(job.status(directory)['state'], 'observation-failed')

    def test_missing_and_failed_manager_never_imply_success(self):
        directory, _ = self.submit()
        with mock.patch.object(job, 'observe_manager', return_value=self.manager):
            self.assertEqual(job.status(directory)['state'], 'not-started')
            (directory / 'claimed').touch()
            self.assertEqual(job.status(directory)['state'], 'interrupted')
            job.write_json(directory / 'result.json', {'protocol': job.PROTOCOL, 'passed': True})
            self.assertFalse(job.status(directory)['passed'])
        self.manager.update(LoadState='loaded', ActiveState='failed', SubState='failed')
        with mock.patch.object(job, 'observe_manager', return_value=self.manager):
            self.assertEqual(job.status(directory)['state'], 'failed')

    def test_invocation_identity_change_rejects_old_success(self):
        directory, _ = self.submit()
        result = self.finish(self.launch(directory), directory, 0)
        result['manager_invocation_id'] = 'first'
        job.write_json(directory / 'result.json', result)
        self.manager['InvocationID'] = 'second'
        with mock.patch.object(job, 'observe_manager', return_value=self.manager):
            self.assertFalse(job.status(directory)['passed'])

    def test_durable_success_receipt_waits_for_original_worker_exit(self):
        directory, _ = self.submit()
        # This is a deterministic manager/receipt boundary check. The other
        # cases exercise real workers; repeating one here couples this race
        # counterexample to unrelated filesystem fsync scheduling.
        launch = job.read_json(directory / 'launch.json')
        job.write_json(directory / 'result.json', {
            'protocol': job.PROTOCOL, 'plan_sha256': launch['plan_sha256'],
            'worker_sha256': launch['worker_sha256'], 'passed': True, 'inputs_unchanged': True,
            'execution': {'passed': True, 'exit_code': 0, 'reason': 'exit'}})
        for state, substate, pid in [('active', 'running', '123'), ('deactivating', 'stop-sigterm', '0'),
                                     ('active', 'exited', '123')]:
            manager = dict(self.manager, ActiveState=state, SubState=substate, MainPID=pid)
            with self.subTest(manager=manager), mock.patch.object(job, 'observe_manager', return_value=manager):
                observed = job.status(directory)
                self.assertEqual(observed['state'], 'finishing')
                self.assertFalse(observed['terminal'])
                self.assertFalse(observed['passed'])
        manager = dict(self.manager, ActiveState='active', SubState='exited', MainPID='0')
        with mock.patch.object(job, 'observe_manager', return_value=manager):
            self.assertTrue(job.status(directory)['passed'])

    def test_failed_exit_retains_code_and_stderr(self):
        self.script.write_text('import sys\nprint("expected-failure", file=sys.stderr)\nsys.exit(7)\n')
        directory, _ = self.submit()
        result = self.finish(self.launch(directory), directory, 1)
        self.assertEqual(result['execution']['exit_code'], 7)
        self.assertFalse(result['passed'])
        self.assertIn('expected-failure', (directory / 'job.log').read_text())

    def test_changed_input_prevents_execution(self):
        self.script.write_text('from pathlib import Path\nPath("executed").touch()\n')
        directory, _ = self.submit()
        self.script.write_text(self.script.read_text() + '# changed after submission\n')
        result = self.finish(self.launch(directory), directory, 1)
        self.assertIn('input mismatch', result['error'])
        self.assertFalse((self.root / 'executed').exists())

    def test_input_modified_by_successful_command_cannot_pass(self):
        artifact = self.root / 'bound.txt'
        artifact.write_text('before')
        self.script.write_text('from pathlib import Path\nPath("bound.txt").write_text("after")\n')
        directory, _ = self.submit(plan=self.plan(extra={str(artifact): job.sha(artifact)}))
        result = self.finish(self.launch(directory), directory, 1)
        self.assertEqual(result['execution']['exit_code'], 0)
        self.assertFalse(result['passed'])
        self.assertIn('input mismatch', result['error'])

    def test_timeout_kills_and_reaps_grandchild(self):
        self.script.write_text('import subprocess,sys,time\nfrom pathlib import Path\np=subprocess.Popen([sys.executable,"-c","import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(60)"])\nPath("grandchild.pid").write_text(str(p.pid))\ntime.sleep(60)\n')
        directory, _ = self.submit(plan=self.plan(timeout=1))
        process = self.launch(directory)
        pid = int(wait_for(lambda: (self.root / 'grandchild.pid').read_text() if (self.root / 'grandchild.pid').exists() else None))
        self.adopted.append(pid)
        result = self.finish(process, directory, 1)
        self.assertEqual(result['execution']['reason'], 'timeout')
        self.assert_reaped(pid)

    def test_log_flood_stops_at_exact_limit(self):
        self.script.write_text('import os\nwhile True: os.write(1,b"x"*65536)\n')
        directory, _ = self.submit(plan=self.plan(limit=1024))
        result = self.finish(self.launch(directory), directory, 1)
        self.assertEqual(result['execution']['reason'], 'log-limit')
        self.assertEqual((directory / 'job.log').stat().st_size, 1024)

    def test_worker_termination_records_failure_and_reaps_command(self):
        self.script.write_text('import os,time\nfrom pathlib import Path\nPath("command.pid").write_text(str(os.getpid()))\ntime.sleep(60)\n')
        directory, _ = self.submit()
        process = self.launch(directory)
        pid = int(wait_for(lambda: (self.root / 'command.pid').read_text() if (self.root / 'command.pid').exists() else None))
        process.terminate()
        result = self.finish(process, directory, 1)
        self.assertEqual(result['error_type'], 'Terminated')
        self.assertFalse(result['passed'])
        self.assertFalse(Path('/proc', str(pid)).exists())

    def test_orphan_retaining_stdout_is_reaped_and_rejected(self):
        self.script.write_text('import subprocess,sys\nfrom pathlib import Path\np=subprocess.Popen([sys.executable,"-c","import time;time.sleep(60)"])\nPath("orphan.pid").write_text(str(p.pid))\n')
        directory, _ = self.submit()
        process = self.launch(directory)
        pid = int(wait_for(lambda: (self.root / 'orphan.pid').read_text() if (self.root / 'orphan.pid').exists() else None))
        self.adopted.append(pid)
        result = self.finish(process, directory, 1)
        self.assertEqual(result['execution']['reason'], 'inherited-output-left-open')
        self.assert_reaped(pid)

    def test_batch_lock_serializes_without_holding_child_fixture_lock(self):
        self.script.write_text('import fcntl,time\nfrom pathlib import Path\nwith open("fixture.lock","w") as lock:\n fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)\n Path("child-ready").touch()\n while not Path("release-child").exists(): time.sleep(.02)\n')
        first, _ = self.submit('first')
        process = self.launch(first)
        wait_for(lambda: (self.root / 'child-ready').exists())
        second, _ = self.submit('second')
        rejected = self.finish(self.launch(second), second, 1)
        self.assertIn('another managed validation batch', rejected['error'])
        self.assertFalse((second / 'job.log').exists())
        (self.root / 'release-child').touch()
        self.assertTrue(self.finish(process, first, 0)['passed'])

    def test_detached_worker_survives_observer_process_exit(self):
        self.script.write_text('import time\nfrom pathlib import Path\ntime.sleep(.5)\nPath("survived").write_text("one")\n')
        directory, _ = self.submit()
        observer = 'import subprocess,sys,os; p=subprocess.Popen(sys.argv[1:],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True); print(p.pid,flush=True); os._exit(0)'
        answer = subprocess.run([str(PYTHON), '-c', observer, str(PYTHON), str(directory / 'worker.py'), '_run', str(directory)],
                                check=True, text=True, capture_output=True, timeout=5, env=job.ENV)
        pid = int(answer.stdout.strip())
        self.adopted.append(pid)
        wait_for(lambda: (directory / 'result.json').exists())
        self.assertTrue(job.read_json(directory / 'result.json')['passed'])
        self.assertEqual((self.root / 'survived').read_text(), 'one')
        self.assert_reaped(pid)

    def test_plan_rejects_unbound_files_unknown_fields_and_unsafe_paths(self):
        good = self.plan()
        invalid = [dict(good, unknown=True), dict(good, cwd='../relative'), dict(good, timeout_seconds=True),
                   dict(good, timeout_seconds=86401), dict(good, log_limit_bytes=1023),
                   dict(good, inputs={str(PYTHON): job.sha(PYTHON)}), dict(good, argv=['python3', '-V'])]
        for plan in invalid:
            with self.subTest(plan=plan), self.assertRaises(ValueError):
                job.normalize_plan(plan)
        for identity in ('../x', 'a/b', 'UPPER', '-first', ''):
            with self.assertRaises(ValueError):
                job.job_path(self.store, identity)
        duplicate = self.root / 'duplicate.json'
        duplicate.write_text('{"same":1,"same":2}')
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            job.read_json(duplicate)


if __name__ == '__main__':
    unittest.main()
