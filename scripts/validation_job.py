#!/usr/bin/env python3
"""Submit an immutable validation job once, or observe its original systemd unit."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

PROTOCOL = 'osv-validation-job/v1'
ENV = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'LANG': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1'}
PROPERTIES = ('LoadState', 'ActiveState', 'SubState', 'Result', 'MainPID', 'InvocationID',
              'ExecMainCode', 'ExecMainStatus')


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate JSON key')
        value[key] = item
    return value


def read_json(path):
    with Path(path).open('rb') as stream:
        data = stream.read((8 << 20) + 1)
    if len(data) > 8 << 20:
        raise ValueError('job metadata too large')
    return json.loads(data, object_pairs_hook=unique_object)


def sync_directory(path):
    fd = os.open(str(path), os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_json(path, value):
    path = Path(path)
    with tempfile.NamedTemporaryFile(dir=str(path.parent), prefix='.record-', delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(canonical(value))
            stream.flush()
            os.fsync(stream.fileno())
            os.replace(str(temporary), str(path))
            sync_directory(path.parent)
        finally:
            if temporary.exists():
                temporary.unlink()


def absolute(value):
    if not isinstance(value, str) or not value or '\0' in value:
        raise ValueError('expected absolute path')
    path = Path(value)
    if not path.is_absolute() or str(path) != value or '..' in path.parts:
        raise ValueError('expected normalized absolute path')
    return path


def normalize_plan(raw):
    keys = {'protocol', 'argv', 'cwd', 'inputs', 'timeout_seconds', 'log_limit_bytes'}
    if not isinstance(raw, dict) or set(raw) != keys or raw['protocol'] != PROTOCOL:
        raise ValueError('unsupported job plan')
    argv = raw['argv']
    if not isinstance(argv, list) or not 1 <= len(argv) <= 128 or any(
            not isinstance(arg, str) or '\0' in arg or len(arg) > 4096 for arg in argv):
        raise ValueError('invalid command argv')
    executable = absolute(argv[0]).resolve(strict=True)
    cwd = absolute(raw['cwd'])
    if not cwd.is_dir() or cwd.resolve() != cwd:
        raise ValueError('working directory must exist without symlink indirection')
    inputs = raw['inputs']
    if not isinstance(inputs, dict) or not 1 <= len(inputs) <= 1024:
        raise ValueError('expected bounded input hashes')
    for name, digest in inputs.items():
        absolute(name)
        if not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest):
            raise ValueError('invalid input digest')
    if str(executable) not in inputs:
        raise ValueError('command interpreter/executable must be bound in inputs')
    for arg in argv[1:]:
        if arg.startswith('/') and Path(arg).is_file() and str(Path(arg).resolve()) not in inputs:
            raise ValueError('absolute command input file missing from input hashes')
    if type(raw['timeout_seconds']) is not int or not 1 <= raw['timeout_seconds'] <= 86400:
        raise ValueError('timeout must be within [1, 86400] seconds')
    if type(raw['log_limit_bytes']) is not int or not 1024 <= raw['log_limit_bytes'] <= 512 << 20:
        raise ValueError('log limit must be within [1024, 512 MiB]')
    return dict(raw, argv=[str(executable), *argv[1:]])


def private_directory(path):
    path = absolute(str(path))
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or path.resolve() != path or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError('job directory must be private, owned by the caller, and not a symlink')
    return path


def lock_file(path):
    fd = os.open(str(path), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        os.close(fd)
        raise ValueError('job lock must be a private regular file')
    return os.fdopen(fd, 'r+')


def job_path(store, identity):
    if not re.fullmatch('[a-z0-9][a-z0-9-]{0,62}', identity):
        raise ValueError('invalid job ID')
    return absolute(str(store)) / identity


def observe_manager(unit):
    try:
        result = subprocess.run(['systemctl', 'show', '--no-pager', '--property=' + ','.join(PROPERTIES), unit],
                                capture_output=True, text=True, timeout=10, env=ENV)
    except (OSError, subprocess.TimeoutExpired) as error:
        return {'observed': False, 'error': type(error).__name__}
    values = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
    # A non-zero DBus/transport response is never interpreted as unit absence.
    if result.returncode != 0 or not all(name in values for name in ('LoadState', 'ActiveState', 'SubState')):
        return {'observed': False, 'command_exit_code': result.returncode}
    return {'observed': True, **{name: values[name] for name in PROPERTIES if name in values}}


def status(directory):
    directory = Path(directory)
    launch_path = directory / 'launch.json'
    report = {'protocol': PROTOCOL, 'job_id': directory.name, 'passed': False, 'terminal': False}
    if not launch_path.exists():
        return dict(report, state='submission-unconfirmed' if directory.exists() else 'absent',
                    terminal=not directory.exists(), execution_replayed=False)
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or directory.resolve() != directory or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError('job directory identity or permissions changed')
    launch = read_json(launch_path)
    manager = observe_manager(launch['unit'])
    report.update(unit=launch['unit'], plan_sha256=launch['plan_sha256'], manager=manager,
                  execution_replayed=False)
    result = read_json(directory / 'result.json') if (directory / 'result.json').exists() else None
    if not manager['observed']:
        return dict(report, state='observation-failed', result=result)
    # The receipt is durable before this worker can exit. Do not report a
    # terminal job while its original manager still observes a live handle.
    active = (manager.get('ActiveState') in ('active', 'activating', 'reloading', 'deactivating')
              and manager.get('SubState') != 'exited')
    if active or manager.get('MainPID', '0') != '0':
        return dict(report, state='finishing' if result is not None else 'running', result=result)
    if manager.get('ActiveState') == 'failed':
        return dict(report, state='failed', terminal=True, result=result)
    if result is not None:
        valid = (result.get('protocol') == PROTOCOL and result.get('plan_sha256') == launch['plan_sha256']
                 and result.get('worker_sha256') == launch['worker_sha256'])
        execution = result.get('execution', {})
        previous_invocation = result.get('manager_invocation_id')
        current_invocation = manager.get('InvocationID')
        same_invocation = not (previous_invocation and current_invocation and previous_invocation != current_invocation)
        passed = (valid and same_invocation and result.get('passed') is True and result.get('inputs_unchanged') is True
                  and execution.get('passed') is True and execution.get('exit_code') == 0
                  and execution.get('reason') == 'exit')
        return dict(report, state='succeeded' if passed else 'failed', passed=passed, terminal=True, result=result)
    return dict(report, state='interrupted' if (directory / 'claimed').exists() else 'not-started', terminal=True)


def submit(store, identity, raw, batch_lock):
    plan = normalize_plan(raw)
    store = private_directory(store)
    directory = job_path(store, identity)
    batch_lock = absolute(str(batch_lock))
    with lock_file(store / '.submission.lock') as guard:
        fcntl.flock(guard, fcntl.LOCK_EX)
        if directory.exists():
            if (directory / 'plan.json').exists() and canonical(read_json(directory / 'plan.json')) != canonical(plan):
                raise ValueError('job ID already belongs to a different plan')
            if (directory / 'launch.json').exists() and read_json(directory / 'launch.json')['batch_lock'] != str(batch_lock):
                raise ValueError('job ID already belongs to a different batch lock')
            return status(directory)
        directory.mkdir(mode=0o700)
        sync_directory(store)
        write_json(directory / 'plan.json', plan)
        worker = directory / 'worker.py'
        shutil.copyfile(Path(__file__).resolve(), worker)
        worker.chmod(0o500)
        with worker.open('rb') as stream:
            os.fsync(stream.fileno())
        interpreter = Path(sys.executable).resolve()
        store_id = hashlib.sha256(str(store).encode()).hexdigest()[:12]
        unit = 'osv-validation-job-' + store_id + '-' + identity + '.service'
        launch = {'protocol': PROTOCOL, 'unit': unit, 'plan_sha256': hashlib.sha256(canonical(plan)).hexdigest(),
                  'worker_sha256': sha(worker), 'interpreter': str(interpreter), 'interpreter_sha256': sha(interpreter),
                  'batch_lock': str(batch_lock), 'created_at_unix': int(time.time())}
        write_json(directory / 'launch.json', launch)
        command = ['systemd-run', '--quiet', '--no-ask-password', '--unit=' + unit, '--service-type=exec',
                   '--property=Restart=no', '--property=RemainAfterExit=yes', '--property=KillMode=control-group',
                   '--property=TimeoutStopSec=10s', '--property=RuntimeMaxSec=' + str(plan['timeout_seconds'] + 120),
                   '--property=UMask=0077', '--property=StandardOutput=null', '--property=StandardError=journal',
                   '--property=WorkingDirectory=' + str(directory), str(interpreter), str(worker), '_run', str(directory)]
        try:
            result = subprocess.run(command, capture_output=True, timeout=15, env=ENV)
            submission = {'response_received': True, 'command_exit_code': result.returncode}
        except (OSError, subprocess.TimeoutExpired) as error:
            submission = {'response_received': False, 'error': type(error).__name__}
        write_json(directory / 'submission.json', submission)
    return status(directory)


def verify_inputs(plan):
    for name, digest in plan['inputs'].items():
        path = Path(name)
        if path.resolve() != path or not stat.S_ISREG(path.lstat().st_mode) or sha(path) != digest:
            raise ValueError('job input mismatch: ' + name)


def stop_group(process):
    if process is None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        pass
    # Always kill surviving members, even if the process group leader exited.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=2)


def execute(plan, log_path):
    process = None
    began = time.monotonic()
    reason, written = 'exit', 0
    try:
        with Path(log_path).open('xb') as log, selectors.DefaultSelector() as selector:
            os.chmod(str(log_path), 0o600)
            process = subprocess.Popen(plan['argv'], cwd=plan['cwd'], env=ENV, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
            selector.register(process.stdout, selectors.EVENT_READ)
            exited_at = None
            while True:
                now = time.monotonic()
                if now - began >= plan['timeout_seconds']:
                    reason = 'timeout'
                    break
                if process.poll() is not None:
                    exited_at = now if exited_at is None else exited_at
                    if now - exited_at > 1:
                        reason = 'inherited-output-left-open'
                        break
                events = selector.select(min(0.1, max(0, plan['timeout_seconds'] - (now - began))))
                if not events:
                    continue
                block = os.read(process.stdout.fileno(), 65536)
                if not block:
                    remaining = max(0, plan['timeout_seconds'] - (time.monotonic() - began))
                    try:
                        process.wait(timeout=remaining)
                    except subprocess.TimeoutExpired:
                        reason = 'timeout'
                    break
                permitted = min(len(block), plan['log_limit_bytes'] - written)
                log.write(block[:permitted])
                written += permitted
                if permitted < len(block):
                    reason = 'log-limit'
                    break
            log.flush()
            os.fsync(log.fileno())
    finally:
        stop_group(process)
        if process is not None and process.stdout is not None:
            process.stdout.close()
    return {'exit_code': process.returncode, 'reason': reason, 'log_bytes': written,
            'duration_seconds': round(time.monotonic() - began, 6),
            'passed': reason == 'exit' and process.returncode == 0}


class Terminated(Exception):
    pass


def run_worker(directory):
    directory = private_directory(directory)
    marker = directory / 'claimed'
    try:
        fd = os.open(str(marker), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        return 75
    os.fsync(fd)
    os.close(fd)
    sync_directory(directory)
    began = time.monotonic()
    record = {'protocol': PROTOCOL, 'passed': False, 'started_at_unix': int(time.time()),
              'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'pid': os.getpid(),
              'manager_invocation_id': os.environ.get('INVOCATION_ID'),
              'start_ticks': int(Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split()[19])}
    previous = {}
    def terminate(signum, frame):
        raise Terminated('worker received signal ' + str(signum))
    for signum in (signal.SIGTERM, signal.SIGINT):
        previous[signum] = signal.signal(signum, terminate)
    try:
        launch = read_json(directory / 'launch.json')
        plan = normalize_plan(read_json(directory / 'plan.json'))
        record.update(plan_sha256=hashlib.sha256(canonical(plan)).hexdigest(), worker_sha256=sha(directory / 'worker.py'))
        if (record['plan_sha256'] != launch['plan_sha256'] or record['worker_sha256'] != launch['worker_sha256']
                or sha(Path(sys.executable).resolve()) != launch['interpreter_sha256']):
            raise ValueError('job launch identity changed')
        with lock_file(launch['batch_lock']) as guard:
            try:
                fcntl.flock(guard, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ValueError('another managed validation batch is running')
            verify_inputs(plan)
            write_json(directory / 'running.json', record)
            execution = execute(plan, directory / 'job.log')
            record['execution'] = execution
            verify_inputs(plan)
            record['inputs_unchanged'] = True
            record['passed'] = execution['passed']
    except BaseException as error:
        record.update(passed=False, error_type=type(error).__name__, error=str(error))
    finally:
        record['total_duration_seconds'] = round(time.monotonic() - began, 6)
        write_json(directory / 'result.json', record)
        for signum, handler in previous.items():
            signal.signal(signum, handler)
    return 0 if record['passed'] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    start = commands.add_parser('submit')
    start.add_argument('--store', type=Path, required=True)
    start.add_argument('--id', required=True)
    start.add_argument('--plan', type=Path, required=True)
    start.add_argument('--batch-lock', type=Path, default=Path('/run/lock/osv-sandbox-validation-jobs.lock'))
    query = commands.add_parser('status')
    query.add_argument('--store', type=Path, required=True)
    query.add_argument('--id', required=True)
    worker = commands.add_parser('_run', help=argparse.SUPPRESS)
    worker.add_argument('directory', type=Path)
    args = parser.parse_args()
    if args.command == '_run':
        return run_worker(args.directory)
    if os.geteuid() != 0:
        parser.error('validation job administration requires root')
    report = (submit(args.store, args.id, read_json(args.plan), args.batch_lock) if args.command == 'submit'
              else status(job_path(args.store, args.id)))
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, OSError) as error:
        print(type(error).__name__ + ': ' + str(error), file=sys.stderr)
        sys.exit(1)
