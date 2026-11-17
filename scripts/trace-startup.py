#!/usr/bin/env python3
"""Bounded launcher-only syscall diagnostics; no payload decoding or perf gate."""
import argparse
import json
import os
from pathlib import Path
import re
import resource
import signal
import subprocess
import sys
import threading
import time

from startup_benchmark import atomic_report, require, sha, start_ticks, validation_lock

RAW = tuple('read write pread64 pwrite64 readv writev recvfrom sendto recvmsg sendmsg getrandom execve execveat getdents64 readlink readlinkat epoll_wait epoll_pwait'.split())
TRACE = RAW + tuple('openat close socket connect fcntl dup dup2 dup3 futex fsync fdatasync rename renameat renameat2 clone clone3 clock_nanosleep nanosleep newfstatat'.split())
SOFT_BYTES, HARD_BYTES, MAX_SECONDS = 48 << 20, 64 << 20, 180


def trace_options():
    return ['-f', '--detach-on=execve', '-I', '1', '-ttt', '-T', '-yy', '-s', '256', '-q',
            '-e', 'signal=none', '-e', 'trace='+','.join(TRACE), '-e', 'raw='+','.join(RAW)]


def tracer_limits():
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_FSIZE, (HARD_BYTES, HARD_BYTES))


def thread_tracers(pid):
    result = {}
    for entry in Path('/proc', str(pid), 'task').iterdir():
        try:
            status = dict(line.split(':',1) for line in (entry/'status').read_text().splitlines() if ':' in line)
            result[int(entry.name)] = int(status['TracerPid'])
        except (FileNotFoundError, ProcessLookupError):
            continue
    return result


class LauncherTrace:
    def __init__(self, pid, output):
        self.pid, self.output = pid, output
        self.generation = start_ticks(pid)
        self.started = time.monotonic()
        self.requested_stop = threading.Event()
        self.errors, self.threads = [], set()
        self.process = None
        self.stderr = None
        self.watcher = None
        self.attached = False

    def start(self):
        require(all(value == 0 for value in thread_tracers(self.pid).values()), 'launcher already traced')
        self.stderr = (self.output/'tracer.stderr').open('x')
        os.chmod(self.output/'tracer.stderr', 0o600)
        self.process = subprocess.Popen(['strace', *trace_options(), '-o', str(self.output/'launcher.trace'), '-p', str(self.pid)],
            stdout=subprocess.DEVNULL, stderr=self.stderr, start_new_session=True, preexec_fn=tracer_limits)
        until = time.monotonic()+5
        while time.monotonic() < until:
            require(self.process.poll() is None, 'tracer exited before attachment')
            require(start_ticks(self.pid) == self.generation, 'launcher generation changed during attachment')
            tracers = thread_tracers(self.pid)
            if tracers and all(value == self.process.pid for value in tracers.values()):
                self.threads.update(tracers)
                self.attached = True
                self.watcher = threading.Thread(target=self.watch, daemon=True)
                self.watcher.start()
                return
            time.sleep(.02)
        raise ValueError('tracer did not attach all launcher threads')

    def watch(self):
        while not self.requested_stop.wait(.02):
            try:
                require(self.process.poll() is None, 'tracer exited unexpectedly')
                require(time.monotonic()-self.started < MAX_SECONDS, 'trace time limit reached')
                require((self.output/'launcher.trace').stat().st_size < SOFT_BYTES, 'trace size limit reached')
                require(start_ticks(self.pid) == self.generation, 'launcher generation changed during trace')
                tracers = thread_tracers(self.pid)
                require(tracers and all(value == self.process.pid for value in tracers.values()), 'launcher thread lost tracing')
                self.threads.update(tracers)
            except Exception as error:
                self.errors.append(type(error).__name__+': '+str(error)[:300])
                if self.process.poll() is None:
                    try:
                        self.process.send_signal(signal.SIGINT)
                    except ProcessLookupError:
                        pass
                return

    def close(self):
        self.requested_stop.set()
        if self.watcher is not None:
            self.watcher.join(2)
            require(not self.watcher.is_alive(), 'trace watcher failed to stop')
        if self.process is not None:
            if self.process.poll() is None:
                self.process.send_signal(signal.SIGINT)
            try:
                code = self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
                self.errors.append('tracer did not detach on SIGINT')
            else:
                if code not in (0, -signal.SIGINT, 128+signal.SIGINT):
                    self.errors.append('tracer exit '+str(code))
        if self.stderr is not None:
            self.stderr.close()
        if start_ticks(self.pid) == self.generation:
            require(all(value == 0 for value in thread_tracers(self.pid).values()), 'launcher retains tracer')


LINE = re.compile(r'^\s*(\d+)\s+(\d+\.\d+)\s+(.*)$')
ENTRY = re.compile(r'^([a-zA-Z_][a-zA-Z_0-9]*)\(')
RESUME = re.compile(r'^<\.\.\. ([a-zA-Z_][a-zA-Z_0-9]*) resumed>(.*)$')


def decimal_ns(value):
    whole, fraction = value.split('.')
    require(len(fraction) <= 9, 'trace timestamp precision exceeds nanoseconds')
    return int(whole)*1_000_000_000+int(fraction.ljust(9,'0'))


def parse_trace(path, *, allow_detach_tail=False):
    require(path.stat().st_size <= HARD_BYTES, 'trace exceeds hard bound')
    pending, calls = {}, []
    with path.open() as source:
        for number, line in enumerate(source,1):
            require(len(line) <= 16384, 'trace line exceeds bound')
            match = LINE.match(line)
            if not match:
                require(not line.strip(), 'unrecognized trace line '+str(number))
                continue
            tid, at, body = int(match[1]), decimal_ns(match[2]), match[3].rstrip()
            if body.startswith('+++') or body.startswith('---'):
                continue
            resumed = RESUME.match(body)
            if resumed:
                require(tid in pending and pending[tid][1] == resumed[1], 'trace resume lacks matching entry')
                at, name, prefix = pending.pop(tid)
                body = prefix+resumed[2]
            else:
                entry = ENTRY.match(body)
                require(entry is not None, 'unrecognized syscall entry '+str(number))
                name = entry[1]
            require(name in TRACE, 'unexpected traced syscall '+name)
            require(name not in RAW or '"' not in body, 'decoded buffer in '+name+' at line '+str(number))
            if body.endswith('<unfinished ...>'):
                require(tid not in pending, 'nested unfinished syscall')
                pending[tid] = (at, name, body[:-len('<unfinished ...>')])
                continue
            duration = re.search(r'<(\d+\.\d+)>$', body)
            if duration is None:
                # SIGINT may interrupt strace while it writes its final entry.
                # Only an explicitly verified detach can accept that EOF tail;
                # it remains unknown, with no invented duration or return value.
                if allow_detach_tail and not line.endswith('\n'):
                    require(tid not in pending, 'nested incomplete syscall')
                    pending[tid] = (at, name, body)
                    continue
                require('detached' in body or '= ?' in body, 'missing syscall duration at line '+str(number))
                continue
            took = decimal_ns(duration[1])
            returned = re.search(r'\)\s+=\s+(-?0x[0-9a-f]+|-?\d+)', body)
            calls.append({'tid':tid, 'at_ns':at, 'duration_ns':took, 'name':name,
                          'returned':int(returned[1],0) if returned and 'x' in returned[1] else int(returned[1]) if returned else None,
                          'body':body})
    return sorted(calls,key=lambda row:row['at_ns']), pending


def guest_calls(calls, initial_threads, instances):
    threads = set(initial_threads)
    while True:
        added = {row['returned'] for row in calls if row['tid'] in threads and row['name'] in ('clone','clone3') and
                 'CLONE_THREAD' in row['body'] and row['returned'] is not None and row['returned'] > 0}
        if added <= threads:
            break
        threads.update(added)
    directories, sockets, selected = {}, {}, []
    serial = 0
    for row in calls:
        if row['tid'] not in threads:
            continue
        name, body, returned = row['name'], row['body'], row['returned']
        first = re.match(r'\w+\((0x[0-9a-f]+|\d+)',body)
        fd = int(first[1],0) if first else None
        if name in ('openat','socket') and returned is not None and returned >= 0:
            directories.pop(returned,None);sockets.pop(returned,None)
            if name == 'openat':
                opened = re.search(r'openat\([^,]+, "([^"]+)"',body)
                if opened:
                    for instance in instances:
                        if opened[1].endswith('/'+instance+'/jailer/firecracker/'+instance+'/root'):
                            directories[returned] = instance
        if name == 'connect':
            short = re.search(r'sun_path="/proc/self/fd/(\d+)/agent.vsock"',body)
            if short and int(short[1]) in directories:
                serial += 1
                sockets[fd] = (directories[int(short[1])],serial)
        if fd in sockets and name in ('connect','read','write','readv','writev','recvfrom','sendto','recvmsg','sendmsg','close','fcntl'):
            instance, connection = sockets[fd]
            selected.append({**row,'instance_id':instance,'connection':connection,'fd':fd})
        if name == 'close' and returned == 0:
            directories.pop(fd,None);sockets.pop(fd,None)
    return selected, threads


def collect(root, package, lock_fd, samples=64):
    require(type(samples) is int and 1 <= samples <= 64, 'trace samples must be within [1, 64]')
    config = json.loads((root/'config.production.json').read_text())
    require(config['run_root'] == str(root/'run') and config['jailer']['parent_cgroup'] == root.name and
            config['backend'] == 'firecracker-linux' and config['warm_pool']['enabled'] and
            config['warm_pool']['health_interval_ms'] == 1000, 'trace fixture is not normal Linux warm configuration')
    output = root/'results/trace'
    output.mkdir(mode=0o700)
    pid = int(subprocess.check_output(['systemctl','show','-p','MainPID','--value',root.name+'-launcher.service'],text=True))
    require(pid > 1 and Path('/proc',str(pid),'exe').resolve().is_relative_to(root/'releases'), 'launcher outside fixture')
    report = {'suite':'api-warm-start-trace/v1', 'diagnostic':True, 'performance_gate_evidence':False,
        'release_eligible':False, 'passed':False, 'launcher_pid':pid, 'launcher_start_ticks':start_ticks(pid),
        'configuration_sha256':sha(root/'config.production.json'), 'candidate_sha256':sha(package),
        'test_sha256':sha(__file__), 'support_sha256':sha(Path(__file__).with_name('startup_benchmark.py')),
        'strace_version':subprocess.check_output(['strace','-V'],text=True),
        'limits':{'seconds':MAX_SECONDS,'soft_bytes':SOFT_BYTES,'hard_bytes':HARD_BYTES},
        'options':trace_options()}
    report['samples_requested'] = samples
    tracer = LauncherTrace(pid,output)
    try:
        tracer.start()
        report['tracer_pid'] = tracer.process.pid
        with (output/'benchmark.log').open('x') as log:
            code = subprocess.run([sys.executable,str(Path(__file__).with_name('startup_benchmark.py')),
                '--root',str(root),'--package',str(package),'--samples',str(samples),'--warmup','5','--diagnostic',
                '--require-phase-timing','--label','startup-traced','--lock-fd',str(lock_fd)],
                stdout=log, stderr=subprocess.STDOUT,
                pass_fds=(lock_fd,), timeout=MAX_SECONDS).returncode
        require(code == 0, 'traced benchmark returned '+str(code))
        require(tracer.process.poll() is None, 'tracer stopped before benchmark completed')
        benchmark = json.loads((root/'results/startup-traced/report.json').read_text())
        require(benchmark['passed'] and benchmark['successes'] == samples, 'traced benchmark is incomplete')
        rows = benchmark['attempts']+benchmark['warmup_attempts']
        require(all(row['preboot_observation']['tracer_pid'] == 0 for row in rows), 'VMM was traced at checkout')
        report['benchmark_sha256'] = sha(root/'results/startup-traced/report.json')
        report['passed'] = True
    except Exception as error:
        report['error'] = type(error).__name__+': '+str(error)[:500]
    finally:
        try:
            tracer.close()
            report['launcher_detached'] = True
        except Exception as error:
            report['launcher_detached'] = False
            report['detach_error'] = type(error).__name__+': '+str(error)[:300]
            report['passed'] = False
        report['tracer_errors'] = tracer.errors
        report['observed_launcher_threads'] = sorted(tracer.threads)
        if tracer.errors or not tracer.attached:
            report['passed'] = False
        path = output/'launcher.trace'
        if path.exists():
            try:
                calls, pending = parse_trace(path, allow_detach_tail=bool(
                    report.get('launcher_detached') and not tracer.errors and report.get('passed')))
                require(bool(calls), 'empty syscall trace')
                report['privacy_format_audit_passed'] = True
                report['complete_syscalls'] = len(calls)
                report['unfinished_at_detach'] = {str(tid):name for tid,(_,name,_) in pending.items()}
                report['trace_sha256'] = sha(path)
                report['trace_bytes'] = path.stat().st_size
            except Exception as error:
                report['privacy_format_audit_passed'] = False
                report['trace_audit_error'] = type(error).__name__+': '+str(error)[:300]
                report['passed'] = False
        atomic_report(output/'report.json',report)
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--package',type=Path,required=True)
    parser.add_argument('--lock-fd',type=int,required=True)
    parser.add_argument('--samples',type=int,default=64)
    args = parser.parse_args()
    root = args.root.resolve()
    require(os.geteuid() == 0 and root.parent == Path('/var/lib') and
            re.fullmatch('osv-offline-validation-20261030-[a-z0-9]+',root.name), 'requires new isolated trace fixture')
    with validation_lock(args.lock_fd) as lock:
        report = collect(root,args.package,lock.fileno(),args.samples)
    print(json.dumps({key:report.get(key) for key in ('passed','complete_syscalls','trace_bytes','error','trace_audit_error','tracer_errors')}),flush=True)
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
