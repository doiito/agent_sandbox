#!/usr/bin/env python3
"""Paced, unqueued warm-start measurements through the real authenticated API."""
import argparse
from collections import OrderedDict, deque
import ctypes
import datetime
import errno
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import socket
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.request


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(path):
    with Path(path).open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def percentiles(values):
    require(all(type(value) in (int, float) and math.isfinite(value) and value >= 0 for value in values),
            'invalid duration sample')
    ordered = sorted(values)
    return {name: ordered[math.ceil(len(ordered) * fraction) - 1] if ordered else None
            for name, fraction in (('p50', .5), ('p95', .95), ('p99', .99), ('max', 1))}


def start_ticks(pid):
    text = Path('/proc', str(pid), 'stat').read_text()
    return int(text[text.rfind(')') + 2:].split()[19])


def process_matches(lease):
    try:
        return start_ticks(lease['pid']) == lease['start_time_ticks']
    except (OSError, ValueError, KeyError, IndexError):
        return False


CPU_COUNTERS = ('usage_usec', 'nr_periods', 'nr_throttled', 'throttled_usec')


class CPUControllerUnavailable(ValueError):
    pass


def parse_cpu_stat(text):
    require(len(text) <= 16384, 'CPU statistics exceed bound')
    values = {}
    for line in text.splitlines():
        parts = line.split()
        require(len(parts) == 2 and re.fullmatch(r'[A-Za-z0-9_.]+', parts[0]) and
                re.fullmatch('[0-9]+', parts[1]) and parts[0] not in values, 'invalid CPU statistics')
        values[parts[0]] = int(parts[1])
    if not all(key in values for key in CPU_COUNTERS):
        raise CPUControllerUnavailable('CPU controller counters unavailable')
    return values


def cpu_snapshot(leaf):
    started = time.monotonic_ns()
    limit = ' '.join((leaf/'cpu.max').read_text().split())
    require(re.fullmatch(r'(?:max|[0-9]+) [0-9]+', limit), 'invalid CPU limit')
    values = parse_cpu_stat((leaf/'cpu.stat').read_text())
    return {'started_monotonic_ns': started, 'monotonic_ns': time.monotonic_ns(),
            'utc_ns': time.time_ns(), 'limit': limit, 'stat': values}


def process_retired(lease):
    """Only an absent, replaced or exited PID proves this generation retired."""
    try:
        text = Path('/proc', str(lease['pid']), 'stat').read_text()
    except (FileNotFoundError, ProcessLookupError):
        return True
    fields = text[text.rfind(')') + 2:].split()
    return int(fields[19]) != lease['start_time_ticks'] or fields[0] in ('Z', 'X', 'x')


def live_cpu_snapshot(leaf, lease):
    try:
        return cpu_snapshot(leaf)
    except (OSError, CPUControllerUnavailable) as error:
        # Only recognized lifecycle errors may become optional after this PID
        # generation retires. Malformed data and other I/O errors remain fatal.
        lifecycle_error = isinstance(error, CPUControllerUnavailable) or getattr(error, 'errno', None) == errno.ENODEV
        if lifecycle_error and process_retired(lease):
            return None
        raise


def observation_error(error, stage, path, vm_id):
    return {'type': type(error).__name__, 'errno': getattr(error, 'errno', None),
            'message': str(error)[:512], 'stage': stage, 'path': str(path),
            'vm_id': vm_id, 'utc_ns': time.time_ns()}


class CPUHistory:
    def __init__(self, max_vms=32, max_samples=64):
        require(max_vms > 0 and max_samples > 0, 'invalid CPU history bound')
        self.max_vms, self.max_samples = max_vms, max_samples
        self.lock = threading.Lock()
        self.samples = OrderedDict()

    def add(self, vm_id, sample):
        with self.lock:
            if vm_id not in self.samples:
                self.samples[vm_id] = deque(maxlen=self.max_samples)
            self.samples[vm_id].append({**sample, 'stat': dict(sample['stat'])})
            self.samples.move_to_end(vm_id)
            while len(self.samples) > self.max_vms:
                self.samples.popitem(last=False)

    def get(self, vm_id):
        with self.lock:
            return [{**row, 'stat': dict(row['stat'])} for row in self.samples.get(vm_id, ())]


def cpu_window(before, samples):
    if before is None:
        return {'coverage': 'missing-before'}
    # Disjoint read intervals avoid classifying a preempted earlier read as a
    # later observation with reversed counters.
    eligible = [row for row in samples if row['started_monotonic_ns'] >= before['monotonic_ns']]
    if not eligible:
        return {'coverage': 'missing-live-after'}
    after = eligible[-1]
    require(after['limit'] == before['limit'] and
            all(after['stat'][key] >= before['stat'][key] for key in CPU_COUNTERS),
            'CPU policy changed or counters reversed during request')
    return {'coverage': 'sampled-live-window', 'before': before, 'last_live': after,
            'delta': {key: after['stat'][key] - before['stat'][key] for key in CPU_COUNTERS}}


def validation_lock(inherited_fd=None, path='/var/lock/osv-sandbox-validation.lock'):
    handle = open(path, 'a') if inherited_fd is None else os.fdopen(os.dup(inherited_fd), 'a')
    try:
        actual, expected = os.fstat(handle.fileno()), os.stat(path)
        require((actual.st_dev, actual.st_ino) == (expected.st_dev, expected.st_ino), 'inherited validation lock is the wrong file')
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BaseException:
        handle.close()
        raise
    return handle


def owned_leases(config):
    root = Path(config['run_root'])
    parent = config['jailer']['parent_cgroup']
    first = config['jailer']['uid']
    last = first + config['jailer']['identity_pool_size']
    result = {}
    for path in root.glob('job-*/lease.json'):
        try:
            lease = json.loads(path.read_text())
            if not process_matches(lease):
                continue
            if lease.get('phase') not in ('ready', 'claiming', 'active'):
                result[lease['vm_id']] = lease
                continue
            pid = lease['pid']
            proc = Path('/proc', str(pid))
            status = dict(line.split(':', 1) for line in (proc/'status').read_text().splitlines() if ':' in line)
            uid, gid = status['Uid'].split(), status['Gid'].split()
            comm, cgroup = (proc/'comm').read_text().strip(), (proc/'cgroup').read_text().strip()
            if not process_matches(lease):
                require(process_retired(lease), 'PID changed during observation without confirmed retirement')
                continue
            require(lease['instance_id'] == path.parent.name and re.fullmatch('[0-9a-f]{24}', lease['vm_id']),
                    'invalid owned VM lease')
            require(uid == gid and len(set(uid)) == 1 and first <= int(uid[0]) < last and int(uid[0]) != 0,
                    'unexpected jail identity')
            require(status['Seccomp'].strip() == '2' and status['CapEff'].strip() == '0000000000000000' and
                    comm == 'firecracker' and cgroup == '0::/' + parent + '/' + path.parent.name,
                    'VM hardening or cgroup mismatch')
            lease['uid'] = int(uid[0])
            lease['tracer_pid'] = int(status['TracerPid'].strip())
            lease['cpu_allowed_list'] = status['Cpus_allowed_list'].strip()
            lease['mems_allowed_list'] = status['Mems_allowed_list'].strip()
            lease['hardening'] = {'uid': uid, 'gid': gid, 'seccomp': status['Seccomp'].strip(),
                                  'cap_eff': status['CapEff'].strip(), 'cgroup': cgroup}
            lease['cpu_snapshot'] = live_cpu_snapshot(Path('/sys/fs/cgroup')/parent/path.parent.name, lease)
            if lease['cpu_snapshot'] is None:
                continue
            result[lease['vm_id']] = lease
        except (FileNotFoundError, ProcessLookupError):
            continue
    require(len(result) <= config['vm_capacity']['max_instances'], 'physical VM ceiling exceeded')
    identities = [row['uid'] for row in result.values() if 'uid' in row]
    require(len(set(identities)) == len(identities), 'VM identity reused')
    return result


class AuditTail:
    def __init__(self, path):
        self.source = Path(path).open('rb')
        self.source.seek(0, os.SEEK_END)
        self.pending = b''

    def read(self):
        data = self.pending + self.source.read(8 * 1024 * 1024 + 1)
        require(len(data) <= 8 * 1024 * 1024, 'audit interval exceeds bound')
        lines = data.split(b'\n')
        self.pending = lines.pop()
        return [json.loads(line) for line in lines if line]

    def close(self):
        self.source.close()


class RSSObserver:
    """Sampling only: this does not establish an exact instantaneous RSS peak."""
    def __init__(self, config):
        self.config = config
        self.stop = threading.Event()
        self.peak = 0
        self.errors = []
        self.retired_cpu_reads = 0
        self.cpu = CPUHistory()
        self.thread = threading.Thread(target=self.observe, daemon=True)

    def observe(self):
        while not self.stop.wait(.02):
            total = 0
            stage, observed_path, vm_id = 'lease-scan', self.config['run_root'], None
            try:
                for path in Path(self.config['run_root']).glob('job-*/lease.json'):
                    try:
                        stage, observed_path, vm_id = 'lease-read', path, None
                        lease = json.loads(path.read_text())
                        vm_id = lease['vm_id']
                        stage = 'process-match'
                        if process_matches(lease):
                            stage, observed_path = 'rss-read', Path('/proc', str(lease['pid']), 'status')
                            for line in observed_path.read_text().splitlines():
                                if line.startswith('VmRSS:'):
                                    total += int(line.split()[1]) * 1024
                            if lease.get('phase') not in ('ready', 'claiming', 'active'):
                                continue
                            try:
                                leaf = Path('/sys/fs/cgroup')/self.config['jailer']['parent_cgroup']/path.parent.name
                                stage, observed_path = 'cpu-read', leaf
                                snapshot = live_cpu_snapshot(leaf, lease)
                                if snapshot is None:
                                    self.retired_cpu_reads += 1
                                else:
                                    self.cpu.add(lease['vm_id'], snapshot)
                            except (FileNotFoundError, ProcessLookupError):
                                pass
                    except (FileNotFoundError, ProcessLookupError):
                        continue
                self.peak = max(self.peak, total)
            except Exception as error:
                if len(self.errors) < 8:
                    self.errors.append(observation_error(error, stage, observed_path, vm_id))

    def close(self):
        self.stop.set()
        self.thread.join(timeout=2)
        require(not self.thread.is_alive(), 'RSS observer did not stop')


PHASE_FIELDS = ('admission_us', 'selection_us', 'readiness_us', 'preparation_us',
                'ownership_us', 'audit_us', 'finalize_us')


def validate_startup_measurements(value, required=False):
    duration = value.get('startup_duration_us')
    require(type(duration) is int and duration > 0, 'missing launcher startup duration')
    timing = value.get('startup_timing')
    require(not required or timing is not None, 'missing required startup timing partition')
    if timing is not None:
        require(isinstance(timing, dict) and timing.get('schema') in ('osv-startup-timing/v1', 'osv-startup-timing/v2') and
                all(type(timing.get(key)) is int and 0 <= timing[key] <= duration for key in PHASE_FIELDS) and
                type(timing.get('total_us')) is int and timing['total_us'] == duration and
                sum(timing[key] for key in PHASE_FIELDS) == duration, 'invalid startup timing partition')
    boot = value.get('vm_boot_duration_us')
    if boot is not None:
        require(value.get('startup_mode') == 'cold' and type(boot) is int and 0 < boot <= duration,
                'VMM boot metric does not represent this cold request')
    return timing


def validate_job(value, backend, expected_output, before, events, used, require_phases=False, mode='warm'):
    require(isinstance(value, dict) and re.fullmatch('[0-9a-f]{24}', value.get('id', '')), 'missing bound job ID')
    guest = value.get('guest_result') or {}
    require(value.get('backend') == backend and value.get('state') == 'succeeded' and value.get('exit_code') == 0 and
            value.get('protocol_ok') is True and guest.get('ok') is True and guest.get('job_id') == value['id'] and
            guest.get('exit_code') == 0 and guest.get('stdout') == expected_output,
            'job result or workload binding mismatch')
    require(mode in ('warm', 'cold') and value.get('startup_mode') == mode, 'request used a different startup route')
    duration = value.get('startup_duration_us')
    timing = validate_startup_measurements(value, required=require_phases)
    claims = [event for event in events if event.get('event') == 'pool.claimed' and event.get('job_id') == value['id']]
    require(len(claims) == 1 and claims[0].get('startup_mode') == mode, 'missing unique durable VM claim')
    claim = claims[0]
    vm_id = claim.get('vm_id', '')
    require(re.fullmatch('[0-9a-f]{24}', vm_id) and vm_id not in used, 'VM identity missing or reused')
    result = {'job_id': value['id'], 'vm_id': vm_id, 'startup_duration_us': duration,
              'startup_timing': timing, 'success': True}
    if mode == 'cold':
        created = [event for event in events if event.get('event') == 'pool.created' and event.get('job_id') == value['id']]
        profile = claim.get('profile_sha256', '')
        require(vm_id not in before and len(created) == 1 and created[0].get('vm_id') == vm_id and
                created[0].get('startup_mode') == 'cold' and created[0].get('code') == 'profile_mismatch' and
                re.fullmatch('[0-9a-f]{64}', profile) and created[0].get('profile_sha256') == profile and
                events.index(created[0]) < events.index(claim), 'cold VM lacks matching durable creation and claim')
        boot = value.get('vm_boot_duration_us')
        require(boot is not None, 'missing independent VMM boot time')
        result.update(cold_boot_ms=boot / 1000, cold_admission_ms=duration / 1000,
                      creation_profile_sha256=profile, cold_reason=created[0]['code'])
    else:
        require(vm_id in before and before[vm_id].get('phase') == 'ready' and
                claim.get('profile_sha256') == before[vm_id]['pool_key'], 'VM was not an observed ready instance')
        require(not process_matches(before[vm_id]), 'used VM still live after completed response')
        result.update(warm_start_ms=duration / 1000,
                      preboot_observation={key: before[vm_id].get(key) for key in
                          ('pid', 'start_time_ticks', 'instance_id', 'vm_id', 'pool_key', 'phase', 'uid', 'tracer_pid',
                           'cpu_allowed_list', 'mems_allowed_list', 'hardening', 'cpu_snapshot')},
                      vm_cpu_allowed_list=before[vm_id].get('cpu_allowed_list'),
                      vm_mems_allowed_list=before[vm_id].get('mems_allowed_list'))
    used.add(vm_id)
    return result


def atomic_report(path, value):
    temporary = path.with_suffix('.tmp')
    with temporary.open('x', encoding='utf-8') as output:
        os.chmod(temporary, 0o600)
        output.write(json.dumps(value, indent=2) + '\n')
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def measure(request, config, output, *, samples=1000, warmup=5, diagnostic=False, candidate=None, require_phases=False,
            mode='warm', science=False):
    """Caller owns the fixture and the global validation flock for this batch."""
    require(type(samples) is int and 1 <= samples <= 100000 and type(warmup) is int and 0 <= warmup <= 100,
            'invalid batch size')
    backend = config['backend']
    require(mode in ('warm', 'cold') and backend in ('firecracker-linux', 'firecracker-osv') and
            (not science or backend == 'firecracker-osv'), 'unsupported measured route or workload')
    config_path = Path(config['run_root']).parent/('config.production.json' if config.get('production') else 'config.json')
    expected = 'WARM_BENCH_OK' if backend == 'firecracker-linux' else 'OSV_NATIVE_MODULE_OK\n'
    body = {'backend': backend, 'entrypoint': '/bin/sh' if backend == 'firecracker-linux' else '/task-probe.so',
            'args': ['-c', 'printf WARM_BENCH_OK'] if backend == 'firecracker-linux' else ['native-success'],
            'memory_mib': 128, 'vcpus': 1, 'timeout_ms': 10000}
    profile_name = 'small'
    if science:
        expected, profile_name = 'OSV_SCIENCE_BENCH_OK\n', 'science'
        body.update(entrypoint='/python3.12.so', args=['-c', "print('OSV_SCIENCE_BENCH_OK')"], memory_mib=512)
    if mode == 'cold':
        pool = config['warm_pool']
        require(pool['enabled'] and pool['on_miss'] == 'cold' and all(
                (p['memory_mib'], p['vcpus']) != (body['memory_mib'], body['vcpus']) for p in pool['profiles']),
                'cold measurement requires an unmatched workload shape')
    output = Path(output)
    output.mkdir(mode=0o700)
    metrics = ('warm_start_ms',) if mode == 'warm' else ('cold_boot_ms', 'cold_admission_ms')
    report = {'suite': 'warm-start-benchmark/v1' if mode == 'warm' else 'cold-start-benchmark/v1',
        'environment': 'real-kvm', 'backend': backend, 'arch': platform.machine(), 'startup_mode': mode, 'diagnostic': diagnostic,
        'release_eligible': False, 'performance_gate_evidence': False, 'samples_requested': samples,
        'phase_timing_required': require_phases,
        'warmup_requested': warmup, 'configuration_sha256': sha(config_path),
        'test_sha256': sha(Path(__file__)), 'generated_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'measurement': {metrics[-1]: 'launcher authenticated admission through durable prepare/claim completion',
            'http_ms': 'entire response body received', 'ready_wait_ms': 'pacing outside launcher startup timer',
            'rss': 'sum of live owned VMM VmRSS sampled every 20ms; observed peak only',
            'cpu': 'request-before to last live 20ms sample; may include execution and miss late increments; not exact readiness attribution',
            'throughput': 'paced full batch with validation, refill waits and sample persistence; not saturated capacity',
            'workload': body}, 'attempts': [], 'warmup_attempts': [], 'passed': False}
    if mode == 'cold':
        report['measurement']['cold_boot_ms'] = 'VMM launch through first verified pristine readiness'
    host = {'uname': platform.uname()._asdict(), 'affinity': sorted(os.sched_getaffinity(0)),
            'cpuinfo': Path('/proc/cpuinfo').read_text(), 'swaps': Path('/proc/swaps').read_text(),
            'meminfo': Path('/proc/meminfo').read_text(), 'loadavg': Path('/proc/loadavg').read_text(),
            'lscpu': subprocess.check_output(['lscpu', '--json'], text=True)}
    atomic_report(output/'host.json', host)
    report['host_baseline_sha256'] = sha(output/'host.json')
    if candidate:
        report['candidate'] = {'path': str(candidate), 'sha256': sha(candidate)}
    runtime_paths = [Path(config['hypervisor_path']),
        Path(config['jailer']['path']), Path(config['artifact_root'])/config['artifact_manifest']['path'],
        Path(config['artifact_root'])/config['artifact_manifest']['sbom_path']]
    for name in ('osv-sandboxd', 'osv-sandbox-launcher'):
        runtime_paths.append(Path(config['hypervisor_path']).parent/name)
    for artifact in ('kernel', 'image'):
        runtime_paths.append(Path(config['artifact_root'])/config[artifact]['path'])
    harness = Path(config['run_root']).parent/'osv-preproduction-harness'
    if harness.exists():
        runtime_paths.append(harness)
    report['runtime_files'] = {str(path): sha(path) for path in runtime_paths}
    cpu_period = config['jailer'].get('cpu_period_us', 100000)
    cpu_quota = config['jailer'].get('cpu_quota_per_vcpu_us', 100000)
    report['cpu_policy'] = {'period_us': cpu_period, 'quota_per_vcpu_us': cpu_quota,
                            'history_max_vms': 32, 'history_max_samples_per_vm': 64, 'sample_interval_ms': 20}
    parent = Path('/sys/fs/cgroup')/config['jailer'].get('parent_cgroup', 'missing')
    report['cpu_parent_limit'] = (parent/'cpu.max').read_text().strip() if (parent/'cpu.max').exists() else None
    audit = AuditTail(config['audit_log_path'])
    observer = RSSObserver(config)
    used = set()
    started = time.monotonic()
    final = None
    try:
        status, caps = request('/v1/capabilities')
        require(status == 200 and caps.get('backend') == backend and caps.get('features', {}).get('warm_pool'),
                'capabilities do not confirm warm pool backend')
        body['artifact_manifest_sha256'] = caps['artifact_manifest_sha256']
        report['manifest_sha256'] = body['artifact_manifest_sha256']
        status, doctor = request('/v1/doctor')
        require(status in (200, 503), 'doctor unavailable')
        report['initial_doctor'] = doctor
        report['production_doctor_ready'] = bool(config.get('production') and caps.get('stage') != 'diagnostic' and doctor.get('ready'))
        require(diagnostic or report['production_doctor_ready'], 'production doctor is not ready; explicit diagnostic batch required')
        observer.thread.start()
        with (output/'samples.jsonl').open('x', encoding='utf-8') as raw:
            os.chmod(output/'samples.jsonl', 0o600)
            for number in range(warmup + samples):
                record = {'index': number - warmup, 'warmup': number < warmup, 'success': False}
                wait_started = time.monotonic()
                try:
                    while True:
                        status, final = request('/v1/doctor')
                        require(status in (200, 503), 'doctor unavailable during batch')
                        require(diagnostic or final.get('ready'), 'production doctor lost readiness')
                        pool = final.get('warm_pool', {})
                        require(pool.get('healthy') and not pool.get('memory_pressure'), 'pool unhealthy or under pressure')
                        before = owned_leases(config)
                        if mode == 'warm':
                            profile = next((row for row in pool['profiles'] if row['name'] == profile_name), None)
                            require(profile is not None, 'expected ready profile is missing')
                            before = {key: row for key, row in before.items()
                                      if row.get('phase') == 'ready' and row.get('pool_key') == profile['key']}
                        if (mode == 'cold' or before) and final['vm_capacity']['active'] == 0 and pool['foreground'] == 0:
                            if mode == 'cold':
                                break
                            require(all(row['cpu_snapshot']['limit'] == str(cpu_quota)+' '+str(cpu_period) for row in before.values()),
                                    'ready VM CPU limit does not match the configured 1-vCPU workload')
                            break
                        require(time.monotonic() - wait_started < 30, 'ready wait deadline exceeded')
                        time.sleep(.01)
                    record['ready_wait_ms'] = (time.monotonic() - wait_started) * 1000
                    audit.read()  # Discard only events before this request; never filter its result.
                    sent = time.monotonic()
                    status, value = request('/v2/jobs', body)
                    record.update(http_status=status, http_ms=(time.monotonic() - sent) * 1000,
                                  startup_mode=value.get('startup_mode') if isinstance(value, dict) else None,
                                  timed_out=value.get('timed_out') is True if isinstance(value, dict) else False)
                    require(status == 200, 'job HTTP status ' + str(status))
                    bound = validate_job(value, backend, expected, before, audit.read(), used,
                                         require_phases=require_phases, mode=mode)
                    if mode == 'warm':
                        bound['cpu_observation'] = cpu_window(before[bound['vm_id']].get('cpu_snapshot'), observer.cpu.get(bound['vm_id']))
                    else:
                        require(bound['vm_id'] not in owned_leases(config), 'used cold VM still live after completed response')
                    record.update(bound)
                except Exception as error:
                    record['success'] = False
                    record['error'] = type(error).__name__ + ': ' + str(error)[:300]
                    record['timed_out'] = bool(record.get('timed_out') or isinstance(error, (TimeoutError, socket.timeout)) or
                        (isinstance(error, urllib.error.URLError) and isinstance(error.reason, TimeoutError)))
                key = 'warmup_attempts' if record['warmup'] else 'attempts'
                report[key].append(record)
                raw.write(json.dumps(record) + '\n')
                raw.flush()
                os.fsync(raw.fileno())
                if not record['success']:
                    break
                if (number + 1) % 100 == 0:
                    print(json.dumps({'benchmark_progress': number + 1, 'requested': warmup + samples}), flush=True)
        report['passed'] = (len(report['attempts']) == samples and len(report['warmup_attempts']) == warmup and
                            all(row['success'] for row in [*report['warmup_attempts'], *report['attempts']]))
    except Exception as error:
        report['error'] = type(error).__name__ + ': ' + str(error)[:300]
    finally:
        if observer.thread.ident is not None:
            observer.close()
        audit.close()
        report['elapsed_seconds'] = time.monotonic() - started
        report['final_observed_doctor'] = final
        report['peak_observed_rss_bytes'] = observer.peak
        report['rss_observation_errors'] = observer.errors
        report['retired_cpu_read_skips'] = observer.retired_cpu_reads
        if observer.errors:
            report['passed'] = False
        successful = [row for row in report['attempts'] if row['success']]
        report['attempted'] = len(report['attempts'])
        report['successes'] = len(successful)
        report['failures'] = len(report['attempts']) - len(successful)
        report['warmup_failures'] = sum(not row['success'] for row in report['warmup_attempts'])
        report['rejections'] = sum(row.get('http_status') in (400, 403, 409, 429, 503) for row in report['attempts'])
        report['timeouts'] = sum(row.get('timed_out', False) for row in report['attempts'])
        report['route_mismatches'] = sum(row.get('startup_mode') not in (None, mode) for row in report['attempts'])
        if mode == 'warm':
            report['cold_misses'] = sum(row.get('startup_mode') == 'cold' for row in report['attempts'])
        report['minimum_samples_met'] = len(successful) >= 1000 and report['failures'] == report['warmup_failures'] == 0
        report['percentiles_ms'] = {key: percentiles([row[key] for row in successful])
                                    for key in (*metrics, 'http_ms', 'ready_wait_ms')}
        partitioned = [row['startup_timing'] for row in successful if row.get('startup_timing') is not None]
        report['phase_samples'] = len(partitioned)
        report['phase_percentiles_ms'] = {key: percentiles([timing[key] / 1000 for timing in partitioned])
                                          for key in PHASE_FIELDS}
        cpu_observed = [row['cpu_observation'] for row in successful
                        if row.get('cpu_observation', {}).get('coverage') == 'sampled-live-window']
        report['cpu_observed_requests'] = len(cpu_observed)
        report['requests_with_observed_throttle_increase'] = sum(row['delta']['nr_throttled'] > 0 for row in cpu_observed)
        report['requests_with_observed_throttled_time_increase'] = sum(row['delta']['throttled_usec'] > 0 for row in cpu_observed)
        report['paced_successes_per_second'] = len(successful) / report['elapsed_seconds']
        report['raw_samples_sha256'] = sha(output/'samples.jsonl') if (output/'samples.jsonl').exists() else None
        report['sampled_workload_succeeded'] = report['passed']
        atomic_report(output/'report.json', report)
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--package', type=Path, required=True)
    parser.add_argument('--samples', type=int, default=1000)
    parser.add_argument('--warmup', type=int, default=5)
    parser.add_argument('--diagnostic', action='store_true')
    parser.add_argument('--label', default='startup')
    parser.add_argument('--require-phase-timing', action='store_true')
    parser.add_argument('--startup-mode', choices=('warm', 'cold'), default='warm')
    parser.add_argument('--osv-science', action='store_true')
    parser.add_argument('--lock-fd', type=int, help='inherit the caller-held global validation lock')
    args = parser.parse_args()
    require(re.fullmatch(r'[a-z0-9][a-z0-9-]{0,63}', args.label), 'invalid result label')
    root = args.root.resolve()
    require(os.geteuid() == 0 and root.parent == Path('/var/lib') and
            re.fullmatch(r'osv-offline-validation-20261030-[a-z0-9]+', root.name), 'requires isolated owned fixture')
    config = json.loads((root/'config.production.json').read_text())
    require(config['run_root'] == str(root/'run') and config['jailer']['parent_cgroup'] == root.name,
            'fixture ownership mismatch')
    with validation_lock(args.lock_fd):
        pid = int(subprocess.check_output(['systemctl','show','-p','MainPID','--value',root.name+'-api.service'],text=True))
        require(pid > 1, 'API is not running')
        with open('/proc/'+str(pid)+'/ns/net') as namespace:
            require(ctypes.CDLL(None, use_errno=True).setns(namespace.fileno(), 0x40000000) == 0, 'could not enter API namespace')
        context = ssl.create_default_context(cafile=root/'tls/ca.crt')
        context.load_cert_chain(root/'tls/client.crt', root/'tls/client.key')
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
        token = (root/'secrets/token').read_text()
        def request(path, body=None):
            req = urllib.request.Request('https://localhost:'+config['listen'].rsplit(':',1)[1]+path,
                data=json.dumps(body).encode() if body is not None else None,
                headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'})
            try:
                response = opener.open(req, timeout=35)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                data = response.read(2 * 1024 * 1024 + 1)
                require(len(data) <= 2 * 1024 * 1024, 'HTTP response exceeds measurement bound')
                return response.status, json.loads(data)
        result = measure(request, config, root/'results'/args.label, samples=args.samples,
                         warmup=args.warmup, diagnostic=args.diagnostic, candidate=args.package,
                         require_phases=args.require_phase_timing, mode=args.startup_mode, science=args.osv_science)
        print(json.dumps({key:result[key] for key in ('passed','successes','failures','minimum_samples_met','percentiles_ms','release_eligible')}))
        return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
