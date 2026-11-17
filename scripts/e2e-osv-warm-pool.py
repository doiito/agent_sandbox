#!/usr/bin/env python3
"""Real mTLS API/launcher/KVM acceptance of the shared OSv pristine pool."""
import argparse
import base64
import datetime
import grp
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import signal
import socket
import ssl
import subprocess
import time
import urllib.error
import urllib.request

from startup_benchmark import validation_lock


def require(value, message):
    if not value:
        raise RuntimeError(message)


def wait_for(predicate, message, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = predicate()
        if result:
            return result
        time.sleep(0.02)
    raise RuntimeError(message)


def sha(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def process_matches(lease):
    try:
        text = Path('/proc', str(lease['pid']), 'stat').read_text()
        return int(text[text.rfind(')') + 2:].split()[19]) == lease['start_time_ticks']
    except (OSError, ValueError, IndexError):
        return False


def leases(root):
    result = {}
    for path in (root / 'run').glob('job-*/lease.json'):
        try:
            item = json.loads(path.read_text())
            if not process_matches(item):
                continue
            item['directory'] = str(path.parent)
            if item.get('phase') in ('ready', 'claiming', 'active'):
                proc = Path('/proc', str(item['pid']))
                status = dict(line.split(':', 1) for line in (proc / 'status').read_text().splitlines() if ':' in line)
                item['uid'] = status['Uid'].split()
                require(item['uid'] == status['Gid'].split() and len(set(item['uid'])) == 1 and
                        232010 <= int(item['uid'][0]) <= 232012 and status['Seccomp'].strip() == '2' and
                        status['CapEff'].strip() == '0000000000000000', 'VM identity or hardening mismatch')
                require((proc / 'cgroup').read_text().strip() == '0::/' + root.name + '/' + path.parent.name,
                        'VM escaped its owned cgroup')
            result[item['vm_id']] = item
        except (FileNotFoundError, ProcessLookupError):
            continue
    used = [row['uid'][0] for row in result.values() if 'uid' in row]
    require(len(result) <= 3 and len(used) == len(set(used)), 'physical ceiling or unique identity violated')
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--template', type=Path, required=True)
    parser.add_argument('--harness', type=Path, required=True)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--benchmark-samples', type=int)
    parser.add_argument('--benchmark-warmup', type=int, default=5)
    parser.add_argument('--require-phase-timing', action='store_true')
    parser.add_argument('--lock-fd', type=int, help='inherit the caller-held global validation lock')
    args = parser.parse_args()
    require(args.benchmark_samples is None or 1 <= args.benchmark_samples <= 100000, 'invalid benchmark sample count')
    require(0 <= args.benchmark_warmup <= 100, 'invalid benchmark warmup count')
    require(os.geteuid() == 0 and args.root.parent == Path('/var/lib') and
            re.fullmatch(r'osv-offline-validation-20261030-rc[0-9]+osvpool[0-9]*', args.root.name) and not args.root.exists(), 'requires root and a fresh isolated fixture')
    require(not subprocess.check_output(['/sbin/ip', 'route', 'show']).strip(), 'requires a namespace without routes')
    with validation_lock(args.lock_fd):
        exercise(args)


def exercise(args):
    root = args.root
    for identity in range(232010, 232013):
        for lookup in (pwd.getpwuid, grp.getgrgid):
            try:
                lookup(identity)
            except KeyError:
                continue
            raise RuntimeError('validation identity already assigned')
    subprocess.run(['/sbin/ip', 'link', 'set', 'lo', 'up'], check=True)
    root.mkdir(mode=0o755)
    for name, mode in (('run', 0o700), ('tls', 0o755), ('results', 0o700)):
        (root / name).mkdir(mode=mode)
    template = root / 'template'
    shutil.copytree(args.template, template)
    manifest = json.loads((template / 'artifacts/manifest.test.json').read_text())
    require('pristine-v1' in manifest.get('agent_features', []), 'unsigned pristine feature')
    uid = pwd.getpwnam('osv-sandbox').pw_uid
    spec = importlib.util.spec_from_file_location('osv_baseline', Path(__file__).with_name('test-osv-cross-process.py'))
    baseline = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(baseline)
    ca, cert, key, client_cert, client_key = baseline.issue_certificates(root / 'tls', uid)
    for public in (root / 'tls').glob('*.crt'):
        public.chmod(0o644)
    tokens = {name: secrets.token_hex(32) for name in ('validation-a', 'validation-b')}
    policy = {'protocol': 'osv-sandbox-auth/v1', 'tenants': [
        {'id': name, 'token_sha256': hashlib.sha256(value.encode()).hexdigest(), 'allowed_entrypoints': ['/task-probe.so'],
         'requests_per_second': 100, 'burst': 100, 'max_concurrent': 1} for name, value in tokens.items()]}
    (root / 'auth.json').write_text(json.dumps(policy))
    (root / 'auth.json').chmod(0o644)
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
    config = {'listen': '127.0.0.1:' + str(port), 'backend': 'firecracker-osv',
        'artifact_root': str(template / 'artifacts'), 'run_root': str(root / 'run'),
        'hypervisor_path': str(template / 'bin/firecracker'),
        'kernel': manifest['kernel'], 'image': manifest['image'], 'allowed_entrypoints': ['/task-probe.so'],
        'jailer': {'path': str(template / 'bin/jailer'), 'uid': 232010, 'gid': 232010, 'identity_pool_size': 3,
                   'cgroup_version': 2, 'parent_cgroup': root.name, 'memory_overhead_mib': 128, 'pids_max': 64},
        'defaults': {'memory_mib': 128, 'vcpus': 1, 'timeout_ms': 10000},
        'limits': {'max_concurrent': 2, 'max_memory_mib': 512, 'max_vcpus': 1, 'max_output_bytes': 16384, 'max_timeout_ms': 30000},
        'vm_capacity': {'max_instances': 3, 'reserved_memory_mib': 1920, 'reserved_vcpus': 3, 'reserved_pids': 192},
        'warm_pool': {'enabled': True, 'on_miss': 'cold', 'max_booting': 2, 'refill_per_second': 4, 'refill_burst': 2,
            'max_idle_age_ms': 120000, 'health_interval_ms': 1000, 'check_timeout_ms': 1000, 'boot_timeout_ms': 10000,
            'checkout_timeout_ms': 10000, 'startup_timeout_ms': 30000, 'min_available_memory_mib': 128,
            'profiles': [{'name': 'small', 'memory_mib': 128, 'vcpus': 1, 'min_ready': 1, 'max_ready': 2},
                         {'name': 'large', 'memory_mib': 256, 'vcpus': 1, 'min_ready': 1, 'max_ready': 1}]},
        'launcher_socket': str(root / 'launcher.sock'), 'auth_policy_path': str(root / 'auth.json'),
        'audit_log_path': str(root / 'audit.jsonl'), 'tls': {'cert_file': str(cert), 'key_file': str(key), 'client_ca_file': str(ca)},
        'artifact_manifest': {'path': 'manifest.test.json', 'signature_path': 'manifest.test.json.sig',
            'public_key_path': str(template / 'artifact-test.public'), 'sbom_path': 'sbom.cdx.json'}}
    config_path = root / 'config.json'
    config_path.write_text(json.dumps(config, indent=2) + '\n')
    config_path.chmod(0o644)
    harness = root / 'osv-preproduction-harness'
    shutil.copyfile(args.harness, harness)
    harness.chmod(0o755)
    context = ssl.create_default_context(cafile=ca)
    context.load_cert_chain(client_cert, client_key)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
    processes, logs, connections, paused, cases = [], [], [], [], []
    digest = sha(template / 'artifacts/manifest.test.json')
    report = {'suite': 'osv-warm-start-benchmark-fixture/v1' if args.benchmark_samples else 'osv-warm-pool-kvm/v1', 'production_validated': False, 'performance_gate_evidence': False,
        'manifest_sha256': digest, 'harness_sha256': sha(harness), 'configuration_sha256': sha(config_path),
        'script_sha256': sha(Path(__file__)), 'cases': cases, 'passed': False}

    def check(name, passed, **evidence):
        cases.append({'name': name, 'passed': bool(passed), **evidence})
        require(passed, name)

    def request(path, body=None, tenant='validation-a', method=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request('https://127.0.0.1:' + str(port) + path, data=data, method=method,
            headers={'Authorization': 'Bearer ' + tokens[tenant], 'Content-Type': 'application/json'})
        try:
            response = opener.open(req, timeout=35)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            data = response.read()
            return response.status, json.loads(data) if data else None

    def ready():
        status, value = request('/v1/doctor')
        pool = value.get('warm_pool', {})
        return value if status in (200, 503) and pool.get('healthy') and value['vm_capacity']['active'] == 0 and all(row['ready'] >= 1 for row in pool['profiles']) else None

    def start(role):
        log = (root / 'results' / (role + '-' + str(len(processes)) + '.stderr')).open('wb')
        logs.append(log)
        cmd = [str(harness), '-role', role, '-config', str(config_path), '-api-uid', str(uid)]
        if role == 'api':
            cmd = ['setpriv', '--reuid=' + str(uid), '--regid=' + str(uid), '--clear-groups', *cmd]
        process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=log)
        processes.append(process)
        if role == 'launcher':
            wait_for(lambda: (require(process.poll() is None, 'launcher exited during start') or (root / 'launcher.sock').exists()), 'launcher did not finish min_ready', timeout=40)
        else:
            def listening():
                require(process.poll() is None, 'API exited during start')
                try:
                    return request('/healthz')[0] == 200
                except (urllib.error.URLError, ConnectionError):
                    return False
            wait_for(listening, 'API did not listen')
        return process

    def payload(argument, memory=128, timeout=10000, **extra):
        return {'backend': 'firecracker-osv', 'artifact_manifest_sha256': digest, 'entrypoint': '/task-probe.so',
                'args': [argument], 'memory_mib': memory, 'vcpus': 1, 'timeout_ms': timeout, **extra}

    def job(argument, tenant='validation-a', memory=128, timeout=10000, **extra):
        status, value = request('/v2/jobs', payload(argument, memory, timeout, **extra), tenant)
        require(status == 200, 'job HTTP status ' + str(status))
        return value

    def open_job(tenant='validation-a', memory=128, argument='native-sleep'):
        raw = socket.create_connection(('127.0.0.1', port), timeout=5)
        conn = context.wrap_socket(raw, server_hostname='127.0.0.1')
        connections.append(conn)
        body = json.dumps(payload(argument, memory, 15000)).encode()
        conn.sendall(('POST /v2/jobs HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer ' + tokens[tenant] +
                     '\r\nContent-Type: application/json\r\nContent-Length: ' + str(len(body)) + '\r\nConnection: close\r\n\r\n').encode() + body)
        return conn

    def owned(tenant):
        return next((row for row in leases(root).values() if row.get('phase') == 'active' and row.get('tenant') == tenant), None)

    def claim(job_id):
        return next((json.loads(line) for line in (root / 'audit.jsonl').read_text().splitlines()
                     if json.loads(line).get('event') == 'pool.claimed' and json.loads(line).get('job_id') == job_id), None)

    def no_jobs():
        return not list((root / 'run').glob('job-*')) and not list((Path('/sys/fs/cgroup') / root.name).glob('job-*'))

    try:
        launcher = start('launcher'); api = start('api')
        initial = wait_for(ready, 'initial pool not ready')
        if args.benchmark_samples:
            from startup_benchmark import measure
            measurement = measure(request, config, root/'results/startup', samples=args.benchmark_samples,
                                  warmup=args.benchmark_warmup, diagnostic=True, require_phases=args.require_phase_timing)
            report['benchmark_report_sha256'] = sha(root/'results/startup/report.json')
            report['passed'] = measurement['passed']
            require(report['passed'], 'startup measurement failed; inspect persisted samples/report')
            return
        events = [json.loads(line) for line in (root / 'audit.jsonl').read_text().splitlines()]
        ready_index = next(index for index, event in enumerate(events) if event['event'] == 'launcher.ready')
        check('initial-minimum-before-ready', len({event.get('profile_sha256') for event in events[:ready_index] if event['event'] == 'pool.ready'}) == 2)
        status, caps = request('/v1/capabilities')
        check('honest-osv-pool-capabilities', status == 200 and caps['stage'] == 'diagnostic' and caps['features']['warm_pool'] and not caps['features']['sessions'] and not caps['features']['input_files'] and caps['guest_result_protocol'] == 'osv-agent/v1')
        profiles = {row['name']: row for row in initial['warm_pool']['profiles']}
        first = next(row for row in leases(root).values() if row.get('phase') == 'ready' and row['pool_key'] == profiles['small']['key'])
        check('idle-physical-without-active', initial['vm_capacity']['active'] == 0 and initial['vm_capacity']['instances'] >= 2)
        live_ids = set(leases(root))
        second = subprocess.run([str(harness), '-role', 'launcher', '-config', str(config_path), '-api-uid', str(uid)], capture_output=True, text=True, timeout=10)
        check('second-owner-rejected', second.returncode != 0 and 'another privileged launcher owns run_root' in second.stderr and live_ids == set(leases(root)))
        value = job('native-env-stdin', environment={'SANDBOX_TEST_MARKER': 'native-env-ok'}, stdin=base64.b64encode(b'A\0B\xff\n').decode())
        event = claim(value['id'])
        check('actual-prebooted-bound-job', value.get('startup_mode') == 'warm' and event and event['vm_id'] == first['vm_id'] and value['state'] == 'succeeded' and 'OSV_NATIVE_STDIN_BINARY_OK' in value['guest_result']['stdout'], vm_id=first['vm_id'], startup_duration_us=value.get('startup_duration_us'))
        from startup_benchmark import validate_startup_measurements
        check('job-startup-timing-partition', validate_startup_measurements(value, required=True) is not None and value['startup_timing']['schema'] == 'osv-startup-timing/v2',
              timing=value['startup_timing'])
        check('used-vm-destroyed', not process_matches(first) and first['vm_id'] not in leases(root))
        wait_for(ready, 'refill after first job')
        value = job('native-env-absent', tenant='validation-b')
        check('tenant-state-isolation', value['state'] == 'succeeded' and claim(value['id'])['vm_id'] != first['vm_id'])
        value = job('native-task')
        check('warm-guest-exit-seven', value['state'] == 'guest_error' and value['exit_code'] == 7 and value['guest_result']['exit_code'] == 7)
        value = job('native-task', memory=384)
        check('profile-mismatch-cold-exit-seven', value.get('startup_mode') == 'cold' and value['state'] == 'guest_error' and value['exit_code'] == 7)
        validate_startup_measurements(value, required=True)
        check('cold-vmm-ready-duration', value['startup_timing']['schema'] == 'osv-startup-timing/v2' and 0 < value.get('vm_boot_duration_us', 0) <= value['startup_duration_us'],
              vm_boot_duration_us=value.get('vm_boot_duration_us'), timing=value['startup_timing'])
        wait_for(ready, 'pool after cold fallback')
        status, _ = request('/v2/sessions', {'backend': 'firecracker-osv', 'artifact_manifest_sha256': digest})
        check('osv-session-rejected', status in (400, 501) and request('/v1/doctor')[1]['vm_capacity']['active'] == 0)
        status, _ = request('/v2/jobs', payload('native-success', input_files=[{'path': 'denied', 'data': 'eA=='}]))
        check('osv-input-files-rejected', status == 400)
        one = open_job(); owner_a = wait_for(lambda: owned('validation-a'), 'job A not active')
        two = open_job('validation-b', 256); owner_b = wait_for(lambda: owned('validation-b'), 'job B not active')
        check('concurrent-identity-and-capacity', owner_a['uid'] != owner_b['uid'] and request('/v1/doctor')[1]['vm_capacity']['active'] == 2)
        status, _ = request('/v2/jobs', payload('native-success'))
        check('tenant-quota-preserves-held-vms', status == 429 and process_matches(owner_a) and process_matches(owner_b))
        one.close(); connections.remove(one)
        wait_for(lambda: not process_matches(owner_a) and request('/v1/doctor')[1]['vm_capacity']['active'] == 1, 'HTTP cancel did not reclaim A', timeout=4)
        check('cancel-preserves-other-tenant', process_matches(owner_b))
        two.close(); connections.remove(two)
        wait_for(ready, 'pool after concurrent cancellations')
        value = job('native-sleep', timeout=1000)
        check('warm-job-timeout-reclaimed', value['state'] == 'timed_out' and value['timed_out'] and request('/v1/doctor')[1]['vm_capacity']['active'] == 0)
        wait_for(ready, 'refill after timeout')
        victim = next(row for row in leases(root).values() if row.get('phase') == 'ready' and row['pool_key'] == profiles['small']['key'])
        os.kill(victim['pid'], signal.SIGKILL)
        value = job('native-success')
        check('dead-vm-not-issued', value['state'] == 'succeeded' and claim(value['id'])['vm_id'] != victim['vm_id'])
        wait_for(ready, 'refill after dead VM')
        paused = [row for row in leases(root).values() if row.get('phase') == 'ready' and row['pool_key'] == profiles['small']['key']]
        for row in paused:
            os.kill(row['pid'], signal.SIGSTOP)
        pending = open_job()
        wait_for(lambda: request('/v1/doctor')[1]['warm_pool']['foreground'] >= 1, 'checkout did not start')
        pending.close(); connections.remove(pending)
        wait_for(lambda: request('/v1/doctor')[1]['vm_capacity']['active'] == 0, 'checkout cancellation retained active', timeout=4)
        for row in paused:
            if process_matches(row):
                os.kill(row['pid'], signal.SIGCONT)
        paused = []
        check('checkout-disconnect-reclaimed', True)
        wait_for(ready, 'refill after checkout cancel')
        active = open_job(); orphan = wait_for(lambda: owned('validation-a'), 'API-crash job missing')
        idle_ids = {key for key, row in leases(root).items() if row.get('phase') == 'ready'}
        api.kill(); api.wait(timeout=10)
        wait_for(lambda: not process_matches(orphan), 'API crash retained active VM', timeout=4)
        check('api-crash-preserves-idle-pool', launcher.poll() is None and bool(idle_ids.intersection(leases(root))))
        active.close(); connections.remove(active)
        api = start('api'); wait_for(ready, 'pool after API restart')
        active = open_job(); wait_for(lambda: owned('validation-a'), 'shutdown job not active')
        old = leases(root)
        launcher.terminate(); launcher.wait(timeout=20)
        wait_for(no_jobs, 'graceful shutdown retained jobs')
        check('shutdown-zero-residue', launcher.returncode == 0 and all(not process_matches(row) for row in old.values()))
        active.close(); connections.remove(active)
        launcher = start('launcher'); wait_for(ready, 'pool after launcher restart')
        old = leases(root)
        launcher.kill(); launcher.wait(timeout=10)
        check('launcher-crash-leaves-owned-evidence', bool(list((root / 'run').glob('job-*/lease.json'))))
        launcher = start('launcher'); wait_for(ready, 'pool after crash reconciliation')
        check('launcher-crash-reconciles-pool', not set(old).intersection(leases(root)))
        ownership = next((row for row in request('/v1/doctor')[1]['checks'] if row['name'] == 'orphan-reconciliation'), {})
        check('diagnostic-runtime-confirms-reconciliation', ownership.get('ok') is True and 'reconciled=0' not in ownership.get('detail', '') and 'reconciled=' in ownership.get('detail', ''))
        value = job('native-success', tenant='validation-b')
        check('post-crash-guest-executes', value['state'] == 'succeeded')
        report['final'] = wait_for(ready, 'final pool not ready')['warm_pool']
        report['passed'] = True
    except Exception as error:
        report['error'] = str(error)
        raise
    finally:
        for row in paused:
            if process_matches(row):
                os.kill(row['pid'], signal.SIGCONT)
        for connection in connections:
            connection.close()
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait(timeout=5)
        for log in logs:
            log.close()
        remaining = [str(path) for path in (root / 'run').glob('job-*')]
        cgroup = Path('/sys/fs/cgroup') / root.name
        leaves = [str(path) for path in cgroup.glob('job-*')]
        report['cleanup'] = {'remaining_dirs': remaining, 'remaining_cgroups': leaves,
                             'live_vms': [row['vm_id'] for row in leases(root).values()]}
        if any(report['cleanup'].values()):
            report['passed'] = False
        if cgroup.exists() and not leaves and not (cgroup / 'cgroup.procs').read_text().strip():
            cgroup.rmdir()
        shutil.rmtree(root / 'tls', ignore_errors=True)
        (root / 'auth.json').unlink(missing_ok=True)
        report['generated_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        (root / 'results/osv-warm-pool.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps({'passed': report['passed'], 'cases': len(cases), 'error': report.get('error'), 'cleanup': report['cleanup']}), flush=True)
    require(report['passed'], 'acceptance or cleanup failed')


if __name__ == '__main__':
    main()
