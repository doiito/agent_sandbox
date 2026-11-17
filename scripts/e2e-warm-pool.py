#!/usr/bin/env python3
"""Real API/launcher/KVM proof of pristine reuse, isolation and pool recovery."""
import argparse
import base64
import ctypes
import hashlib
import json
import os
from pathlib import Path
import pwd
import secrets
import signal
import socket
import ssl
import subprocess
import time

import osv_sandbox_client as sdk
from startup_benchmark import validate_startup_measurements, validation_lock


def require(value, message):
    if not value:
        raise RuntimeError(message)


def wait_for(predicate, message, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = predicate()
        if result:
            return result
        time.sleep(0.02)
    raise RuntimeError(message)


def unit_pid(unit):
    return int(subprocess.check_output(['systemctl', 'show', '-p', 'MainPID', '--value', unit], text=True))


def enter_api(root):
    pid = unit_pid(root.name + '-api.service')
    require(pid > 1, 'API fixture inactive')
    fd = os.open('/proc/' + str(pid) + '/ns/net', os.O_RDONLY)
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.setns(fd, 0) != 0:
            raise OSError(ctypes.get_errno(), 'enter API network namespace')
    finally:
        os.close(fd)


def process_matches(lease):
    try:
        value = Path('/proc', str(lease['pid']), 'stat').read_text()
        return int(value[value.rfind(')') + 2:].split()[19]) == lease['start_time_ticks']
    except (OSError, ValueError, IndexError):
        return False


def leases(root):
    rows = {}
    for path in (root / 'run').glob('job-*/lease.json'):
        try:
            value = json.loads(path.read_text())
            if not process_matches(value):
                continue
            value['directory'] = str(path.parent)
            if value.get('phase') in ('ready', 'claiming', 'active'):
                status = dict(line.split(':', 1) for line in Path('/proc', str(value['pid']), 'status').read_text().splitlines() if ':' in line)
                value['uid'] = status['Uid'].split()
                value['gid'] = status['Gid'].split()
                require(value['uid'] == value['gid'] and len(set(value['uid'])) == 1 and
                        230000 <= int(value['uid'][0]) <= 230002 and status['Seccomp'].strip() == '2' and
                        status['CapEff'].strip() == '0000000000000000', 'VM jail identity or hardening mismatch')
                require(Path('/proc', str(value['pid']), 'cgroup').read_text().strip() == '0::/' + root.name + '/' + path.parent.name,
                        'VM escaped fixture cgroup')
            rows[value['vm_id']] = value
        except (FileNotFoundError, ProcessLookupError):
            continue
    identities = [row['uid'][0] for row in rows.values() if 'uid' in row]
    require(len(identities) == len(set(identities)), 'live VMs share a jail identity')
    require(len(rows) <= 3, 'physical VM ceiling exceeded')
    return rows


def pristine_pings(root, lease, port, count):
    uds = Path(lease['directory']) / 'jailer/firecracker' / lease['instance_id'] / 'root/agent.vsock'
    directory = os.open(uds.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        _pristine_pings('/proc/self/fd/' + str(directory) + '/' + uds.name, port, count)
    finally:
        os.close(directory)


def _pristine_pings(uds, port, count):
    for _ in range(count):
        job_id = secrets.token_hex(12)
        with socket.socket(socket.AF_UNIX) as conn:
            conn.settimeout(3)
            conn.connect(str(uds))
            reader = conn.makefile('rb')
            conn.sendall(('CONNECT ' + str(port) + '\n').encode())
            require(reader.readline(4096).startswith(b'OK '), 'vsock handshake failed')
            conn.sendall(json.dumps({'protocol': 'fc-agent/v3', 'job_id': job_id, 'operation': 'ping'}).encode() + b'\n')
            line = reader.readline(16384)
            require(line.startswith(b'FC_AGENT_RESULT '), 'pristine ping envelope missing')
            result = json.loads(line[len(b'FC_AGENT_RESULT '):])
            require(result.get('ok') is True and result.get('job_id') == job_id and
                    result.get('guest_state') == 'pristine' and result.get('pristine_revision') == 2 and
                    result.get('binding') is None, 'guest did not prove unused revision-2 readiness')
            reader.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--package', type=Path, required=True)
    parser.add_argument('--lock-fd', type=int, help='inherit the caller-held global validation lock')
    args = parser.parse_args()
    root = args.root.resolve()
    require(os.geteuid() == 0 and root.name.startswith('osv-offline-validation-20261030-') and root.is_dir(), 'requires isolated root fixture')
    release, = [p for p in (root / 'releases').iterdir() if p.is_dir()]
    require(Path(sdk.__file__).resolve() == (release / 'sdk/python/osv_sandbox_client.py').resolve(), 'SDK not from installed package')
    config = json.loads((root / 'config.production.json').read_text())
    require(config['warm_pool']['enabled'] and config['vm_capacity']['max_instances'] == 3 and
            config['limits']['max_concurrent'] == 2, 'wrong warm pool fixture')
    with validation_lock(args.lock_fd):
        exercise(root, args.package, config)


def exercise(root, package, config):
    enter_api(root)
    url = 'https://localhost:' + config['listen'].rsplit(':', 1)[1]
    options = dict(ca_file=str(root / 'tls/ca.crt'), cert_file=str(root / 'tls/client.crt'), key_file=str(root / 'tls/client.key'), request_timeout_seconds=65)
    a = sdk.Client(url, token=(root / 'secrets/token').read_text(), **options)
    b = sdk.Client(url, token=(root / 'secrets/token-b').read_text(), **options)
    cases, active, paused = [], [], []
    report = {'suite': 'warm-pool-kvm/v1', 'production_validated': False,
              'candidate_sha256': hashlib.sha256(package.read_bytes()).hexdigest(), 'cases': cases, 'passed': False,
              'performance_gate_evidence': False}

    def check(name, passed, **evidence):
        cases.append({'name': name, 'passed': bool(passed), **evidence})
        require(passed, name)

    def ready():
        status = a.doctor()
        return status if status['warm_pool']['healthy'] and status['vm_capacity']['active'] == 0 and all(p['ready'] >= 1 for p in status['warm_pool']['profiles']) else None

    def ready_after_api_restart():
        # Type=exec confirms exec, before the HTTPS listener necessarily binds.
        try:
            return ready()
        except sdk.TransportError:
            return None

    def create(client, memory=128, inputs=None, ttl_ms=60000, retry_busy=False):
        deadline = time.monotonic() + 20
        while True:
            try:
                info = client._exchange('POST', '/v2/sessions', {'backend': 'firecracker-linux',
                    'artifact_manifest_sha256': digest, 'memory_mib': memory, 'ttl_ms': ttl_ms,
                    'input_files': inputs or []}, accepted=(201,))
                break
            except sdk.APIError as error:
                if not retry_busy or error.status != 429 or error.code != 'busy' or time.monotonic() >= deadline:
                    raise
                time.sleep(0.1)
        handle = client.connect_session(info['id'])
        active.append(handle)
        return info, handle

    def close(handle):
        handle.close()
        active.remove(handle)

    def bound_lease(session_id):
        return next((row for row in leases(root).values() if row.get('request_id') == session_id and row.get('phase') == 'active'), None)

    digest = a.capabilities()['artifact_manifest_sha256']
    try:
        initial = wait_for(ready, 'initial pools not ready')
        profiles = {p['name']: p for p in initial['warm_pool']['profiles']}
        before = leases(root)
        first = next(row for row in before.values() if row['pool_key'] == profiles['small']['key'] and row['phase'] == 'ready')
        check('idle-physical-without-active', initial['vm_capacity']['active'] == 0 and initial['vm_capacity']['instances'] >= 2)
        duplicate = subprocess.run([str(Path(config['hypervisor_path']).parent / 'osv-sandbox-launcher'),
            '-config', str(root / 'config.production.json'), '-allowed-uid', str(pwd.getpwnam('osv-sandbox').pw_uid)],
            capture_output=True, text=True, timeout=10)
        check('second-owner-rejected', duplicate.returncode != 0 and
              'another privileged launcher owns run_root' in duplicate.stderr and
              all(process_matches(row) for row in before.values()))
        pristine_pings(root, first, config['linux_guest']['vsock_port'], 110)
        check('health-budget-preserves-unused-vm', process_matches(first) and a.doctor()['vm_capacity']['active'] == 0, pings=110)
        info_a, session_a = create(a, inputs=[{'path': 'prompt', 'data': base64.b64encode(b'input-a').decode()}])
        owner_a = wait_for(lambda: bound_lease(info_a['id']), 'session A owner missing')
        check('actual-prebooted-checkout', info_a.get('startup_mode') == 'warm' and owner_a['vm_id'] == first['vm_id'] and info_a.get('startup_duration_us', 0) > 0,
              vm_id=owner_a['vm_id'], startup_duration_us=info_a['startup_duration_us'])
        check('session-startup-timing-partition', validate_startup_measurements(info_a, required=True) is not None and info_a['startup_timing']['schema'] == 'osv-startup-timing/v2',
              timing=info_a['startup_timing'])
        result = session_a.run(sdk.SessionCommand('/bin/sh', ('-c', 'cat /input/prompt; if printf bad > /input/prompt; then exit 31; fi; printf tenant-a > /workspace/marker')))
        check('prepared-input-readonly', result.succeeded and result.guest_result['stdout'] == 'input-a')
        wait_for(lambda: a.doctor()['warm_pool']['profiles'][0]['ready'] >= 1, 'small pool did not refill')
        info_b, session_b = create(b)
        owner_b = wait_for(lambda: bound_lease(info_b['id']), 'session B owner missing')
        check('unique-concurrent-identity', info_b.get('startup_mode') == 'warm' and owner_a['vm_id'] != owner_b['vm_id'] and owner_a['uid'] != owner_b['uid'])
        try:
            session_b.read_file('/workspace/marker')
        except sdk.APIError as error:
            check('tenant-state-isolation', error.status == 404)
        else:
            raise RuntimeError('tenant A file leaked into tenant B')
        try:
            b.connect_session(info_a['id'])
        except sdk.APIError as error:
            check('cross-tenant-session-denied', error.status == 404)
        else:
            raise RuntimeError('cross-tenant session query succeeded')
        held = a.doctor()['vm_capacity']
        try:
            a.create_session(sdk.SessionRequest())
        except sdk.APIError as error:
            check('quota-rejection-preserves-pool', error.status == 429 and a.doctor()['vm_capacity'] == held)
        else:
            raise RuntimeError('held tenant quota bypassed')
        used = {owner_a['vm_id'], owner_b['vm_id']}
        close(session_a); close(session_b)
        wait_for(ready, 'pool not reusable after closes')
        check('used-vms-destroyed', not used.intersection(leases(root)))
        raw = a._exchange('POST', '/v2/jobs', {'backend': 'firecracker-linux', 'artifact_manifest_sha256': digest,
            'entrypoint': '/bin/sh', 'args': ['-c', 'printf warm-job'], 'memory_mib': 128, 'timeout_ms': 10000})
        check('warm-job-executes-once', raw.get('startup_mode') == 'warm' and raw['state'] == 'succeeded' and raw['guest_result']['stdout'] == 'warm-job')
        check('job-startup-timing-partition', validate_startup_measurements(raw, required=True) is not None and raw['startup_timing']['schema'] == 'osv-startup-timing/v2',
              timing=raw['startup_timing'])
        wait_for(ready, 'pool not ready before exit-code test')
        failed = a._exchange('POST', '/v2/jobs', {'backend': 'firecracker-linux', 'artifact_manifest_sha256': digest,
            'entrypoint': '/bin/sh', 'args': ['-c', 'exit 7'], 'memory_mib': 128, 'timeout_ms': 10000})
        check('warm-guest-exit-seven', failed.get('startup_mode') == 'warm' and failed['state'] == 'guest_error' and failed['exit_code'] == 7 and failed['guest_result']['exit_code'] == 7)
        wait_for(ready, 'pool not ready before TTL test')
        expiring, ttl_session = create(a, ttl_ms=1500)
        ttl_owner = wait_for(lambda: bound_lease(expiring['id']), 'TTL session owner missing')
        wait_for(lambda: not process_matches(ttl_owner) and a.doctor()['vm_capacity']['active'] == 0, 'expired warm VM retained resources', timeout=5)
        try:
            ttl_session.info()
        except sdk.APIError as error:
            check('warm-ttl-destroys-instance', error.status == 404 and expiring.get('startup_mode') == 'warm')
        else:
            raise RuntimeError('expired warm session still visible')
        active.remove(ttl_session)
        wait_for(ready, 'pool did not refill after TTL')
        raw = a._exchange('POST', '/v2/jobs', {'backend': 'firecracker-linux', 'artifact_manifest_sha256': digest,
            'entrypoint': '/bin/sh', 'args': ['-c', 'printf fallback'], 'memory_mib': 384, 'timeout_ms': 10000})
        check('profile-mismatch-cold-path', raw.get('startup_mode') == 'cold' and raw['state'] == 'succeeded' and raw['guest_result']['stdout'] == 'fallback')
        validate_startup_measurements(raw, required=True)
        check('cold-vmm-ready-duration', raw['startup_timing']['schema'] == 'osv-startup-timing/v2' and 0 < raw.get('vm_boot_duration_us', 0) <= raw['startup_duration_us'],
              vm_boot_duration_us=raw.get('vm_boot_duration_us'), timing=raw['startup_timing'])
        wait_for(ready, 'pool did not recover after cold fallback')
        check('refill-and-path-counters', a.doctor()['warm_pool']['hits'] >= 2 and a.doctor()['warm_pool']['misses'].get('profile_mismatch', 0) >= 1)

        victim = next(row for row in leases(root).values() if row['phase'] == 'ready' and row['pool_key'] == profiles['small']['key'])
        os.kill(victim['pid'], signal.SIGKILL)
        recovered, session = create(a)
        owner = wait_for(lambda: bound_lease(recovered['id']), 'replacement owner missing')
        check('dead-vm-not-issued', owner['vm_id'] != victim['vm_id'] and session.run(sdk.SessionCommand('/bin/sh', ('-c', 'printf alive'))).succeeded)
        close(session); wait_for(ready, 'pool did not refill after dead VM')

        # Pause every eligible small VM so a checkout is in health/prepare IO.
        paused = [row for row in leases(root).values() if row['phase'] == 'ready' and row['pool_key'] == profiles['small']['key']]
        for row in paused:
            os.kill(row['pid'], signal.SIGSTOP)
        context_tls = ssl.create_default_context(cafile=str(root / 'tls/ca.crt'))
        context_tls.load_cert_chain(str(root / 'tls/client.crt'), str(root / 'tls/client.key'))
        raw_socket = socket.create_connection(('127.0.0.1', int(config['listen'].rsplit(':', 1)[1])), timeout=5)
        connection = context_tls.wrap_socket(raw_socket, server_hostname='localhost')
        body = json.dumps({'backend': 'firecracker-linux', 'artifact_manifest_sha256': digest, 'memory_mib': 128, 'ttl_ms': 60000}).encode()
        token = (root / 'secrets/token').read_text()
        connection.sendall(('POST /v2/sessions HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer ' + token + '\r\nContent-Type: application/json\r\nContent-Length: ' + str(len(body)) + '\r\n\r\n').encode() + body)
        wait_for(lambda: b.doctor()['warm_pool']['foreground'] >= 1, 'checkout did not begin')
        connection.close()
        wait_for(lambda: b.doctor()['vm_capacity']['active'] == 0, 'disconnect did not cancel checkout', timeout=3)
        for row in paused:
            if process_matches(row):
                os.kill(row['pid'], signal.SIGCONT)
        paused = []
        check('checkout-disconnect-reclaimed', True)
        live = b.run(sdk.JobRequest('/bin/sh', args=('-c', 'printf other-tenant'), memory_mib=256, timeout_ms=10000))
        check('other-tenant-after-cancel', live.succeeded and live.guest_result['stdout'] == 'other-tenant')

        wait_for(ready, 'pool not ready before API crash')
        # Lost create ACK keeps this tenant's quota quarantined for 15 seconds.
        # Only a busy rejection is retried; no create with an unknown result is retried.
        orphan_info, orphan = create(a, retry_busy=True)
        orphan_owner = wait_for(lambda: bound_lease(orphan_info['id']), 'API-crash session owner missing')
        idle_before_api_crash = {key for key, value in leases(root).items() if value['phase'] == 'ready'}
        launcher = root.name + '-launcher.service'; api = root.name + '-api.service'
        launcher_pid = unit_pid(launcher)
        os.kill(unit_pid(api), signal.SIGKILL)
        wait_for(lambda: unit_pid(api) == 0 and not process_matches(orphan_owner), 'API crash did not reap its active VM')
        check('api-crash-preserves-pristine-pool', unit_pid(launcher) == launcher_pid and bool(idle_before_api_crash.intersection(leases(root))))
        active.remove(orphan)
        subprocess.run(['systemctl', 'reset-failed', api], check=True)
        subprocess.run(['systemctl', 'start', api], check=True)
        enter_api(root); wait_for(ready_after_api_restart, 'pool not ready after API restart')
        try:
            a.connect_session(orphan_info['id'])
        except sdk.APIError as error:
            check('api-crash-session-not-resurrected', error.status == 404)
        else:
            raise RuntimeError('API crash resurrected tenant session')

        # Stop while both unused pool VMs and a tenant session exist.
        _, tenant = create(b, 256)
        old_session = tenant.id
        old = leases(root)
        os.kill(unit_pid(launcher), signal.SIGTERM)
        wait_for(lambda: unit_pid(launcher) == 0, 'launcher did not terminate')
        exit_status = subprocess.check_output(['systemctl', 'show', '-p', 'ExecMainStatus', '--value', launcher], text=True).strip()
        wait_for(lambda: not list((root / 'run').glob('job-*')) and not list((Path('/sys/fs/cgroup') / root.name).glob('job-*')), 'pool shutdown left resources')
        check('shutdown-zero-residue', exit_status == '0' and all(not process_matches(row) for row in old.values()))
        active.clear()
        subprocess.run(['systemctl', 'start', launcher, api], check=True)
        enter_api(root); wait_for(ready, 'restarted pool not ready')
        try:
            b.connect_session(old_session)
        except sdk.APIError as error:
            check('old-session-not-resurrected', error.status == 404)
        else:
            raise RuntimeError('old tenant session resurrected')
        old_ready = leases(root)
        os.kill(unit_pid(launcher), signal.SIGKILL)
        wait_for(lambda: unit_pid(launcher) == 0, 'crashed launcher did not stop')
        check('crash-leaves-owned-recovery-evidence', bool(list((root / 'run').glob('job-*/lease.json'))))
        subprocess.run(['systemctl', 'reset-failed', launcher], check=True)
        subprocess.run(['systemctl', 'start', launcher, api], check=True)
        enter_api(root); wait_for(ready, 'pool failed to reconcile and restart')
        check('crash-reconciles-old-pool', not set(old_ready).intersection(leases(root)))
        ownership = next((row for row in a.doctor()['checks'] if row['name'] == 'orphan-reconciliation'), {})
        check('runtime-confirms-reconciliation', ownership.get('ok') is True and
              'reconciled=0' not in ownership.get('detail', '') and 'reconciled=' in ownership.get('detail', ''))
        deadline = time.monotonic() + 20
        while True:
            try:
                final_job = b.run(sdk.JobRequest('/bin/sh', args=('-c', 'printf after-crash'), memory_mib=128, timeout_ms=10000))
                break
            except sdk.APIError as error:
                if error.status != 429 or error.code != 'busy' or time.monotonic() >= deadline:
                    raise
                time.sleep(0.1)
        check('post-crash-guest-executes', final_job.succeeded and final_job.guest_result['stdout'] == 'after-crash')
        report['final'] = wait_for(ready, 'final pool unhealthy')['warm_pool']
        report['passed'] = True
    except Exception as error:
        report['error'] = str(error)
        raise
    finally:
        for row in paused:
            if process_matches(row):
                os.kill(row['pid'], signal.SIGCONT)
        for handle in active:
            try:
                handle.close()
            except sdk.SandboxError:
                pass
        (root / 'results/warm-pool.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps({'passed': report['passed'], 'cases': len(cases), 'error': report.get('error')}), flush=True)


if __name__ == '__main__':
    main()
