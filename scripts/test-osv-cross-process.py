#!/usr/bin/env python3
"""Isolated no-route OSv API -> launcher -> KVM acceptance on the x64 host."""

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import time
import urllib.error
import urllib.request

ROOT = Path('/var/lib/osv-cross-process-validation-20261029')
PORT = 18538


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


def issue_certificates(directory, uid):
    ca_key, ca_cert = directory / 'ca.key', directory / 'ca.crt'
    run('openssl', 'req', '-x509', '-newkey', 'ed25519', '-noenc', '-days', '1',
        '-subj', '/CN=isolated-osv-ca', '-addext', 'basicConstraints=critical,CA:TRUE',
        '-keyout', str(ca_key), '-out', str(ca_cert))
    for name, extension in [('server', 'subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n'),
                            ('client', 'extendedKeyUsage=clientAuth\n')]:
        key, csr, cert, ext = (directory / f'{name}.{suffix}'
                               for suffix in ('key', 'csr', 'crt', 'ext'))
        ext.write_text(extension)
        run('openssl', 'req', '-newkey', 'ed25519', '-noenc',
            '-subj', f'/CN=isolated-osv-{name}', '-keyout', str(key), '-out', str(csr))
        run('openssl', 'x509', '-req', '-in', str(csr), '-CA', str(ca_cert),
            '-CAkey', str(ca_key), '-CAcreateserial', '-days', '1',
            '-extfile', str(ext), '-out', str(cert))
        if name == 'server':
            os.chown(key, uid, uid)
            os.chmod(key, 0o600)
    return ca_cert, directory / 'server.crt', directory / 'server.key', directory / 'client.crt', directory / 'client.key'


def main():
    global ROOT
    parser = argparse.ArgumentParser()
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--harness', type=Path, required=True)
    parser.add_argument('--result', type=Path, required=True)
    parser.add_argument('--root', type=Path, help='fresh isolated fixture directory under /var/lib')
    parser.add_argument('--stress-jobs', type=int, default=0)
    parser.add_argument('--stress-concurrency', type=int, default=4)
    args = parser.parse_args()
    if args.root is not None:
        if args.root.parent != Path('/var/lib') or not re.fullmatch(
                r'osv-cross-process-validation-[0-9]{8}(?:-[a-z0-9]+)?', args.root.name):
            raise SystemExit('invalid isolated fixture path')
        ROOT = args.root
    if args.stress_jobs < 0 or not 1 <= args.stress_concurrency <= 4:
        raise SystemExit('stress jobs must be nonnegative and concurrency must be in [1,4]')
    if os.geteuid() != 0 or ROOT.exists():
        raise SystemExit('requires root and an unused isolated fixture directory')
    if run('/sbin/ip', 'route', 'show').strip():
        raise SystemExit('network namespace has outbound routes')
    run('/sbin/ip', 'link', 'set', 'lo', 'up')
    uid = int(run('id', '-u', 'osv-sandbox').strip())
    root = args.candidate.resolve()
    artifact = root / 'artifacts'
    manifest = json.loads((artifact / 'manifest.test.json').read_text())
    ROOT.mkdir(mode=0o755)
    (ROOT / 'jobs').mkdir(mode=0o700)
    (ROOT / 'tls').mkdir(mode=0o755)
    ca, server_cert, server_key, client_cert, client_key = issue_certificates(ROOT / 'tls', uid)
    harness = ROOT / 'osv-preproduction-harness'
    shutil.copy2(args.harness, harness)
    harness.chmod(0o755)
    token = secrets.token_hex(24)
    slots = args.stress_concurrency if args.stress_jobs else 1
    policy = {'protocol': 'osv-sandbox-auth/v1', 'tenants': [{
        'id': 'osv-fixture', 'token_sha256': hashlib.sha256(token.encode()).hexdigest(),
        'allowed_entrypoints': ['/task-probe.so'], 'requests_per_second': 100,
        'burst': max(100, min(args.stress_jobs, 10000)), 'max_concurrent': slots}]}
    policy_path = ROOT / 'auth.json'
    policy_path.write_text(json.dumps(policy))
    policy_path.chmod(0o644)
    config = {'listen': f'127.0.0.1:{PORT}', 'artifact_root': str(artifact),
              'run_root': str(ROOT / 'jobs'), 'backend': 'firecracker-osv',
              'hypervisor_path': str(root / 'bin/firecracker'),
              'jailer': {'path': str(root / 'bin/jailer'), 'uid': 220210, 'gid': 220210,
                         'cgroup_version': 2, 'parent_cgroup': ROOT.name,
                         'identity_pool_size': slots},
              'kernel': manifest['kernel'], 'image': manifest['image'],
              'allowed_entrypoints': manifest['entrypoints'],
              'limits': {'max_concurrent': slots, 'max_output_bytes': 16384,
                         'max_timeout_ms': 30000},
              'launcher_socket': str(ROOT / 'launcher.sock'),
              'artifact_manifest': {'path': 'manifest.test.json',
                                    'signature_path': 'manifest.test.json.sig',
                                    'public_key_path': str(root / 'artifact-test.public'),
                                    'sbom_path': 'sbom.cdx.json'},
              'auth_policy_path': str(policy_path),
              'tls': {'cert_file': str(server_cert), 'key_file': str(server_key),
                      'client_ca_file': str(ca)},
              'audit_log_path': str(ROOT / 'audit.jsonl')}
    config_path = ROOT / 'config.json'
    config_path.write_text(json.dumps(config))
    config_path.chmod(0o644)
    tls = ssl.create_default_context(cafile=str(ca))
    tls.load_cert_chain(str(client_cert), str(client_key))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                         urllib.request.HTTPSHandler(context=tls))
    result = {'suite': 'osv-cross-process/v1', 'no_routes': True,
              'artifact_manifest_sha256': hashlib.sha256((artifact / 'manifest.test.json').read_bytes()).hexdigest(),
              'harness_sha256': hashlib.sha256(harness.read_bytes()).hexdigest(), 'cases': []}
    processes = []
    logs = []

    def request(path, body=None, auth=token):
        data = json.dumps(body).encode() if body is not None else None
        headers = {'Content-Type': 'application/json'}
        if auth is not None:
            headers['Authorization'] = f'Bearer {auth}'
        req = urllib.request.Request(f'https://127.0.0.1:{PORT}{path}', data=data, headers=headers)
        try:
            with opener.open(req, timeout=35) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read())

    def check(name, passed, **evidence):
        result['cases'].append({'name': name, 'passed': bool(passed), **evidence})
        if not passed:
            raise RuntimeError(f'{name} failed: {evidence}')

    def start_api(name):
        api_log = (ROOT / name).open('wb')
        logs.append(api_log)
        process = subprocess.Popen(['setpriv', f'--reuid={uid}', f'--regid={uid}', '--clear-groups',
                                    str(harness), '-role', 'api', '-config', str(config_path),
                                    '-api-uid', str(uid)], stderr=api_log)
        processes.append(process)
        for _ in range(100):
            if process.poll() is not None:
                raise RuntimeError('API exited during startup')
            try:
                if request('/healthz')[0] == 200:
                    return process
            except (urllib.error.URLError, ConnectionError):
                time.sleep(.05)
        raise RuntimeError('API did not listen')

    try:
        invalid_config = dict(config)
        invalid_config['artifact_manifest'] = dict(config['artifact_manifest'],
                                                   signature_path='sbom.cdx.json')
        invalid_path = ROOT / 'invalid-config.json'
        invalid_path.write_text(json.dumps(invalid_config))
        startup = subprocess.run([str(harness), '-role', 'launcher', '-config', str(invalid_path),
                                  '-api-uid', str(uid)], capture_output=True, text=True, timeout=10)
        check('tampered-signature-refuses-start', startup.returncode != 0 and
              'signature verification failed' in startup.stderr and
              not (ROOT / 'launcher.sock').exists(), exit_code=startup.returncode)
        invalid_config['production'] = True
        invalid_path.write_text(json.dumps(invalid_config))
        startup = subprocess.run([str(harness), '-role', 'launcher', '-config', str(invalid_path),
                                  '-api-uid', str(uid)], capture_output=True, text=True, timeout=10)
        check('osv-production-gate-closed', startup.returncode != 0 and
              'production mode currently requires backend=firecracker-linux' in startup.stderr,
              exit_code=startup.returncode)
        launcher_log = (ROOT / 'launcher.stderr').open('wb')
        logs.append(launcher_log)
        launcher = subprocess.Popen([str(harness), '-role', 'launcher', '-config', str(config_path),
                                     '-api-uid', str(uid)], stderr=launcher_log)
        processes.append(launcher)
        for _ in range(100):
            if launcher.poll() is not None:
                raise RuntimeError('launcher exited during startup')
            if (ROOT / 'launcher.sock').exists():
                break
            time.sleep(.05)
        else:
            raise RuntimeError('launcher socket was not created')
        api = start_api('api.stderr')
        status, doctor = request('/v1/doctor')
        check('doctor', status == 200 and doctor.get('ready') is True,
              status=status, checks=doctor.get('checks'))
        status, capabilities = request('/v1/capabilities')
        features = capabilities.get('features') or {}
        check('signed-osv-capability-contract', status == 200 and
              capabilities.get('protocol') == 'osv-sandbox-capabilities/v1' and
              capabilities.get('backend') == 'firecracker-osv' and
              capabilities.get('workload') == 'osv-native-module' and
              capabilities.get('stage') == 'diagnostic' and
              capabilities.get('artifact_authenticated') is True and
              capabilities.get('artifact_manifest_protocol') == 'osv-sandbox-artifacts/v2' and
              capabilities.get('artifact_manifest_sha256') == result['artifact_manifest_sha256'] and
              capabilities.get('allowed_entrypoints') == ['/task-probe.so'] and
              'POST /v2/jobs' in capabilities.get('methods', []) and
              features.get('input_files') is False and
              features.get('network_egress') is False and
              features.get('snapshots') is False,
              status=status, backend=capabilities.get('backend'),
              manifest_sha256=capabilities.get('artifact_manifest_sha256'))
        signed_features = manifest.get('agent_features', [])
        environment_signed = 'environment' in signed_features
        stdin_signed = 'stdin' in signed_features
        check('signed-environment-capability', features.get('environment') is environment_signed and
              (not environment_signed or
               (capabilities.get('limits', {}).get('max_env_entries') == 32 and
                capabilities.get('limits', {}).get('max_env_bytes') == 8192)),
              signed=environment_signed, advertised=features.get('environment'))
        check('signed-stdin-capability', features.get('stdin') is stdin_signed and
              (not stdin_signed or capabilities.get('limits', {}).get('max_stdin_bytes') == 16384),
              signed=stdin_signed, advertised=features.get('stdin'))
        status, _ = request('/v1/doctor', auth='wrong-token')
        check('tenant-auth-rejection', status == 401, status=status)
        status, _ = request('/v1/capabilities', auth='wrong-token')
        check('capability-auth-rejection', status == 401, status=status)
        selection = {'entrypoint': '/task-probe.so', 'args': ['native-success'],
                     'backend': 'firecracker-osv',
                     'artifact_manifest_sha256': result['artifact_manifest_sha256']}
        status, value = request('/v2/jobs', {'entrypoint': '/task-probe.so'})
        check('v2-requires-template-selection', status == 400 and
              value.get('code') == 'invalid_request', status=status, code=value.get('code'))
        status, value = request('/v2/jobs', dict(selection, backend='firecracker-linux'))
        check('v2-rejects-backend-switch', status == 409 and
              value.get('code') == 'template_mismatch', status=status, code=value.get('code'))
        status, value = request('/v2/jobs', dict(selection, artifact_manifest_sha256='0' * 64))
        check('v2-rejects-stale-template', status == 409 and
              value.get('code') == 'template_mismatch', status=status, code=value.get('code'))
        status, value = request('/v2/jobs', selection)
        guest = value.get('guest_result') or {}
        check('v2-executes-selected-osv-template', status == 200 and
              value.get('backend') == 'firecracker-osv' and value.get('state') == 'succeeded' and
              value.get('protocol_ok') is True and guest.get('job_id') == value.get('id'),
              status=status, state=value.get('state'))
        if environment_signed:
            status, value = request('/v2/jobs', dict(selection, args=['native-env'],
                                    environment={'SANDBOX_TEST_MARKER': 'native-env-ok',
                                                 'SANDBOX_EMPTY': ''}))
            guest = value.get('guest_result') or {}
            check('signed-osv-environment-reaches-module',
                  status == 200 and value.get('state') == 'succeeded' and
                  value.get('protocol_ok') is True and
                  'OSV_NATIVE_ENV_OK' in guest.get('stdout', ''),
                  status=status, state=value.get('state'))
            status, value = request('/v2/jobs', dict(selection, args=['native-env-absent']))
            guest = value.get('guest_result') or {}
            check('environment-isolated-between-vms',
                  status == 200 and value.get('state') == 'succeeded' and
                  'OSV_NATIVE_ENV_ABSENT' in guest.get('stdout', ''),
                  status=status, state=value.get('state'))
            for name, environment in [('reserved', {'LD_PRELOAD': 'x'}),
                                      ('invalid-name', {'1BAD': 'x'}),
                                      ('too-many', {f'KEY_{i:02d}': '' for i in range(33)})]:
                status, value = request('/v2/jobs', dict(selection, args=['native-env'],
                                        environment=environment))
                check('environment-' + name + '-rejected-before-vm',
                      status == 400 and not list((ROOT / 'jobs').glob('job-*')),
                      status=status, code=value.get('code'))
        if stdin_signed:
            for name, content, marker in [
                    ('empty', b'', 'OSV_NATIVE_STDIN_EMPTY_OK'),
                    ('binary', b'A\x00B\xff\n', 'OSV_NATIVE_STDIN_BINARY_OK'),
                    ('max', bytes(index % 251 for index in range(16384)), 'OSV_NATIVE_STDIN_MAX_OK'),
                    ('ignore', bytes(index % 251 for index in range(16384)), 'OSV_NATIVE_STDIN_IGNORE_OK')]:
                status, value = request('/v2/jobs', dict(selection, args=['native-stdin-' + name],
                                        stdin=base64.b64encode(content).decode('ascii')))
                guest = value.get('guest_result') or {}
                check('signed-osv-stdin-' + name, status == 200 and
                      value.get('state') == 'succeeded' and
                      marker in guest.get('stdout', ''),
                      status=status, state=value.get('state'))
            if environment_signed:
                status, value = request('/v2/jobs', dict(selection, args=['native-env-stdin'],
                                        environment={'SANDBOX_TEST_MARKER': 'native-env-ok'},
                                        stdin=base64.b64encode(b'A\x00B\xff\n').decode()))
                guest = value.get('guest_result') or {}
                check('signed-osv-env-stdin-combination', status == 200 and
                      value.get('state') == 'succeeded' and
                      'OSV_NATIVE_STDIN_BINARY_OK' in guest.get('stdout', ''),
                      status=status, state=value.get('state'))
            status, value = request('/v2/jobs', dict(selection, args=['native-success']))
            guest = value.get('guest_result') or {}
            check('next-vm-after-stdin-runs-normally', status == 200 and
                  value.get('state') == 'succeeded' and
                  'OSV_NATIVE_MODULE_OK' in guest.get('stdout', ''),
                  status=status, state=value.get('state'))
        else:
            status, value = request('/v2/jobs', dict(selection, args=['native-stdin-empty'], stdin=''))
            check('unsigned-stdin-rejected-before-vm', status == 400 and
                  not list((ROOT / 'jobs').glob('job-*')),
                  status=status, code=value.get('code'))
        for name, value in [('oversized', base64.b64encode(b'x' * 16385).decode()),
                            ('invalid-base64', '!!!!')]:
            status, response = request('/v2/jobs', dict(selection, args=['native-stdin-empty'],
                                                       stdin=value))
            check('stdin-' + name + '-rejected-before-vm', status == 400 and
                  not list((ROOT / 'jobs').glob('job-*')),
                  status=status, code=response.get('code'))
        status, _ = request('/v1/jobs', {'entrypoint': '/unsigned.so'})
        check('unsigned-entrypoint-rejection', status in (400, 403), status=status)
        for name, argument, state, exit_code in [('native-success', 'native-success', 'succeeded', 0),
                                                  ('module-exit', 'native-task', 'guest_error', 7)]:
            status, value = request('/v1/jobs', {'entrypoint': '/task-probe.so',
                                                 'args': [argument], 'timeout_ms': 10000})
            guest = value.get('guest_result') or {}
            check(name, status == 200 and value.get('backend') == 'firecracker-osv' and
                  value.get('state') == state and value.get('protocol_ok') is True and
                  guest.get('job_id') == value.get('id') and guest.get('exit_code') == exit_code,
                  status=status, state=value.get('state'), guest_exit=guest.get('exit_code'))
        status, value = request('/v1/jobs', {'entrypoint': '/task-probe.so',
                                            'args': ['native-sleep'], 'timeout_ms': 500})
        check('host-timeout', status == 200 and value.get('state') == 'timed_out' and
              value.get('timed_out') is True, status=status, state=value.get('state'))
        with socket.socket(socket.AF_UNIX) as peer:
            peer.settimeout(2)
            peer.connect(config['launcher_socket'])
            try:
                peer.sendall(b'{"protocol":"osv-sandbox-launcher/v1","operation":"doctor"}\n')
                rejected = peer.recv(1) == b''
            except ConnectionResetError:
                rejected = True
        check('root-peer-rejected', rejected)
        conn = http.client.HTTPSConnection('127.0.0.1', PORT, context=tls, timeout=5)
        conn.request('POST', '/v1/jobs', json.dumps({'entrypoint': '/task-probe.so',
                                                      'args': ['native-sleep'], 'timeout_ms': 20000}),
                     {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'})
        deadline = time.monotonic() + 4
        while not list((ROOT / 'jobs').glob('job-*/lease.json')) and time.monotonic() < deadline:
            time.sleep(.02)
        leases = list((ROOT / 'jobs').glob('job-*/lease.json'))
        observed = bool(leases)
        pid = json.loads(leases[0].read_text())['pid'] if observed else 0
        conn.close()
        deadline = time.monotonic() + 5
        while (list((ROOT / 'jobs').glob('job-*')) or Path(f'/proc/{pid}').exists()) and time.monotonic() < deadline:
            time.sleep(.02)
        check('client-disconnect-cleanup', observed and not list((ROOT / 'jobs').glob('job-*')) and
              not Path(f'/proc/{pid}').exists(), observed_vm=observed, pid=pid)
        if args.stress_jobs:
            conn = http.client.HTTPSConnection('127.0.0.1', PORT, context=tls, timeout=5)
            conn.request('POST', '/v1/jobs', json.dumps({'entrypoint': '/task-probe.so',
                                                          'args': ['native-sleep'], 'timeout_ms': 20000}),
                         {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'})
            deadline = time.monotonic() + 4
            while not list((ROOT / 'jobs').glob('job-*/lease.json')) and time.monotonic() < deadline:
                time.sleep(.02)
            leases = list((ROOT / 'jobs').glob('job-*/lease.json'))
            observed = bool(leases)
            pid = json.loads(leases[0].read_text())['pid'] if observed else 0
            api.kill()
            api.wait(timeout=5)
            conn.close()
            deadline = time.monotonic() + 5
            while (list((ROOT / 'jobs').glob('job-*')) or Path(f'/proc/{pid}').exists()) and time.monotonic() < deadline:
                time.sleep(.02)
            check('api-crash-kills-vm', observed and not list((ROOT / 'jobs').glob('job-*')) and
                  not Path(f'/proc/{pid}').exists() and launcher.poll() is None,
                  observed_vm=observed, pid=pid, launcher_alive=launcher.poll() is None)
            api = start_api('api-restart.stderr')
            status, value = request('/v1/jobs', {'entrypoint': '/task-probe.so',
                                                 'args': ['native-success'], 'timeout_ms': 10000})
            check('api-restart-recovery', status == 200 and value.get('state') == 'succeeded',
                  status=status, state=value.get('state'))

            def sleeping_job(_):
                return request('/v1/jobs', {'entrypoint': '/task-probe.so',
                                            'args': ['native-sleep'], 'timeout_ms': 2500})

            with ThreadPoolExecutor(max_workers=slots) as executor:
                pending = [executor.submit(sleeping_job, index) for index in range(slots)]
                deadline = time.monotonic() + 2.2
                seen = 0
                uids, gids = set(), set()
                while time.monotonic() < deadline:
                    leases = list((ROOT / 'jobs').glob('job-*/lease.json'))
                    seen = max(seen, len(leases))
                    current_uids, current_gids = set(), set()
                    for lease in leases:
                        pid = json.loads(lease.read_text())['pid']
                        try:
                            lines = Path(f'/proc/{pid}/status').read_text().splitlines()
                        except FileNotFoundError:
                            continue
                        for line in lines:
                            if line.startswith('Uid:'):
                                current_uids.add(int(line.split()[1]))
                            if line.startswith('Gid:'):
                                current_gids.add(int(line.split()[1]))
                    if len(current_uids) == slots and len(current_gids) == slots:
                        uids, gids = current_uids, current_gids
                        break
                    time.sleep(.02)
                sleeping_results = [future.result(timeout=10) for future in pending]
            check('concurrent-distinct-jail-identities', seen == slots and
                  uids == set(range(220210, 220210 + slots)) and
                  gids == set(range(220210, 220210 + slots)) and
                  all(status == 200 and value.get('state') == 'timed_out'
                      for status, value in sleeping_results),
                  observed_concurrent=seen, uids=sorted(uids), gids=sorted(gids),
                  states=[value.get('state') for _, value in sleeping_results])

            def short_job(_):
                started = time.monotonic()
                status, value = request('/v1/jobs', {'entrypoint': '/task-probe.so',
                                                     'args': ['native-success'], 'timeout_ms': 10000})
                return (status, value.get('state'), value.get('protocol_ok'),
                        round((time.monotonic() - started) * 1000))

            started = time.monotonic()
            with ThreadPoolExecutor(max_workers=slots) as executor:
                samples = list(executor.map(short_job, range(args.stress_jobs)))
            latencies = sorted(sample[3] for sample in samples)
            failures = [sample for sample in samples if sample[:3] != (200, 'succeeded', True)]
            check('bounded-concurrency-functional-stress', not failures and
                  not list((ROOT / 'jobs').glob('job-*')),
                  jobs=args.stress_jobs, concurrency=slots, failures=failures[:10],
                  duration_ms=round((time.monotonic() - started) * 1000),
                  p50_ms=latencies[len(latencies) // 2],
                  p95_ms=latencies[min(len(latencies) - 1, int(len(latencies) * .95))],
                  p99_ms=latencies[min(len(latencies) - 1, int(len(latencies) * .99))])
        events = [json.loads(line) for line in (ROOT / 'audit.jsonl').read_text().splitlines()]
        completed = [event for event in events if event['event'] == 'run.completed']
        check('durable-tenant-audit', len(completed) >= 3 and
              all(event.get('tenant') == 'osv-fixture' for event in completed) and
              any(event['event'] == 'peer.rejected' for event in events),
              events=len(events), completed=len(completed))
        check('no-running-job-leak', not list((ROOT / 'jobs').glob('job-*')))
        result['ok'] = True
    except Exception as error:
        result['ok'] = False
        result['error'] = str(error)
    finally:
        for process in reversed(processes):
            process.terminate()
        for process in reversed(processes):
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        for stream in logs:
            stream.close()
        for name in ('launcher.stderr', 'api.stderr', 'api-restart.stderr'):
            log_path = ROOT / name
            if log_path.exists():
                result[name] = log_path.read_text(errors='replace')[-3000:]
        cgroup = Path('/sys/fs/cgroup') / ROOT.name
        if cgroup.exists():
            for leaf in cgroup.iterdir():
                if leaf.is_dir() and not (leaf / 'cgroup.procs').read_text().strip():
                    leaf.rmdir()
            if not (cgroup / 'cgroup.procs').read_text().strip():
                cgroup.rmdir()
        shutil.rmtree(ROOT)
        result['cleanup'] = {'fixture_absent': not ROOT.exists(),
                             'cgroup_absent': not cgroup.exists()}
        args.result.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'ok': result['ok'], 'cases': len(result['cases']),
                      'error': result.get('error'), 'cleanup': result['cleanup']}))
    if not result['ok'] or not all(result['cleanup'].values()):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
