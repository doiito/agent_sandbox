#!/usr/bin/env python3
"""Localhost API to manager to jailer to OSv KVM acceptance fixture."""
import argparse
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import urllib.error
import urllib.request

ROOT = Path('/var/lib/osv-job-api-validation-20261029')
PORT = 18537
TOKEN = 'isolated-osv-job-api-fixture-token'


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--upload', type=Path, required=True)
    parser.add_argument('--candidate', type=Path,
                        help='signed OSv template candidate with optional agent features')
    args = parser.parse_args()
    if os.geteuid() != 0 or ROOT.exists():
        raise SystemExit('requires root and an unused isolated fixture directory')
    ROOT.mkdir(mode=0o700)
    signed = args.candidate is not None
    artifact_root = args.candidate / 'artifacts' if signed else args.upload
    manifest = json.loads((artifact_root / 'manifest.test.json').read_text()) if signed else None
    config = {
        'listen': f'127.0.0.1:{PORT}', 'artifact_root': str(artifact_root),
        'run_root': str(ROOT / 'jobs'), 'backend': 'firecracker-osv',
        'hypervisor_path': str(args.candidate / 'bin/firecracker') if signed else '/usr/local/bin/firecracker',
        'jailer': {'path': str(args.candidate / 'bin/jailer') if signed else '/usr/local/bin/jailer',
                   'uid': 220210, 'gid': 220210,
                   'cgroup_version': 2, 'parent_cgroup': 'osv-job-api-validation-20261029'},
        'kernel': manifest['kernel'] if signed else
                  {'path': 'loader-stripped.elf', 'sha256': sha(args.upload / 'loader-stripped.elf')},
        'image': manifest['image'] if signed else
                 {'path': 'osv-native-agent.raw', 'format': 'raw',
                  'sha256': sha(args.upload / 'osv-native-agent.raw')},
        'allowed_entrypoints': ['/task-probe.so'],
        'limits': {'max_concurrent': 1, 'max_output_bytes': 16384,
                   'max_timeout_ms': 30000},
    }
    if signed:
        config['artifact_manifest'] = {
            'path': 'manifest.test.json', 'signature_path': 'manifest.test.json.sig',
            'public_key_path': str(args.candidate / 'artifact-test.public'),
            'sbom_path': 'sbom.cdx.json'}
    config_path = ROOT / 'config.json'
    config_path.write_text(json.dumps(config))
    environment = dict(os.environ, OSV_SANDBOX_TOKEN=TOKEN)
    process = None
    result = {'cases': [], 'image_sha256': config['image']['sha256'],
              'signed_candidate': signed}
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def request(path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(f'http://127.0.0.1:{PORT}{path}', data=data,
                                     headers={'Authorization': f'Bearer {TOKEN}',
                                              'Content-Type': 'application/json'})
        try:
            with opener.open(req, timeout=35) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read())

    def case(argument, expected_state, expected_exit, environment=None, stdin=None):
        started = time.monotonic()
        arguments = [argument]
        if argument == 'native-many-args':
            arguments.extend(f'arg-{index:02d}' for index in range(1, 64))
        payload = {'entrypoint': '/task-probe.so', 'args': arguments, 'timeout_ms': 10000}
        if environment is not None:
            payload['environment'] = environment
        if stdin is not None:
            payload['stdin'] = base64.b64encode(stdin).decode('ascii')
        status, response = request('/v1/jobs', payload)
        elapsed_ms = round((time.monotonic() - started) * 1000)
        guest = response.get('guest_result') or {}
        passed = (status == 200 and response.get('backend') == 'firecracker-osv' and
                  response.get('state') == expected_state and response.get('protocol_ok') is True and
                  guest.get('protocol') == 'osv-agent/v1' and guest.get('job_id') == response.get('id') and
                  guest.get('runner_status') == 0 and guest.get('exit_code') == expected_exit)
        if argument == 'native-success':
            passed = passed and 'OSV_NATIVE_MODULE_OK' in guest.get('stdout', '')
        if argument == 'native-stderr':
            passed = passed and 'OSV_NATIVE_STDERR' in guest.get('stderr', '')
        if argument == 'native-flood':
            passed = passed and guest.get('output_truncated') is True and len(guest.get('stdout', '')) <= 2048
        if argument == 'native-background-fd':
            passed = passed and 'OSV_NATIVE_BACKGROUND_MAIN_DONE' in guest.get('stdout', '') and elapsed_ms < 2000
        if argument == 'native-many-args':
            passed = passed and 'OSV_NATIVE_64_ARGS_OK' in guest.get('stdout', '')
        if argument == 'native-env':
            passed = passed and 'OSV_NATIVE_ENV_OK' in guest.get('stdout', '')
        if argument == 'native-env-absent':
            passed = passed and 'OSV_NATIVE_ENV_ABSENT' in guest.get('stdout', '')
        for name, marker in [('native-stdin-empty', 'OSV_NATIVE_STDIN_EMPTY_OK'),
                             ('native-stdin-binary', 'OSV_NATIVE_STDIN_BINARY_OK'),
                             ('native-stdin-max', 'OSV_NATIVE_STDIN_MAX_OK'),
                             ('native-stdin-ignore', 'OSV_NATIVE_STDIN_IGNORE_OK'),
                             ('native-env-stdin', 'OSV_NATIVE_STDIN_BINARY_OK')]:
            if argument == name:
                passed = passed and marker in guest.get('stdout', '')
        item = {'argument': argument, 'passed': passed, 'http_status': status,
                'state': response.get('state'), 'protocol_ok': response.get('protocol_ok'),
                'guest_exit': guest.get('exit_code'), 'guest_stdout_len': len(guest.get('stdout', '')),
                'guest_stderr_len': len(guest.get('stderr', '')),
                'guest_truncated': guest.get('output_truncated'), 'elapsed_ms': elapsed_ms}
        result['cases'].append(item)
        if not passed:
            raise RuntimeError(f'API case failed: {item}')

    try:
        binary = args.candidate / 'bin/osv-sandboxd' if signed else args.upload / 'osv-sandboxd-osv-job'
        process = subprocess.Popen([str(binary), '-config', str(config_path)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=environment)
        for _ in range(100):
            if process.poll() is not None:
                raise RuntimeError(f'API stopped during startup: {process.stderr.read()[-2000:]!r}')
            try:
                if request('/healthz')[0] == 200:
                    break
            except urllib.error.URLError:
                time.sleep(.05)
        else:
            raise RuntimeError('API did not listen')
        status, doctor = request('/v1/doctor')
        if status != 200 or doctor.get('ready') is not True:
            raise RuntimeError(f'doctor not ready: {doctor}')
        result['doctor_ready'] = True
        status, capabilities = request('/v1/capabilities')
        signed_features = manifest.get('agent_features', []) if signed else []
        if status != 200 or capabilities.get('features', {}).get('environment') is not ('environment' in signed_features):
            raise RuntimeError('OSv environment capability does not match signed agent')
        if 'environment' in signed_features and (capabilities.get('limits', {}).get('max_env_entries') != 32 or
                       capabilities.get('limits', {}).get('max_env_bytes') != 8192):
            raise RuntimeError('OSv environment limits missing')
        if capabilities.get('features', {}).get('stdin') is not ('stdin' in signed_features):
            raise RuntimeError('OSv stdin capability does not match signed agent')
        if 'stdin' in signed_features and capabilities.get('limits', {}).get('max_stdin_bytes') != 16384:
            raise RuntimeError('OSv stdin limit missing')
        result['environment_capability'] = 'environment' in signed_features
        result['stdin_capability'] = 'stdin' in signed_features
        for argument, state, exit_code in [('native-success', 'succeeded', 0),
                                           ('native-task', 'guest_error', 7),
                                           ('rejected', 'guest_error', 64),
                                           ('native-stderr', 'succeeded', 0),
                                           ('native-flood', 'succeeded', 0),
                                           ('native-background-fd', 'succeeded', 0),
                                           ('native-many-args', 'succeeded', 0)]:
            case(argument, state, exit_code)
        if 'environment' in signed_features:
            case('native-env', 'succeeded', 0,
                 {'SANDBOX_TEST_MARKER': 'native-env-ok', 'SANDBOX_EMPTY': ''})
            case('native-env-absent', 'succeeded', 0)
        if 'stdin' in signed_features:
            case('native-stdin-empty', 'succeeded', 0, stdin=b'')
            case('native-stdin-binary', 'succeeded', 0, stdin=b'A\x00B\xff\n')
            case('native-stdin-max', 'succeeded', 0,
                 stdin=bytes(index % 251 for index in range(16384)))
            case('native-stdin-ignore', 'succeeded', 0,
                 stdin=bytes(index % 251 for index in range(16384)))
            if 'environment' in signed_features:
                case('native-env-stdin', 'succeeded', 0,
                     {'SANDBOX_TEST_MARKER': 'native-env-ok'}, b'A\x00B\xff\n')
        crash_status, crash = request('/v1/jobs', {'entrypoint': '/task-probe.so',
                                                    'args': ['native-crash'], 'timeout_ms': 3000})
        result['guest_crash'] = {'http_status': crash_status, 'state': crash.get('state'),
                                 'protocol_ok': crash.get('protocol_ok')}
        if crash_status != 200 or crash.get('state') == 'succeeded' or crash.get('protocol_ok') is True:
            raise RuntimeError(f'guest crash did not fail closed: {result["guest_crash"]}')
        status, _ = request('/v1/jobs', {'entrypoint': '/not-signed.so'})
        result['unsigned_entrypoint_rejected'] = status == 400
        if status != 400:
            raise RuntimeError(f'unsigned entrypoint returned HTTP {status}')
        status, _ = request('/v1/jobs', {'entrypoint': '/task-probe.so', 'args': ['x'] * 65})
        result['too_many_args_rejected'] = status == 400
        if status != 400:
            raise RuntimeError(f'65 user arguments returned HTTP {status}')
        path = '/task-probe.so'
        over_budget = ['a' * (4097 - len(path))] + ['b' * 4096] * 7
        status, _ = request('/v1/jobs', {'entrypoint': path, 'args': over_budget})
        result['argv_budget_rejected'] = status == 400
        if status != 400:
            raise RuntimeError(f'argv budget overflow returned HTTP {status}')
        if signed:
            for environment in ({'1BAD': 'value'}, {'LD_PRELOAD': 'value'},
                                {'OSV_DEBUG': 'value'}, {'GOOD': 'bad\x00value'},
                                {'GOOD': 'v' * 1025}, {f'KEY_{i:02d}': '' for i in range(33)}):
                status, _ = request('/v1/jobs', {'entrypoint': path,
                                                 'args': ['native-env'],
                                                 'environment': environment})
                if status != 400 or list((ROOT / 'jobs').glob('job-*')):
                    raise RuntimeError('invalid OSv environment reached a VM')
            result['invalid_environment_rejected'] = True
        else:
            status, _ = request('/v1/jobs', {'entrypoint': path,
                                             'args': ['native-env'],
                                             'environment': {'SANDBOX_TEST_MARKER': 'native-env-ok'}})
            result['unsigned_environment_rejected'] = status == 400
            if status != 400:
                raise RuntimeError('unsigned OSv environment was accepted')
        for encoded in (base64.b64encode(b'x' * 16385).decode(), '!!!!'):
            status, _ = request('/v1/jobs', {'entrypoint': path,
                                             'args': ['native-stdin-binary'],
                                             'stdin': encoded})
            if status != 400 or list((ROOT / 'jobs').glob('job-*')):
                raise RuntimeError('invalid OSv stdin reached a VM')
        result['invalid_stdin_rejected'] = True
        if 'stdin' not in signed_features:
            status, _ = request('/v1/jobs', {'entrypoint': path,
                                             'args': ['native-stdin-empty'], 'stdin': ''})
            result['unsigned_stdin_rejected'] = status == 400
            if status != 400:
                raise RuntimeError('unsigned OSv stdin was accepted')
        started = time.monotonic()
        status, timeout_result = request('/v1/jobs', {'entrypoint': '/task-probe.so',
                                                      'args': ['native-sleep'], 'timeout_ms': 500})
        elapsed_ms = round((time.monotonic() - started) * 1000)
        result['timeout'] = {'http_status': status, 'state': timeout_result.get('state'),
                             'timed_out': timeout_result.get('timed_out'), 'elapsed_ms': elapsed_ms}
        if status != 200 or timeout_result.get('state') != 'timed_out' or \
                timeout_result.get('timed_out') is not True or elapsed_ms > 5000:
            raise RuntimeError(f'host deadline did not kill guest: {result["timeout"]}')
        conn = http.client.HTTPConnection('127.0.0.1', PORT, timeout=5)
        disconnect_body = json.dumps({'entrypoint': '/task-probe.so',
                                      'args': ['native-sleep'], 'timeout_ms': 20000})
        conn.request('POST', '/v1/jobs', disconnect_body,
                     {'Authorization': f'Bearer {TOKEN}', 'Content-Type': 'application/json'})
        deadline = time.monotonic() + 3
        while not list((ROOT / 'jobs').glob('job-*/lease.json')) and time.monotonic() < deadline:
            time.sleep(.02)
        leases = list((ROOT / 'jobs').glob('job-*/lease.json'))
        saw_running_job = bool(leases)
        vmm_pid = json.loads(leases[0].read_text())['pid'] if leases else 0
        process_path = Path(f'/proc/{vmm_pid}')
        cgroup_leaf = Path('/sys/fs/cgroup/osv-job-api-validation-20261029') / leases[0].parent.name if leases else None
        process_seen = process_path.exists() if vmm_pid else False
        cgroup_seen = cgroup_leaf.exists() if cgroup_leaf else False
        conn.close()
        deadline = time.monotonic() + 5
        while (list((ROOT / 'jobs').glob('job-*')) or process_path.exists() or
               (cgroup_leaf and cgroup_leaf.exists())) and time.monotonic() < deadline:
            time.sleep(.02)
        result['client_disconnect'] = {'saw_running_job': saw_running_job,
                                       'vmm_process_seen': process_seen,
                                       'cgroup_seen': cgroup_seen,
                                       'job_dirs_absent': not list((ROOT / 'jobs').glob('job-*')),
                                       'vmm_process_absent': not process_path.exists(),
                                       'cgroup_absent': not cgroup_leaf.exists() if cgroup_leaf else False}
        if not all(result['client_disconnect'].values()):
            raise RuntimeError(f'client disconnect did not cancel VMM: {result["client_disconnect"]}')
        case('native-success', 'succeeded', 0)
        result['post_timeout_recovery'] = True
        result['ok'] = True
    except Exception as error:
        result['ok'] = False
        result['error'] = str(error)
    finally:
        if process:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            result['api_exit'] = process.returncode
        shutil.rmtree(ROOT)
        parent = Path('/sys/fs/cgroup/osv-job-api-validation-20261029')
        if parent.exists():
            for leaf in parent.iterdir():
                if leaf.is_dir() and not (leaf / 'cgroup.procs').read_text().strip():
                    leaf.rmdir()
            if not (parent / 'cgroup.procs').read_text().strip():
                parent.rmdir()
        result['cleanup'] = {'fixture_absent': not ROOT.exists(), 'cgroup_absent': not parent.exists()}
        (args.upload / 'job-api-result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    if not result['ok']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
