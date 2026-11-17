#!/usr/bin/env python3
"""Signed OSv Python/science template through the shared one-use KVM pool."""
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
import socket
import ssl
import subprocess
import time
import urllib.error
import urllib.request

from startup_benchmark import validation_lock


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


pool = load('osv_pool_fixture', 'e2e-osv-warm-pool.py')
baseline = load('osv_baseline_fixture', 'test-osv-cross-process.py')
require, wait_for, sha = pool.require, pool.wait_for, pool.sha


WORKLOADS = [
    ('versions', 'import sys,numpy,pandas; assert sys.version_info[:3]==(3,12,16); assert numpy.__version__=="2.5.4"; assert pandas.__version__=="3.1.0"; print("SCIENCE_VERSIONS_OK")'),
    ('stdlib', 'import hashlib,zlib,bz2,lzma,sqlite3,ssl,ctypes; b=b"science"*100; assert hashlib.sha256(b).hexdigest()=="d491309fef80720ce9f3a4fd30473d9ea886880f45ec1f1d0420cce176011dfa"; assert all(d(c(b))==b for c,d in [(zlib.compress,zlib.decompress),(bz2.compress,bz2.decompress),(lzma.compress,lzma.decompress)]); db=sqlite3.connect(":memory:"); assert db.execute("select 6*7").fetchone()==(42,); assert ctypes.sizeof(ctypes.c_void_p)==8; print("STDLIB_OK")'),
    ('numpy-linalg', 'import numpy as n; a=n.array([[3.,1.],[1.,2.]]); b=n.array([9.,8.]); assert n.allclose(a@n.linalg.solve(a,b),b); assert n.isclose(n.linalg.det(a),5.); assert n.arange(1000).sum()==499500; print("NUMPY_LINALG_OK")'),
    ('pandas-csv-groupby-merge-time', 'import io,pandas as p; a=p.read_csv(io.StringIO("key,value\\na,1\\na,2\\nb,4\\n")); assert a.groupby("key")["value"].sum().to_dict()=={"a":3,"b":4}; b=p.DataFrame({"key":["a","b"],"label":["A","B"]}); assert a.merge(b,on="key")["label"].tolist()==["A","A","B"]; assert (p.Timestamp("2026-10-31")+p.Timedelta(days=1)).isoformat()=="2026-11-01T00:00:00"; print("PANDAS_OK")'),
    ('threading', 'import threading; values=[]; t=threading.Thread(target=lambda:values.append(42)); t.start(); t.join(); assert values==[42]; print("THREADING_OK")'),
]


def valid_result(status, value, expected_exit, expect=None, stderr_expect=None):
    guest = value.get('guest_result') or {}
    # The shared API reports a completed nonzero guest exit as guest_error.
    # `failed` describes a different host-side execution failure.
    passed = (status == 200 and value.get('protocol_ok') is True and value.get('timed_out') is False and
              value.get('exit_code') == expected_exit and guest.get('exit_code') == expected_exit and
              guest.get('runner_status') == 0 and isinstance(value.get('id'), str) and
              guest.get('job_id') == value['id'] and guest.get('ok') is (expected_exit == 0) and
              value.get('state') == ('succeeded' if expected_exit == 0 else 'guest_error'))
    stdout, stderr = guest.get('stdout'), guest.get('stderr')
    if not isinstance(stdout, str) or not isinstance(stderr, str):
        return False
    if expect:
        markers = (expect,) if isinstance(expect, str) else expect
        passed = passed and all(marker in stdout for marker in markers)
    if stderr_expect:
        passed = passed and stderr_expect in stderr
    return passed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--template', type=Path, required=True)
    parser.add_argument('--harness', type=Path, required=True)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--functional-memory', type=int, choices=(128, 512), default=512)
    args = parser.parse_args()
    require(os.geteuid() == 0 and args.root.parent == Path('/var/lib') and
            re.fullmatch(r'osv-offline-validation-20261031-python[0-9]+', args.root.name) and
            not args.root.exists(), 'requires root and a fresh isolated fixture')
    require(not subprocess.check_output(['/sbin/ip', 'route', 'show']).strip(), 'requires no outbound routes')
    with validation_lock(None):
        exercise(args)


def exercise(args):
    root = args.root
    functional_memory = args.functional_memory
    for identity in range(232010, 232012):
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
    require(manifest['entrypoints'] == ['/python3.12.so'] and
            {'pristine-v1', 'environment', 'stdin'}.issubset(manifest.get('agent_features', [])), 'incorrect template contract')
    uid = pwd.getpwnam('osv-sandbox').pw_uid
    ca, cert, key, client_cert, client_key = baseline.issue_certificates(root / 'tls', uid)
    for public in (root / 'tls').glob('*.crt'):
        public.chmod(0o644)
    token = secrets.token_hex(32)
    policy = {'protocol': 'osv-sandbox-auth/v1', 'tenants': [{'id': 'science-validation',
        'token_sha256': hashlib.sha256(token.encode()).hexdigest(), 'allowed_entrypoints': ['/python3.12.so'],
        'requests_per_second': 100, 'burst': 100, 'max_concurrent': 1}]}
    (root / 'auth.json').write_text(json.dumps(policy))
    (root / 'auth.json').chmod(0o644)
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
    config = {'listen': f'127.0.0.1:{port}', 'backend': 'firecracker-osv',
        'artifact_root': str(template / 'artifacts'), 'run_root': str(root / 'run'),
        'hypervisor_path': str(template / 'bin/firecracker'), 'kernel': manifest['kernel'], 'image': manifest['image'],
        'allowed_entrypoints': ['/python3.12.so'],
        'jailer': {'path': str(template / 'bin/jailer'), 'uid': 232010, 'gid': 232010, 'identity_pool_size': 2,
            'cgroup_version': 2, 'parent_cgroup': root.name, 'memory_overhead_mib': 128, 'pids_max': 64},
        'defaults': {'memory_mib': functional_memory, 'vcpus': 1, 'timeout_ms': 30000},
        'limits': {'max_concurrent': 1, 'min_memory_mib': 64, 'max_memory_mib': functional_memory, 'max_vcpus': 1,
            'max_output_bytes': 16384, 'max_timeout_ms': 30000},
        'vm_capacity': {'max_instances': 2, 'reserved_memory_mib': 2*(functional_memory+128), 'reserved_vcpus': 2, 'reserved_pids': 128},
        'warm_pool': {'enabled': True, 'on_miss': 'cold', 'max_booting': 1, 'refill_per_second': 4, 'refill_burst': 1,
            'max_idle_age_ms': 120000, 'health_interval_ms': 1000, 'check_timeout_ms': 1000,
            'boot_timeout_ms': 10000, 'checkout_timeout_ms': 10000, 'startup_timeout_ms': 30000,
            'min_available_memory_mib': 128,
            'profiles': [{'name': 'science', 'memory_mib': functional_memory, 'vcpus': 1, 'min_ready': 1, 'max_ready': 1}]},
        'launcher_socket': str(root / 'launcher.sock'), 'auth_policy_path': str(root / 'auth.json'),
        'audit_log_path': str(root / 'audit.jsonl'),
        'tls': {'cert_file': str(cert), 'key_file': str(key), 'client_ca_file': str(ca)},
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
    processes, logs, cases = [], [], []
    report = {'suite': 'osv-python-science-kvm/v1', 'production_validated': False, 'performance_gate_evidence': False,
        'no_routes': True, 'manifest_sha256': sha(template / 'artifacts/manifest.test.json'),
        'harness_sha256': sha(harness), 'configuration_sha256': sha(config_path), 'script_sha256': sha(Path(__file__)),
        'cases': cases, 'functional_memory_mib': functional_memory, 'functional_profile_passed': False,
        'functional_512_passed': False, 'memory_64_target_passed': False, 'passed': False,
        'signed_rofs_cache_policy': manifest.get('osv_rofs_cache', ''), 'observed_warm_boot_args': []}

    def request(path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(f'https://127.0.0.1:{port}' + path, data=data,
            headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
        try:
            response = opener.open(req, timeout=40)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return response.status, json.loads(response.read())

    def ready():
        try:
            status, value = request('/v1/doctor')
        except (urllib.error.URLError, ConnectionError):
            return None
        state = value.get('warm_pool', {})
        return value if status in (200, 503) and state.get('healthy') and value['vm_capacity']['active'] == 0 and all(
            row['ready'] >= 1 for row in state['profiles']) else None

    def start(role):
        log = (root / 'results' / (role + '.stderr')).open('wb')
        logs.append(log)
        command = [str(harness), '-role', role, '-config', str(config_path), '-api-uid', str(uid)]
        if role == 'api':
            command = ['setpriv', '--reuid=' + str(uid), '--regid=' + str(uid), '--clear-groups', *command]
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=log)
        processes.append(process)
        wait_for(lambda: require(process.poll() is None, role + ' exited') or
                 ((root / 'launcher.sock').exists() if role == 'launcher' else ready()), role + ' not ready', timeout=40)
        return process

    def job(name, code=None, expected_exit=0, memory=None, environment=None, stdin=None, expect=None,
            stderr_expect=None, extra_args=(), mandatory=True, cli_args=None):
        memory = functional_memory if memory is None else memory
        wait_for(ready, 'pool refill before ' + name)
        before = pool.leases(root)
        for lease in before.values():
            configs = list(Path(lease['directory']).glob('jailer/firecracker/*/root/config.json'))
            require(len(configs) == 1, 'cannot observe the ready VM boot policy')
            boot_args = json.loads(configs[0].read_text())['boot-source']['boot_args']
            require(('--disable_rofs_cache' in boot_args.split()) == (manifest.get('osv_rofs_cache') == 'disabled'),
                    'VM boot policy differs from signed template')
            if boot_args not in report['observed_warm_boot_args']:
                report['observed_warm_boot_args'].append(boot_args)
        payload = {'backend': 'firecracker-osv', 'artifact_manifest_sha256': report['manifest_sha256'],
            'entrypoint': '/python3.12.so', 'args': list(cli_args) if cli_args is not None else ['-c', code, *extra_args],
            'memory_mib': memory, 'vcpus': 1, 'timeout_ms': 30000}
        if environment is not None:
            payload['environment'] = environment
        if stdin is not None:
            payload['stdin'] = base64.b64encode(stdin).decode()
        started = time.monotonic()
        status, value = request('/v2/jobs', payload)
        passed = valid_result(status, value, expected_exit, expect, stderr_expect)
        cases.append({'name': name, 'memory_mib': memory, 'passed': passed, 'mandatory': mandatory,
            'http_status': status, 'wall_ms': round((time.monotonic() - started) * 1000, 3), 'result': value})
        if memory == functional_memory and status == 200:
            require(value.get('startup_mode') == 'warm', 'science job did not use warm pool')
        wait_for(ready, 'refill after ' + name)
        after = pool.leases(root)
        if memory == functional_memory and status == 200:
            used = set(before) - set(after)
            require(len(used) == 1 and all(not pool.process_matches(before[key]) for key in used), 'used VM was retained or reused')
        if mandatory:
            require(passed, name + ': ' + json.dumps(value)[:2500])
        print(json.dumps({'case': name, 'memory_mib': memory, 'passed': passed}), flush=True)

    try:
        start('launcher')
        start('api')
        job('interpreter', 'import sys; assert sys.version_info[:3]==(3,12,16); print("PYTHON_RUNTIME_OK")', expect='PYTHON_RUNTIME_OK')
        job('numpy-import', 'import numpy; assert numpy.__version__=="2.5.4"; print("NUMPY_IMPORT_OK")', expect='NUMPY_IMPORT_OK')
        job('pandas-import', 'import pandas; assert pandas.__version__=="3.1.0"; print("PANDAS_IMPORT_OK")', expect='PANDAS_IMPORT_OK')
        for name, code in WORKLOADS:
            job(name, code, expect=re.search(r'print\("([A-Z_]+)"\)', code).group(1))
        job('argv-env-binary-stdin', 'import os,sys; assert os.environ["SCIENCE_MARKER"]=="bounded-env"; assert sys.argv==["-c","one arg","\u6c49\u5b57"]; assert sys.stdin.buffer.read()==b"A\\x00B\\xff\\n"; print("IO_OK")', environment={'SCIENCE_MARKER': 'bounded-env'}, stdin=b'A\x00B\xff\n', expect='IO_OK', extra_args=('one arg', '\u6c49\u5b57'))
        job('isolated-python-path', 'import sys; assert sys.flags.isolated and sys.flags.ignore_environment and sys.flags.no_user_site; assert "/attacker" not in sys.path; print("ISOLATION_OK")', environment={'PYTHONPATH': '/attacker', 'PYTHONHOME': '/attacker'}, expect='ISOLATION_OK')
        job('stderr-and-exit', 'import sys; print("SCIENCE_OUT"); print("SCIENCE_ERR",file=sys.stderr); sys.exit(7)', expected_exit=7, expect='SCIENCE_OUT', stderr_expect='SCIENCE_ERR')
        job('sys-exit-atexit', 'import atexit,sys; atexit.register(lambda:print("PYTHON_ATEXIT_OK")); sys.exit(7)', expected_exit=7, expect='PYTHON_ATEXIT_OK')
        job('sys-exit-none', 'import atexit,sys; atexit.register(lambda:print("PYTHON_EXIT_NONE_OK")); sys.exit(None)', expect='PYTHON_EXIT_NONE_OK')
        job('sys-exit-message', 'import sys; sys.exit("PYTHON_EXIT_MESSAGE")', expected_exit=1, stderr_expect='PYTHON_EXIT_MESSAGE')
        job('cli-version', cli_args=('-V',), expect='Python 3.12.16')
        job('cli-module-json', cli_args=('-m', 'json.tool'), stdin=b'{"science_cli":42}\n', expect='"science_cli": 42')
        job('cli-file-json', cli_args=('/opt/python/lib/python3.12/json/tool.py',), stdin=b'{"science_file":42}\n', expect='"science_file": 42')
        job('exception', 'raise RuntimeError("SCIENCE_EXPECTED_EXCEPTION")', expected_exit=1, stderr_expect='SCIENCE_EXPECTED_EXCEPTION')
        job('fresh-interpreter-state', 'import builtins; assert not hasattr(builtins,"science_previous_tenant"); builtins.science_previous_tenant=True; print("FRESH_OK")', expect='FRESH_OK')
        job('fresh-interpreter-state-again', 'import builtins; assert not hasattr(builtins,"science_previous_tenant"); print("FRESH_OK")', expect='FRESH_OK')
        job('64mib-cold-interpreter', 'print("COLD_INTERPRETER_OK")', memory=64, expect='COLD_INTERPRETER_OK')
        # Preserve the full workload and its failure if 64MiB is insufficient.
        job('64mib-science', WORKLOADS[0][1] + ';' + WORKLOADS[2][1] + ';' + WORKLOADS[3][1], memory=64,
            expect=('SCIENCE_VERSIONS_OK', 'NUMPY_LINALG_OK', 'PANDAS_OK'), mandatory=False)
        functional_rows = [row for row in cases if row['memory_mib'] == functional_memory]
        report['functional_profile_passed'] = len(functional_rows) == 20 and all(row['passed'] for row in functional_rows)
        report['functional_512_passed'] = functional_memory == 512 and report['functional_profile_passed']
        report['memory_64_target_passed'] = cases[-1]['name'] == '64mib-science' and cases[-1]['passed']
        report['passed'] = report['functional_profile_passed'] and report['memory_64_target_passed']
    except Exception as error:
        report['error'] = str(error)
        raise
    finally:
        old = pool.leases(root)
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        for log in logs:
            log.close()
        cgroup = Path('/sys/fs/cgroup') / root.name
        report['cleanup'] = {'remaining_dirs': [str(path) for path in (root / 'run').glob('job-*')],
            'remaining_cgroups': [str(path) for path in cgroup.glob('job-*')],
            'live_original_vms': [key for key, lease in old.items() if pool.process_matches(lease)]}
        if any(report['cleanup'].values()):
            report['passed'] = False
        if cgroup.exists() and not report['cleanup']['remaining_cgroups'] and not (cgroup / 'cgroup.procs').read_text().strip():
            cgroup.rmdir()
        shutil.rmtree(root / 'tls')
        (root / 'auth.json').unlink(missing_ok=True)
        report['cleanup']['remaining_parent_cgroups'] = [str(cgroup)] if cgroup.exists() else []
        report['cleanup']['remaining_credentials'] = [name for name in ('tls', 'auth.json') if (root / name).exists()]
        if any(report['cleanup'].values()):
            report['passed'] = False
        report['generated_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        (root / 'results/python-science.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps({'passed': report['passed'], 'cases': len(cases), 'cleanup': report['cleanup']}), flush=True)
    require(report['passed'], 'science template acceptance failed')


if __name__ == '__main__':
    main()
