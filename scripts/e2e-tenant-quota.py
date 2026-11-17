#!/usr/bin/env python3
"""Real two-tenant KVM quota, rate and identity isolation acceptance."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def wait_for(predicate, seconds, message):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.04)
    raise RuntimeError(message)


def job_dirs(path):
    return sorted(item.name for item in path.glob('job-*'))


def uid(pid):
    for line in (Path('/proc') / str(pid) / 'status').read_text().splitlines():
        if line.startswith('Uid:'):
            return int(line.split()[1])
    raise RuntimeError('process UID is unavailable')


def unit_pid(unit):
    shown = subprocess.run(['systemctl', 'show', '-p', 'MainPID', '--value', unit],
                           check=True, capture_output=True, text=True)
    return int(shown.stdout.strip())


def vm_pid(leaf):
    try:
        for value in (leaf / 'cgroup.procs').read_text().split():
            if (Path('/proc') / value / 'comm').read_text().strip() == 'firecracker':
                return int(value)
    except OSError:
        pass
    return None


def client(root, role):
    config = json.loads((root / 'config.production.json').read_text())
    token_name = 'token-b' if role.startswith('b-') else 'token'
    token = (root / 'secrets' / token_name).read_text()
    context = ssl.create_default_context(cafile=root / 'tls/ca.crt')
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(root / 'tls/client.crt', root / 'tls/client.key')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                         urllib.request.HTTPSHandler(context=context))
    script = ('sleep 12' if role == 'a-long' else
              'sleep 4' if role == 'b-long' else
              'printf quota-' + role)
    body = json.dumps({'entrypoint': '/bin/sh', 'args': ['-c', script],
                       'timeout_ms': 25000}).encode()
    url = 'https://localhost:' + config['listen'].rsplit(':', 1)[1] + '/v1/jobs'
    req = urllib.request.Request(url, body, headers={
        'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
    try:
        with opener.open(req, timeout=35) as response:
            result = json.load(response)
            guest = result.get('guest_result') or {}
            print(json.dumps({'status': response.status, 'state': result.get('state'),
                              'protocol_ok': result.get('protocol_ok'),
                              'stdout': guest.get('stdout', ''),
                              'job_id_bound': guest.get('job_id') == result.get('id')}), flush=True)
    except urllib.error.HTTPError as response:
        result = json.load(response)
        print(json.dumps({'status': response.code, 'code': result.get('code')}), flush=True)


def start_client(api_pid, root, role):
    return subprocess.Popen(['nsenter', '-t', str(api_pid), '-n', sys.executable,
                             __file__, '--root', str(root), '--client', role],
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)


def complete(process, timeout=40):
    output, stderr = process.communicate(timeout=timeout)
    require(process.returncode == 0 and output and not stderr,
            'tenant client process failed')
    return json.loads(output)


def successful(response, role):
    return response == {'status': 200, 'state': 'succeeded', 'protocol_ok': True,
                        'stdout': '' if role.endswith('long') else 'quota-' + role,
                        'job_id_bound': True}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--package', type=Path)
    parser.add_argument('--client', choices=('a-long', 'b-long', 'a-reject',
                                            'a-third', 'a-fourth', 'b-followup'))
    args = parser.parse_args()
    root = args.root.resolve()
    require(root.parent == Path('/var/lib') and
            root.name.startswith('osv-offline-validation-20261030-'),
            'requires isolated validation fixture')
    if args.client:
        client(root, args.client)
        return
    require(os.geteuid() == 0 and args.package is not None,
            'orchestration requires root and package')
    config = json.loads((root / 'config.production.json').read_text())
    policy = json.loads((root / 'auth.json').read_text())
    tenants = {tenant['id']: tenant for tenant in policy['tenants']}
    require(config['run_root'] == str(root / 'run') and
            config['jailer']['parent_cgroup'] == root.name and
            config['jailer']['identity_pool_size'] == 2 and
            config['limits']['max_concurrent'] == 2,
            'fixture identity or global concurrency policy mismatch')
    require(set(tenants) == {'validation-a', 'validation-b'} and
            tenants['validation-a']['max_concurrent'] == 1 and
            tenants['validation-a']['burst'] == 3 and
            tenants['validation-a']['requests_per_second'] == 0.001 and
            tenants['validation-b']['max_concurrent'] == 1 and
            tenants['validation-b']['burst'] == 100,
            'tenant quota policy mismatch')
    api_pid = unit_pid(root.name + '-api.service')
    launcher_pid = unit_pid(root.name + '-launcher.service')
    require(api_pid > 1 and launcher_pid > 1 and uid(api_pid) != 0 and uid(launcher_pid) == 0,
            'API/launcher privilege split mismatch')
    cgroups = Path('/sys/fs/cgroup') / root.name
    require(not job_dirs(root / 'run') and not job_dirs(cgroups),
            'fixture already has task resources')
    audit_events = [json.loads(line)['event'] for path in (root / 'audit').iterdir()
                    if path.is_file() for line in path.read_text().splitlines()]
    require(audit_events == ['launcher.ready'] and not any((root / 'results').iterdir()),
            'quota proof requires a fresh, unused fixture')
    a = b = None
    try:
        a = start_client(api_pid, root, 'a-long')
        a_work = wait_for(lambda: next((item for item in (root / 'run').glob('job-*')
                                        if (item / 'lease.json').is_file()), None),
                          20, 'tenant A did not start a real VM')
        a_vm = wait_for(lambda: vm_pid(cgroups / a_work.name), 10,
                        'tenant A Firecracker missing from cgroup')
        require(a.poll() is None, 'tenant A task exited before concurrency check')
        a_reject = complete(start_client(api_pid, root, 'a-reject'), 10)
        require(a_reject == {'status': 429, 'code': None} and a.poll() is None,
                'second tenant A request was not rejected by concurrency limit: ' + repr(a_reject))
        require(job_dirs(root / 'run') == [a_work.name],
                'rejected tenant A request created a task')

        b = start_client(api_pid, root, 'b-long')
        b_work = wait_for(lambda: next((item for item in (root / 'run').glob('job-*')
                                        if item.name != a_work.name and
                                        (item / 'lease.json').is_file()), None),
                          20, 'tenant B did not start a concurrent VM')
        b_vm = wait_for(lambda: vm_pid(cgroups / b_work.name), 10,
                        'tenant B Firecracker missing from cgroup')
        a_uid, b_uid = uid(a_vm), uid(b_vm)
        require({a_uid, b_uid} == {230000, 230001} and
                a.poll() is None and b.poll() is None,
                'concurrent tenants did not receive isolated VM identities')
        for pid, workdir in ((a_vm, a_work), (b_vm, b_work)):
            require(root.name + '/' + workdir.name in
                    (Path('/proc') / str(pid) / 'cgroup').read_text(),
                    'VM process is outside its task cgroup')
        b_first = complete(b)
        a_first = complete(a)
        require(successful(a_first, 'a-long') and successful(b_first, 'b-long'),
                'concurrent tenant jobs did not finish successfully')
        wait_for(lambda: not job_dirs(root / 'run') and not job_dirs(cgroups),
                 5, 'concurrent tasks left resources')

        a_third = complete(start_client(api_pid, root, 'a-third'))
        require(successful(a_third, 'a-third'),
                'tenant A third request did not use remaining token: ' + repr(a_third))
        a_fourth = complete(start_client(api_pid, root, 'a-fourth'))
        require(a_fourth == {'status': 429, 'code': None},
                'tenant A exceeded rate bucket without rejection: ' + repr(a_fourth))
        b_followup = complete(start_client(api_pid, root, 'b-followup'))
        require(successful(b_followup, 'b-followup'),
                'tenant B was throttled by tenant A quota')
        wait_for(lambda: not job_dirs(root / 'run') and not job_dirs(cgroups),
                 5, 'followup tasks left resources')

        def digest(path):
            with path.open('rb') as stream:
                return hashlib.file_digest(stream, 'sha256').hexdigest()

        report = {'suite': 'tenant-quota-kvm/v1',
                  'generated_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                  'package_sha256': digest(args.package),
                  'test_script_sha256': digest(Path(__file__)),
                  'api_uid': uid(api_pid), 'launcher_uid': uid(launcher_pid),
                  'policy': {'global_max_concurrent': 2, 'a_max_concurrent': 1,
                             'a_burst': 3, 'a_requests_per_second': 0.001,
                             'b_max_concurrent': 1, 'b_burst': 100},
                  'concurrent_vms': [{'job_dir': a_work.name, 'uid': a_uid},
                                     {'job_dir': b_work.name, 'uid': b_uid}],
                  'responses': {'a_first': a_first, 'a_concurrent_reject': a_reject,
                                'b_first': b_first, 'a_third': a_third,
                                'a_rate_reject': a_fourth, 'b_followup': b_followup},
                  'remaining_workdirs': job_dirs(root / 'run'),
                  'remaining_cgroups': job_dirs(cgroups), 'passed': True}
        (root / 'results/tenant-quota.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps({'passed': True, 'a_concurrent_reject': a_reject,
                          'a_rate_reject': a_fourth, 'b_followup': b_followup}), flush=True)
    finally:
        for process in (a, b):
            if process and process.poll() is None:
                process.terminate()
                try:
                    process.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate()


if __name__ == '__main__':
    main()
