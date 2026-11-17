#!/usr/bin/env python3
"""Bounded OOM isolation test with two concurrent authenticated VM tenants."""

import argparse
import json
import os
from pathlib import Path
import signal
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def wait_for(predicate, timeout, message):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.05)
    raise RuntimeError(message)


def unit_pid(unit):
    result = subprocess.run(['systemctl', 'show', '-p', 'MainPID', '--value', unit],
                            check=True, text=True, capture_output=True)
    return int(result.stdout.strip())


def job_dirs(path):
    return sorted(item.name for item in path.glob('job-*'))


def run_client(root, tenant, followup):
    config = json.loads((root / 'config.production.json').read_text())
    context = ssl.create_default_context(cafile=root / 'tls/ca.crt')
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(root / 'tls/client.crt', root / 'tls/client.key')
    token = (root / 'secrets' / ('token-b' if tenant == 'b' else 'token')).read_text()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                         urllib.request.HTTPSHandler(context=context))
    script = ('printf after-cross-tenant-oom' if followup else
              'sleep 20' if tenant == 'b' else 'sleep 35')
    body = json.dumps({'entrypoint': '/bin/sh', 'args': ['-c', script],
                       'timeout_ms': 55000 if tenant == 'a' else 40000}).encode()
    url = 'https://localhost:' + config['listen'].rsplit(':', 1)[1] + '/v1/jobs'
    request = urllib.request.Request(url, body, headers={
        'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
    try:
        with opener.open(request, timeout=60) as response:
            result = json.load(response)
            print(json.dumps({'status': response.status, 'state': result.get('state'),
                              'protocol_ok': result.get('protocol_ok')}), flush=True)
    except urllib.error.HTTPError as error:
        print(json.dumps({'status': error.code}), flush=True)
    except Exception as error:
        print(json.dumps({'error_type': type(error).__name__}), flush=True)


def netns_client(api_pid, root, tenant='a', followup=False):
    role = '--followup-a' if followup else '--client-b' if tenant == 'b' else '--client-a'
    return subprocess.Popen(['nsenter', '-t', str(api_pid), '-n', sys.executable,
                             __file__, '--root', str(root), role],
                            stdin=subprocess.DEVNULL, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def complete_client(process, timeout):
    stdout, stderr = process.communicate(timeout=timeout)
    require(process.returncode == 0 and not stderr and stdout,
            'API client failed')
    return json.loads(stdout)


def vm_member(leaf):
    try:
        for value in (leaf / 'cgroup.procs').read_text().split():
            if Path('/proc', value, 'comm').read_text().strip() == 'firecracker':
                return int(value)
    except OSError:
        pass
    return None


def vm_uid(pid):
    for line in Path('/proc', str(pid), 'status').read_text().splitlines():
        if line.startswith('Uid:'):
            return int(line.split()[1])
    raise RuntimeError('VM process has no UID status')


def allocate():
    # Parent moves this blocked process into the job leaf before release.
    if sys.stdin.readline() != 'go\n':
        return
    chunks = []
    for index in range(64):  # At most 512 MiB, even if cgroup policy is missing.
        chunk = bytearray(8 << 20)
        for offset in range(0, len(chunk), 4096):
            chunk[offset] = 1
        chunks.append(chunk)
        print(index + 1, flush=True)
        time.sleep(0.002)
    print('allocation-completed', flush=True)


class MemoryWitness:
    def __init__(self, leaf):
        self.events = (leaf / 'memory.events').open()
        self.swap = (leaf / 'memory.swap.current').open()
        self.stop = threading.Event()
        self.maximum = {'oom': 0, 'oom_kill': 0, 'oom_group_kill': 0,
                        'swap_current': 0}
        self.thread = threading.Thread(target=self.observe)
        self.sample()
        self.before = dict(self.maximum)
        self.thread.start()

    def sample(self):
        try:
            self.events.seek(0)
            values = dict(line.split() for line in self.events.read().splitlines())
            self.swap.seek(0)
            swap = int(self.swap.read().strip())
            for name in ('oom', 'oom_kill', 'oom_group_kill'):
                self.maximum[name] = max(self.maximum[name], int(values.get(name, 0)))
            self.maximum['swap_current'] = max(self.maximum['swap_current'], swap)
        except (OSError, ValueError):
            # The manager may remove the leaf as soon as the VM exits.
            pass

    def observe(self):
        while not self.stop.wait(0.002):
            self.sample()

    def close(self):
        self.stop.set()
        self.thread.join()
        self.sample()
        self.events.close()
        self.swap.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--client-a', action='store_true')
    parser.add_argument('--client-b', action='store_true')
    parser.add_argument('--followup-a', action='store_true')
    parser.add_argument('--allocate', action='store_true')
    args = parser.parse_args()
    root = args.root.resolve()
    require(root.is_dir() and root.name.startswith('osv-offline-validation-20261029-'),
            'requires isolated validation fixture')
    if args.client_a or args.client_b or args.followup_a:
        run_client(root, 'b' if args.client_b else 'a', args.followup_a)
        return
    if args.allocate:
        allocate()
        return
    require(os.geteuid() == 0, 'requires root')
    config = json.loads((root / 'config.production.json').read_text())
    require(config['run_root'] == str(root / 'run') and
            config['jailer']['parent_cgroup'] == root.name and
            config['jailer']['identity_pool_size'] == 2 and
            config['limits']['max_concurrent'] == 2,
            'fixture paths or concurrency limits mismatch')
    policy = json.loads((root / 'auth.json').read_text())
    require({tenant['id'] for tenant in policy['tenants']} ==
            {'validation-a', 'validation-b'} and
            all(tenant['max_concurrent'] == 1 for tenant in policy['tenants']),
            'fixture is not configured for distinct tenants')
    api_unit, launcher_unit = root.name + '-api.service', root.name + '-launcher.service'
    api_pid, launcher_pid = unit_pid(api_unit), unit_pid(launcher_unit)
    require(api_pid > 1 and launcher_pid > 1, 'validation services must be active')
    cgroup_root = Path('/sys/fs/cgroup') / root.name
    require(not job_dirs(root / 'run') and not job_dirs(cgroup_root),
            'fixture already has job resources')
    sentinel = subprocess.Popen(['sleep', '60'])
    request_a = netns_client(api_pid, root)
    request_b = None
    helper = None
    witness = None
    try:
        workdir_a = wait_for(lambda: next((item for item in (root / 'run').glob('job-*')
                                          if (item / 'lease.json').is_file()), None),
                             20, 'tenant A VM did not write a lease')
        leaf_a = cgroup_root / workdir_a.name
        vm_a = wait_for(lambda: vm_member(leaf_a), 10,
                        'tenant A Firecracker did not enter its cgroup')
        request_b = netns_client(api_pid, root, 'b')
        workdir_b = wait_for(lambda: next((item for item in (root / 'run').glob('job-*')
                                          if item.name != workdir_a.name and
                                          (item / 'lease.json').is_file()), None),
                             20, 'tenant B VM did not write a distinct lease')
        leaf_b = cgroup_root / workdir_b.name
        vm_b = wait_for(lambda: vm_member(leaf_b), 10,
                        'tenant B Firecracker did not enter its cgroup')
        uid_a, uid_b = vm_uid(vm_a), vm_uid(vm_b)
        require({uid_a, uid_b} == {230000, 230001} and
                workdir_a.name != workdir_b.name,
                'concurrent tenants did not receive distinct jail identities')
        for pid, workdir in ((vm_a, workdir_a), (vm_b, workdir_b)):
            require(root.name + '/' + workdir.name in
                    Path('/proc', str(pid), 'cgroup').read_text(),
                    'observed VM is outside its validation job leaf')
        limits = {name: (leaf_a / name).read_text().strip() for name in
                  ('memory.max', 'memory.swap.max', 'memory.oom.group')}
        limits_b = {name: (leaf_b / name).read_text().strip() for name in limits}
        require(limits == {'memory.max': '402653184', 'memory.swap.max': '0',
                           'memory.oom.group': '1'} and limits_b == limits,
                'expected memory/swap/OOM-group limits not active')
        require(request_a.poll() is None and request_b.poll() is None,
                'concurrent VM task completed before memory fault')
        witness = MemoryWitness(leaf_a)
        helper = subprocess.Popen([sys.executable, __file__, '--root', str(root),
                                   '--allocate'], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  text=True)
        (leaf_a / 'cgroup.procs').write_text(str(helper.pid))
        require(root.name + '/' + workdir_a.name in
                Path('/proc', str(helper.pid), 'cgroup').read_text(),
                'allocator was not moved into the job leaf')
        helper.stdin.write('go\n')
        helper.stdin.flush()
        allocation_output, allocation_error = helper.communicate(timeout=15)
        witness.close()
        maximum, before = dict(witness.maximum), witness.before
        witness = None
        require(not allocation_error, 'allocator emitted diagnostic stderr')
        require(helper.returncode == -signal.SIGKILL and
                'allocation-completed' not in allocation_output,
                'bounded allocation did not trigger cgroup OOM kill')
        require(maximum['oom_kill'] > before['oom_kill'] and
                maximum['oom_group_kill'] > before['oom_group_kill'],
                'memory.events did not prove group OOM enforcement')
        require(maximum['swap_current'] == 0,
                'job cgroup used swap despite memory.swap.max=0')
        require(sentinel.poll() is None, 'unrelated host process was killed')
        require(request_b.poll() is None and Path('/proc', str(vm_b)).exists() and
                root.name + '/' + workdir_b.name in
                Path('/proc', str(vm_b), 'cgroup').read_text(),
                'tenant B VM was affected by tenant A OOM')
        first = complete_client(request_a, 15)
        require(first == {'status': 200, 'state': 'failed', 'protocol_ok': False},
                'OOM-killed tenant A VM has unexpected result')
        require(request_b.poll() is None,
                'tenant B completed before tenant A result was observed')
        second = complete_client(request_b, 30)
        require(second == {'status': 200, 'state': 'succeeded', 'protocol_ok': True},
                'tenant B VM failed after tenant A OOM')
        wait_for(lambda: not job_dirs(root / 'run') and not job_dirs(cgroup_root),
                 5, 'concurrent jobs left resources')
        followup = complete_client(netns_client(unit_pid(api_unit), root,
                                                 followup=True), 15)
        require(followup == {'status': 200, 'state': 'succeeded', 'protocol_ok': True},
                'follow-up VM job failed')
        wait_for(lambda: not job_dirs(root / 'run') and not job_dirs(cgroup_root),
                 5, 'follow-up job left resources')
        report = {'suite': 'cross-tenant-oom-kvm/v1',
                  'package_version': '2026.10.29-rc11',
                  'tenant_a': {'job': workdir_a.name, 'vm_pid': vm_a, 'uid': uid_a},
                  'tenant_b': {'job': workdir_b.name, 'vm_pid': vm_b, 'uid': uid_b},
                  'tenant_a_limits': limits, 'tenant_b_limits': limits_b,
                  'allocator_exit_code': helper.returncode,
                  'allocator_chunks_touched': len(allocation_output.splitlines()),
                  'events_before': before, 'events_maximum': maximum,
                  'unrelated_process_survived': True,
                  'tenant_a_job': first, 'tenant_b_job': second,
                  'followup_job': followup,
                  'remaining_workdirs': job_dirs(root / 'run'),
                  'remaining_cgroups': job_dirs(cgroup_root), 'passed': True}
        (root / 'results/cross-tenant-oom.json').write_text(
            json.dumps(report, indent=2) + '\n')
        print(json.dumps({'passed': True, 'oom_kill_delta':
                          maximum['oom_kill'] - before['oom_kill'],
                          'swap_peak': maximum['swap_current'],
                          'tenant_a_job': first, 'tenant_b_job': second}),
              flush=True)
    finally:
        if witness:
            witness.close()
        if helper and helper.poll() is None:
            helper.kill()
            helper.communicate()
        for request in (request_a, request_b):
            if request and request.poll() is None:
                request.kill()
                request.communicate()
        sentinel.terminate()
        sentinel.wait()


if __name__ == '__main__':
    main()
