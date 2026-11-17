#!/usr/bin/env python3
"""Bounded memory OOM test in an isolated real-VM job cgroup."""

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


def run_client(root, followup):
    config = json.loads((root / 'config.production.json').read_text())
    context = ssl.create_default_context(cafile=root / 'tls/ca.crt')
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(root / 'tls/client.crt', root / 'tls/client.key')
    token = (root / 'secrets/token').read_text()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                         urllib.request.HTTPSHandler(context=context))
    script = 'printf after-oom' if followup else 'sleep 30'
    body = json.dumps({'entrypoint': '/bin/sh', 'args': ['-c', script],
                       'timeout_ms': 45000}).encode()
    url = 'https://localhost:' + config['listen'].rsplit(':', 1)[1] + '/v1/jobs'
    request = urllib.request.Request(url, body, headers={
        'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
    try:
        with opener.open(request, timeout=50) as response:
            result = json.load(response)
            print(json.dumps({'status': response.status, 'state': result.get('state'),
                              'protocol_ok': result.get('protocol_ok')}), flush=True)
    except urllib.error.HTTPError as error:
        print(json.dumps({'status': error.code}), flush=True)
    except Exception as error:
        print(json.dumps({'error_type': type(error).__name__}), flush=True)


def netns_client(api_pid, root, followup=False):
    return subprocess.Popen(['nsenter', '-t', str(api_pid), '-n', sys.executable,
                             __file__, '--root', str(root),
                             '--followup-client' if followup else '--client'],
                            stdin=subprocess.DEVNULL, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def complete_client(process, timeout):
    stdout, stderr = process.communicate(timeout=timeout)
    require(process.returncode == 0 and not stderr and stdout,
            'API client failed')
    return json.loads(stdout)


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
    parser.add_argument('--client', action='store_true')
    parser.add_argument('--followup-client', action='store_true')
    parser.add_argument('--allocate', action='store_true')
    args = parser.parse_args()
    root = args.root.resolve()
    require(root.is_dir() and root.name.startswith('osv-offline-validation-20261029-'),
            'requires isolated validation fixture')
    if args.client or args.followup_client:
        run_client(root, args.followup_client)
        return
    if args.allocate:
        allocate()
        return
    require(os.geteuid() == 0, 'requires root')
    config = json.loads((root / 'config.production.json').read_text())
    require(config['run_root'] == str(root / 'run') and
            config['jailer']['parent_cgroup'] == root.name,
            'fixture paths or cgroup parent mismatch')
    api_unit, launcher_unit = root.name + '-api.service', root.name + '-launcher.service'
    api_pid, launcher_pid = unit_pid(api_unit), unit_pid(launcher_unit)
    require(api_pid > 1 and launcher_pid > 1, 'validation services must be active')
    cgroup_root = Path('/sys/fs/cgroup') / root.name
    require(not job_dirs(root / 'run') and not job_dirs(cgroup_root),
            'fixture already has job resources')
    sentinel = subprocess.Popen(['sleep', '60'])
    request = netns_client(api_pid, root)
    helper = None
    witness = None
    try:
        workdir = wait_for(lambda: next((item for item in (root / 'run').glob('job-*')
                                        if (item / 'lease.json').is_file()), None),
                           20, 'running VM did not write a lease')
        leaf = cgroup_root / workdir.name
        def firecracker_member():
            try:
                for value in (leaf / 'cgroup.procs').read_text().split():
                    if Path('/proc', value, 'comm').read_text().strip() == 'firecracker':
                        return value
            except OSError:
                pass
            return None
        vm_pid = wait_for(firecracker_member, 10, 'Firecracker did not enter cgroup')
        require(root.name + '/' + workdir.name in
                Path('/proc', vm_pid, 'cgroup').read_text(),
                'observed VM is outside the validation job leaf')
        limits = {name: (leaf / name).read_text().strip() for name in
                  ('memory.max', 'memory.swap.max', 'memory.oom.group')}
        require(limits == {'memory.max': '402653184', 'memory.swap.max': '0',
                           'memory.oom.group': '1'},
                'expected memory/swap/OOM-group limits not active')
        require(request.poll() is None, 'VM task completed before memory fault')
        witness = MemoryWitness(leaf)
        helper = subprocess.Popen([sys.executable, __file__, '--root', str(root),
                                   '--allocate'], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  text=True)
        (leaf / 'cgroup.procs').write_text(str(helper.pid))
        require(root.name + '/' + workdir.name in
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
        first = complete_client(request, 15)
        require(first.get('state') != 'succeeded' and
                first.get('status') in (200, 503),
                'OOM-killed VM was reported as successful')
        wait_for(lambda: not job_dirs(root / 'run') and not job_dirs(cgroup_root),
                 5, 'OOM job left resources')
        followup = complete_client(netns_client(unit_pid(api_unit), root, True), 15)
        require(followup == {'status': 200, 'state': 'succeeded', 'protocol_ok': True},
                'follow-up VM job failed')
        wait_for(lambda: not job_dirs(root / 'run') and not job_dirs(cgroup_root),
                 5, 'follow-up job left resources')
        report = {'suite': 'memory-limit-kvm/v1', 'package_version': '2026.10.29-rc11',
                  'job': workdir.name, 'vm_pid': int(vm_pid), 'limits': limits,
                  'allocator_exit_code': helper.returncode,
                  'allocator_chunks_touched': len(allocation_output.splitlines()),
                  'events_before': before, 'events_maximum': maximum,
                  'unrelated_process_survived': True,
                  'first_job': first, 'followup_job': followup,
                  'remaining_workdirs': job_dirs(root / 'run'),
                  'remaining_cgroups': job_dirs(cgroup_root), 'passed': True}
        (root / 'results/memory-limit.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps({'passed': True, 'oom_kill_delta':
                          maximum['oom_kill'] - before['oom_kill'],
                          'swap_peak': maximum['swap_current'], 'first_job': first}),
              flush=True)
    finally:
        if witness:
            witness.close()
        if helper and helper.poll() is None:
            helper.kill()
            helper.communicate()
        if request.poll() is None:
            request.kill()
            request.communicate()
        sentinel.terminate()
        sentinel.wait()


if __name__ == '__main__':
    main()
