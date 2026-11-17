#!/usr/bin/env python3
"""Validate pids.max enforcement inside an isolated real-VM job cgroup."""

import argparse
import errno
import json
import os
from pathlib import Path
import signal
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def wait_for(predicate, timeout, message):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = predicate()
        if result:
            return result
        time.sleep(0.05)
    raise RuntimeError(message)


def unit_pid(unit):
    result = subprocess.run(['systemctl', 'show', '-p', 'MainPID', '--value', unit],
                            check=True, text=True, capture_output=True)
    return int(result.stdout.strip())


def job_dirs(root):
    return sorted(path.name for path in root.glob('job-*'))


def cgroup_value(path, name):
    return (path / name).read_text().strip()


def event_max(path):
    fields = dict(line.split() for line in cgroup_value(path, 'pids.events').splitlines())
    return int(fields['max'])


def run_client(root, followup):
    config = json.loads((root / 'config.production.json').read_text())
    context = ssl.create_default_context(cafile=root / 'tls/ca.crt')
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(root / 'tls/client.crt', root / 'tls/client.key')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                         urllib.request.HTTPSHandler(context=context))
    token = (root / 'secrets/token').read_text()
    script = 'printf after-pids' if followup else 'sleep 8'
    body = json.dumps({'entrypoint': '/bin/sh', 'args': ['-c', script],
                       'timeout_ms': 20000}).encode()
    url = 'https://localhost:' + config['listen'].rsplit(':', 1)[1] + '/v1/jobs'
    request = urllib.request.Request(url, body, headers={
        'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
    try:
        with opener.open(request, timeout=25) as response:
            result = json.load(response)
            print(json.dumps({'status': response.status, 'state': result.get('state'),
                              'protocol_ok': result.get('protocol_ok')}), flush=True)
    except urllib.error.HTTPError as error:
        print(json.dumps({'status': error.code}), flush=True)
    except Exception as error:
        print(json.dumps({'error_type': type(error).__name__}), flush=True)


def probe(leaf):
    # Parent moves this blocked process into the job cgroup before releasing it.
    if sys.stdin.readline() != 'go\n':
        return
    children = []
    denied = None
    peak = int(cgroup_value(leaf, 'pids.current'))
    def terminate(_signum, _frame):
        raise SystemExit(2)
    signal.signal(signal.SIGTERM, terminate)
    try:
        for _ in range(70):
            try:
                children.append(subprocess.Popen(['sleep', '20']))
            except OSError as error:
                denied = error.errno
                break
            peak = max(peak, int(cgroup_value(leaf, 'pids.current')))
        print(json.dumps({'attempts_limit': 70, 'spawned': len(children),
                          'denied_errno': denied, 'peak_pids_current': peak}), flush=True)
    finally:
        for child in children:
            child.terminate()
        for child in children:
            child.wait()


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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--client', action='store_true')
    parser.add_argument('--followup-client', action='store_true')
    parser.add_argument('--probe-leaf', type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    require(root.is_dir() and root.name.startswith('osv-offline-validation-20261029-'),
            'requires isolated validation fixture')
    if args.client or args.followup_client:
        run_client(root, args.followup_client)
        return
    if args.probe_leaf:
        probe(args.probe_leaf)
        return
    require(os.geteuid() == 0, 'requires root')
    config = json.loads((root / 'config.production.json').read_text())
    require(config['run_root'] == str(root / 'run') and
            config['jailer']['parent_cgroup'] == root.name and
            config['jailer']['pids_max'] == 64,
            'fixture paths or expected pids limit mismatch')
    api_unit, launcher_unit = root.name + '-api.service', root.name + '-launcher.service'
    api_pid, launcher_pid = unit_pid(api_unit), unit_pid(launcher_unit)
    require(api_pid > 1 and launcher_pid > 1, 'validation services must be active')
    cgroup_root = Path('/sys/fs/cgroup') / root.name
    require(not job_dirs(root / 'run') and not job_dirs(cgroup_root),
            'fixture already has job resources')
    request = netns_client(api_pid, root)
    helper = None
    try:
        workdir = wait_for(lambda: next((path for path in (root / 'run').glob('job-*')
                                         if (path / 'lease.json').is_file()), None),
                           20, 'running job did not write a lease')
        leaf = cgroup_root / workdir.name
        def firecracker_member():
            try:
                for value in cgroup_value(leaf, 'cgroup.procs').split():
                    if Path('/proc', value, 'comm').read_text().strip() == 'firecracker':
                        return value
            except OSError:
                pass
            return None
        vm_pid = wait_for(firecracker_member, 10, 'Firecracker did not enter cgroup')
        require(root.name + '/' + workdir.name in
                Path('/proc', vm_pid, 'cgroup').read_text(),
                'observed VM is outside job cgroup')
        require(cgroup_value(leaf, 'pids.max') == '64', 'pids.max not enforced')
        require(request.poll() is None, 'VM job completed before fault injection')
        before = event_max(leaf)
        helper = subprocess.Popen([sys.executable, __file__, '--root', str(root),
                                   '--probe-leaf', str(leaf)], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  text=True)
        (leaf / 'cgroup.procs').write_text(str(helper.pid))
        require(root.name + '/' + workdir.name in
                Path('/proc', str(helper.pid), 'cgroup').read_text(),
                'probe was not moved into job cgroup')
        helper.stdin.write('go\n')
        helper.stdin.flush()
        stdout, stderr = helper.communicate(timeout=10)
        require(helper.returncode == 0 and not stderr and stdout, 'bounded probe failed')
        spawned = json.loads(stdout)
        after = event_max(leaf)
        require(spawned['spawned'] < 70 and spawned['denied_errno'] == errno.EAGAIN,
                'pids limit did not reject bounded fork attempts')
        require(after > before and spawned['peak_pids_current'] <= 64,
                'pids kernel counters did not prove enforcement')
        require(request.poll() is None, 'pids fault terminated the VM job')
        first = complete_client(request, 25)
        require(first == {'status': 200, 'state': 'succeeded', 'protocol_ok': True},
                'VM job failed after pids limit event')
        wait_for(lambda: not job_dirs(root / 'run') and not job_dirs(cgroup_root),
                 5, 'first job left resources')
        followup = complete_client(netns_client(unit_pid(api_unit), root, True), 15)
        require(followup == {'status': 200, 'state': 'succeeded', 'protocol_ok': True},
                'follow-up VM job failed')
        wait_for(lambda: not job_dirs(root / 'run') and not job_dirs(cgroup_root),
                 5, 'follow-up job left resources')
        report = {'suite': 'pids-limit-kvm/v1', 'package_version': '2026.10.29-rc11',
                  'job': workdir.name, 'vm_pid': int(vm_pid), 'pids_max': 64,
                  'pids_events_before': before, 'pids_events_after': after,
                  'probe': spawned, 'first_job': first, 'followup_job': followup,
                  'remaining_workdirs': job_dirs(root / 'run'),
                  'remaining_cgroups': job_dirs(cgroup_root), 'passed': True}
        (root / 'results/pids-limit.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps({'passed': True, 'spawned': spawned['spawned'],
                          'pids_events_delta': after - before}), flush=True)
    finally:
        if helper and helper.poll() is None:
            helper.terminate()
            helper.communicate(timeout=5)
        if request.poll() is None:
            request.kill()
            request.communicate()


if __name__ == '__main__':
    main()
