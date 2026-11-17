#!/usr/bin/env python3
"""Crash only an isolated validation launcher during a real KVM job."""

import argparse
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


def systemctl(*args):
    return subprocess.run(['systemctl', *args], check=True, text=True,
                          capture_output=True).stdout.strip()


def unit_pid(unit):
    return int(systemctl('show', '-p', 'MainPID', '--value', unit))


def is_active(unit):
    return subprocess.run(['systemctl', 'is-active', '--quiet', unit]).returncode == 0


def wait_for(predicate, timeout, message):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.05)
    raise RuntimeError(message)


def job_dirs(path):
    return sorted(item.name for item in path.glob('job-*'))


def client(root, mode):
    config = json.loads((root / 'config.production.json').read_text())
    context = ssl.create_default_context(cafile=root / 'tls/ca.crt')
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(root / 'tls/client.crt', root / 'tls/client.key')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                         urllib.request.HTTPSHandler(context=context))
    token = (root / 'secrets/token').read_text()
    script = 'sleep 45' if mode == 'client' else 'printf after-restart'
    body = json.dumps({'entrypoint': '/bin/sh', 'args': ['-c', script],
                       'timeout_ms': 60000}).encode()
    url = 'https://localhost:' + config['listen'].rsplit(':', 1)[1] + '/v1/jobs'
    request = urllib.request.Request(url, body, headers={
        'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
    try:
        with opener.open(request, timeout=75) as response:
            result = json.load(response)
            print(json.dumps({'status': response.status, 'state': result.get('state'),
                              'protocol_ok': result.get('protocol_ok')}), flush=True)
    except urllib.error.HTTPError as error:
        print(json.dumps({'status': error.code}), flush=True)
    except Exception as error:
        print(json.dumps({'error_type': type(error).__name__}), flush=True)


def run_client_in_api_netns(api_pid, root, mode, timeout):
    proc = subprocess.Popen(['nsenter', '-t', str(api_pid), '-n', sys.executable,
                             __file__, '--root', str(root), '--' + mode],
                            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if mode == 'client':
        return proc
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        raise RuntimeError('follow-up client timed out')
    require(proc.returncode == 0 and not stderr, 'follow-up client failed')
    return json.loads(stdout)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--client', action='store_true')
    parser.add_argument('--probe', action='store_true')
    args = parser.parse_args()
    root = args.root.resolve()
    require(root.name.startswith(('osv-offline-validation-20261029-',
                                  'osv-offline-validation-20261030-')) and root.is_dir(),
            'requires an existing isolated validation fixture')
    if args.client or args.probe:
        client(root, 'client' if args.client else 'probe')
        return
    require(os.geteuid() == 0, 'requires root')
    config = json.loads((root / 'config.production.json').read_text())
    require(config['run_root'] == str(root / 'run') and
            config['jailer']['parent_cgroup'] == root.name,
            'fixture path or cgroup parent mismatch')
    api_unit = root.name + '-api.service'
    launcher_unit = root.name + '-launcher.service'
    require(is_active(api_unit) and is_active(launcher_unit),
            'validation services must already be active')
    cgroup_root = Path('/sys/fs/cgroup') / root.name
    require(not job_dirs(root / 'run') and not job_dirs(cgroup_root),
            'validation fixture already has job resources')
    old_api_pid, old_launcher_pid = unit_pid(api_unit), unit_pid(launcher_unit)
    require(old_api_pid > 1 and old_launcher_pid > 1, 'invalid validation service PID')
    sentinel = subprocess.Popen(['sleep', '60'])
    request = run_client_in_api_netns(old_api_pid, root, 'client', 0)
    try:
        workdir = wait_for(lambda: next((item for item in (root / 'run').glob('job-*')
                                        if (item / 'lease.json').is_file()), None),
                           20, 'running job did not write a lease')
        leaf = cgroup_root / workdir.name
        def firecracker_member():
            try:
                for value in (leaf / 'cgroup.procs').read_text().split():
                    pid = int(value)
                    if Path('/proc', value, 'comm').read_text().strip() == 'firecracker':
                        return pid
            except OSError:
                pass
            return None
        pid = wait_for(firecracker_member, 10,
                       'Firecracker did not enter its dedicated cgroup')
        membership = Path('/proc', str(pid), 'cgroup').read_text()
        require(root.name + '/' + workdir.name in membership,
                'observed PID is not in the validation job cgroup')
        time.sleep(0.5)
        require(request.poll() is None, 'job completed before launcher crash')
        observed = {'job': workdir.name, 'member_pid': pid,
                    'member_comm': 'firecracker',
                    'launcher_pid_before': old_launcher_pid,
                    'cgroup_bound_before_crash': True}
        os.kill(old_launcher_pid, signal.SIGKILL)
        wait_for(lambda: unit_pid(launcher_unit) == 0, 10,
                 'launcher did not exit after injected crash')
        observed['workdirs_after_crash'] = job_dirs(root / 'run')
        observed['cgroups_after_crash'] = job_dirs(cgroup_root)
        require(workdir.name in observed['workdirs_after_crash'] and
                workdir.name in observed['cgroups_after_crash'],
                'crash left no recovery evidence')
        try:
            stdout, stderr = request.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            request.kill()
            stdout, stderr = request.communicate()
        observed['inflight_client'] = json.loads(stdout) if stdout else {
            'error_type': 'no-response'}
        require(not stderr, 'in-flight client emitted diagnostic stderr')
        require(observed['inflight_client'] == {'status': 503},
                'launcher crash was not reported as service unavailable')
        systemctl('reset-failed', launcher_unit)
        systemctl('start', launcher_unit)
        if not is_active(api_unit):
            systemctl('start', api_unit)
        new_launcher_pid = wait_for(lambda: unit_pid(launcher_unit), 10,
                                    'launcher did not restart')
        new_api_pid = wait_for(lambda: unit_pid(api_unit), 10,
                               'API did not restart')
        observed['launcher_pid_after'] = new_launcher_pid
        require(new_launcher_pid != old_launcher_pid, 'launcher PID did not change')
        wait_for(lambda: not job_dirs(root / 'run') and not job_dirs(cgroup_root),
                 10, 'restart did not reconcile orphan resources')
        require(sentinel.poll() is None, 'unrelated host process was killed')
        followup = run_client_in_api_netns(new_api_pid, root, 'probe', 15)
        observed['followup'] = followup
        require(followup == {'status': 200, 'state': 'succeeded',
                             'protocol_ok': True}, 'follow-up VM job failed')
        observed['remaining_workdirs'] = job_dirs(root / 'run')
        observed['remaining_cgroups'] = job_dirs(cgroup_root)
        require(not observed['remaining_workdirs'] and not observed['remaining_cgroups'],
                'follow-up job left resources')
        observed['passed'] = True
        report = root / 'results/launcher-crash.json'
        report.write_text(json.dumps(observed, indent=2) + '\n')
        print(json.dumps({'passed': True, 'reconciled_job': workdir.name,
                          'followup': followup}), flush=True)
    finally:
        if request.poll() is None:
            request.kill()
            request.communicate()
        sentinel.terminate()
        sentinel.wait()


if __name__ == '__main__':
    main()
