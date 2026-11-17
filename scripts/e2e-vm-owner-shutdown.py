#!/usr/bin/env python3
"""Terminate one isolated launcher with an actual KVM job and session alive."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

import osv_sandbox_client as sdk


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def wait_for(predicate, message, seconds=15):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.05)
    raise RuntimeError(message)


def unit_pid(unit):
    return int(subprocess.check_output(['systemctl', 'show', '-p', 'MainPID', '--value', unit], text=True).strip())


def client(root, mode, old_id):
    config = json.loads((root / 'config.production.json').read_text())
    token = root / ('secrets/token-b' if mode == 'job' else 'secrets/token')
    c = sdk.Client('https://localhost:' + config['listen'].rsplit(':', 1)[1], token=token.read_text(),
                   ca_file=str(root / 'tls/ca.crt'), cert_file=str(root / 'tls/client.crt'),
                   key_file=str(root / 'tls/client.key'), request_timeout_seconds=65)
    if mode == 'session':
        session = c.create_session(sdk.SessionRequest(memory_mib=128, ttl_ms=60000))
        require(session.run(sdk.SessionCommand('/bin/sh', ('-c', 'printf owned > /workspace/marker'))).succeeded,
                'session did not execute in its guest')
        return {'id': session.id}
    if mode == 'probe':
        return c.doctor()
    if mode == 'followup':
        try:
            c.connect_session(old_id).info()
        except sdk.APIError as error:
            require(error.status == 404, 'old session returned wrong status')
        else:
            raise RuntimeError('old session survived launcher shutdown')
        # The API retains quota for 15 seconds when the old launcher cannot
        # acknowledge cleanup. A busy rejection has not executed the job.
        deadline = time.monotonic() + 20
        while True:
            try:
                result = c.run(sdk.JobRequest('/bin/sh', args=('-c', 'printf owner-recovered'),
                                               memory_mib=128, timeout_ms=60000))
                return {'state': result.state, 'protocol_ok': result.protocol_ok,
                        'stdout': result.guest_result.get('stdout') if result.guest_result else None}
            except sdk.APIError as error:
                if error.status != 429 or error.code != 'busy' or time.monotonic() >= deadline:
                    raise
                time.sleep(0.1)
    try:
        result = c.run(sdk.JobRequest('/bin/sh', args=('-c', 'sleep 45' if mode == 'job' else 'printf owner-recovered'),
                                       memory_mib=128, timeout_ms=60000))
        return {'state': result.state, 'protocol_ok': result.protocol_ok,
                'stdout': result.guest_result.get('stdout') if result.guest_result else None}
    except sdk.APIError as error:
        return {'status': error.status}
    except sdk.SandboxError as error:
        return {'error': type(error).__name__}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--package', type=Path, required=True)
    parser.add_argument('--client', choices=('session', 'job', 'probe', 'followup'))
    parser.add_argument('--old-id', default='')
    args = parser.parse_args()
    root = args.root.resolve()
    require(root.name.startswith('osv-offline-validation-20261030-') and root.is_dir(), 'requires isolated fixture')
    release, = [p for p in (root / 'releases').iterdir() if p.is_dir()]
    require(Path(sdk.__file__).resolve() == (release / 'sdk/python/osv_sandbox_client.py').resolve(),
            'SDK not from installed package')
    if args.client:
        print(json.dumps(client(root, args.client, args.old_id)), flush=True)
        return
    require(os.geteuid() == 0, 'requires validation root')
    with open('/var/lock/osv-sandbox-validation.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        exercise(root, args.package)


def exercise(root, package):
    api_unit, launcher_unit = root.name + '-api.service', root.name + '-launcher.service'
    parent = Path('/sys/fs/cgroup') / root.name
    require(not list((root / 'run').glob('job-*')) and not list(parent.glob('job-*')), 'fixture already busy')
    api_pid, launcher_pid = unit_pid(api_unit), unit_pid(launcher_unit)
    require(api_pid > 1 and launcher_pid > 1, 'fixture inactive')

    def launch(mode, pid, old_id=''):
        return subprocess.Popen(['nsenter', '-t', str(pid), '-n', sys.executable, __file__,
                                  '--root', str(root), '--package', str(package), '--client', mode,
                                  '--old-id', old_id], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def invoke(mode, pid, old_id=''):
        process = launch(mode, pid, old_id)
        try:
            stdout, stderr = process.communicate(timeout=75)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            raise RuntimeError('validation client timed out')
        require(process.returncode == 0 and not stderr, 'validation client failed: ' + stderr[-2000:])
        return json.loads(stdout)

    session = invoke('session', api_pid)
    sentinel = subprocess.Popen(['sleep', '120'])
    job = launch('job', api_pid)
    try:
        leases = wait_for(lambda: (items if len(items := list((root / 'run').glob('job-*/lease.json'))) == 2 else None),
                          'job and session did not both start')
        before = invoke('probe', api_pid)
        require(before['vm_capacity']['active'] == before['vm_capacity']['instances'] == 2 and
                before['vm_instances']['states'] == {'active': 2}, 'owner did not track both active VMs')
        members = []
        for lease_path in leases:
            leaf = parent / lease_path.parent.name
            pid = wait_for(lambda: next((int(p) for p in (leaf / 'cgroup.procs').read_text().split()
                                         if Path('/proc', p, 'comm').read_text().strip() == 'firecracker'), None),
                           'Firecracker missing from dedicated cgroup')
            members.append(pid)
        require(job.poll() is None, 'job completed before termination')
        # Signal the launcher directly, so dependency ordering cannot close
        # the API and its VMs before the launcher's own shutdown path runs.
        os.kill(launcher_pid, signal.SIGTERM)
        wait_for(lambda: unit_pid(launcher_unit) == 0, 'launcher failed to stop')
        status = subprocess.check_output(['systemctl', 'show', '-p', 'ExecMainStatus', '--value', launcher_unit], text=True).strip()
        require(status == '0', 'launcher exited with cleanup error')
        wait_for(lambda: not list((root / 'run').glob('job-*')) and not list(parent.glob('job-*')),
                 'launcher left VM directories or cgroups')
        require(all(not Path('/proc', str(pid)).exists() for pid in members), 'VMM process survived shutdown')
        require(sentinel.poll() is None, 'unrelated process was killed')
        stdout, stderr = job.communicate(timeout=20)
        require(job.returncode == 0 and not stderr and json.loads(stdout).get('state') != 'succeeded',
                'interrupted job reported successful completion')
        interrupted = json.loads(stdout)
        subprocess.run(['systemctl', 'start', launcher_unit, api_unit], check=True)
        new_api_pid = wait_for(lambda: unit_pid(api_unit), 'API failed to restart')
        recovered = invoke('probe', new_api_pid)
        capacity = recovered['vm_capacity']
        require(capacity['active'] == capacity['instances'] == capacity['reserved_memory_mib'] ==
                capacity['reserved_vcpus'] == capacity['reserved_pids'] == 0 and not capacity['blocked'] and
                recovered['vm_instances'] == {'stopping': False, 'states': {}}, 'restart retained owner resources')
        followup = invoke('followup', new_api_pid, session['id'])
        require(followup == {'state': 'succeeded', 'protocol_ok': True, 'stdout': 'owner-recovered'},
                'follow-up job failed')
        report = {'suite': 'vm-owner-shutdown-kvm/v1', 'package_sha256': hashlib.sha256(package.read_bytes()).hexdigest(),
                  'production_validated': False, 'observed_vms': 2, 'before': before['vm_instances'],
                  'interrupted_job': interrupted, 'launcher_exit_status': 0, 'old_session_status': 404,
                  'unrelated_process_alive': True, 'after_restart': recovered['vm_instances'],
                  'followup': followup, 'passed': True}
        (root / 'results/vm-owner-shutdown.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps({'passed': True, 'observed_vms': 2, 'followup': followup}), flush=True)
    finally:
        if job.poll() is None:
            job.kill()
            job.communicate()
        sentinel.terminate()
        sentinel.wait()


if __name__ == '__main__':
    main()
