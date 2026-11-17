#!/usr/bin/env python3
"""Exercise the isolated signed x64 release and inspect real VM processes."""

import argparse
import fcntl
import json
import os
from pathlib import Path
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.request


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve()
    config = json.loads((root / 'config.production.json').read_text())
    parent = Path('/sys/fs/cgroup') / config['jailer']['parent_cgroup']
    with open('/var/lock/osv-sandbox-validation.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = exercise(root, config, parent)
    (root / 'results/host-inspection.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: result[key] for key in ('passed', 'observed_vms', 'remaining_dirs',
                                                   'remaining_cgroups', 'remaining_processes')}))
    raise SystemExit(0 if result['passed'] else 1)


def exercise(root, config, parent):
    observations, violations, first = {}, [], {}
    stop = threading.Event()

    def observe():
        while not stop.wait(0.025):
            for lease in (root / 'run').glob('job-*/lease.json'):
                try:
                    job = json.loads(lease.read_text())
                    pid = job['pid']
                    proc = Path('/proc') / str(pid)
                    if proc.joinpath('comm').read_text().strip() != 'firecracker':
                        continue
                    first.setdefault(pid, time.monotonic())
                    if time.monotonic() - first[pid] < 0.1:
                        continue
                    status = dict(line.split(':', 1) for line in proc.joinpath('status').read_text().splitlines() if ':' in line)
                    leaf = parent / lease.parent.name
                    cgroup = proc.joinpath('cgroup').read_text().strip()
                    row = {'uid': status['Uid'].split(), 'gid': status['Gid'].split(),
                           'seccomp': status['Seccomp'].strip(), 'caps': status['CapEff'].strip(),
                           'cgroup_bound': config['jailer']['parent_cgroup'] + '/' + lease.parent.name in cgroup}
                    for name in ('memory.max', 'memory.swap.max', 'memory.oom.group',
                                 'cpu.max', 'pids.max', 'io.max'):
                        row[name] = leaf.joinpath(name).read_text().strip()
                    identities = config['jailer']
                    protected_identity = any(
                        row['uid'] == [str(identities['uid'] + offset)] * 4 and
                        row['gid'] == [str(identities['gid'] + offset)] * 4
                        for offset in range(identities['identity_pool_size']))
                    protected = (protected_identity
                                 and row['seccomp'] == '2' and row['caps'] == '0000000000000000'
                                 and row['cgroup_bound'] and row['memory.swap.max'] == '0'
                                 and row['memory.oom.group'] == '1' and row['pids.max'] == '64'
                                 and 'rbps=104857600' in row['io.max']
                                 and 'wbps=52428800' in row['io.max'])
                    observations[lease.parent.name] = row
                    if not protected:
                        violations.append({'job': lease.parent.name, 'row': row})
                except (OSError, ValueError, KeyError):
                    pass

    watcher = threading.Thread(target=observe)
    watcher.start()
    env = os.environ.copy()
    env['OSV_SANDBOX_TOKEN'] = (root / 'secrets/token').read_text()
    url = 'https://localhost:' + config['listen'].rsplit(':', 1)[1]
    command = ['python3', str(root / 'e2e-api.py'), '--url', url,
               '--backend', 'firecracker-linux', '--ca', str(root / 'tls/ca.crt'),
               '--cert', str(root / 'tls/client.crt'), '--key', str(root / 'tls/client.key'),
               '--diagnostic-allow-unready', '--output', str(root / 'results/api-e2e.json')]
    if (root/'egress.production.json').exists() and json.loads((root/'egress.production.json').read_text()).get('guest_proxy',False):command.append('--expect-guest-proxy')
    try:
        completed = subprocess.run(command, env=env, timeout=180)
    finally:
        stop.set()
        watcher.join()
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if not list((root / 'run').glob('job-*')) and not list(parent.glob('job-*')):
            break
        time.sleep(0.05)
    dirs = [item.name for item in (root / 'run').glob('job-*')]
    cgroups = [item.name for item in parent.glob('job-*')]
    processes = []
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit():
            continue
        try:
            if config['jailer']['parent_cgroup'] + '/' in proc.joinpath('cgroup').read_text():
                processes.append(proc.name)
        except OSError:
            pass
    context = ssl.create_default_context(cafile=root / 'tls/ca.crt')
    context.load_cert_chain(root / 'tls/client.crt', root / 'tls/client.key')
    request = urllib.request.Request(url + '/v1/doctor',
                                     headers={'Authorization': 'Bearer ' + env['OSV_SANDBOX_TOKEN']})
    try:
        response = urllib.request.urlopen(request, context=context, timeout=10)
    except urllib.error.HTTPError as error:
        response = error
    doctor = json.load(response)
    return {'suite': 'offline-release-host-inspection/v1',
            'api_exit_code': completed.returncode, 'observed_vms': len(observations),
            'observations': observations, 'violations': violations,
            'remaining_dirs': dirs, 'remaining_cgroups': cgroups,
            'remaining_processes': processes, 'doctor': doctor,
            'production_validated': False,
            'passed': completed.returncode == 0 and bool(observations)
            and not any((violations, dirs, cgroups, processes))}


if __name__ == '__main__':
    main()
