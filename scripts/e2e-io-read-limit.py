#!/usr/bin/env python3
"""Bounded direct-read io.max test in an isolated real-VM job cgroup."""

import argparse
import json
import mmap
import os
from pathlib import Path
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request


DEVICE = '8:0'
READ_BPS = 1 << 20
READ_BYTES = 8 << 20


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


def job_dirs(path):
    return sorted(item.name for item in path.glob('job-*'))


def io_stat(leaf):
    for line in (leaf / 'io.stat').read_text().splitlines():
        fields = line.split()
        if fields and fields[0] == DEVICE:
            return {key: int(value) for key, value in
                    (item.split('=', 1) for item in fields[1:])}
    return {'rbytes': 0, 'wbytes': 0, 'rios': 0, 'wios': 0}


def run_client(root, followup):
    config = json.loads((root / 'config.production.json').read_text())
    context = ssl.create_default_context(cafile=root / 'tls/ca.crt')
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(root / 'tls/client.crt', root / 'tls/client.key')
    token = (root / 'secrets/token').read_text()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                         urllib.request.HTTPSHandler(context=context))
    script = 'printf after-io-read' if followup else 'sleep 40'
    body = json.dumps({'entrypoint': '/bin/sh', 'args': ['-c', script],
                       'timeout_ms': 60000}).encode()
    url = 'https://localhost:' + config['listen'].rsplit(':', 1)[1] + '/v1/jobs'
    request = urllib.request.Request(url, body, headers={
        'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
    try:
        with opener.open(request, timeout=65) as response:
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


def direct_read(root):
    # Parent moves this blocked process into the job leaf before release.
    if sys.stdin.readline() != 'go\n':
        return
    path = root / 'results/io-read-probe.bin'
    fd = os.open(path, os.O_RDONLY | os.O_DIRECT)
    block = mmap.mmap(-1, 1 << 20)
    try:
        started = time.monotonic()
        for _ in range(8):
            count = os.readv(fd, [block])
            require(count == 1 << 20, 'short direct read')
        elapsed_ms = round((time.monotonic() - started) * 1000)
        print(json.dumps({'bytes_read': READ_BYTES,
                          'elapsed_ms': elapsed_ms}), flush=True)
    finally:
        block.close()
        os.close(fd)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--client', action='store_true')
    parser.add_argument('--followup-client', action='store_true')
    parser.add_argument('--direct-read', action='store_true')
    args = parser.parse_args()
    root = args.root.resolve()
    require(root.is_dir() and root.name.startswith('osv-offline-validation-20261029-'),
            'requires isolated validation fixture')
    if args.client or args.followup_client:
        run_client(root, args.followup_client)
        return
    if args.direct_read:
        direct_read(root)
        return
    require(os.geteuid() == 0, 'requires root')
    config = json.loads((root / 'config.production.json').read_text())
    require(config['run_root'] == str(root / 'run') and
            config['jailer']['parent_cgroup'] == root.name and
            config['jailer']['io_read_bps'] == READ_BPS,
            'fixture paths or IO read limit mismatch')
    api_unit, launcher_unit = root.name + '-api.service', root.name + '-launcher.service'
    api_pid, launcher_pid = unit_pid(api_unit), unit_pid(launcher_unit)
    require(api_pid > 1 and launcher_pid > 1, 'validation services must be active')
    cgroup_root = Path('/sys/fs/cgroup') / root.name
    require(not job_dirs(root / 'run') and not job_dirs(cgroup_root),
            'fixture already has job resources')
    probe_file = root / 'results/io-read-probe.bin'
    with probe_file.open('xb') as stream:
        block = b'R' * (1 << 20)
        for _ in range(8):
            stream.write(block)
        stream.flush()
        os.fsync(stream.fileno())
    require(probe_file.stat().st_size == READ_BYTES, 'read probe file size mismatch')
    request = netns_client(api_pid, root)
    helper = None
    try:
        workdir = wait_for(lambda: next((item for item in (root / 'run').glob('job-*')
                                        if (item / 'lease.json').is_file()), None),
                           30, 'running VM did not write a lease')
        leaf = cgroup_root / workdir.name
        def firecracker_member():
            try:
                for value in (leaf / 'cgroup.procs').read_text().split():
                    if Path('/proc', value, 'comm').read_text().strip() == 'firecracker':
                        return value
            except OSError:
                pass
            return None
        vm_pid = wait_for(firecracker_member, 15, 'Firecracker did not enter cgroup')
        require(root.name + '/' + workdir.name in
                Path('/proc', vm_pid, 'cgroup').read_text(),
                'observed VM is outside the validation job leaf')
        limits = (leaf / 'io.max').read_text().strip()
        require(limits.startswith(DEVICE + ' ') and
                'rbps=' + str(READ_BPS) in limits.split() and
                'wbps=52428800' in limits.split(),
                'expected io.max limit not active on backing device')
        require(request.poll() is None, 'VM task completed before IO probe')
        before = io_stat(leaf)
        helper = subprocess.Popen([sys.executable, __file__, '--root', str(root),
                                   '--direct-read'], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  text=True)
        (leaf / 'cgroup.procs').write_text(str(helper.pid))
        require(root.name + '/' + workdir.name in
                Path('/proc', str(helper.pid), 'cgroup').read_text(),
                'probe was not moved into job leaf')
        helper.stdin.write('go\n')
        helper.stdin.flush()
        stdout, stderr = helper.communicate(timeout=25)
        require(helper.returncode == 0 and not stderr and stdout,
                'bounded O_DIRECT probe failed: ' + stderr[-1000:])
        probe = json.loads(stdout)
        after = io_stat(leaf)
        delta = after.get('rbytes', 0) - before.get('rbytes', 0)
        require(probe['bytes_read'] == READ_BYTES and delta >= READ_BYTES,
                'io.stat did not account the direct reads')
        require(probe['elapsed_ms'] >= 5500,
                '8 MiB direct read completed too quickly for 1 MiB/s limit')
        require(request.poll() is None, 'IO probe terminated the VM job')
        first = complete_client(request, 50)
        require(first == {'status': 200, 'state': 'succeeded', 'protocol_ok': True},
                'original VM job failed after IO probe')
        wait_for(lambda: not job_dirs(root / 'run') and not job_dirs(cgroup_root),
                 5, 'original job left resources')
        followup = complete_client(netns_client(unit_pid(api_unit), root, True), 15)
        require(followup == first, 'follow-up VM job failed')
        wait_for(lambda: not job_dirs(root / 'run') and not job_dirs(cgroup_root),
                 5, 'follow-up job left resources')
        report = {'suite': 'io-read-limit-kvm/v1', 'package_version': '2026.10.29-rc11',
                  'job': workdir.name, 'vm_pid': int(vm_pid),
                  'io_max': limits, 'device': DEVICE, 'probe': probe,
                  'io_stat_before': before, 'io_stat_after': after,
                  'rbytes_delta': delta, 'first_job': first, 'followup_job': followup,
                  'remaining_workdirs': job_dirs(root / 'run'),
                  'remaining_cgroups': job_dirs(cgroup_root), 'passed': True}
        (root / 'results/io-read-limit.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps({'passed': True, 'elapsed_ms': probe['elapsed_ms'],
                          'rbytes_delta': delta}), flush=True)
    finally:
        if helper and helper.poll() is None:
            helper.kill()
            helper.communicate()
        if request.poll() is None:
            request.kill()
            request.communicate()
        probe_file.unlink(missing_ok=True)


if __name__ == '__main__':
    main()
