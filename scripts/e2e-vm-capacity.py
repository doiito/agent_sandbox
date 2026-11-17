#!/usr/bin/env python3
"""Real KVM cross-tenant job/session admission against one physical memory budget."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import osv_sandbox_client as sdk


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--package', type=Path, required=True)
    parser.add_argument('--in-netns', action='store_true')
    args = parser.parse_args()
    root = args.root.resolve()
    require(root.name.startswith('osv-offline-validation-20261030-'), 'requires isolated fixture')
    if not args.in_netns:
        pid = subprocess.check_output(['systemctl', 'show', '-p', 'MainPID', '--value', root.name + '-api.service'], text=True).strip()
        require(pid.isdigit() and int(pid) > 1, 'fixture API inactive')
        subprocess.run(['nsenter', '-t', pid, '-n', sys.executable, __file__, '--root', str(root),
                        '--package', str(args.package), '--in-netns'], check=True)
        return
    release, = [p for p in (root / 'releases').iterdir() if p.is_dir()]
    require(Path(sdk.__file__).resolve() == (release / 'sdk/python/osv_sandbox_client.py').resolve(), 'SDK not from installed package')
    config = json.loads((root / 'config.production.json').read_text())
    require(config['limits']['max_concurrent'] == 2 and config['jailer']['identity_pool_size'] == 2 and
            config['vm_capacity']['max_instances'] == 2 and
            config['vm_capacity']['reserved_memory_mib'] == 256 and
            config['jailer']['memory_overhead_mib'] == 128, 'wrong capacity fixture')
    options = dict(ca_file=str(root / 'tls/ca.crt'), cert_file=str(root / 'tls/client.crt'),
                   key_file=str(root / 'tls/client.key'), request_timeout_seconds=65)
    url = 'https://localhost:' + config['listen'].rsplit(':', 1)[1]
    a = sdk.Client(url, token=(root / 'secrets/token').read_text(), **options)
    b = sdk.Client(url, token=(root / 'secrets/token-b').read_text(), **options)
    def assert_empty():
        value = a.doctor()['vm_capacity']
        require(value['active'] == value['instances'] == value['reserved_memory_mib'] ==
                value['reserved_vcpus'] == value['reserved_pids'] == 0 and
                value['available_identities'] == 2 and value['blocked'] is False, 'capacity did not return to zero')
        require(not list((root / 'run').glob('job-*')) and
                not list((Path('/sys/fs/cgroup') / root.name).glob('job-*')), 'VM resources remain')
    assert_empty()
    session = a.create_session(sdk.SessionRequest(memory_mib=128, vcpus=1, ttl_ms=30000))
    first_id = session.id
    try:
        held = a.doctor()['vm_capacity']
        require(held['active'] == held['instances'] == 1 and held['reserved_memory_mib'] == 256 and
                held['reserved_vcpus'] == 1 and held['reserved_pids'] == 64 and
                held['available_identities'] == 1, 'guest plus VMM reservation is incorrect')
        before = sorted(p.name for p in (root / 'run').glob('job-*'))
        for action in ('session', 'job'):
            try:
                if action == 'session':
                    unexpected = b.create_session(sdk.SessionRequest(memory_mib=128, vcpus=1, ttl_ms=30000))
                    unexpected.close()
                else:
                    b.run(sdk.JobRequest('/bin/sh', args=('-c', 'printf should-not-run'), memory_mib=128, vcpus=1))
            except sdk.APIError as error:
                require(error.status == 429 and error.code == 'busy', 'wrong physical capacity rejection')
            else:
                raise RuntimeError('physical budget admitted a second VM')
            require(a.doctor()['vm_capacity'] == held and
                    sorted(p.name for p in (root / 'run').glob('job-*')) == before, 'rejection changed capacity or booted VM')
        result = session.run(sdk.SessionCommand('/bin/sh', ('-c', 'printf capacity-live')))
        require(result.succeeded and result.guest_result['stdout'] == 'capacity-live', 'held session was affected by denied tenant')
    finally:
        session.close()
    assert_empty()
    following = b.create_session(sdk.SessionRequest(memory_mib=128, vcpus=1, ttl_ms=30000))
    try:
        require(following.id != first_id, 'session ID reused')
        require(following.run(sdk.SessionCommand('/bin/sh', ('-c', 'printf capacity-recovered'))).succeeded, 'capacity not usable after cleanup')
    finally:
        following.close()
    assert_empty()
    report = {'suite': 'vm-capacity-kvm/v1', 'package_sha256': hashlib.sha256(args.package.read_bytes()).hexdigest(),
              'memory_budget_mib': 256, 'charged_guest_mib': 128, 'charged_vmm_overhead_mib': 128,
              'active_limit': 2, 'instance_limit': 2, 'cross_tenant_session_status': 429,
              'cross_tenant_job_status': 429, 'existing_guest_unaffected': True,
              'capacity_recovered': True, 'final': a.doctor()['vm_capacity'], 'passed': True}
    (root / 'results/vm-capacity.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'passed': True, 'physical_memory_budget_mib': 256, 'session_status': 429, 'job_status': 429}))


if __name__ == '__main__':
    main()
