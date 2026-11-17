#!/usr/bin/env python3
"""Bounded serial-only OSv runtime diagnosis; not API or pool acceptance."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import grp
import re
import shutil
import subprocess
import time

from startup_benchmark import validation_lock


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--template', type=Path, required=True)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--verbose', action='store_true', help='enable OSv diagnostic console messages')
    args = parser.parse_args()
    if (os.geteuid() != 0 or args.root.parent != Path('/var/lib') or args.root.exists() or
            not re.fullmatch(r'osv-runtime-boot-probe-20261031-[0-9]+', args.root.name) or
            subprocess.check_output(['/sbin/ip', 'route', 'show']).strip()):
        raise SystemExit('requires root, fresh owned fixture and no outbound routes')
    for lookup in (pwd.getpwuid, grp.getgrgid):
        try:
            lookup(232020)
        except KeyError:
            pass
        else:
            raise SystemExit('probe identity is already assigned')
    with validation_lock(None):
        exercise(args)


def exercise(args):
    root = args.root
    root.mkdir(mode=0o755)
    (root / 'results').mkdir(mode=0o700)
    template = root / 'template'
    shutil.copytree(args.template, template)
    manifest = json.loads((template / 'artifacts/manifest.test.json').read_text())
    if sha(template / 'artifacts/manifest.test.json') != args.manifest_sha256:
        raise ValueError('probe manifest differs from expected digest')
    for item in ('kernel', 'image'):
        if sha(template / 'artifacts' / manifest[item]['path']) != manifest[item]['sha256']:
            raise ValueError('probe runtime file digest mismatch')
    commands = ['/python3.12.so -V',
                '/python3.12.so -c "import sys; print(sys.version, flush=True)"',
                '/python3.12.so -c "import numpy; print(numpy.__version__, flush=True)"',
                '/python3.12.so -c "import pandas; print(pandas.__version__, flush=True)"']
    results = []
    for number, command in enumerate(commands):
        ident = f'probe-{number}'
        jailroot = root / 'jailer/firecracker' / ident / 'root'
        jailroot.mkdir(parents=True)
        for field, name in [('kernel', 'kernel'), ('image', 'rootfs')]:
            target = jailroot / name
            os.link(template / 'artifacts' / manifest[field]['path'], target)
            target.chmod(0o444)
        config = {'boot-source': {'kernel_image_path': '/kernel',
            'boot_args': '--nopci --console=serial --rootfs=rofs ' + ('--verbose ' if args.verbose else '') + command},
            'drives': [{'drive_id': 'rootfs', 'path_on_host': '/rootfs', 'is_root_device': True, 'is_read_only': True}],
            'machine-config': {'vcpu_count': 1, 'mem_size_mib': 512, 'smt': False, 'track_dirty_pages': False}}
        (jailroot / 'config.json').write_text(json.dumps(config))
        (jailroot / 'config.json').chmod(0o444)
        executable = template / 'bin/firecracker'
        commandline = [str(template / 'bin/jailer'), '--id', ident, '--exec-file', str(executable),
            '--uid', '232020', '--gid', '232020', '--chroot-base-dir', str(root / 'jailer'),
            '--cgroup-version', '2', '--parent-cgroup', root.name,
            '--cgroup', 'memory.max=671088640', '--cgroup', 'memory.swap.max=0',
            '--cgroup', 'memory.oom.group=1', '--cgroup', 'cpu.max=100000 100000', '--cgroup', 'pids.max=64',
            '--resource-limit', 'no-file=1024', '--resource-limit', 'fsize=671088640',
            '--', '--no-api', '--config-file', '/config.json']
        with (root / 'results' / f'serial-{number}.log').open('wb') as log:
            process = subprocess.Popen(commandline, stdout=log, stderr=subprocess.STDOUT)
            timeout = False
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                timeout = True
                process.kill()
                process.wait(timeout=5)
        cgroup = Path('/sys/fs/cgroup') / root.name / ident
        deadline = time.monotonic() + 5
        while cgroup.exists() and (cgroup / 'cgroup.procs').read_text().strip() and time.monotonic() < deadline:
            time.sleep(.05)
        remaining = (cgroup / 'cgroup.procs').read_text().split() if cgroup.exists() else []
        if cgroup.exists() and not remaining:
            cgroup.rmdir()
        results.append({'command': command, 'exit_code': process.returncode, 'timeout': timeout,
                        'remaining_pids': remaining, 'serial_sha256': sha(root / 'results' / f'serial-{number}.log')})
        if remaining:
            raise RuntimeError('probe retained owned VM processes')
    parent = Path('/sys/fs/cgroup') / root.name
    if parent.exists():
        parent.rmdir()
    report = {'suite': 'osv-runtime-serial-diagnostic/v1', 'acceptance': False,
              'manifest_sha256': args.manifest_sha256, 'script_sha256': sha(Path(__file__)),
              'no_routes': True, 'verbose': args.verbose, 'cases': results, 'cgroup_removed': not parent.exists()}
    (root / 'results/report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report), flush=True)


if __name__ == '__main__':
    main()
