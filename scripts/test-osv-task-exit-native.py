#!/usr/bin/env python3
"""Targeted true-KVM exit/return/ACK tests on a pinned single-use agent image."""
import argparse
import grp
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import subprocess
import time

from startup_benchmark import validation_lock

spec = importlib.util.spec_from_file_location('exit_wire_fixture', Path(__file__).with_name('e2e-osv-job-agent.py'))
wire = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wire)
FILES = {'loader-stripped.elf', 'osv-native-agent.raw', 'osv-job-agent.so', 'task-probe.so',
         'bin/firecracker', 'bin/jailer'}


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--descriptor-sha256', required=True)
    parser.add_argument('--protocol-regression', action='store_true')
    args = parser.parse_args()
    if (os.geteuid() != 0 or args.root.parent != Path('/var/lib') or args.root.exists() or
            not re.fullmatch(r'osv-task-exit-validation-20261102-[a-z0-9]+', args.root.name) or
            subprocess.check_output(['/sbin/ip', 'route', 'show']).strip()):
        raise SystemExit('requires root, fresh owned fixture and no outbound routes')
    for lookup in (pwd.getpwuid, grp.getgrgid):
        try:
            lookup(232040)
        except KeyError:
            continue
        raise SystemExit('validation identity already assigned')
    descriptor = args.input/'diagnostic.json'
    if sha(descriptor) != args.descriptor_sha256:
        raise ValueError('exit probe descriptor changed')
    inputs = json.loads(descriptor.read_text())
    if inputs.get('protocol') != 'osv-task-exit-diagnostic/v1' or set(inputs['files_sha256']) != FILES:
        raise ValueError('exit probe file inventory mismatch')
    for name, digest in inputs['files_sha256'].items():
        path = args.input/name
        if path.is_symlink() or sha(path) != digest:
            raise ValueError('exit probe input differs from descriptor')
    with validation_lock(None):
        exercise(args, inputs)


def exercise(args, inputs):
    root = args.root
    root.mkdir(mode=0o755)
    (root/'results').mkdir(mode=0o700)
    local = root/'input'
    local.mkdir()
    for name, digest in inputs['files_sha256'].items():
        path = local/name
        path.parent.mkdir(exist_ok=True)
        shutil.copyfile(args.input/name, path)
        path.chmod(0o755 if name.startswith('bin/') else 0o444)
        if sha(path) != digest:
            raise ValueError('copied exit probe input changed')
    report = {'suite': 'osv-task-exit-native-kvm/v1', 'production_validated': False,
              'performance_gate_evidence': False, 'descriptor_sha256': args.descriptor_sha256,
              'no_routes': True, 'cases': [], 'passed': False}
    cases = [
        ('native-success', 0, {}), ('native-task', 7, {}),
        ('native-explicit-exit', 23, {'stdout_marker': b'OSV_NATIVE_EXPLICIT_EXIT'}),
        ('native-immediate-exit', 29, {'stderr_marker': b'OSV_NATIVE_IMMEDIATE_EXIT',
                                      'forbidden_stdout': b'OSV_MUST_NOT_FLUSH'}),
        ('native-thread-exit', 19, {'stdout_marker': b'OSV_NATIVE_THREAD_EXIT'}),
        ('native-exit-binding-locked', 0, {'stdout_marker': b'OSV_NATIVE_EXIT_BINDING_LOCKED'}),
        *[('native-exit-race', (0, 19), {}) for _ in range(4)],
        ('native-explicit-exit', 23, {'ack_mode': 'omit', 'stdout_marker': b'OSV_NATIVE_EXPLICIT_EXIT'}),
        ('native-explicit-exit', 23, {'ack_mode': 'disconnect', 'stdout_marker': b'OSV_NATIVE_EXPLICIT_EXIT'}),
    ]
    if args.protocol_regression:
        cases = [(name, expected, {'invalid_kind': invalid}) for name, expected, invalid in wire.protocol_cases()] + cases
    report['protocol_regression_included'] = args.protocol_regression
    parent = Path('/sys/fs/cgroup')/root.name
    try:
        for number, (argument, expected, options) in enumerate(cases):
            started = time.monotonic()
            row = wire.run_case(local, number, argument, expected, root=root, uid=232040,
                                binaries=local/'bin', timeout_ms=500, socket_timeout=5,
                                stop_timeout=5, **options)
            row['wall_ms'] = round((time.monotonic()-started)*1000, 3)
            leaf = parent/f'osv-job-{number}'
            deadline = time.monotonic()+5
            while leaf.exists() and (leaf/'cgroup.procs').read_text().strip() and time.monotonic() < deadline:
                time.sleep(.02)
            row['remaining_pids'] = (leaf/'cgroup.procs').read_text().split() if leaf.exists() else []
            if leaf.exists() and not row['remaining_pids']:
                leaf.rmdir()
            if row['remaining_pids'] or row['wall_ms'] > 5000:
                row['ok'] = False
            report['cases'].append(row)
            if not row['ok']:
                raise RuntimeError(f'exit probe case {number} failed: '+row.get('error', 'cleanup or bound'))
        report['passed'] = True
    finally:
        if parent.exists() and not list(parent.glob('osv-job-*')) and not (parent/'cgroup.procs').read_text().strip():
            parent.rmdir()
        report['cgroup_removed'] = not parent.exists()
        if not report['cgroup_removed']:
            report['passed'] = False
        (root/'results/report.json').write_text(json.dumps(report, indent=2)+'\n')
        print(json.dumps({'passed': report['passed'], 'cases': len(report['cases']),
                          'cgroup_removed': report['cgroup_removed']}), flush=True)
    if not report['passed']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
