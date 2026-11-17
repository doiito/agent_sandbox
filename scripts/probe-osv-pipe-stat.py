#!/usr/bin/env python3
"""Bounded native pipe ABI probe; separate from signed agent/product acceptance."""
import argparse
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import subprocess
import time

from startup_benchmark import validation_lock

CHECKS = set('''pipe both-ends-fstat fifo-metadata shared-identity dup-identity pipe-roundtrip
read-only-end write-only-end nonseekable nonterminal distinct-identity creation-time-write
creation-time-read eof closed-fd invalid-fd stdin-io stdin-stat stdout-io stdout-stat
stderr-io stderr-stat concurrent-io concurrent-stat nonblocking-empty zero-byte-io
broken-pipe repeated-distinct-pipes no-fd-leak reject-invalid-flags invalid-flags-no-leak invalid-isatty'''.split())
LEGACY_ERRORS = set('''both-ends-fstat fifo-metadata shared-identity dup-identity distinct-identity
creation-time-write creation-time-read stdin-stat stdout-stat stderr-stat concurrent-stat
repeated-distinct-pipes nonterminal invalid-isatty'''.split())
FILES = {'artifacts/kernel.elf', 'artifacts/rootfs.raw', 'artifacts/pipe-stat-probe.so',
         'bin/firecracker', 'bin/jailer'}


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def classify(serial, phase):
    rows = re.findall(r'^PIPE_STAT_CHECK name=([a-z-]+) passed=([01])\r?$', serial, re.MULTILINE)
    endings = re.findall(r'^PIPE_STAT_PROBE_END checks=(\d+) failed=(\d+)\r?$', serial, re.MULTILINE)
    checks = {name: value == '1' for name, value in rows}
    complete = (len(rows) == len(checks) == len(CHECKS) and set(checks) == CHECKS and
                len(endings) == 1 and int(endings[0][0]) == len(CHECKS) and
                int(endings[0][1]) == sum(not value for value in checks.values()))
    legacy_fds = re.findall(r'^PIPE_STAT_FD name=(read-end|write-end) fd=\d+ result=-1 errno=9 flags=(\d+)\r?$',
                            serial, re.MULTILINE)
    reproduced = (complete and set(name for name, _ in legacy_fds) == {'read-end', 'write-end'} and
                  all(value == (name not in LEGACY_ERRORS) for name, value in checks.items()))
    passed = complete and all(checks.values())
    return {'complete': complete, 'checks': checks, 'legacy_ebadf_reproduced': reproduced,
            'functional_probe_passed': passed, 'expected_observation': reproduced if phase == 'baseline' else passed}


def stopped_after_probe(serial, exit_code):
    endings = list(re.finditer(r'^PIPE_STAT_PROBE_END checks=\d+ failed=\d+\r?$', serial, re.MULTILINE))
    if not endings or any(word in serial.lower() for word in
                          ('assertion failed', 'general protection fault', 'fatal page fault', 'aborted.')):
        return False
    tail = serial[endings[-1].end():]
    # The pinned x64 poweroff deliberately resets/triple-faults when ACPI is
    # absent. Firecracker's no-API runner reports Shutdown(GenericError), code 1.
    return exit_code == 0 or (exit_code == 1 and
            'Unexpected exit reason on vcpu run: Shutdown' in tail and 'Shutdown(GenericError)' in tail)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--template', type=Path, required=True)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--descriptor-sha256', required=True)
    parser.add_argument('--phase', choices=('baseline', 'fixed'), required=True)
    args = parser.parse_args()
    if (os.geteuid() != 0 or args.root.parent != Path('/var/lib') or args.root.exists() or
            not re.fullmatch(r'osv-pipe-stat-validation-20261101-[a-z0-9]+', args.root.name) or
            subprocess.check_output(['/sbin/ip', 'route', 'show']).strip()):
        raise SystemExit('requires root, fresh owned probe fixture and no outbound routes')
    for lookup in (pwd.getpwuid, grp.getgrgid):
        try:
            lookup(232030)
        except KeyError:
            continue
        raise SystemExit('probe identity is already assigned')
    with validation_lock(None):
        exercise(args)


def exercise(args):
    descriptor = args.template / 'diagnostic.json'
    if sha(descriptor) != args.descriptor_sha256:
        raise ValueError('probe descriptor differs from pinned digest')
    inputs = json.loads(descriptor.read_text())
    if inputs.get('protocol') != 'osv-pipe-stat-diagnostic/v1' or set(inputs['files_sha256']) != FILES:
        raise ValueError('unexpected probe input inventory')
    for name, digest in inputs['files_sha256'].items():
        path = args.template / name
        if path.is_symlink() or sha(path) != digest:
            raise ValueError('probe input file digest mismatch: ' + name)
    root = args.root
    root.mkdir(mode=0o755)
    (root/'results').mkdir(mode=0o700)
    template = root/'template'
    template.mkdir()
    for name in sorted(FILES):
        destination = template/name
        destination.parent.mkdir(exist_ok=True)
        shutil.copyfile(args.template/name, destination)
        destination.chmod(0o755 if name.startswith('bin/') else 0o644)
    for name, digest in inputs['files_sha256'].items():
        if sha(template/name) != digest:
            raise ValueError('copied probe input differs')
    ident = 'pipe-stat'
    jailroot = root/'jailer/firecracker'/ident/'root'
    jailroot.mkdir(parents=True)
    for source, name in [('kernel.elf', 'kernel'), ('rootfs.raw', 'rootfs')]:
        os.link(template/'artifacts'/source, jailroot/name)
        (jailroot/name).chmod(0o444)
    config = {'boot-source': {'kernel_image_path': '/kernel',
              'boot_args': '--nopci --console=serial --rootfs=rofs /pipe-stat-probe.so'},
              'drives': [{'drive_id': 'rootfs', 'path_on_host': '/rootfs', 'is_root_device': True, 'is_read_only': True}],
              'machine-config': {'vcpu_count': 1, 'mem_size_mib': 128, 'smt': False, 'track_dirty_pages': False}}
    (jailroot/'config.json').write_text(json.dumps(config))
    (jailroot/'config.json').chmod(0o444)
    command = [str(template/'bin/jailer'), '--id', ident, '--exec-file', str(template/'bin/firecracker'),
               '--uid', '232030', '--gid', '232030', '--chroot-base-dir', str(root/'jailer'),
               '--cgroup-version', '2', '--parent-cgroup', root.name,
               '--cgroup', 'memory.max=268435456', '--cgroup', 'memory.swap.max=0',
               '--cgroup', 'memory.oom.group=1', '--cgroup', 'cpu.max=100000 100000', '--cgroup', 'pids.max=64',
               '--resource-limit', 'no-file=1024', '--resource-limit', 'fsize=268435456',
               '--', '--no-api', '--config-file', '/config.json']
    parent = Path('/sys/fs/cgroup')/root.name
    leaf = parent/ident
    serial = root/'results/serial.log'
    process = None
    report = {'suite': 'osv-pipe-stat-native-diagnostic/v1', 'phase': args.phase,
              'acceptance': False, 'production_validated': False, 'performance_gate_evidence': False,
              'no_routes': True, 'descriptor_sha256': args.descriptor_sha256,
              'script_sha256': sha(Path(__file__)), 'expected_observation': False, 'timeout': False}
    try:
        with serial.open('wb') as output:
            process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT)
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                report['timeout'] = True
                process.kill()
                process.wait(timeout=5)
        report['exit_code'] = process.returncode
        output = serial.read_text(errors='replace')
        report.update(classify(output, args.phase))
        report['stopped_after_probe'] = stopped_after_probe(output, process.returncode)
        report['serial_sha256'] = sha(serial)
        if report['timeout'] or not report['stopped_after_probe']:
            report['expected_observation'] = False
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        deadline = time.monotonic() + 5
        while leaf.exists() and (leaf/'cgroup.procs').read_text().strip() and time.monotonic() < deadline:
            time.sleep(.02)
        remaining = (leaf/'cgroup.procs').read_text().split() if leaf.exists() else []
        report['remaining_pids'] = remaining
        if leaf.exists() and not remaining:
            leaf.rmdir()
        if parent.exists() and not list(parent.iterdir()):
            parent.rmdir()
        elif parent.exists() and not leaf.exists() and not (parent/'cgroup.procs').read_text().strip():
            parent.rmdir()
        report['cgroup_removed'] = not parent.exists()
        if remaining or not report['cgroup_removed']:
            report['expected_observation'] = False
        (root/'results/report.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report), flush=True)
    if not report['expected_observation']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
