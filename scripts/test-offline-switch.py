#!/usr/bin/env python3
"""Exercise signed release switching only inside a stopped validation fixture."""

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser()
    for name in ('binary', 'previous', 'candidate', 'public-key', 'root', 'run-root', 'cgroup-root', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--previous-target', required=True)
    parser.add_argument('--candidate-target', required=True)
    args = parser.parse_args()
    root = args.root.resolve()
    run_root = args.run_root.resolve()
    if os.geteuid() != 0 or not root.name.startswith('osv-offline-validation-') or not root.is_dir():
        raise SystemExit('requires root and an existing isolated validation fixture')
    if run_root != root / 'run' or not run_root.is_dir():
        raise SystemExit('run_root is outside the validation fixture')
    expected_previous = args.previous_target
    expected_candidate = args.candidate_target
    for target in (expected_previous, expected_candidate):
        parts = target.split('/')
        if len(parts) != 2 or parts[0] != 'releases' or not parts[1].endswith('-linux-amd64') or '..' in target:
            raise SystemExit('expected targets must be installed amd64 release links')
    current = root / 'current'
    cases = []

    def command(package, allow=True, root_override=None):
        argv = [str(args.binary), 'switch', '-archive', str(package),
                '-public-key', str(args.public_key), '-root', str(root_override or root),
                '-run-root', str(run_root), '-cgroup-root', str(args.cgroup_root)]
        if allow:
            argv.append('-allow-test-candidate')
        return subprocess.run(argv, text=True, capture_output=True, timeout=30)

    def selected():
        return os.readlink(current)

    def record(name, condition):
        cases.append({'name': name, 'passed': bool(condition)})
        print(('PASS ' if condition else 'FAIL ') + name, flush=True)
        if not condition:
            raise AssertionError(name)

    try:
        baseline = selected()
        record('baseline-candidate-selected', baseline == expected_candidate)
        denied = command(args.candidate, allow=False)
        record('dirty-candidate-default-deny', denied.returncode != 0 and selected() == baseline)
        denied = command(args.candidate, root_override=root.parent / 'not-validation')
        record('dirty-candidate-outside-validation-deny', denied.returncode != 0 and
               'isolated validation root' in denied.stderr and selected() == baseline)

        extra = root / expected_candidate / 'extra-directory'
        extra.mkdir(mode=0o700)
        try:
            denied = command(args.candidate)
            record('extra-installed-directory-deny', denied.returncode != 0 and selected() == baseline)
        finally:
            extra.rmdir()

        with (run_root / '.launcher.lock').open('a+b') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            denied = command(args.previous)
            record('launcher-lock-deny', denied.returncode != 0 and selected() == baseline)

        remnant = run_root / 'job-switch-validation'
        remnant.mkdir(mode=0o700)
        try:
            denied = command(args.previous)
            record('run-residue-deny', denied.returncode != 0 and selected() == baseline)
        finally:
            remnant.rmdir()

        changed = command(args.previous)
        record('switch-to-previous', changed.returncode == 0 and
               'changed=true' in changed.stdout and selected() == expected_previous)
        changed = command(args.candidate)
        record('rollback-to-candidate', changed.returncode == 0 and
               'changed=true' in changed.stdout and selected() == expected_candidate)
        repeated = command(args.candidate)
        record('idempotent-switch', repeated.returncode == 0 and
               'changed=false' in repeated.stdout and selected() == expected_candidate)
        states = subprocess.run(['systemctl', 'show', '-p', 'ActiveState', '--value',
                                 'osv-sandboxd.service', 'osv-sandbox-launcher.service', 'osv-sandbox-egress.service'],
                                text=True, capture_output=True, timeout=10)
        record('production-services-stopped', states.returncode == 0 and
               states.stdout.split() == ['inactive', 'inactive', 'inactive'])
    finally:
        if current.is_symlink() and selected() != expected_candidate:
            command(args.candidate)

    report = {'suite': 'offline-switch/v1', 'passed': all(row['passed'] for row in cases),
              'cases': cases, 'current': selected(), 'binary_sha256': digest(args.binary),
              'previous_archive_sha256': digest(args.previous),
              'candidate_archive_sha256': digest(args.candidate)}
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'passed': report['passed'], 'cases': len(cases), 'current': report['current']}))


if __name__ == '__main__':
    main()
