#!/usr/bin/env python3
"""Check production API configuration fail-closed behavior on a Linux host."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--fixture-dir', type=Path, required=True)
    parser.add_argument('--expected-binary-sha256', required=True)
    args = parser.parse_args()
    directory = args.fixture_dir
    binary = directory / 'osv-sandboxd-configtrust'
    unit = directory / 'osv-sandboxd-production.service'
    diagnostic = directory / 'osv-config-diagnostic.json'
    production = directory / 'osv-config-untrusted-production.json'
    if hashlib.sha256(binary.read_bytes()).hexdigest() != args.expected_binary_sha256:
        raise SystemExit('validation binary hash mismatch')
    if '-require-production' not in unit.read_text():
        raise SystemExit('production API unit lacks the mandatory CLI flag')
    result = {'binary_sha256': args.expected_binary_sha256, 'cases': []}

    def check(name, command, expected_status, marker=None):
        completed = subprocess.run(command, text=True, capture_output=True, timeout=15)
        passed = completed.returncode == expected_status and (marker is None or marker in completed.stderr)
        result['cases'].append({'name': name, 'passed': passed, 'exit_code': completed.returncode})
        if not passed:
            raise RuntimeError(f'{name} failed: status={completed.returncode}; stderr={completed.stderr[-800:]}')

    link = directory / 'osv-config-link-validation.json'
    if link.exists() or link.is_symlink():
        raise SystemExit('validation symlink already exists')
    try:
        check('require-production-rejects-diagnostic',
              [str(binary), '-require-production', '-config', str(diagnostic)],
              1, 'requires production=true')
        check('untrusted-production-config-rejected',
              [str(binary), '-config', str(production)],
              1, 'untrusted production configuration')
        os.symlink(production.name, link)
        check('symlink-config-rejected', [str(binary), '-config', str(link)],
              1, 'contains a symbolic link')
        check('production-unit-verifies', ['systemd-analyze', 'verify', str(unit)], 0)
        result['ok'] = True
    except Exception as error:
        result['ok'] = False
        result['error'] = str(error)
    finally:
        link.unlink(missing_ok=True)
        result['validation_symlink_absent'] = not link.exists() and not link.is_symlink()
        (directory / 'config-trust-result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    if not result['ok']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
