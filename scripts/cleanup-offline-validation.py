#!/usr/bin/env python3
"""Stop only the isolated offline validation units; preserve evidence files."""

import argparse
import os
from pathlib import Path
import shutil
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve()
    if os.geteuid() != 0 or not any(root.name.startswith(prefix) for prefix in
                                    ('osv-offline-validation-20261029-',
                                     'osv-offline-validation-20261030-')):
        raise SystemExit('refusing to clean a non-validation fixture')
    units = [root.name + suffix for suffix in ('-api.service','-launcher.service','-egress.service','-upstream.service')]
    active = [unit for unit in units
              if subprocess.run(['systemctl', 'is-active', '--quiet', unit]).returncode == 0]
    if active:
        subprocess.run(['systemctl', 'stop', *active], check=True)
    for unit in units:
        if subprocess.run(['systemctl', 'is-active', '--quiet', unit]).returncode == 0:
            raise SystemExit(f'validation unit remains active: {unit}')
    for unit in units:
        target = Path('/run/systemd/system') / unit
        if target.exists():
            target.unlink()
        dropin = Path('/run/systemd/system') / (unit + '.d') / 'offline.conf'
        if dropin.exists():
            dropin.unlink()
            dropin.parent.rmdir()
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    jobs = list((root / 'run').glob('job-*'))
    cgroups = list((Path('/sys/fs/cgroup') / root.name).glob('job-*'))
    if jobs or cgroups:
        raise SystemExit(f'validation resources remain: jobs={jobs}, cgroups={cgroups}')
    for directory in ('tls', 'secrets'):
        shutil.rmtree(root / directory, ignore_errors=True)
    (root / 'egress-state/provider-credential').unlink(missing_ok=True)
    for name in ('auth.json', 'launcher.env', 'config.production.json','egress.production.json','upstream-ready.json'):
        (root / name).unlink(missing_ok=True)
    print(f'cleaned units and test credentials for {root}; evidence retained')


if __name__ == '__main__':
    main()
