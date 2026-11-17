#!/usr/bin/env python3
"""Run the actual ARM kernels and owned-descendant prototype in no-NIC QEMU."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

from linux_code_runtime_closure import inventory, sha

ROOT = Path(__file__).resolve().parents[1]
INPUTS = ['linux-guest/code-kernels/python.py', 'linux-guest/code-kernels/node.cjs',
          'tests/reference-code-kernels.py', 'tests/qemu-code-kernel-init/main.go',
          'scripts/test-code-kernels-qemu.py']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--kernel', type=Path, default=ROOT / 'build/validation/qemu-arm64/Image')
    args = parser.parse_args()
    work = args.work.resolve()
    if not work.is_relative_to(ROOT / 'build/validation') or work.exists() or not args.kernel.is_file():
        parser.error('require a fresh project validation directory and ARM64 initrd kernel')
    asset = ROOT / 'assets/runtimes/linux-code/linux-arm64'
    seal = asset / 'runtime-inventory.json'
    expected = json.loads(seal.read_text())
    if inventory(asset / 'rootfs') != expected['files']:
        raise ValueError('runtime asset differs from its seal')
    rootfs = work / 'rootfs'
    shutil.copytree(asset / 'rootfs', rootfs, symlinks=True)
    (rootfs / 'validation/kernels').mkdir(parents=True)
    inputs = {}
    for name in INPUTS:
        target = work / 'inputs' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
        inputs[name] = sha(target)
    for name in ['python.py', 'node.cjs']:
        shutil.copyfile(work / 'inputs/linux-guest/code-kernels' / name, rootfs / 'validation/kernels' / name)
    shutil.copyfile(work / 'inputs/tests/reference-code-kernels.py', rootfs / 'validation/kernels-reference.py')
    env = dict(os.environ, GOCACHE='/tmp/osv-sandbox-go-cache', CGO_ENABLED='0', GOOS='linux', GOARCH='arm64')
    subprocess.run(['go', 'build', '-buildvcs=false', '-trimpath', '-o', str(rootfs / 'init'),
                    './tests/qemu-code-kernel-init'], cwd=ROOT, env=env, check=True)
    with (work / 'initrd.cpio').open('wb') as output:
        files = subprocess.Popen(['find', '.', '-print0'], cwd=rootfs, stdout=subprocess.PIPE)
        try:
            subprocess.run(['cpio', '--null', '--create', '--format=newc', '--quiet'], cwd=rootfs,
                           stdin=files.stdout, stdout=output, check=True)
        finally:
            files.stdout.close()
        if files.wait() != 0:
            raise ValueError('cpio input enumeration failed')
    binding = {'protocol': 'osv-code-kernel-qemu-prototype/v1', 'architecture': 'arm64',
               'runtime_inventory_sha256': sha(seal), 'inputs_sha256': inputs,
               'qemu_kernel_sha256': sha(args.kernel), 'init_binary_sha256': sha(rootfs / 'init'),
               'initrd_sha256': sha(work / 'initrd.cpio'), 'memory_mib': 1536, 'network': 'none'}
    (work / 'binding.json').write_text(json.dumps(binding, indent=2) + '\n')
    started = time.monotonic()
    with (work / 'qemu.log').open('w') as output:
        subprocess.run(['qemu-system-aarch64', '-machine', 'virt', '-cpu', 'cortex-a72', '-m', '1536M',
                        '-nic', 'none', '-nographic', '-no-reboot', '-kernel', str(args.kernel),
                        '-initrd', str(work / 'initrd.cpio'),
                        '-append', 'console=ttyAMA0 rdinit=/init panic=1'], cwd=ROOT,
                       stdout=output, stderr=subprocess.STDOUT, timeout=420, check=True)
    log = (work / 'qemu.log').read_text()
    markers = ['PASS namespace-stop-includes-setsid-descendant-keeps-other-workload',
               'PASS namespace-command-completion-reaps-detached-descendant',
               'PASS namespace-prototype-zero-owned-processes',
               'PASS code-kernel-python-', 'PASS code-kernel-javascript-', 'PASS code-kernel-typescript-',
               'CODE_KERNEL_REFERENCE_PASS', 'ARM64_CODE_KERNEL_PASS']
    if any(marker not in log for marker in markers) or 'ARM64_CODE_KERNEL_FAIL' in log:
        raise ValueError('ARM code kernel prototype failed; inspect ' + str(work / 'qemu.log'))
    if any(sha(ROOT / name) != digest for name, digest in inputs.items()):
        raise ValueError('prototype sources changed during QEMU execution')
    if inventory(asset / 'rootfs') != expected['files']:
        raise ValueError('QEMU validation changed the real runtime asset')
    binding.update(passed=True, duration_ms=round((time.monotonic() - started) * 1000, 3),
                   log_sha256=sha(work / 'qemu.log'), production_code_api_accepted=False,
                   real_kvm_accepted=False, minimal_64mib_accepted=False)
    (work / 'receipt.json').write_text(json.dumps(binding, indent=2) + '\n')
    for line in log.splitlines():
        if line.startswith(('PASS ', 'CODE_KERNEL_', 'ARM64_CODE_')):
            print(line)
    print('Prototype receipt: ' + str(work / 'receipt.json'))


if __name__ == '__main__':
    main()
