#!/usr/bin/env python3
"""Validate sealed runtime copies on x64 or inside ARM64 QEMU with no NIC."""
import argparse
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import time

from linux_code_runtime_closure import inventory, resolve, sha

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / 'assets/runtimes/linux-code'
IMAGE = 'osv-sandbox-code-runtime-builder:bookworm-20261104'


def run(arguments, **kwargs):
    return subprocess.run(list(map(str, arguments)), check=True, **kwargs)


def native_inside(root):
    for directory in ['dev', 'dev/shm', 'tmp', 'workspace']:
        (root / directory).mkdir(parents=True, exist_ok=True)
    (root / 'tmp').chmod(0o1777)
    (root / 'dev/shm').chmod(0o1777)
    os.chown(root / 'workspace', 10000, 10000)
    for name, minor in [('null', 3), ('urandom', 9)]:
        path = root / 'dev' / name
        os.mknod(path, stat.S_IFCHR | 0o666, os.makedev(1, minor))
        path.chmod(0o666)
    env = dict(PATH='/usr/bin:/bin', HOME='/workspace', LANG='C.UTF-8',
               PYTHONDONTWRITEBYTECODE='1', OPENBLAS_NUM_THREADS='1', OMP_NUM_THREADS='1')
    run(['/usr/sbin/chroot', '--userspec=10000:10000', root, '/opt/python/bin/python3.12',
         '-B', '/validation/runtime.py'], env=env, timeout=180)


def finish(work, architecture, kernel=None):
    request = json.loads((work / 'invocation.json').read_text())
    asset = ASSETS / ('linux-' + architecture)
    seal = asset / 'runtime-inventory.json'
    if (request['architecture'] != architecture or request['runtime_inventory_sha256'] != sha(seal)
            or request['runner_sha256'] != sha(Path(__file__))
            or request['validation_script_sha256'] != sha(ROOT / 'tests/reference-linux-code-runtime.py')):
        raise ValueError('validation inputs changed after preparing the fixture')
    document = json.loads(seal.read_text())
    log = work / 'validation.log'
    text = log.read_text()
    marker = 'LINUX_CODE_RUNTIME_REFERENCE_PASS' if architecture == 'amd64' else 'ARM64_CODE_RUNTIME_PASS'
    if marker not in text or 'RUNTIME_NODE_FACTS' not in text or 'Traceback (most recent call last)' in text:
        raise ValueError('runtime functional validation failed; inspect ' + str(log))
    if inventory(asset / 'rootfs') != document['files']:
        raise ValueError('validation unexpectedly changed the sealed runtime')
    receipt = {'protocol': 'osv-linux-code-runtime-functional/v1', 'architecture': architecture,
               'runtime_inventory_sha256': sha(seal), 'source_lock_sha256': sha(ASSETS / 'source-lock.json'),
               'validation_script_sha256': request['validation_script_sha256'],
               'runner_sha256': sha(Path(__file__)), 'log_sha256': sha(log),
               'elapsed_since_prepare_ms': round((time.time() - request['prepared_unix']) * 1000, 3),
               'network': 'none', 'guest_uid': 10000, 'passed': True, 'runtime_files': len(document['files']),
               'mode': 'qemu-system-tcg' if architecture == 'arm64' else 'native-container-chroot',
               'production_kvm_acceptance': False, 'minimal_64mib_acceptance': False}
    if architecture == 'arm64':
        if sha(kernel) != request['qemu_kernel_sha256']:
            raise ValueError('QEMU kernel changed after preparing the fixture')
        receipt['qemu_kernel_sha256'] = sha(kernel)
        receipt['qemu_memory_mib'] = 1536
    (work / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    for line in text.splitlines():
        if line.startswith(('PASS runtime-', 'RUNTIME_', 'LINUX_CODE_', 'ARM64_CODE_')):
            print(line)
    print('Functional runtime receipt: ' + str(work / 'receipt.json'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--architecture', choices=['amd64', 'arm64'])
    parser.add_argument('--work', type=Path)
    parser.add_argument('--kernel', type=Path, default=ROOT / 'build/validation/qemu-arm64/Image')
    parser.add_argument('--native-inside', type=Path)
    parser.add_argument('--prepare-only', action='store_true', help='prepare and print the privileged container/QEMU invocation')
    parser.add_argument('--finish', action='store_true', help='check the prepared invocation log and issue a receipt')
    args = parser.parse_args()
    if args.native_inside:
        native_inside(args.native_inside)
        return
    if not args.architecture or not args.work:
        parser.error('architecture and fresh work directory are required')
    work = args.work.resolve()
    if not work.is_relative_to(ROOT / 'build/validation'):
        parser.error('work must be a fresh project build/validation directory')
    if args.finish:
        finish(work, args.architecture, args.kernel)
        return
    if work.exists():
        parser.error('work must be a fresh project build/validation directory')
    asset = ASSETS / ('linux-' + args.architecture)
    seal = asset / 'runtime-inventory.json'
    document = json.loads(seal.read_text())
    if (document['files'] != inventory(asset / 'rootfs')
            or document['closure']['edges'] != resolve(asset / 'rootfs', args.architecture)['edges']):
        raise ValueError('sealed runtime verification failed before validation')
    root = work / 'rootfs'
    shutil.copytree(asset / 'rootfs', root, symlinks=True)
    (root / 'validation').mkdir()
    shutil.copyfile(ROOT / 'tests/reference-linux-code-runtime.py', root / 'validation/runtime.py')
    log = work / 'validation.log'
    if args.architecture == 'amd64':
        argv = ['docker', 'run', '--rm', '--network', 'none', '-v', str(ROOT) + ':/work',
                '-w', '/work', IMAGE, 'python3', 'scripts/test-linux-code-runtime.py',
                '--native-inside', '/work/' + str(root.relative_to(ROOT))]
    else:
        if not args.kernel.is_file():
            parser.error('ARM64 QEMU kernel with initrd support is required')
        env = dict(os.environ, GOCACHE='/tmp/osv-sandbox-go-cache', CGO_ENABLED='0',
                   GOOS='linux', GOARCH='arm64')
        run(['go', 'build', '-buildvcs=false', '-trimpath', '-o', root / 'init',
             './tests/qemu-code-runtime-init'], cwd=ROOT, env=env)
        with (work / 'initrd.cpio').open('wb') as output:
            listing = subprocess.Popen(['find', '.', '-print0'], cwd=root, stdout=subprocess.PIPE)
            try:
                run(['cpio', '--null', '--create', '--format=newc', '--quiet'], cwd=root,
                    stdin=listing.stdout, stdout=output)
            finally:
                listing.stdout.close()
            if listing.wait() != 0:
                raise ValueError('initrd file enumeration failed')
        argv = ['qemu-system-aarch64', '-machine', 'virt', '-cpu', 'cortex-a72', '-m', '1536M',
                '-nic', 'none', '-nographic', '-no-reboot', '-kernel', args.kernel,
                '-initrd', work / 'initrd.cpio',
                '-append', 'console=ttyAMA0 rdinit=/init panic=1']
    invocation = {'architecture': args.architecture, 'argv': list(map(str, argv)),
                  'runtime_inventory_sha256': sha(seal), 'prepared_unix': time.time(),
                  'runner_sha256': sha(Path(__file__)),
                  'validation_script_sha256': sha(ROOT / 'tests/reference-linux-code-runtime.py')}
    if args.architecture == 'arm64':
        invocation['qemu_kernel_sha256'] = sha(args.kernel)
    (work / 'invocation.json').write_text(json.dumps(invocation, indent=2) + '\n')
    if args.prepare_only:
        print(json.dumps(invocation, indent=2))
        return
    with log.open('w') as output:
        run(argv, cwd=ROOT, stdout=output, stderr=subprocess.STDOUT, timeout=300)
    finish(work, args.architecture, args.kernel)


if __name__ == '__main__':
    main()
