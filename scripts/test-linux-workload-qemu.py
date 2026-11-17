#!/usr/bin/env python3
"""Build/test the shared Rust workload supervisor under actual guest PID 1."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

from linux_code_runtime_closure import inventory, sha
from linux_code_vm_bootstrap import stage_arm_modules

ROOT = Path(__file__).resolve().parents[1]
INPUTS = ['linux-guest/src/main.rs', 'linux-guest/src/workload.rs', 'linux-guest/src/lib.rs', 'linux-guest/validation/workload_init.rs',
          'linux-guest/validation/kernel_init.rs', 'linux-guest/code-kernels/python.py', 'linux-guest/code-kernels/node.cjs',
          'linux-guest/validation/context_init.rs',
          'tests/test_code_kernel_interrupt.py', 'tests/test_code_kernel_idle.py', 'tests/reference-code-kernels.py',
          'linux-guest/Cargo.toml', 'linux-guest/Cargo.lock', 'scripts/test-linux-workload-qemu.py',
          'scripts/linux_code_vm_bootstrap.py']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--architecture', choices=['amd64', 'arm64'], default='arm64')
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--pipeline', action='store_true', help='run the actual agent command/stream supervisor as guest PID1')
    parser.add_argument('--fatal', action='store_true', help='verify the real fatal VM reset path after helper death')
    parser.add_argument('--kernels', action='store_true', help='run actual Python/JS/TS through the production helper')
    parser.add_argument('--contexts', action='store_true', help='test the permanent code worker through its actual command interface')
    parser.add_argument('--code-service', action='store_true', help='test actual code service/main session handlers with real interpreters and ext4')
    parser.add_argument('--ports', action='store_true', help='test actual PID1 port authorization and framed relay with real loopback TCP')
    parser.add_argument('--resume-preboot', action='store_true', help='reuse an exact code-service fixture whose mkfs failed before the first VM launch')
    parser.add_argument('--arm64-module-directory', type=Path, help='sealed matching modules/order.json for the modular ARM verification kernel')
    args = parser.parse_args()
    if sum([args.pipeline, args.fatal, args.kernels, args.contexts, args.code_service, args.ports]) > 1:
        parser.error('pipeline, fatal, kernels, contexts, code-service and ports modes are mutually exclusive')
    with_runtime = args.kernels or args.contexts or args.code_service
    if bool(args.arm64_module_directory) != bool(args.code_service and args.architecture == 'arm64'):
        parser.error('code-service on the modular ARM validation kernel requires --arm64-module-directory; other modes omit it')
    arch = args.architecture
    work = args.work.resolve()
    if not work.is_relative_to(ROOT / 'build/validation') or work.is_symlink() or (work.exists() and not args.resume_preboot):
        parser.error('work must be a fresh project validation directory')
    machine = 'aarch64' if arch == 'arm64' else 'x86_64'
    rust_target = machine + '-unknown-linux-musl'
    rootfs = work / 'rootfs'
    runtime = ROOT / 'assets/runtimes/linux-code' / ('linux-' + arch)
    reused_preboot = None
    if args.resume_preboot:
        if (not args.code_service or not (work / 'initrd.cpio').is_file()
                or (work / 'binding.json').exists() or (work / 'qemu.log').exists()
                or (work / 'preboot-r1').exists()
                or 'Invalid filesystem option set:' not in (work / 'mkfs.log').read_text()):
            parser.error('resume requires the exact unlaunched mkfs-failed code-service fixture')
        previous = {str(path.relative_to(work / 'inputs')): sha(path)
                    for path in (work / 'inputs').rglob('*') if path.is_file()}
        names = sorted(set(INPUTS + [str(path.relative_to(ROOT)) for path in (ROOT / 'linux-guest/src').rglob('*.rs')]))
        if set(previous) != set(names) or any(sha(ROOT / name) != digest for name, digest in previous.items()
                                            if name != 'scripts/test-linux-workload-qemu.py'):
            raise ValueError('compiled fixture inputs changed; rebuild in a fresh directory')
        shutil.copytree(work / 'inputs', work / 'preboot-r1/inputs')
        shutil.copyfile(work / 'mkfs.log', work / 'preboot-r1/mkfs.log')
        reused_preboot = {'previous_inputs_sha256': previous, 'never_booted': True,
                          'initrd_sha256': sha(work / 'initrd.cpio')}
    if with_runtime:
        expected = json.loads((runtime / 'runtime-inventory.json').read_text())
        if args.resume_preboot:
            copied = inventory(rootfs)
            if any(copied.get(name) != identity for name, identity in expected['files'].items()):
                raise ValueError('staged runtime differs from the full published closure seal')
        else:
            if inventory(runtime / 'rootfs') != expected['files']:
                raise ValueError('runtime asset differs from its seal')
            shutil.copytree(runtime / 'rootfs', rootfs, symlinks=True)
            (rootfs / 'validation/kernels').mkdir(parents=True)
            for name in ['python.py', 'node.cjs']:
                shutil.copyfile(ROOT / 'linux-guest/code-kernels' / name, rootfs / 'validation/kernels' / name)
            if args.code_service:
                (rootfs / 'opt/osv/code-kernels').mkdir(parents=True)
                for name in ['python.py', 'node.cjs']:
                    shutil.copyfile(ROOT / 'linux-guest/code-kernels' / name, rootfs / 'opt/osv/code-kernels' / name)
    for name in ['bin', 'sbin', 'dev', 'proc', 'run', 'tmp', 'workspace']:
        (rootfs / name).mkdir(parents=True, exist_ok=True)
    bound = {}
    names = sorted(set(INPUTS + [str(path.relative_to(ROOT)) for path in (ROOT / 'linux-guest/src').rglob('*.rs')]))
    for name in names:
        target = work / 'inputs' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
        bound[name] = sha(target)
    module_bootstrap = None
    if args.resume_preboot and (work / 'arm-module-bootstrap.json').exists():
        module_bootstrap = json.loads((work / 'arm-module-bootstrap.json').read_text())
    if not args.resume_preboot:
        subprocess.run(['cargo', 'build', '--manifest-path', 'linux-guest/Cargo.toml', '--locked', '--offline',
                        '--release', '--bin', 'agent-init', '--bin', 'osv-workload-supervisor',
                        '--target', rust_target], cwd=ROOT, check=True)
        target_dir = Path(os.environ.get('CARGO_TARGET_DIR', str(ROOT / 'linux-guest/target')))
        helper = target_dir / rust_target / 'release/agent-init'
        shutil.copyfile(helper, rootfs / 'sbin/agent-init')
        (rootfs / 'sbin/agent-init').chmod(0o755)
        supervisor = target_dir / rust_target / 'release/osv-workload-supervisor'
        shutil.copyfile(supervisor, rootfs / 'sbin/osv-workload-supervisor')
        (rootfs / 'sbin/osv-workload-supervisor').chmod(0o755)
        if args.pipeline or args.fatal or args.code_service or args.ports:
            compiled = subprocess.run(['cargo', 'test', '--manifest-path', 'linux-guest/Cargo.toml', '--locked', '--offline',
                                      '--release', '--no-run', '--bin', 'agent-init', '--target', rust_target,
                                      '--message-format=json'], cwd=ROOT, check=True, text=True, capture_output=True)
            binary = next(Path(value['executable']) for line in compiled.stdout.splitlines()
                          if (value := json.loads(line)).get('reason') == 'compiler-artifact'
                          and value.get('target',{}).get('name') == 'agent-init'
                          and value.get('executable') and value.get('profile',{}).get('test'))
        else:
            validator = ('context-validation-init' if args.contexts else
                         'kernel-validation-init' if args.kernels else 'workload-validation-init')
            subprocess.run(['cargo', 'build', '--manifest-path', 'linux-guest/Cargo.toml', '--locked', '--offline',
                            '--release', '--features', 'workload-validation', '--bin', validator,
                            '--target', rust_target], cwd=ROOT, check=True)
            binary = target_dir / rust_target / 'release' / validator
        shutil.copyfile(binary, rootfs / 'init')
        (rootfs / 'init').chmod(0o755)
        busybox = ROOT / 'assets/offline' / ('linux-' + arch) / 'guest/busybox'
        bash = ROOT / 'assets/bash/artifacts' / ('linux-' + arch) / 'bash'
        shutil.copyfile(busybox, rootfs / 'bin/busybox')
        shutil.copyfile(bash, rootfs / 'bin/bash')
        (rootfs / 'bin/busybox').chmod(0o755)
        (rootfs / 'bin/bash').chmod(0o755)
        for name in ['sh', 'sleep', 'cat', 'head', 'id', 'printf', 'echo', 'yes']:
            if (rootfs / 'bin' / name).exists() or (rootfs / 'bin' / name).is_symlink():
                (rootfs / 'bin' / name).unlink()
            (rootfs / 'bin' / name).symlink_to('busybox')
        if args.arm64_module_directory:
            module_bootstrap = stage_arm_modules(rootfs, args.arm64_module_directory)
            (work / 'arm-module-bootstrap.json').write_text(json.dumps(module_bootstrap, indent=2) + '\n')
        with (work / 'initrd.cpio').open('wb') as output:
            listing = subprocess.Popen(['find', '.', '-print0'], cwd=rootfs, stdout=subprocess.PIPE)
            try:
                subprocess.run(['cpio', '--null', '--create', '--format=newc', '--quiet'], cwd=rootfs,
                               stdin=listing.stdout, stdout=output, check=True)
            finally:
                listing.stdout.close()
            if listing.wait() != 0:
                raise ValueError('cpio enumeration failed')
    busybox = ROOT / 'assets/offline' / ('linux-' + arch) / 'guest/busybox'
    bash = ROOT / 'assets/bash/artifacts' / ('linux-' + arch) / 'bash'
    if arch == 'arm64':
        kernel = ROOT / 'build/validation/qemu-arm64/Image'
        argv = ['qemu-system-aarch64', '-machine', 'virt', '-cpu', 'cortex-a72', '-nographic']
        console = 'ttyAMA0'
    else:
        kernel = ROOT / 'assets/offline/linux-amd64/artifacts/kernel'
        qemu = shutil.which('qemu-system-x86_64') or shutil.which('qemu-kvm')
        if not qemu:
            raise ValueError('an existing x64 QEMU binary with TCG/microvm support is required')
        firmware = next((path for path in [Path('/usr/share/qemu/bios-256k.bin'), Path('/usr/share/seabios/bios-256k.bin')]
                         if path.is_file()), None)
        if firmware is None:
            raise ValueError('an existing PC BIOS is required for the no-NIC TCG validation fixture')
        # The pinned NumPy wheel contains unconditional SSE4.1 (e.g. pinsrq).
        # qemu64 intentionally hides it; use TCG's supported ISA for runtime tests.
        cpu = 'max' if with_runtime else 'qemu64'
        argv = [qemu, '-machine', 'pc', '-cpu', cpu, '-nodefaults', '-L', '/usr/share/qemu',
                '-display', 'none', '-serial', 'stdio']
        argv += ['-bios', str(firmware)]
        console = 'ttyS0'
    append = 'console=' + console + ' rdinit=/init panic=1'
    if args.pipeline or args.fatal or args.code_service or args.ports:
        case = ('port_vm_tests::actual_session_port_service_at_pid_one' if args.ports else
                'code_vm_tests::actual_session_code_service_at_pid_one' if args.code_service else
                'workload_vm_tests::actual_fatal_helper_resets_vm' if args.fatal else
                'workload_vm_tests::actual_command_pipeline_at_pid_one')
        append += ' -- --exact ' + case + ' --ignored --nocapture --test-threads=1'
    memory_mib = 1536 if with_runtime else 256
    argv += ['-accel', 'tcg', '-m', str(memory_mib) + 'M', '-nic', 'none', '-no-reboot', '-kernel', str(kernel),
             '-initrd', str(work / 'initrd.cpio'), '-append', append]
    filesystem = None
    if args.code_service:
        mkfs = Path(shutil.which('mke2fs') or '/nonexistent').resolve()
        if not mkfs.is_file():
            raise ValueError('an existing host mke2fs is required only for the ext4 verification fixture')
        workspace = work / 'workspace.ext4'
        with workspace.open('wb') as output:
            output.truncate(64 * 1024 * 1024)
        slot = work / 'boot-slot.raw'
        with slot.open('wb') as output:
            output.truncate(1024 * 1024)
        # The verification host's e2fsprogs 1.46 does not recognize orphan_file,
        # including the negative spelling; it cannot enable that feature.
        mkfs_argv = [str(mkfs), '-t', 'ext4', '-F', '-q', '-O', '^metadata_csum_seed',
                     '-E', 'lazy_itable_init=0,lazy_journal_init=0', str(workspace)]
        with (work / 'mkfs.log').open('w') as output:
            subprocess.run(mkfs_argv, stdout=output, stderr=subprocess.STDOUT, check=True)
        device = 'virtio-blk-device' if arch == 'arm64' else 'virtio-blk-pci'
        disks = [['-drive', f'file={slot},format=raw,if=none,id=boot-slot,readonly=on',
                  '-device', device + ',drive=boot-slot'],
                 ['-drive', f'file={workspace},format=raw,if=none,id=workspace',
                  '-device', device + ',drive=workspace']]
        # virt's DT enumerates the MMIO slots in reverse creation order.
        if arch == 'arm64':
            disks.reverse()
        for disk in disks:
            argv += disk
        filesystem = {'mkfs_sha256': sha(mkfs), 'argv': mkfs_argv,
                      'workspace_initial_sha256': sha(workspace), 'verification_only_host_tool': True}
    binding = {'protocol': 'osv-rust-workload-qemu/v1', 'architecture': arch, 'memory_mib': memory_mib,
               'network': 'none', 'inputs_sha256': bound, 'init_sha256': sha(rootfs / 'init'),
               'kernel_sha256': sha(kernel), 'busybox_sha256': sha(busybox), 'bash_sha256': sha(bash),
               'production_agent_sha256': sha(rootfs / 'sbin/agent-init'),
               'production_helper_sha256': sha(rootfs / 'sbin/osv-workload-supervisor'),
               'production_helper_path': '/sbin/osv-workload-supervisor',
               'actual_agent_pipeline': args.pipeline,
               'actual_port_service_main': args.ports,
               'actual_port_vsock_accepted': False,
               'actual_fatal_vm_reset': args.fatal,
               'actual_supervised_interpreters': args.kernels,
               'actual_code_worker': args.contexts,
               'actual_code_service_main': args.code_service,
               'arm_validation_module_bootstrap': module_bootstrap,
               'code_service_validation_transport': 'unix-socket' if args.code_service else None,
               'actual_code_vsock_accepted': False,
               'reused_unlaunched_preboot_fixture': reused_preboot,
               'actual_workspace_ext4': filesystem,
               'initrd_sha256': reused_preboot['initrd_sha256'] if reused_preboot else sha(work / 'initrd.cpio'),
               'argv': argv, 'mode': 'qemu-system-tcg'}
    if arch == 'amd64':
        binding['qemu_firmware_sha256'] = sha(firmware)
    if with_runtime:
        binding['runtime_inventory_sha256'] = sha(runtime / 'runtime-inventory.json')
    (work / 'binding.json').write_text(json.dumps(binding, indent=2) + '\n')
    started = time.monotonic()
    with (work / 'qemu.log').open('w') as output:
        subprocess.run(argv, cwd=ROOT, stdout=output, stderr=subprocess.STDOUT,
                       timeout=1000 if args.contexts or args.code_service else 420 if with_runtime else 90, check=True)
    log = (work / 'qemu.log').read_text()
    marker = ('RUST_PORT_SERVICE_PASS' if args.ports else
              'RUST_CODE_SERVICE_PASS' if args.code_service else
              'RUST_CODE_WORKER_PASS' if args.contexts else
              'RUST_SUPERVISED_KERNEL_PASS' if args.kernels else
              'RUST_AGENT_FATAL_SUPERVISION_RESET' if args.fatal else
              'RUST_AGENT_WORKLOAD_PIPELINE_PASS' if args.pipeline else 'RUST_WORKLOAD_SUPERVISION_PASS')
    if marker not in log or 'panicked at' in log or 'CODE_SERVICE_FAIL' in log:
        raise ValueError('actual Rust supervisor failed; inspect ' + str(work / 'qemu.log'))
    if args.fatal and ('RUST_AGENT_FATAL_HELPER_KILLED' not in log or 'reboot: Restarting system' not in log):
        raise ValueError('fatal verification requires the injected helper death and actual VM restart')
    if any(sha(ROOT / name) != digest for name, digest in bound.items()):
        raise ValueError('supervision sources changed during validation')
    if with_runtime and inventory(runtime / 'rootfs') != expected['files']:
        raise ValueError('validation changed the real runtime asset')
    if args.code_service:
        binding['workspace_final_sha256'] = sha(work / 'workspace.ext4')
    binding.update(passed=True, log_sha256=sha(work / 'qemu.log'),
                   duration_ms=round((time.monotonic() - started) * 1000, 3),
                   production_agent_uses_supervision=True, full_guest_protocol_accepted=False,
                   real_kvm_accepted=False, full_code_api_accepted=False)
    (work / 'receipt.json').write_text(json.dumps(binding, indent=2) + '\n')
    for line in log.splitlines():
        if line.startswith(('PASS workload-', 'PASS agent-pipeline-', 'PASS supervised-kernel-', 'PASS code-worker-',
                            'PASS code-service-', 'RUST_CODE_SERVICE_', 'PASS port-service-', 'RUST_PORT_SERVICE_',
                            'RUST_AGENT_', 'RUST_WORKLOAD_', 'RUST_SUPERVISED_', 'RUST_CODE_WORKER_')):
            print(line)
    print('Shared Rust workload evidence: ' + str(work / 'receipt.json'))


if __name__ == '__main__':
    main()
