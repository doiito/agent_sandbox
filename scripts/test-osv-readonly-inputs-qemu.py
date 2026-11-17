#!/usr/bin/env python3
"""Probe actual OSv readonly RAMFS under no-NIC QEMU/TCG; not a release gate."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
COMMON = set('''reject-traversal-before-mount reject-duplicate-before-mount reject-count-before-mount
reject-null-before-mount deny-create deny-mkdir deny-symlink deny-root-chmod root-mode
no-created-file deny-replacement-mount'''.split())
MAXIMUM = set('''exact-data-budget mount-max-files-and-bytes all-files-own-data-after-source-free
deny-write-open deny-readwrite-open deny-truncate-open deny-truncate deny-unlink deny-rename
deny-cross-mount-rename deny-chmod deny-chown deny-lchown readonly-descriptor-open deny-fchown deny-ftruncate deny-utimes deny-link deny-cross-mount-link
existing-file-still-intact'''.split())


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', required=True, type=Path)
    parser.add_argument('--qemu', type=Path, default=Path('/usr/libexec/qemu-kvm'))
    args = parser.parse_args()
    work = args.work.absolute()
    if (not work.is_relative_to(ROOT/'build/validation') or work.exists() or work.is_symlink()
            or work.resolve() != work):
        parser.error('work must be a fresh project validation directory')
    release = ROOT/'osv-upstream/build/release.x64'
    work.mkdir(parents=True)
    for name in ('loader-stripped.elf', 'usr.img'):
        shutil.copyfile(release/name, work/name)
    subprocess.run(['qemu-img', 'convert', '-f', 'qcow2', '-O', 'raw',
                    str(work/'usr.img'), str(work/'rootfs.raw')], check=True)
    if (work/'rootfs.raw').stat().st_size != 64*1024*1024:
        raise ValueError('unexpected diagnostic image size')
    report = {'suite': 'osv-readonly-inputs-qemu/v1', 'passed': False,
              'production_validated': False, 'performance_gate_evidence': False,
              'nic_count': 0, 'accelerator': 'tcg', 'architecture': 'x86_64', 'cases': [],
              'files_sha256': {name: sha(work/name) for name in ('loader-stripped.elf','usr.img','rootfs.raw')},
              'probe_source_sha256': sha(ROOT/'osv-native/apps/input-mount-test/main.c'),
              'runner_sha256': sha(Path(__file__)), 'qemu_sha256': sha(args.qemu),
              'qemu_version': subprocess.check_output([str(args.qemu),'--version'], text=True).splitlines()[0]}
    try:
        for mode in ('maximum', 'empty'):
            command = [str(args.qemu), '-machine',
                       'microvm,x-option-roms=off,pit=off,pic=off,rtc=off,auto-kernel-cmdline=on,acpi=off',
                       '-accel','tcg','-cpu','max','-smp','1','-m','256',
                       '-nodefaults','-no-user-config','-nographic','-serial','stdio','-monitor','none',
                       '-no-reboot','-nic','none','-global','virtio-mmio.force-legacy=off',
                       '-kernel',str(work/'loader-stripped.elf'), '-append',
                       '--nopci --console=serial --rootfs=rofs /input-mount-test.so'+(' empty' if mode == 'empty' else ''),
                       '-drive',f'file={work/"rootfs.raw"},if=none,id=root,format=raw,readonly=on',
                       '-device','virtio-blk-device,drive=root']
            row = {'mode': mode, 'command': command, 'passed': False, 'timeout': False}
            report['cases'].append(row)
            started = time.monotonic()
            log = work/(mode+'.log')
            with log.open('wb') as output:
                process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT)
                try:
                    process.wait(timeout=60)
                except subprocess.TimeoutExpired:
                    row['timeout'] = True
                    process.kill()
                    process.wait(timeout=5)
            row.update(exit_code=process.returncode, wall_ms=round((time.monotonic()-started)*1000,3), serial_sha256=sha(log))
            serial = log.read_text(errors='replace')
            matches = re.findall(r'^INPUT_MOUNT_CHECK name=([a-z-]+) passed=([01]) errno=(\d+)\r?$', serial, re.M)
            row['checks'] = {name: value == '1' for name, value, _ in matches}
            row['errors'] = {name: int(error) for name, value, error in matches if value != '1'}
            expected = COMMON | (MAXIMUM if mode == 'maximum' else {'mount-empty'})
            endings = re.findall(r'^INPUT_MOUNT_END mode=([a-z]+) checks=(\d+) failed=(\d+)\r?$',serial,re.M)
            row['passed'] = (not row['timeout'] and row['exit_code'] == 0 and len(matches) == len(expected)
                             and set(row['checks']) == expected and all(row['checks'].values())
                             and endings == [(mode,str(len(expected)),'0')])
            if not row['passed']:
                raise RuntimeError(f'{mode} actual readonly mount failed; see {log}')
        if any(sha(work/name) != digest for name,digest in report['files_sha256'].items()):
            raise ValueError('QEMU changed sealed diagnostic inputs')
        report['passed'] = True
    finally:
        (work/'receipt.json').write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps({'passed':report['passed'], 'cases':len(report['cases']), 'work':str(work)}),flush=True)


if __name__ == '__main__':
    main()
