#!/usr/bin/env python3
"""Run the readonly mount component on the actual release kernel under jailed KVM."""
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

spec = importlib.util.spec_from_file_location('readonly_qemu', Path(__file__).with_name('test-osv-readonly-inputs-qemu.py'))
wire = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wire)
FILES = {'kernel.elf', 'rootfs.raw', 'input-mount-test.so', 'bin/firecracker', 'bin/jailer'}


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def save(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--descriptor-sha256', required=True)
    args = parser.parse_args()
    if (os.geteuid() != 0 or args.root.parent != Path('/var/lib') or args.root.exists()
            or not re.fullmatch(r'osv-readonly-inputs-validation-20261114-r[1-9][0-9]*', args.root.name)
            or subprocess.check_output(['/sbin/ip','route','show']).strip()):
        parser.error('requires root, a fresh private fixture and no outbound routes')
    for lookup in (pwd.getpwuid, grp.getgrgid):
        try:
            lookup(232050)
        except KeyError:
            continue
        raise ValueError('diagnostic identity is already allocated')
    descriptor = args.input/'diagnostic.json'
    if sha(descriptor) != args.descriptor_sha256:
        raise ValueError('diagnostic descriptor changed')
    metadata = json.loads(descriptor.read_text())
    if metadata.get('protocol') != 'osv-readonly-inputs-kvm-component/v1' or set(metadata['files_sha256']) != FILES:
        raise ValueError('unexpected diagnostic inventory')
    if any((args.input/name).is_symlink() or sha(args.input/name) != digest for name,digest in metadata['files_sha256'].items()):
        raise ValueError('diagnostic input changed')
    args.root.mkdir(mode=0o755)
    results = args.root/'results'
    results.mkdir(mode=0o700)
    parent = Path('/sys/fs/cgroup')/args.root.name
    report = {'suite':'osv-readonly-inputs-native-kvm/v1','passed':False,'cases':[],
              'production_validated':False,'performance_gate_evidence':False,'component_only':True,
              'backend':'firecracker-osv','nic_count':0,'no_outbound_routes':True,
              'descriptor_sha256':args.descriptor_sha256,'runner_sha256':sha(Path(__file__)),
              'files_sha256':metadata['files_sha256']}
    try:
        for mode in ('maximum','empty'):
            jail = args.root/'jailer/firecracker'/mode/'root'
            jail.mkdir(parents=True)
            os.chown(jail,232050,232050)
            for source,target in [('kernel.elf','kernel'),('rootfs.raw','rootfs')]:
                shutil.copyfile(args.input/source,jail/target)
                (jail/target).chmod(0o444)
            config = {'boot-source':{'kernel_image_path':'/kernel','boot_args':
                      '--nopci --console=serial --rootfs=rofs /input-mount-test.so'+(' empty' if mode == 'empty' else '')},
                      'drives':[{'drive_id':'rootfs','path_on_host':'/rootfs','is_root_device':True,'is_read_only':True}],
                      'machine-config':{'vcpu_count':1,'mem_size_mib':256,'smt':False,'track_dirty_pages':False}}
            (jail/'config.json').write_text(json.dumps(config))
            (jail/'config.json').chmod(0o444)
            command = [str(args.input/'bin/jailer'),'--id',mode,'--exec-file',str(args.input/'bin/firecracker'),
                       '--uid','232050','--gid','232050','--chroot-base-dir',str(args.root/'jailer'),
                       '--cgroup-version','2','--parent-cgroup',args.root.name,
                       '--cgroup','memory.max=402653184','--cgroup','memory.swap.max=0','--cgroup','memory.oom.group=1',
                       '--cgroup','cpu.max=100000 100000','--cgroup','pids.max=64',
                       '--resource-limit','no-file=1024','--resource-limit','fsize=268435456',
                       '--','--no-api','--config-file','/config.json']
            row = {'mode':mode,'command':command,'passed':False,'timeout':False}
            report['cases'].append(row)
            log = results/(mode+'.log')
            began = time.monotonic()
            process = None
            try:
                with log.open('xb') as output:
                    process = subprocess.Popen(command,stdout=output,stderr=subprocess.STDOUT,start_new_session=True)
                    try:
                        process.wait(timeout=20)
                    except subprocess.TimeoutExpired:
                        row['timeout'] = True
                        process.kill()
                        process.wait(timeout=5)
            finally:
                if process is not None and process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)
                leaf = parent/mode
                if leaf.exists():
                    if (leaf/'cgroup.procs').read_text().strip():
                        (leaf/'cgroup.kill').write_text('1')
                    deadline = time.monotonic()+5
                    while (leaf/'cgroup.procs').read_text().strip() and time.monotonic() < deadline:
                        time.sleep(.02)
                    row['remaining_pids'] = (leaf/'cgroup.procs').read_text().split()
                    if not row['remaining_pids']:
                        leaf.rmdir()
                else:
                    row['remaining_pids'] = []
            serial = log.read_text(errors='replace')
            row.update(exit_code=process.returncode,wall_ms=round((time.monotonic()-began)*1000,3),serial_sha256=sha(log))
            matches = re.findall(r'^INPUT_MOUNT_CHECK name=([a-z-]+) passed=([01]) errno=(\d+)\r?$',serial,re.M)
            row['checks'] = {name:value == '1' for name,value,_ in matches}
            row['errors'] = {name:int(error) for name,value,error in matches if value != '1'}
            expected = wire.COMMON | (wire.MAXIMUM if mode == 'maximum' else {'mount-empty'})
            endings = re.findall(r'^INPUT_MOUNT_END mode=([a-z]+) checks=(\d+) failed=(\d+)\r?$',serial,re.M)
            # With no ACPI, pinned x64 OSv powers off by triple fault. Retain
            # that specific VMM shutdown after the complete marker; no panic.
            tail = serial[serial.rfind('INPUT_MOUNT_END'):]
            shutdown = row['exit_code'] == 0 or (row['exit_code'] == 1 and
                       'Unexpected exit reason on vcpu run: Shutdown' in tail and 'Shutdown(GenericError)' in tail)
            row['passed'] = (not row['timeout'] and shutdown and not row['remaining_pids']
                             and len(matches) == len(expected) and set(row['checks']) == expected
                             and all(row['checks'].values()) and endings == [(mode,str(len(expected)),'0')]
                             and not any(text in serial.lower() for text in ('assertion failed','fatal page fault','aborted.')))
            save(results/(mode+'.json'),row)
            if not row['passed']:
                raise RuntimeError(mode+' readonly mount failed; retain original serial and invocation')
        if any(sha(args.input/name) != digest for name,digest in metadata['files_sha256'].items()):
            raise ValueError('diagnostic input changed during execution')
        report['passed'] = True
    finally:
        if parent.exists() and not list(parent.iterdir()):
            parent.rmdir()
        elif parent.exists() and not list(parent.glob('maximum')) and not list(parent.glob('empty')) and not (parent/'cgroup.procs').read_text().strip():
            parent.rmdir()
        report['cgroup_removed'] = not parent.exists()
        if not report['cgroup_removed']:
            report['passed'] = False
        save(results/'receipt.json',report)
        print(json.dumps({'passed':report['passed'],'cases':len(report['cases']),'cgroup_removed':report['cgroup_removed']}),flush=True)
    if not report['passed']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
