#!/usr/bin/env python3
"""Actual ARM interpreters and thin SDKs under no-NIC TCG; no v7/OSv/KVM claim."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
from linux_code_runtime_closure import inventory, sha

ROOT=Path(__file__).resolve().parents[1]
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work',type=Path,required=True)
    args=parser.parse_args();work=args.work.resolve()
    assert work.is_relative_to(ROOT/'build/validation') and not work.exists()
    asset=ROOT/'assets/runtimes/linux-code/linux-arm64';seal=asset/'runtime-inventory.json'
    expected=json.loads(seal.read_text());assert inventory(asset/'rootfs')==expected['files']
    rootfs=work/'rootfs'
    # Host staging is read only for runtime files; cpio snapshots their bytes.
    # Hard links avoid a second 385 MiB expanded runtime on the host disk.
    shutil.copytree(asset/'rootfs',rootfs,symlinks=True,copy_function=os.link)
    validation=rootfs/'validation';validation.mkdir()
    sources=[*sorted((ROOT/'guest-sdk').rglob('*.py')),*sorted((ROOT/'guest-sdk').rglob('*.cjs'))]
    sources += [ROOT/name for name in ['tests/test_guest_inference.py','tests/test_guest_inference_node.cjs','tests/reference_guest_inference_arm.py','tests/fixtures/inference-sdk.json','tests/qemu-guest-inference-init/main.go','scripts/test-guest-inference-arm64-qemu.py','scripts/linux_code_runtime_closure.py']]
    inputs={str(path.relative_to(ROOT)):sha(path) for path in sources if '__pycache__' not in path.parts}
    for relative in inputs:
        target=validation/relative;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/relative,target)
    (rootfs/'bin').mkdir(exist_ok=True)
    shutil.copyfile(ROOT/'assets/offline/linux-arm64/guest/busybox',rootfs/'bin/busybox');(rootfs/'bin/busybox').chmod(0o755)
    env=dict(os.environ,GOCACHE='/tmp/osv-sandbox-go-cache',GOPROXY='off',CGO_ENABLED='0',GOOS='linux',GOARCH='arm64')
    subprocess.run(['go','build','-trimpath','-buildvcs=false','-o',str(rootfs/'init'),'./tests/qemu-guest-inference-init'],cwd=ROOT,env=env,check=True)
    with (work/'initrd.cpio').open('wb') as output:
        listing=subprocess.Popen(['find','.','-print0'],cwd=rootfs,stdout=subprocess.PIPE)
        try:subprocess.run(['cpio','--null','--create','--format=newc','--quiet'],cwd=rootfs,stdin=listing.stdout,stdout=output,check=True)
        finally:listing.stdout.close()
        assert listing.wait()==0
    kernel=ROOT/'build/validation/qemu-arm64/Image'
    binding={'protocol':'osv-guest-inference-arm-functions/v1','inputs_sha256':inputs,'runtime_inventory_sha256':sha(seal),
             'init_sha256':sha(rootfs/'init'),'initrd_sha256':sha(work/'initrd.cpio'),'kernel_sha256':sha(kernel),
             'busybox_sha256':sha(rootfs/'bin/busybox'),'memory_mib':1536,'nic':'none','architecture':'arm64',
             'scope':'Actual ARM CPython and Node SDK unit and fixed-loopback functions. Local model/accounting fixture; no host-vsock, signed-v7/offline installation, OSv, KVM, performance or 64 MiB acceptance.'}
    (work/'binding.json').write_text(json.dumps(binding,indent=2)+'\n')
    began=time.monotonic()
    with (work/'qemu.log').open('w') as output:
        subprocess.run(['qemu-system-aarch64','-machine','virt','-cpu','cortex-a72','-m','1536M','-nic','none','-nographic','-no-reboot','-kernel',str(kernel),'-initrd',str(work/'initrd.cpio'),'-append','console=ttyAMA0 rdinit=/init panic=1'],cwd=ROOT,stdout=output,stderr=subprocess.STDOUT,timeout=300,check=True)
    log=(work/'qemu.log').read_text()
    assert 'ARM64_GUEST_INFERENCE_PASS' in log and 'ARM64_GUEST_INFERENCE_FAIL' not in log
    assert 'Ran 9 tests' in log and '# pass 13' in log
    assert all('PASS ARM64-guest-SDK-'+runtime+'-fixed-loopback' in log for runtime in ['python','node'])
    assert all(sha(ROOT/relative)==digest for relative,digest in inputs.items())
    assert inventory(asset/'rootfs')==expected['files']
    binding.update(passed=True,duration_seconds=round(time.monotonic()-began,3),log_sha256=sha(work/'qemu.log'),python_tests=9,node_tests=13,actual_fixed_loopback_modes=['python','node'])
    (work/'receipt.json').write_text(json.dumps(binding,indent=2)+'\n');print(json.dumps(binding))

if __name__=='__main__':main()
