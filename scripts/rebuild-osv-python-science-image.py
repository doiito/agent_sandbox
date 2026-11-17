#!/usr/bin/env python3
"""Rebuild the OSv image using a verified, unchanged project-owned Python runtime."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

import guest_inference_image
import osv_input_profile
import python_science_closure
import python_science_sbom

ROOT=Path(__file__).resolve().parents[1]
ASSETS=ROOT/'assets/osv-native/python-3.12-science'


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    base=args.base.resolve();output=args.output.absolute()
    if (not base.is_relative_to(ASSETS) or output.parent != ASSETS/'candidates'
            or output.resolve() != output or output.exists() or not re.fullmatch('[a-z0-9][a-z0-9-]{0,79}',output.name)):
        parser.error('requires an existing project science base and a fresh candidate output directory')
    subprocess.run(['sha256sum','--quiet','-c','SHA256SUMS'],cwd=base,check=True)
    base_seal=osv_input_profile.sha(base/'SHA256SUMS')
    inventory=json.loads((base/'runtime-inventory.json').read_text())
    python_science_closure.verify(base/'rootfs',inventory)
    if (base/'guest-inference.json').exists():
        guest_inference_image.validate(base/'rootfs',json.loads((base/'guest-inference.json').read_text()),'firecracker-osv','amd64')
    builder=os.environ.get('OSV_PYTHON_BUILDER_IMAGE','osv-sandbox-python-science-builder:ubuntu22.04')
    builder_id=subprocess.check_output(['docker','image','inspect',builder,'--format','{{.Id}}'],text=True).strip()
    output.mkdir()
    subprocess.run(['cp','--archive','--reflink=auto',str(base/'rootfs'),str(output/'rootfs')],check=True)
    for name in ('runtime-inventory.json','cpython-install-inventory.json','pre-bytecode-inventory.json','guest-inference.json'):
        if (base/name).exists():shutil.copyfile(base/name,output/name)
    python_science_closure.verify(output/'rootfs',inventory)
    relative=str(output.relative_to(ROOT))
    with (output/'image-build.log').open('xb') as log:
        subprocess.run(['bash',ROOT/'scripts/build-osv-native-kernel.sh'],cwd=ROOT,check=True,stdout=log,stderr=subprocess.STDOUT)
        subprocess.run(['docker','run','--rm','--network','none','-e','OSV_PYTHON_ASSET_RELATIVE='+relative,
            '-e','OSV_JOB_AGENT_DIAGNOSTIC_IMAGE=0','-v',str(ROOT)+':/work','-w','/work/osv-upstream',builder,
            './scripts/build','-j4','fs=rofs','image=python-science','fs_size_mb=384',
            'conf_dot_file=/work/osv-native/conf/agent-sandbox.config',
            'bootfs_manifest=../osv-native/conf/agent-sandbox-bootfs.manifest'],cwd=ROOT,check=True,stdout=log,stderr=subprocess.STDOUT)
    release=ROOT/'osv-upstream/build/release.x64'
    subprocess.run(['qemu-img','convert','-f','qcow2','-O','raw',release/'usr.img',output/'rootfs.raw'],check=True)
    if (output/'rootfs.raw').stat().st_size != 402653184:
        raise ValueError('unexpected OSv science image size')
    (output/'modules').mkdir()
    for source,destination in [(release/'loader-stripped.elf','kernel.elf'),
            (ROOT/'osv-upstream/apps/job-agent/osv-job-agent.so','modules/osv-job-agent.so'),
            (output/'rootfs/python3.12.so','modules/python3.12.so')]:
        shutil.copyfile(source,output/destination)
    # This compares every runtime file against the disk and rejects unexpected
    # diagnostic modules or stale/partial image output, even if upstream build
    # reports success after a failed ROFS conversion.
    sbom=python_science_sbom.export(output/'rootfs',output/'runtime-inventory.json',output/'rootfs.raw')
    (output/'runtime-sbom-input.json').write_text(json.dumps(sbom,indent=2)+'\n')
    profile=osv_input_profile.create(output)
    (output/'readonly-input-profile.json').write_text(json.dumps(profile,indent=2)+'\n')
    files=['kernel.elf','rootfs.raw','runtime-inventory.json','runtime-sbom-input.json','cpython-install-inventory.json',
           'pre-bytecode-inventory.json','modules/osv-job-agent.so','modules/python3.12.so','readonly-input-profile.json']
    if (output/'guest-inference.json').exists():files.append('guest-inference.json')
    sources=['scripts/rebuild-osv-python-science-image.py','scripts/build-osv-native-kernel.sh','scripts/apply-osv-native.py',
             'scripts/python_science_sbom.py','scripts/rofs_inventory.py','scripts/osv_input_profile.py']
    sources += [str(p.relative_to(ROOT)) for p in (ROOT/'osv-native').rglob('*') if p.is_file()]
    record={'protocol':'osv-python-science-image/v1','builder_image_id':builder_id,
            'osv_upstream_commit':'0e34e4dc2b278b7f64e4169abbf297b7de46fb6b',
            'runtime_reused_from':{'path':str(base.relative_to(ROOT)),'sha256sums_sha256':base_seal,
                'image_build_provenance_sha256':osv_input_profile.sha(base/'image-build-provenance.json')},
            'inputs_sha256':{name:osv_input_profile.sha(ROOT/name) for name in sorted(sources)},
            'files_sha256':{name:osv_input_profile.sha(output/name) for name in files},
            'runtime_build_provenance_sha256':osv_input_profile.sha(output/'rootfs/build-provenance.json'),
            'performance_acceptance':False,'real_KVM_acceptance':False,'minimal_64MiB_acceptance':False}
    if 'guest-inference.json' in files:record['guest_inference_sha256']=osv_input_profile.sha(output/'guest-inference.json')
    (output/'image-build-provenance.json').write_text(json.dumps(record,indent=2)+'\n')
    files += ['image-build-provenance.json','image-build.log']
    (output/'SHA256SUMS').write_text(''.join(osv_input_profile.sha(output/name)+'  '+name+'\n' for name in files))
    subprocess.run(['sha256sum','--quiet','-c','SHA256SUMS'],cwd=output,check=True)
    if osv_input_profile.sha(base/'SHA256SUMS') != base_seal:
        raise ValueError('base runtime seal changed')
    subprocess.run(['sha256sum','--quiet','-c','SHA256SUMS'],cwd=base,check=True)
    print(json.dumps({'built':True,'output':relative,'runtime_reused':True,'readonly_inputs':True,
                      'guest_inference':(output/'guest-inference.json').exists(),'production_validated':False}),flush=True)


if __name__=='__main__':main()
