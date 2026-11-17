#!/usr/bin/env python3
"""Stage the locked x64 OSv science template alongside a Linux service release."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import guest_inference_image as inference_sdk
import osv_input_profile
from reproducible_license_archive import write_license_archive

ROOT=Path(__file__).resolve().parents[1]

def sha(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage',type=Path,required=True)
    parser.add_argument('--assets',type=Path,required=True)
    parser.add_argument('--private-key',type=Path,required=True)
    parser.add_argument('--inference',action='store_true',help='sign the actual embedded Python SDK with v7')
    args=parser.parse_args();stage=args.stage.resolve();asset=args.assets.resolve()
    if not asset.is_relative_to(ROOT/'assets/osv-native/python-3.12-science'):
        raise ValueError('OSv dependencies must be inside the project science asset directory')
    subprocess.run(['sha256sum','--quiet','-c','SHA256SUMS'],cwd=asset,check=True)
    if (asset/'guest-inference.json').exists()!=args.inference:raise ValueError('explicit inference signing must match the actual OSv image SDK')
    if args.inference:
        inference_sdk.validate(asset/'rootfs',json.loads((asset/'guest-inference.json').read_text()),'firecracker-osv','amd64')
    input_flags=[]
    if (asset/'readonly-input-profile.json').exists():
        osv_input_profile.verify(asset,json.loads((asset/'readonly-input-profile.json').read_text()))
        input_flags=['-agent-feature','input-files-v1']
    template=stage/'templates/python-science';artifacts=template/'artifacts';docs=template/'docs'
    artifacts.mkdir(parents=True,exist_ok=False);docs.mkdir()
    for source,name in [(asset/'kernel.elf','kernel.elf'),(asset/'rootfs.raw','rootfs.raw'),
                        (asset/'modules/osv-job-agent.so','osv-job-agent.so'),(asset/'modules/python3.12.so','python3.12.so'),
                        (asset/'runtime-inventory.json','runtime-inventory.json'),(asset/'runtime-sbom-input.json','runtime-sbom-input.json')]:
        subprocess.run(['cp','--sparse=always',str(source),str(artifacts/name)],check=True)
    shutil.copyfile(asset/'image-build-provenance.json',docs/'image-build-provenance.json')
    if input_flags:shutil.copyfile(asset/'readonly-input-profile.json',docs/'readonly-input-profile.json')
    shutil.copyfile(asset/'rootfs/runtime-components.json',docs/'runtime-components.json')
    if args.inference:shutil.copyfile(asset/'guest-inference.json',docs/'guest-inference.json')
    shutil.copyfile(ROOT/'osv-upstream/LICENSE',docs/'kernel-LICENSE.txt')
    provenance=json.loads((docs/'runtime-components.json').read_text())
    inventory={row['path']:row for row in json.loads((artifacts/'runtime-inventory.json').read_text())['files']}
    licenses=sorted({path for component in provenance['components'] for path in component.get('licenses',[])})
    entries=[]
    for name in licenses:
        assert name.startswith('/') and '..' not in Path(name).parts
        source=asset/'rootfs'/name.lstrip('/')
        assert source.is_file() and not source.is_symlink()
        assert sha(source)==inventory[name]['sha256'],name
        entries.append((source,name.lstrip('/')))
    write_license_archive(docs/'runtime-licenses.tar.gz',entries)
    def run(*command):subprocess.run(command,cwd=ROOT,check=True)
    run('go','run','./cmd/osv-sbom','-profile','osv','-osv-upstream-commit','0e34e4dc2b278b7f64e4169abbf297b7de46fb6b',
        '-runtime-components',str(artifacts/'runtime-sbom-input.json'),'-runtime-inventory',str(artifacts/'runtime-inventory.json'),
        '-kernel',str(artifacts/'kernel.elf'),'-rootfs',str(artifacts/'rootfs.raw'),'-agent',str(artifacts/'osv-job-agent.so'),
        '-module','/python3.12.so='+str(artifacts/'python3.12.so'),'-api',str(stage/'bin/osv-sandboxd'),'-launcher',str(stage/'bin/osv-sandbox-launcher'),
        '-firecracker',str(stage/'bin/firecracker'),'-jailer',str(stage/'bin/jailer'),'-output',str(artifacts/'sbom.cdx.json'))
    inference_flags=['-agent-feature','remote-infer-v1','-agent-feature','vsock-proxy-v1','-guest-inference',str(docs/'guest-inference.json')] if args.inference else []
    run('go','run','./cmd/osv-artifact-manifest',*inference_flags,*input_flags,'-backend','firecracker-osv','-osv-upstream-commit','0e34e4dc2b278b7f64e4169abbf297b7de46fb6b',
        '-osv-rofs-cache','disabled','-entrypoint','/python3.12.so','-agent-feature','environment','-agent-feature','pristine-v1','-agent-feature','stdin',
        '-artifact-root',str(artifacts),'-kernel','kernel.elf','-image','rootfs.raw','-firecracker',str(stage/'bin/firecracker'),'-jailer',str(stage/'bin/jailer'),
        '-sbom','sbom.cdx.json','-private-key',str(args.private_key),'-output',str(artifacts/'manifest.json'),'-valid-for','720h')
    config=json.loads((ROOT/'examples/config.production.json').read_text())
    value={'id':'python-science','backend':'firecracker-osv','artifact_root':'/opt/osv-sandbox/current/templates/python-science/artifacts',
           'kernel':{'path':'kernel.elf','sha256':sha(artifacts/'kernel.elf')},'image':{'path':'rootfs.raw','sha256':sha(artifacts/'rootfs.raw'),'format':'raw'},
           'artifact_manifest':{'path':'manifest.json','signature_path':'manifest.json.sig','public_key_path':config['artifact_manifest']['public_key_path'],'sbom_path':'sbom.cdx.json'},
           'allowed_entrypoints':['/python3.12.so'],'defaults':{'memory_mib':512,'vcpus':1,'timeout_ms':30000}}
    (template/'template.json').write_text(json.dumps(value,indent=2)+'\n')
    print('Staged project-owned signed OSv science template and '+str(len(licenses))+' runtime license files',flush=True)

if __name__=='__main__':main()
