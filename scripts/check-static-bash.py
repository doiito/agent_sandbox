#!/usr/bin/env python3
"""Check the actual static Bash build selected for an offline guest."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[1]
def sha(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()
def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--architecture',choices=('amd64','arm64'),required=True)
    parser.add_argument('--artifacts',type=Path)
    args=parser.parse_args()
    directory=args.artifacts or ROOT/'assets/bash/artifacts'/('linux-'+args.architecture)
    report=json.loads((directory/'build-provenance.json').read_text())
    lock=json.loads((ROOT/'assets/bash/source-lock.json').read_text())
    arch={'amd64':'x86_64','arm64':'aarch64'}[args.architecture]
    assert report['protocol']=='osv-static-bash/v1' and report['architecture']==arch and report['version']==lock['version']=='5.3'
    assert report['binary_sha256']==sha(directory/'bash')
    assert report['source_lock_sha256']==sha(ROOT/'assets/bash/source-lock.json')
    assert lock['sha256']==sha(ROOT/'assets/bash/source/bash-5.3.tar.gz')
    assert report['compiler_script_sha256']==sha(ROOT/'scripts/bash-musl-cc.sh')
    assert report['build_script_sha256']==sha(ROOT/'scripts/build-static-bash.sh')
    for name,expected in report['link_input_sha256'].items():
        assert Path(name).name==name and sha(ROOT/'assets/bash/toolchain'/arch/'lib'/name)==expected
    headers=subprocess.check_output(['readelf','-h',str(directory/'bash')],text=True)
    assert ('AArch64' if args.architecture=='arm64' else 'Advanced Micro Devices X86-64') in headers
    assert 'INTERP' not in subprocess.check_output(['readelf','-l',str(directory/'bash')],text=True)
    assert 'NEEDED' not in subprocess.check_output(['readelf','-d',str(directory/'bash')],text=True)
    print(json.dumps({'passed':True,'architecture':args.architecture,'sha256':report['binary_sha256']}))
if __name__=='__main__':main()
