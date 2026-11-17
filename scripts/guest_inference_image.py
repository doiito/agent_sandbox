"""Fixed guest SDK files and their signed, project-owned image contract."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

ROOT=Path(__file__).resolve().parents[1]
META='/opt/osv/guest-inference.json'
PROTOCOL='osv-sandbox-guest-inference/v1'

def sha(path):
    digest=hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(1048576),b''):digest.update(block)
    return digest.hexdigest()

def sources(backend):
    if backend not in {'firecracker-linux','firecracker-osv'}:raise ValueError('unsupported SDK backend')
    prefix='/opt/python/lib/python3.12/site-packages/'
    files={prefix+'remote_infer/'+name:'guest-sdk/python/remote_infer/'+name for name in ['__init__.py','_contract.py','_transport.py']}
    files[prefix+'sandbox.py']='guest-sdk/python/sandbox.py'
    if backend=='firecracker-linux':
        files.update({'/opt/osv/'+name:'guest-sdk/node/'+name for name in ['remote-infer.cjs','inference-contract.cjs']})
    return files

def input_names(backend):
    return sorted(set(sources(backend).values())|{'scripts/guest_inference_image.py','scripts/build-guest-inference-sdk.py',
                    'sdk/python/osv_sandbox_client.py','sdk/node/index.js'}|
                  ({'osv-native/include/osv/vsock.h'} if backend=='firecracker-osv' else set()))

def profile_for(backend,architecture):
    if architecture not in {'amd64','arm64'} or backend=='firecracker-osv' and architecture!='amd64':raise ValueError('unsupported SDK architecture')
    return {'protocol':PROTOCOL,'architecture':architecture,
            'transport':'linux-loopback-v1' if backend=='firecracker-linux' else 'osv-vsock-cabi-v1',
            'files_sha256':{path:sha(ROOT/source) for path,source in sources(backend).items()}}

def checked_path(root,name):
    path=root/name.lstrip('/')
    if path.is_symlink() or any(parent.is_symlink() for parent in path.parents if parent!=root and parent.is_relative_to(root)):
        raise ValueError('SDK destination traverses a symlink: '+name)
    return path

def make_parents(root,path):
    created=[];parent=path.parent
    while parent!=root and not parent.exists():
        created.append(parent);parent=parent.parent
    path.parent.mkdir(parents=True,exist_ok=True)
    for directory in created:directory.chmod(0o755)

def install(root,backend,architecture):
    root=Path(root).resolve(strict=True)
    if not root.is_relative_to(ROOT):raise ValueError('SDK install root must remain inside the project')
    subprocess.run(['python3',str(ROOT/'scripts/build-guest-inference-sdk.py'),'--check'],check=True)
    profile=profile_for(backend,architecture)
    for name,relative in sources(backend).items():
        path=checked_path(root,name)
        if path.exists():raise ValueError('SDK path already exists: '+name)
        make_parents(root,path)
        shutil.copyfile(ROOT/relative,path);path.chmod(0o644)
    meta=checked_path(root,META)
    if meta.exists():raise ValueError('SDK metadata already exists')
    make_parents(root,meta);meta.write_text(json.dumps(profile,indent=2)+'\n');meta.chmod(0o644)
    validate(root,profile,backend,architecture)
    return profile

def validate(root,profile,backend,architecture):
    root=Path(root).resolve(strict=True)
    if profile!=profile_for(backend,architecture):raise ValueError('SDK profile differs from current project contract')
    for name,digest in profile['files_sha256'].items():
        path=checked_path(root,name)
        if not path.is_file() or path.stat().st_mode&0o777!=0o644 or sha(path)!=digest:raise ValueError('SDK file differs from signed contract: '+name)
    meta=checked_path(root,META)
    if not meta.is_file() or json.loads(meta.read_text())!=profile:raise ValueError('embedded SDK metadata mismatch')

def validate_inventory(files,profile,backend,architecture):
    if profile!=profile_for(backend,architecture):raise ValueError('SDK inventory profile differs from project sources')
    for name,digest in profile['files_sha256'].items():
        entry=files.get(name,{})
        if entry.get('kind')!='file' or entry.get('sha256')!=digest or entry.get('mode')!=0o644:raise ValueError('sealed image does not contain canonical SDK file: '+name)
