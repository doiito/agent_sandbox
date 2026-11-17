"""Bind opt-in readonly-input signing to the actual new kernel, agent and ROFS."""
import hashlib
import re
import subprocess

import rofs_inventory

PROTOCOL = 'osv-readonly-input-profile/v1'
LIMITS = {'files':64,'data_bytes':524288,'path_bytes':32768,'path':1024,'segment':255,'depth':16}
FILES = {'kernel':'kernel.elf','image':'rootfs.raw','agent':'modules/osv-job-agent.so'}


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream,'sha256').hexdigest()


def create(asset):
    value = {'protocol':PROTOCOL,'preparation':'OSP2/revision-2/OSJ1','mountpoint':'/input',
             'limits':dict(LIMITS),'files_sha256':{name:sha(asset/path) for name,path in FILES.items()}}
    verify(asset,value)
    return value


def verify(asset,value):
    if (not isinstance(value,dict) or set(value) != {'protocol','preparation','mountpoint','limits','files_sha256'}
            or value['protocol'] != PROTOCOL or value['preparation'] != 'OSP2/revision-2/OSJ1'
            or value['mountpoint'] != '/input' or value['limits'] != LIMITS
            or not isinstance(value['files_sha256'],dict) or set(value['files_sha256']) != set(FILES)):
        raise ValueError('unsupported readonly input profile')
    if any(not isinstance(digest,str) or not re.fullmatch('[0-9a-f]{64}',digest)
           or sha(asset/FILES[name]) != digest for name,digest in value['files_sha256'].items()):
        raise ValueError('readonly input profile does not bind actual artifacts')
    kernel = subprocess.check_output(['readelf','--dyn-syms','--wide',asset/FILES['kernel']],text=True)
    if not re.search(r' FUNC\s+GLOBAL DEFAULT\s+\d+ osv_sandbox_mount_inputs_v1$',kernel,re.M):
        raise ValueError('readonly input kernel ABI is missing')
    agent = subprocess.check_output(['readelf','--dyn-syms','--wide',asset/FILES['agent']],text=True)
    if ' UND osv_sandbox_mount_inputs_v1' not in agent or b'--pristine-inputs-v1\x00' not in (asset/FILES['agent']).read_bytes():
        raise ValueError('agent does not use the readonly input protocol and kernel ABI')
    image = rofs_inventory.inspect(asset/FILES['image'],include_directories=True)
    anchors = [row for row in image['directories'] if row['path'] == '/input']
    if len(anchors) != 1 or anchors[0]['children'] != 0:
        raise ValueError('readonly inputs require an empty in-image directory mountpoint')
    return value
