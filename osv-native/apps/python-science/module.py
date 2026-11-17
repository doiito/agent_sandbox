import os
import re
from osv.modules import api, filemap, resolve

asset = os.environ.get('OSV_PYTHON_ASSET_RELATIVE','assets/osv-native/python-3.12-science/linux-amd64')
if not re.fullmatch(r'assets/osv-native/python-3\.12-science/(linux-amd64|candidates/[a-z0-9][a-z0-9-]{0,79})',asset):
    raise ValueError('invalid Python science asset path')
usr_files = filemap.FileMap()
usr_files.add(os.path.join(resolve.get_osv_base(),'..',asset,'rootfs')).to('/').allow_symlink()

api.require('job-agent')
default = api.run('/osv-job-agent.so')
