import os
from osv.modules import api, filemap, resolve

usr_files = filemap.FileMap()
usr_files.add(os.path.join(resolve.get_osv_base(), 'apps/input-mount-test/input-mount-test.so')).to('/input-mount-test.so')

default = api.run('/input-mount-test.so')
