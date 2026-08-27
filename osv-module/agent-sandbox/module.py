import os
from osv.modules.api import run
from osv.modules.filemap import FileMap

binary = os.environ.get('OSV_AGENT_BINARY')
if not binary:
    raise Exception('OSV_AGENT_BINARY must point to an OSv-compatible agent executable')

usr_files = FileMap()
usr_files.add(binary).to('/agent')
default = run('/agent')
