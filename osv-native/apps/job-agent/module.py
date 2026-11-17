import os
from osv.modules import api, filemap, resolve

diagnostic = os.environ.get('OSV_JOB_AGENT_DIAGNOSTIC_IMAGE','1')
if diagnostic not in ('0','1'):
    raise ValueError('OSV_JOB_AGENT_DIAGNOSTIC_IMAGE must be 0 or 1')
usr_files = filemap.FileMap()
directory = os.path.join(resolve.get_osv_base(),'apps/job-agent')
usr_files.add(os.path.join(directory,'osv-job-agent.so')).to('/osv-job-agent.so')
if diagnostic == '1':
    usr_files.add(os.path.join(directory,'task-probe.so')).to('/task-probe.so')

default = api.run('/osv-job-agent.so')
