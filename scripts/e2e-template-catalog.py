#!/usr/bin/env python3
"""Same-package production API/launcher with real Linux and OSv KVM VMs."""
import argparse
import base64
import concurrent.futures
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import time


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--package',type=Path,required=True)
    parser.add_argument('--expected-mode',choices=['cold','warm'],required=True)
    parser.add_argument('--in-netns',action='store_true')
    parser.add_argument('--expect-oci-import', action='store_true')
    args=parser.parse_args();root=args.root
    if not args.in_netns:
        pid=subprocess.check_output(['systemctl','show','-p','MainPID','--value',root.name+'-api.service'],text=True).strip();assert int(pid)>1
        raise SystemExit(subprocess.run(['nsenter','-t',pid,'-n',sys.executable,__file__,'--root',str(root),'--package',str(args.package),'--expected-mode',args.expected_mode,'--in-netns']+(['--expect-oci-import'] if args.expect_oci_import else [])).returncode)
    release=next((root/'releases').iterdir());sys.path.insert(0,str(release/'sdk/python'))
    import osv_sandbox_client as sdk
    config=json.loads((root/'config.production.json').read_text());run_root=Path(config['run_root'])
    endpoint='https://localhost:'+config['listen'].rsplit(':',1)[1]
    def client(name):return sdk.Client(endpoint,token=(root/'secrets'/name).read_text(),ca_file=str(root/'tls/ca.crt'),cert_file=str(root/'tls/client.crt'),key_file=str(root/'tls/client.key'),request_timeout_seconds=65)
    a,b=client('token'),client('token-b')
    report={'suite':'multi-template-production-real-KVM/v1','passed':False,'mode':args.expected_mode,'default_backend':config['backend'],'cases':[],
            'package_sha256':hashlib.file_digest(args.package.open('rb'),'sha256').hexdigest(),'production_validated':False,'performance_gate_evidence':False}
    sessions=[];mcp=None
    imported_profiles = {}
    image_cache = {}
    def check(name,condition):
        assert condition,name
        report['cases'].append(name);print('PASS',name,flush=True)
    def wait(predicate,message,seconds=15):
        deadline=time.monotonic()+seconds
        while not predicate():
            assert time.monotonic()<deadline,message
            time.sleep(.025)
    def ready(backend):
        if args.expected_mode=='warm':wait(lambda:any(row.get('backend')==backend and row['ready']>=1 for row in a.doctor()['warm_pool']['profiles']),'selected template did not refill')
    def stdout(value):return value.guest_result.get('stdout','').strip()
    def binding(value,selected):return value.artifact_manifest_sha256==selected.artifact_manifest_sha256 and value.backend==selected.backend
    def py(code,*,owner=a,timeout=10000,stdin=None,environment=None):
        ready('firecracker-osv')
        # The public argv contract rejects control characters. Preserve the
        # exact Python source through a printable string literal for exec().
        wire_code='exec('+json.dumps(code)+')' if '\n' in code or '\r' in code else code
        assert len(wire_code.encode())<=4096 and not any(ord(ch)<32 or ord(ch)==127 for ch in wire_code)
        value=owner.run(sdk.JobRequest('/python3.12.so',('-c',wire_code),memory_mib=512,timeout_ms=timeout,stdin=stdin,environment=environment),template=python)
        assert binding(value,python)
        if args.expected_mode=='warm':assert value.startup_mode=='warm'
        return value
    def live_bindings():
        found=[]
        for directory in run_root.glob('job-*'):
            try:
                lease=json.loads((directory/'lease.json').read_text())
                if args.expected_mode=='warm' and lease.get('phase')!='active':continue
                pid=lease['pid'];proc=Path('/proc')/str(pid)
                ticks=int((proc/'stat').read_text().rsplit(')',1)[1].split()[19]);assert ticks==lease['start_time_ticks']
                executable=Path((proc/'exe').readlink())
                # A cold lease is written before jailer drops privilege and
                # execs the VMM. Observe an actual VMM, retaining its strict UID check.
                if executable.name=='jailer':
                    starting=report.setdefault('observed_starting_processes',[])
                    if not any(row['pid']==pid for row in starting):starting.append({'pid':pid,'start_time_ticks':ticks,'executable':str(executable)})
                    continue
                assert executable.name=='firecracker',str(executable)
                uid=int(next(line for line in (proc/'status').read_text().splitlines() if line.startswith('Uid:')).split()[2])
                configs=list(directory.rglob('config.json'));assert len(configs)==1
                fc=json.loads(configs[0].read_text());kernel=configs[0].parent/fc['boot-source']['kernel_image_path'].lstrip('/')
                digest=hashlib.file_digest(kernel.open('rb'),'sha256').hexdigest()
                backend=next(name for name,sha in kernels.items() if sha==digest)
                assert not fc.get('network-interfaces') and uid>0
                sample = {'backend':backend,'kernel_sha256':digest,'pid':pid,'uid':uid,'start_time_ticks':ticks,'executable':str(executable),'vm_id':lease.get('vm_id'),'pool_key':lease.get('pool_key','')}
                if args.expect_oci_import:
                    selected = imported_profiles[backend]
                    drive = next(row for row in fc['drives'] if row['drive_id'] == 'rootfs')
                    assert drive['is_read_only'] and drive['is_root_device']
                    image = configs[0].parent / drive['path_on_host'].lstrip('/')
                    info = image.stat()
                    key = (pid, ticks, info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
                    if key not in image_cache:
                        with image.open('rb') as stream:
                            image_cache[key] = hashlib.file_digest(stream, 'sha256').hexdigest()
                    assert digest == selected['files'][selected['kernel']]
                    assert image_cache[key] == selected['files'][selected['image']]
                    sample.update(image_sha256=image_cache[key], oci_manifest_digest=selected['oci_manifest_digest'])
                found.append(sample)
            except (FileNotFoundError,ProcessLookupError):continue
        return found
    try:
        if args.expect_oci_import:
            from oci_template_fixture import config_sha, namespace_view
            imported = json.loads((root / 'results/oci-import-preparation.json').read_text())
            assert imported['passed'] and len(imported['profiles']) == 2
            assert config_sha(config) == imported['configuration_sha256']
            imported_profiles = {row['backend']: row for row in imported['profiles']}
            views = []
            for role in ('api', 'launcher'):
                unit = root.name + '-' + role + '.service'
                pid = int(subprocess.check_output(['systemctl', 'show', '-p', 'MainPID', '--value', unit], text=True).strip())
                assert pid > 1
                proc = Path('/proc') / str(pid)
                ticks = int((proc / 'stat').read_text().rsplit(')', 1)[1].split()[19])
                view = namespace_view(imported['profiles'], proc / 'root')
                assert int((proc / 'stat').read_text().rsplit(')', 1)[1].split()[19]) == ticks
                views.append({'unit': unit, 'pid': pid, 'start_time_ticks': ticks, 'profiles': view})
            report['imported_service_views'] = views
            report['oci_imports_expected'] = True
            check('actual-API-and-launcher-see-imports-and-cannot-read-packaged-source', len(views) == 2)
        catalog=a.templates();entries=catalog['templates'];assert len(entries)==2
        by_backend={row['capabilities']['backend']:row for row in entries}
        linux_entry,python_entry=by_backend['firecracker-linux'],by_backend['firecracker-osv']
        linux=sdk.TemplateSelector('firecracker-linux',linux_entry['capabilities']['artifact_manifest_sha256'])
        python=sdk.TemplateSelector('firecracker-osv',python_entry['capabilities']['artifact_manifest_sha256'])
        kernels={'firecracker-linux':json.loads((release/'artifacts/manifest.json').read_text())['kernel']['sha256'],
                 'firecracker-osv':json.loads((release/'templates/python-science/artifacts/manifest.json').read_text())['kernel']['sha256']}
        check('two-installed-authenticated-production-templates',all(row['available'] and row['capabilities']['artifact_authenticated'] and row['capabilities']['stage']=='production' for row in entries))
        check('selected-backend-capabilities-remain-distinct',not python_entry['capabilities']['features']['sessions'] and linux_entry['capabilities']['features']['sessions'] and python_entry['capabilities']['features']['stdin'])
        check('capability-query-binds-selected-digest',a.capabilities(template=python)['artifact_manifest_sha256']==python.artifact_manifest_sha256)
        visible=b.templates();check('tenant-template-filter-does-not-leak-hidden-default',len(visible['templates'])==1 and visible['templates'][0]['capabilities']['backend']=='firecracker-osv' and (visible['default_template_id']=='' if config['backend']=='firecracker-linux' else visible['default_template_id']=='python-science'))
        if config['backend']=='firecracker-linux':
            check('denied-default-identity-redacted',not b.capabilities()['artifact_authenticated'] and b.capabilities()['backend']=='')
            try:b.run(sdk.JobRequest('/bin/sh'))
            except sdk.UnsupportedCapability:check('no-implicit-fallback-for-hidden-default',True)
            else:raise AssertionError('hidden default silently selected another template')
        try:b.run(sdk.JobRequest('/bin/sh'),template=linux)
        except sdk.APIError as error:check('forbidden-template-refused-before-VM',error.status==403)
        else:raise AssertionError('tenant ran forbidden Linux template')
        stale=sdk.TemplateSelector('firecracker-osv','c'*64)
        try:a.run(sdk.JobRequest('/python3.12.so',('-c','print(1)')),template=stale)
        except sdk.TemplateMismatch:check('stale-selector-never-substitutes-default',True)
        else:raise AssertionError('stale selector was accepted')
        value=py("import json,numpy as np,pandas as pd; a=np.arange(12).reshape(3,4); f=pd.DataFrame({'k':['a','a','b'],'v':[2,3,7]}); print(json.dumps({'sum':int(a.sum()),'group':f.groupby('k')['v'].sum().to_dict(),'numpy':np.__version__,'pandas':pd.__version__},sort_keys=True))")
        data=json.loads(stdout(value));check('actual-OSv-Python-numpy-pandas-through-production-API',value.succeeded and data['sum']==66 and data['group']=={'a':5,'b':7})
        report['runtime_versions']={'numpy':data['numpy'],'pandas':data['pandas']}
        value=py('''import ctypes,errno,json,time
class TS(ctypes.Structure): _fields_=[('tv_sec',ctypes.c_long),('tv_nsec',ctypes.c_long)]
lib=ctypes.CDLL(None,use_errno=True)
lib.clock_nanosleep.argtypes=[ctypes.c_int,ctypes.c_int,ctypes.POINTER(TS),ctypes.POINTER(TS)]
lib.clock_nanosleep.restype=ctypes.c_int
lib.clock_gettime.argtypes=[ctypes.c_int,ctypes.POINTER(TS)]
def call(clock,flags,request):
    remain=TS(17,29);ctypes.set_errno(123)
    result=lib.clock_nanosleep(clock,flags,ctypes.byref(request) if request is not None else None,ctypes.byref(remain))
    assert ctypes.get_errno()==123 and (remain.tv_sec,remain.tv_nsec)==(17,29)
    return result
checks=[]
start=time.monotonic();time.sleep(0.025);assert time.monotonic()-start>=0.025
time.sleep(0);checks.append('Python-fractional-and-zero-sleep')
try: time.sleep(-0.1)
except ValueError: checks.append('Python-negative-sleep-rejected')
else: raise AssertionError('negative Python sleep accepted')
for clock in (0,1):
    start=time.monotonic();assert call(clock,0,TS(0,10000000))==0;assert time.monotonic()-start>=0.01
    current=TS();assert lib.clock_gettime(clock,ctypes.byref(current))==0
    deadline=current.tv_sec*1000000000+current.tv_nsec+20000000
    start=time.monotonic();assert call(clock,1,TS(deadline//1000000000,deadline%1000000000))==0;assert time.monotonic()-start>=0.015
    assert call(clock,1,TS(0,0))==0
    checks.append('clock-'+str(clock)+'-relative-absolute-expired-errno-remain')
for invalid in (TS(-1,0),TS(0,-1),TS(0,1000000000)):
    assert call(1,0,invalid)==errno.EINVAL
assert call(1,2,TS(0,0))==errno.EINVAL
assert call(3,0,TS(0,0))==errno.ENOTSUP
assert call(1,0,None)==errno.EFAULT
checks.append('C-ABI-invalid-time-flags-clock-pointer')
print(json.dumps({'checks':checks}))''')
        report['clock_sleep_C_ABI']=json.loads(stdout(value)) if value.succeeded else value.guest_result
        check('OSv-Python-sleep-and-C-clock-nanosleep-real-scheduler',value.succeeded and len(report['clock_sleep_C_ABI']['checks'])==5)
        data=b'\0\xffcatalog-binary-stdin'
        value=py("import os,sys,hashlib; print(os.environ['CATALOG_VALUE']+'|'+hashlib.sha256(sys.stdin.buffer.read()).hexdigest())",owner=b,stdin=data,environment={'CATALOG_VALUE':'signed-python'})
        check('OSv-selected-tenant-environment-and-binary-stdin',value.succeeded and stdout(value)=='signed-python|'+hashlib.sha256(data).hexdigest())
        value=py('import sys; print("failure-observed",file=sys.stderr); sys.exit(7)')
        check('OSv-nonzero-exit-and-stderr-preserved',not value.succeeded and value.exit_code==7 and 'failure-observed' in value.guest_result.get('stderr',''))
        ready('firecracker-linux')
        session=a.create_session(sdk.SessionRequest(memory_mib=128,vcpus=1,ttl_ms=90000),template=linux);sessions.append(session)
        check('Linux-session-selected-in-mixed-service',session.created.backend=='firecracker-linux' and session.created.artifact_manifest_sha256==linux.artifact_manifest_sha256)
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as worker:
            future=worker.submit(py,'import time; time.sleep(5); print("parallel-python")',owner=b)
            wait(lambda:a.doctor()['vm_capacity']['active']==2,'different templates did not share the active ledger')
            wait(lambda:{row['backend'] for row in live_bindings()}=={'firecracker-linux','firecracker-osv'},'two real backends not observed')
            observed=live_bindings();check('actual-mixed-VM-kernel-pid-UID-and-no-NIC',len(observed)==2 and len({row['uid'] for row in observed})==2)
            report['observed_VM_bindings']=observed
            try:a.run(sdk.JobRequest('/python3.12.so',('-c','print("must-not-run")'),memory_mib=512,timeout_ms=10000),template=python)
            except sdk.APIError as error:check('global-concurrency-applies-across-templates-and-tenants',error.status==429 and error.code=='busy')
            else:raise AssertionError('third VM exceeded shared active budget')
            value=future.result(timeout=20)
            report['concurrent_OSv_result']={'state':value.state,'exit_code':value.exit_code,'guest_result':value.guest_result}
            check('concurrent-OSv-job-survives-other-template-quota-rejection',value.succeeded and stdout(value)=='parallel-python')
        result=session.run(sdk.SessionCommand('/bin/bash',('-c','printf linux-kept')))
        check('Linux-session-remains-usable-after-mixed-job',result.succeeded and stdout(result)=='linux-kept')
        session.close()
        value=py('import time; time.sleep(10)',timeout=500)
        check('OSv-timeout-destroys-only-selected-VM',value.timed_out and not value.succeeded)
        wait(lambda:a.doctor()['vm_capacity']['active']==0,'timed-out OSv VM retained active capacity')
        ready('firecracker-linux')
        value=a.run(sdk.JobRequest('/bin/bash',('-c','printf after-osv-timeout'),memory_mib=128,timeout_ms=5000),template=linux)
        check('Linux-works-after-OSv-timeout',value.succeeded and stdout(value)=='after-osv-timeout' and binding(value,linux))
        try:py('print(1)',environment={'LD_PRELOAD':'/bad.so'})
        except sdk.ConfigurationError:check('selected-OSv-reserved-environment-stays-rejected',True)
        else:raise AssertionError('OSv reserved environment accepted')
        # Installed Node client performs discovery and an actual OSv request.
        node_config=root/'catalog-node.json';node_config.write_text(json.dumps({'url':endpoint,'token':str(root/'secrets/token-b'),'ca':str(root/'tls/ca.crt'),'cert':str(root/'tls/client.crt'),'key':str(root/'tls/client.key')}));node_config.chmod(0o600)
        code="import{Client}from "+json.dumps((release/'sdk/node/index.js').as_uri())+";import fs from'node:fs';const c=JSON.parse(fs.readFileSync(process.argv[1]));const sdk=new Client(c.url,{token:fs.readFileSync(c.token,'utf8'),caFile:c.ca,certFile:c.cert,keyFile:c.key});const rows=await sdk.templates();if(rows.templates.length!==1)throw Error('tenant discovery');const cap=rows.templates[0].capabilities;const t={backend:cap.backend,artifactManifestSha256:cap.artifact_manifest_sha256};const r=await sdk.run({entrypoint:'/python3.12.so',args:['-c','print(6*7)'],memoryMiB:512,timeoutMs:10000},{template:t});if(!r.succeeded||r.guestResult.stdout.trim()!=='42'||r.artifactManifestSha256!==t.artifactManifestSha256)throw Error('Node selected OSv execution');"
        ready('firecracker-osv');subprocess.run(['node','--input-type=module','-e',code,str(node_config)],check=True,capture_output=True)
        check('installed-Node-SDK-discovers-and-executes-authorized-OSv',True)
        spec=importlib.util.spec_from_file_location('catalog_mcp',Path(__file__).with_name('e2e-mcp.py'));module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        mcp_config=root/'catalog-mcp.json';mcp_config.write_text(json.dumps({'api_url':endpoint,'ca_file':str(root/'tls/ca.crt'),'cert_file':str(root/'tls/client.crt'),'key_file':str(root/'tls/client.key'),'token_file':str(root/'secrets/token')}));mcp_config.chmod(0o600)
        mcp=module.MCP(release/'bin/osv-sandbox-mcp',mcp_config)
        rows=mcp.call('sandbox.templates')['templates'];check('installed-MCP-lists-both-authenticated-templates',len(rows)==2 and {row['backend'] for row in rows}=={'firecracker-linux','firecracker-osv'})
        ready('firecracker-osv');result=mcp.call('sandbox.exec',entrypoint='/python3.12.so',args=['-c','print(7*7)'],backend=python.backend,artifact_manifest_sha256=python.artifact_manifest_sha256,memory_mib=512,timeout_ms=10000)
        check('installed-MCP-selects-real-OSv-VM',result['state']=='succeeded' and result['guest_result']['stdout'].strip()=='49' and result['artifact_manifest_sha256']==python.artifact_manifest_sha256)
        ready('firecracker-linux');created=mcp.call('sandbox.session.create',backend=linux.backend,artifact_manifest_sha256=linux.artifact_manifest_sha256,memory_mib=128,ttl_ms=60000)
        try:
            result=mcp.call('sandbox.exec',session_id=created['id'],entrypoint='/bin/bash',args=['-c','printf selected-session'])
            check('MCP-session-exec-uses-bound-Linux-template',result['result']['guest_result']['stdout']=='selected-session')
            denied=mcp.call('sandbox.exec',expected_error=True,session_id=created['id'],entrypoint='/python3.12.so',backend=python.backend,artifact_manifest_sha256=python.artifact_manifest_sha256)
            check('MCP-session-rejects-conflicting-explicit-template','error' in denied)
        finally:mcp.call('sandbox.session.close',session_id=created['id'])
        wait(lambda:a.doctor()['vm_capacity']['active']==0,'catalog requests retained active capacity')
        if args.expected_mode=='warm':
            ready('firecracker-linux');ready('firecracker-osv')
            status=a.doctor();profiles=status['warm_pool']['profiles'];keys={row['key'] for row in profiles}
            check('template-pools-have-distinct-keys-and-one-capacity-snapshot',len(keys)==2 and len(profiles)==2 and status['vm_capacity']['instances']==2 and status['vm_capacity']['active']==0)
        else:check('cold-catalog-has-no-residual-VMs',a.doctor()['vm_capacity']['instances']==0)
        report['passed']=True
    finally:
        if mcp is not None:mcp.stop()
        for session in sessions:
            try:session.close()
            except sdk.APIError as error:
                if error.status!=404:raise
        (root/'results'/('template-catalog-'+args.expected_mode+'.json')).write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))


if __name__=='__main__':main()
