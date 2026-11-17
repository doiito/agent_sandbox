#!/usr/bin/env python3
"""Installed Python SDK fixed-input jobs, in isolated cold or warm real-KVM fixture."""
import argparse,base64,hashlib,json,subprocess,sys,time
from pathlib import Path
import osv_sandbox_client as sdk
p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);p.add_argument('--package',type=Path,required=True);p.add_argument('--expected-mode',choices=('cold','warm'),required=True);p.add_argument('--in-netns',action='store_true');args=p.parse_args();root=args.root
if not args.in_netns:
 pid=subprocess.check_output(['systemctl','show','-p','MainPID','--value',root.name+'-api.service'],text=True).strip();assert int(pid)>1
 raise SystemExit(subprocess.run(['nsenter','-t',pid,'-n',sys.executable,__file__,'--root',str(root),'--package',str(args.package),'--expected-mode',args.expected_mode,'--in-netns']).returncode)
config=json.loads((root/'config.production.json').read_text());client=sdk.Client('https://localhost:'+config['listen'].rsplit(':',1)[1],token=(root/'secrets/token').read_text(),ca_file=str(root/'tls/ca.crt'),cert_file=str(root/'tls/client.crt'),key_file=str(root/'tls/client.key'),request_timeout_seconds=65)
report={'suite':'python-job-inputs-kvm/v1','passed':False,'mode':args.expected_mode,'cases':[],'job_ids':[],'performance_gate_evidence':False}
def check(name,value):assert value,name;report['cases'].append(name)
def wait_ready():
 if args.expected_mode!='warm':return
 deadline=time.monotonic()+20
 while True:
  doctor=client.doctor()
  if doctor['warm_pool']['healthy'] and any(row['name']=='small' and row['ready']>=1 for row in doctor['warm_pool']['profiles']):return
  assert time.monotonic()<deadline,'warm profile did not refill';time.sleep(0.05)
def run(script,*,legacy=False,**options):
 wait_ready();job=sdk.JobRequest('/bin/sh',('-c',script),memory_mib=128,timeout_ms=options.pop('timeout_ms',5000),**options)
 result=(client.run_legacy if legacy else client.run)(job);report['job_ids'].append(result.id)
 if args.expected_mode=='warm':assert result.startup_mode=='warm','input test silently used cold fallback'
 return result
def denied(name,action,status):
 try:action()
 except sdk.APIError as error:check(name,error.status==status)
 else:raise AssertionError(name+' accepted')
try:
 caps=client.capabilities();check('capabilities',all(caps['features'][k] for k in ('environment','stdin','working_directory')) and caps['limits']['max_stdin_bytes']==16384 and caps['limits']['max_env_entries']==32 and caps['limits']['max_env_bytes']==8192)
 check('fixture-mode',bool(config.get('warm_pool',{}).get('enabled'))==(args.expected_mode=='warm'))
 data=bytes([0,255])+'中文\n'.encode()
 value="中文='quoted'"
 result=run('printf "%s|%s|%s|%s|" "$KEY" "$PWD" "$LD_LIBRARY_PATH" "$(/bin/busybox id -u)"; /bin/busybox cat marker; /bin/busybox sha256sum; printf job-stderr >&2',environment={'KEY':value,'LD_LIBRARY_PATH':'/workspace/lib'},cwd='/input/nested',stdin=data,input_files=(sdk.InputFile('nested/marker',b'marker|'),))
 check('combined-env-cwd-binary-stdin',result.succeeded and result.guest_result['stdout']==value+'|/input/nested|/workspace/lib|10000|marker|'+hashlib.sha256(data).hexdigest()+'  -\n' and result.guest_result['stderr']=='job-stderr')
 check('empty-stdin-eof',run('/bin/busybox wc -c',stdin=b'').guest_result['stdout'].strip()=='0')
 check('omitted-stdin-eof',run('/bin/busybox wc -c').guest_result['stdout'].strip()=='0')
 data=bytes(range(256))*64
 assert len(data)==16384
 result=run('/bin/busybox sha256sum',stdin=data);check('full-16k-binary-stdin',result.succeeded and result.guest_result['stdout'].split()[0]==hashlib.sha256(data).hexdigest())
 result=run('/bin/busybox head -c 65536 /dev/zero; /bin/busybox sha256sum >&2',stdin=data)
 check('duplex-output-and-input',result.succeeded and len(result.guest_result['stdout'])==65536 and result.guest_result['stderr'].split()[0]==hashlib.sha256(data).hexdigest())
 result=run('exit 7',stdin=data);check('program-may-close-stdin-early',result.state=='guest_error' and result.exit_code==7 and result.protocol_ok)
 result=run('printf started; sleep 20',stdin=data,timeout_ms=1500);check('unconsumed-input-deadline',result.timed_out and result.state=='timed_out')
 result=run('printf should-not-run',cwd='/missing-job-cwd');check('missing-cwd-fails',result.state=='guest_error' and result.guest_result.get('error') and 'should-not-run' not in result.guest_result['stdout'])
 result=run('printf should-not-run',cwd='/lost+found');check('cwd-checked-after-dropping-uid',result.state=='guest_error' and 'Permission denied' in result.guest_result.get('error',''))
 result=run('printf "%s|%s" "${KEY-unset}" "$PWD"');check('next-job-env-and-workspace-fresh',result.succeeded and result.guest_result['stdout']=='unset|/workspace')
 result=run('printf "%s|%s|" "$KEY" "$PWD"; /bin/busybox wc -c',legacy=True,environment={'KEY':'legacy'},cwd='/input',stdin=b'input',input_files=(sdk.InputFile('marker',b'kept'),))
 check('v1-legacy-carries-inputs',result.succeeded and result.guest_result['stdout'].strip()=='legacy|/input|5')
 for name,job in [('sdk-relative-cwd',sdk.JobRequest('/bin/sh',cwd='relative')),('sdk-oversized-input',sdk.JobRequest('/bin/sh',stdin=data+b'x'))]:
  try:client.run(job)
  except sdk.ConfigurationError:report['cases'].append(name)
  else:raise AssertionError(name+' accepted')
 selector={'backend':caps['backend'],'artifact_manifest_sha256':caps['artifact_manifest_sha256'],'entrypoint':'/bin/sh','args':['-c','true'],'memory_mib':128}
 for name,extra in [('api-relative-cwd',{'cwd':'relative'}),('api-oversized-input',{'stdin':base64.b64encode(data+b'x').decode()}),('api-invalid-environment',{'environment':{'1BAD':'value'}}),('api-invalid-base64',{'stdin':'??=='})]:
  denied(name,lambda extra=extra:client._exchange('POST','/v2/jobs',dict(selector,**extra)),400)
 result=run('printf recovered');check('quota-reusable-after-failures',result.succeeded and result.guest_result['stdout']=='recovered')
 check('distinct-job-identities',len(set(report['job_ids']))==len(report['job_ids']))
 inspection=subprocess.run([sys.executable,str(Path(__file__).with_name('check-job-input-pool-state.py')),'--root',str(root),'--expected-mode',args.expected_mode],check=True,capture_output=True,text=True)
 report['cleanup_inspection']=json.loads(inspection.stdout)
 check('no-active-workdir-residual',report['cleanup_inspection']['active_jobs']==0 and not report['cleanup_inspection']['remaining_active_workdirs'])
 check('remaining-cgroups-belong-only-to-idle-pool',report['cleanup_inspection']['passed'] and not report['cleanup_inspection']['remaining_active_cgroups'])
 report['passed']=True
finally:
 with args.package.open('rb') as f:report['candidate_sha256']=hashlib.file_digest(f,'sha256').hexdigest()
 report['installed_sdk_sha256']=hashlib.sha256(Path(sdk.__file__).read_bytes()).hexdigest();report['case_count']=len(report['cases'])
 (root/'results/python-job-inputs.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'passed':report['passed'],'cases':report['case_count'],'mode':args.expected_mode}),flush=True)
