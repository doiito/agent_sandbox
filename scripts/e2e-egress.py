#!/usr/bin/env python3
"""Same-package real egress/API/MCP/SDK alongside a real cold/warm KVM session."""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time

def main():
 p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);p.add_argument('--package',type=Path,required=True);p.add_argument('--expected-mode',choices=['cold','warm'],required=True);p.add_argument('--in-netns',action='store_true');args=p.parse_args();root=args.root
 if not args.in_netns:
  pid=subprocess.check_output(['systemctl','show','-p','MainPID','--value',root.name+'-api.service'],text=True).strip();assert int(pid)>1
  raise SystemExit(subprocess.run(['nsenter','-t',pid,'-n',sys.executable,__file__,'--root',str(root),'--package',str(args.package),'--expected-mode',args.expected_mode,'--in-netns']).returncode)
 release=next((root/'releases').iterdir());sys.path.insert(0,str(release/'sdk/python'))
 import osv_sandbox_client as sdk
 spec=importlib.util.spec_from_file_location('MCP_KVM_client',Path(__file__).with_name('e2e-mcp.py'));mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
 config=json.loads((root/'config.production.json').read_text());url='https://localhost:'+config['listen'].rsplit(':',1)[1]
 client=sdk.Client(url,token=(root/'secrets/token').read_text(),ca_file=str(root/'tls/ca.crt'),cert_file=str(root/'tls/client.crt'),key_file=str(root/'tls/client.key'))
 tenant_b=sdk.Client(url,token=(root/'secrets/token-b').read_text(),ca_file=str(root/'tls/ca.crt'),cert_file=str(root/'tls/client.crt'),key_file=str(root/'tls/client.key'))
 credentials={'api_url':url,'ca_file':str(root/'tls/ca.crt'),'cert_file':str(root/'tls/client.crt'),'key_file':str(root/'tls/client.key'),'token_file':str(root/'secrets/token'),'max_in_flight':4}
 cfg=root/'mcp-egress.json';cfg.write_text(json.dumps(credentials));cfg.chmod(0o600)
 binary=release/'bin/osv-sandbox-mcp';mcp=None;session=None
 report={'suite':'egress-real-KVM-coexistence/v1','passed':False,'cases':[],'mode':args.expected_mode,'performance_gate_evidence':False,'guest_network_egress_enabled':False,'production_validated':False}
 def check(name,value):assert value,name;report['cases'].append(name)
 def wait(predicate,label):
  deadline=time.monotonic()+10
  while not predicate():assert time.monotonic()<deadline,label;time.sleep(.03)
 def events(path):
  text=path.read_text() if path.exists() else ''
  lines=text.splitlines()
  if text and not text.endswith('\n'):lines=lines[:-1]
  return [json.loads(line) for line in lines]
 def closed(path):return any(row.get('event')=='slow-closed' and row.get('path')==path for row in events(root/'results/upstream-events.jsonl'))
 def cancel_count():return sum(row.get('code')=='egress_cancelled' for row in events(root/'egress-audit/network.jsonl'))
 try:
  pids={role:int(subprocess.check_output(['systemctl','show','-p','MainPID','--value',root.name+'-'+role+'.service'],text=True)) for role in ['api','egress','upstream']}
  namespaces={role:os.readlink('/proc/'+str(pid)+'/ns/net') for role,pid in pids.items()}
  check('API-separated-from-egress-and-upstream-network',namespaces['api']!=namespaces['egress']==namespaces['upstream'])
  status=Path('/proc',str(pids['egress']),'status').read_text();uid=int(next(line.split()[1] for line in status.splitlines() if line.startswith('Uid:')))
  check('actual-egress-process-nonroot',uid>0);report['service_pids']=pids;report['network_namespaces']=namespaces
  caps=client.capabilities();expected_proxy=json.loads((root/'egress.production.json').read_text()).get('guest_proxy',False)
  report['guest_network_egress_enabled']=expected_proxy
  check('fetch-and-guest-proxy-capability-match-fixture',caps['features']['network_fetch'] and caps['features']['network_egress']==expected_proxy and caps['network_fetch_policy']['max_concurrent']==1)
  check('disabled-tenant-not-advertised',not tenant_b.capabilities()['features']['network_fetch'])
  try:tenant_b._exchange('POST','/v2/net/fetch',{'url':'https://localhost:44443/data'})
  except sdk.APIError as error:check('disabled-tenant-denied',error.status==403)
  else:raise AssertionError('disabled tenant could fetch')
  if args.expected_mode=='warm':wait(lambda:any(row['name']=='small' and row['ready']>=1 for row in client.doctor()['warm_pool']['profiles']),'pool did not prepare session')
  session=client.create_session(sdk.SessionRequest(memory_mib=128,vcpus=1,ttl_ms=90000))
  result=session.run(sdk.SessionCommand('/bin/sh',('-c','printf held-vm'),timeout_ms=5000))
  check('real-guest-session-exec',result.succeeded and result.guest_result['stdout']=='held-vm')
  mcp=mod.MCP(binary,cfg)
  data=b'\0\xffnetwork-body'
  value=mcp.call('sandbox.net.fetch',url='https://localhost:44443/echo',method='POST',body_base64=base64.b64encode(data).decode())
  check('MCP-TLS-binary-POST-while-VM-quota-held',base64.b64decode(value['body_base64'])==data and client.doctor()['vm_capacity']['active']==1)
  v4=client.fetch_network('https://localhost:44443/data');check('Python-SDK-DNS-IPv4-TLS',v4.status==200 and v4.body.startswith(b'\0\xff'))
  v6=client.fetch_network('https://localhost:44444/data');check('actual-IPv6-TLS',v6.status==200 and any(row.get('event')=='net.allow' and row.get('ip')=='::1' and row.get('origin')=='https://localhost:44444' for row in events(root/'egress-audit/network.jsonl')))
  node_module=(release/'sdk/node/index.js').as_uri()
  code="import{Client}from "+json.dumps(node_module)+";import fs from'node:fs';const c=JSON.parse(fs.readFileSync(process.argv[1]));const sdk=new Client(c.api_url,{token:fs.readFileSync(c.token_file,'utf8'),caFile:c.ca_file,certFile:c.cert_file,keyFile:c.key_file});const r=await sdk.fetchNetwork('https://localhost:44443/echo',{method:'POST',body:new Uint8Array([0,255])});if(r.body.length!==2||r.body[1]!==255)throw Error('body mismatch');"
  subprocess.run(['node','--input-type=module','-e',code,str(cfg)],check=True,capture_output=True);check('installed-Node-SDK-binary-fetch',True)
  value=mcp.call('sandbox.net.fetch',url='https://localhost:44443/redirect',headers={'Authorization':'remote-secret','X-API-Key':'remote-key'},follow_redirects=True)
  requests=[row for row in events(root/'results/upstream-events.jsonl') if row.get('event')=='request']
  check('cross-origin-redirect-no-secret-forwarding',value['redirects']==1 and requests[-1]['path']=='/final' and 'authorization' not in requests[-1]['header_names'] and 'x-api-key' not in requests[-1]['header_names'])
  for name,path,code in [('redirect-origin-denied','/denied-redirect','egress_origin_denied'),('response-size-bound','/large','egress_response_limit')]:
   value=mcp.call('sandbox.net.fetch',expected_error=True,url='https://localhost:44443'+path,follow_redirects=True);check(name,value['error']['code']==code)
  value=mcp.call('sandbox.net.fetch',expected_error=True,url='https://localhost:44443/not-found');check('upstream-HTTP404-isError',value['status']==404)
  try:client.fetch_network('https://localhost:44443/echo',method='POST',body=b'x'*4097)
  except sdk.ConfigurationError:check('SDK-request-limit-before-submit',True)
  else:raise AssertionError('oversized SDK request accepted')
  value=mcp.call('sandbox.net.fetch',expected_error=True,url='https://localhost:44443/echo',method='POST',body_base64=base64.b64encode(b'x'*4097).decode());check('API-request-body-limit',value['error']['status']==400)
  value=mcp.call('sandbox.net.fetch',expected_error=True,url='https://169.254.169.254/data');check('metadata-unlisted-origin-denied',value['error']['status']==403)
  for label in ['notify','EOF']:
   path='/slow-'+label+'-'+secrets.token_hex(4);before=cancel_count()
   rid=mcp.request('tools/call',{'name':'sandbox.net.fetch','arguments':{'url':'https://localhost:44443'+path}})
   wait(lambda:any(row.get('event')=='slow-entered' and row.get('path')==path for row in events(root/'results/upstream-events.jsonl')),'slow request did not enter')
   busy=mcp.call('sandbox.net.fetch',expected_error=True,url='https://localhost:44443/data');check('network-quota-'+label,busy['error']['status']==429)
   if label=='notify':mcp.send({'jsonrpc':'2.0','method':'notifications/cancelled','params':{'requestId':rid}});mcp.receive(mcp.request('server/discover',{}))
   else:mcp.stop();mcp=None
   wait(lambda:closed(path) and cancel_count()>before,'cancel/EOF did not close upstream and release quota')
   if mcp is None:mcp=mod.MCP(binary,cfg)
   check('cancel-'+label+'-upstream-closed-and-slot-reused',mcp.call('sandbox.net.fetch',url='https://localhost:44443/data')['status']==200)
  try:client.fetch_network('https://localhost:44443/slow-deadline',timeout_ms=500)
  except sdk.APIError as error:check('network-deadline504',error.status==504)
  else:raise AssertionError('slow request did not time out')
  wait(lambda:closed('/slow-deadline'),'deadline left upstream open')
  secret='query-marker-'+secrets.token_hex(8)
  mcp.call('sandbox.net.fetch',url='https://localhost:44443/data?'+secret,headers={'Authorization':'remote-secret'})
  audit=(root/'egress-audit/network.jsonl').read_text();check('audit-origin-only-no-query-token-body-credentials',all(value not in audit for value in [secret,'remote-secret','network-body',(root/'secrets/token').read_text()]))
  subprocess.run(['systemctl','stop',root.name+'-egress.service'],check=True)
  check('daemon-stop-withdraws-capability',not client.capabilities()['features']['network_fetch'])
  try:client._exchange('POST','/v2/net/fetch',{'url':'https://localhost:44443/data'})
  except sdk.APIError as error:check('no-direct-network-fallback',error.status==503)
  else:raise AssertionError('fetch bypassed stopped daemon')
  subprocess.run(['systemctl','start',root.name+'-egress.service'],check=True)
  wait(lambda:client.capabilities()['features']['network_fetch'],'restarted daemon did not recover')
  report['egress_pid_after_restart']=int(subprocess.check_output(['systemctl','show','-p','MainPID','--value',root.name+'-egress.service'],text=True))
  check('restart-preserves-audit-and-policy',client.fetch_network('https://localhost:44443/data').status==200 and len(events(root/'egress-audit/network.jsonl'))>10)
  result=session.run(sdk.SessionCommand('/bin/sh',('-c','printf guest-kept-after-network-restart'),timeout_ms=5000));check('held-VM-survives-egress-restart',result.succeeded and result.guest_result['stdout']=='guest-kept-after-network-restart')
  session.close();session=None
  inspection=subprocess.run([sys.executable,str(Path(__file__).with_name('check-job-input-pool-state.py')),'--root',str(root),'--expected-mode',args.expected_mode],capture_output=True,text=True)
  assert inspection.returncode==0,inspection.stderr;report['host_inspection']=json.loads(inspection.stdout);check('VM-network-slots-and-idle-pool-accounted',report['host_inspection']['passed'])
  report['passed']=True
 finally:
  if mcp is not None:mcp.stop()
  if session is not None:session.close()
  cfg.unlink(missing_ok=True)
  with args.package.open('rb') as stream:report['candidate_sha256']=hashlib.file_digest(stream,'sha256').hexdigest()
  report['installed_mcp_sha256']=hashlib.sha256(binary.read_bytes()).hexdigest();report['installed_egress_sha256']=hashlib.sha256((release/'bin/osv-sandbox-egress').read_bytes()).hexdigest();report['case_count']=len(report['cases'])
  (root/'results/egress.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'passed':report['passed'],'cases':report['case_count'],'mode':args.expected_mode}),flush=True)
if __name__=='__main__':main()
