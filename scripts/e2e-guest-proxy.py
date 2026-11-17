#!/usr/bin/env python3
"""Actual signed-package Linux guest HTTP/TLS over vsock, cold and warm KVM."""
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
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--package',type=Path,required=True)
    parser.add_argument('--expected-mode',choices=['cold','warm'],required=True)
    parser.add_argument('--in-netns',action='store_true')
    args=parser.parse_args();root=args.root
    if not args.in_netns:
        pid=subprocess.check_output(['systemctl','show','-p','MainPID','--value',root.name+'-api.service'],text=True).strip()
        assert int(pid)>1
        raise SystemExit(subprocess.run(['nsenter','-t',pid,'-n',sys.executable,__file__,'--root',str(root),'--package',str(args.package),'--expected-mode',args.expected_mode,'--in-netns']).returncode)
    release=next((root/'releases').iterdir());sys.path.insert(0,str(release/'sdk/python'))
    import osv_sandbox_client as sdk
    config=json.loads((root/'config.production.json').read_text())
    run_root=Path(config['run_root'])
    endpoint='https://localhost:'+config['listen'].rsplit(':',1)[1]
    def client(token):
        return sdk.Client(endpoint,token=(root/'secrets'/token).read_text(),ca_file=str(root/'tls/ca.crt'),cert_file=str(root/'tls/client.crt'),key_file=str(root/'tls/client.key'))
    a,b=client('token'),client('token-b')
    report={'suite':'linux-guest-proxy-real-KVM/v1','passed':False,'mode':args.expected_mode,'cases':[],
            'package_sha256':hashlib.file_digest(args.package.open('rb'),'sha256').hexdigest(),
            'actual_guest_transport':'loopback TCP -> virtio-vsock -> per-VM launcher Unix relay -> nonroot egress',
            'production_validated':False,'performance_gate_evidence':False,'NET_01_complete':False}
    sessions=[];mcp=None;egress=root.name+'-egress.service'
    ca=(root/'tls/ca.crt').read_bytes();inputs=(sdk.InputFile('fixture-ca.crt',ca),)
    http='http://localhost:44445';https='https://localhost:44443'
    expected=base64.b64encode(b'\0\xffegress-real-KVM-fixture').decode()
    def check(name,condition):
        assert condition,name
        report['cases'].append(name)
        print('PASS',name,flush=True)
    def wait(predicate,message,seconds=10):
        deadline=time.monotonic()+seconds
        while not predicate():
            assert time.monotonic()<deadline,message
            time.sleep(.025)
    def records(path):
        if not path.exists():return []
        return [json.loads(line) for line in path.read_text().splitlines(keepends=True) if line.endswith('\n')]
    def quiescent():
        rows=records(root/'egress-audit/network.jsonl')
        admitted={row['request_id'] for row in rows if row['event']=='net.admit'}
        ended={row['request_id'] for row in rows if row['event'] in ('net.complete','net.deny')}
        return not admitted-ended
    def ready():
        if args.expected_mode=='warm':
            wait(lambda:any(row['name']=='small' and row['ready']>=1 for row in a.doctor()['warm_pool']['profiles']),'pristine small profile not ready')
    def job(command,network='proxy'):
        ready()
        value=a.run(sdk.JobRequest('/bin/bash',('-c','set -o pipefail; '+command),memory_mib=128,vcpus=1,timeout_ms=10000,network=network,input_files=inputs))
        wait(quiescent,'job left network admission active')
        return value
    def output(value):return value.guest_result.get('stdout','').strip()
    def execute(session,command,environment=None):
        value=session.run(sdk.SessionCommand('/bin/bash',('-c','set -o pipefail; '+command),timeout_ms=8000,environment=environment))
        wait(quiescent,'session command retained upstream')
        return value
    def session(ttl=90000,network='proxy',after_expiry=False):
        ready()
        started=time.monotonic();deadline=started+20;rejections=0
        while True:
            try:
                value=a.create_session(sdk.SessionRequest(memory_mib=128,vcpus=1,ttl_ms=ttl,network=network,input_files=inputs))
                break
            except sdk.APIError as error:
                # Only an explicit admission rejection is safe to repeat. TTL
                # can lose its close acknowledgment and retain the API quota
                # for the existing 15s cleanup window after the VM is gone.
                if not after_expiry or error.status!=429 or error.code!='busy' or time.monotonic()>=deadline:raise
                rejections+=1;time.sleep(.05)
        if after_expiry:
            report['after-expiry-admission']={'explicit_429_rejections':rejections,'wait_seconds':round(time.monotonic()-started,3),'bound_seconds':20}
        sessions.append(value)
        return value
    def closed_slow(path):return any(row.get('event')=='slow-closed' and row.get('path')==path for row in records(root/'results/upstream-events.jsonl'))
    def start_slow(value,label):
        path='/slow-guest-'+label+'-'+secrets.token_hex(4)
        handle=value.start_command(sdk.SessionCommand('/bin/sh',('-c','exec /usr/bin/osv-http -timeout 10s -cacert /input/fixture-ca.crt '+https+path),timeout_ms=10000))
        wait(lambda:any(row.get('event')=='slow-entered' and row.get('path')==path for row in records(root/'results/upstream-events.jsonl')),'real guest did not reach TLS upstream')
        return handle,path
    def session_gone(value):
        try:value.info()
        except sdk.APIError as error:return error.status==404
        return False
    try:
        manifest=json.loads((release/'artifacts/manifest.json').read_text())
        proxy_profiles={'osv-sandbox-artifacts/v3':['vsock-proxy-v1'],
                        'osv-sandbox-artifacts/v4':['vsock-proxy-v1','workspace-watch-v1']}
        check('signed-Linux-proxy-feature',manifest['protocol'] in proxy_profiles and manifest['agent_features']==proxy_profiles[manifest['protocol']])
        check('live-authorized-proxy-capability',a.capabilities()['features']['network_egress'] and not b.capabilities()['features']['network_egress'])
        try:b._exchange('POST','/v2/sessions',{'backend':'firecracker-linux','artifact_manifest_sha256':a.capabilities()['artifact_manifest_sha256'],'network':'proxy'})
        except sdk.APIError as error:check('tenant-without-egress-cannot-create-proxy-VM',error.status==403)
        else:raise AssertionError('disabled tenant created proxy VM')
        value=job('test "${http_proxy-unset}" = unset; test "$(ls /sys/class/net)" = lo; if /usr/bin/osv-http -timeout 1s http://127.0.0.1:44445/data >/dev/null 2>&1; then exit 91; fi; printf none-isolated',network='none')
        check('default-none-has-no-proxy-or-NIC-or-direct-upstream',value.succeeded and output(value)=='none-isolated')
        value=job('/usr/bin/osv-http -method POST -data actual-guest-post '+http+'/echo')
        check('actual-guest-HTTP-POST',value.succeeded and output(value)=='actual-guest-post')
        if args.expected_mode=='warm':check('proxy-job-used-prebooted-VM',value.startup_mode=='warm')
        value=job('/usr/bin/osv-http -cacert /input/fixture-ca.crt '+https+'/data | /bin/busybox base64')
        check('actual-guest-HTTPS-client-verifies-CA-and-preserves-binary',value.succeeded and output(value)==expected)
        value=job('/usr/bin/osv-http '+https+'/data')
        check('guest-HTTPS-rejects-untrusted-upstream-CA',not value.succeeded and value.exit_code==1 and 'certificate' in value.guest_result.get('stderr',''))
        value=job('/usr/bin/osv-http http://unlisted.invalid/private')
        check('guest-origin-denied-at-host-policy',not value.succeeded and value.exit_code==22 and 'egress_origin_denied' in output(value))
        value=job('test "$(ls /sys/class/net)" = lo; test "$HTTP_PROXY" = http://127.0.0.1:3128; test "$HTTPS_PROXY" = "$http_proxy"; test -z "$NO_PROXY"; printf proxy-without-NIC')
        check('proxy-mode-only-loopback-and-explicit-environment',value.succeeded and output(value)=='proxy-without-NIC')
        value=session()
        check('session-network-and-startup-metadata',value.created.network=='proxy' and value.created.startup_mode==args.expected_mode)
        result=execute(value,'/usr/bin/osv-http -cacert /input/fixture-ca.crt '+https+'/data | /bin/busybox base64')
        check('persistent-session-HTTPS',result.succeeded and output(result)==expected)
        vm_ids={row['vm_id'] for row in records(root/'egress-audit/network.jsonl') if row.get('lease_id')==value.id and row.get('vm_id')}
        assert len(vm_ids)==1
        vm_id=next(iter(vm_ids));directories=list(run_root.glob('job-'+vm_id+'-*'));assert len(directories)==1
        owner=json.loads((directories[0]/'lease.json').read_text());pid=owner['pid']
        process=Path('/proc')/str(pid);uid=int(next(line for line in (process/'status').read_text().splitlines() if line.startswith('Uid:')).split()[2])
        ticks=int((process/'stat').read_text().rsplit(')',1)[1].split()[19]);proxy_sockets=list(directories[0].rglob('agent.vsock_5001'))
        check('network-audit-bound-to-live-VM-pid-UID-and-owned-listener',ticks==owner['start_time_ticks'] and uid>0 and len(proxy_sockets)==1 and proxy_sockets[0].stat().st_uid==uid and proxy_sockets[0].stat().st_mode&0o777==0o600)
        report['observed_VM_binding']={'vm_id':vm_id,'lease_id':value.id,'pid':pid,'uid':uid,'start_time_ticks':ticks}
        result=execute(value,'printf workspace-retained > /workspace/network-check; /usr/bin/osv-http -method POST -data second-command '+http+'/echo')
        check('same-session-HTTP-and-workspace',result.succeeded and output(result)=='second-command')
        try:b._exchange('POST','/v2/sessions/'+value.id+'/commands',{'entrypoint':'/bin/sh','args':['-c','echo forbidden']})
        except sdk.APIError as error:check('proxy-session-remains-tenant-owned',error.status==404)
        else:raise AssertionError('foreign tenant used proxy session')
        handle,path=start_slow(value,'kill')
        try:a.fetch_network(https+'/data')
        except sdk.APIError as error:check('guest-and-host-fetch-share-network-quota',error.status==429)
        else:raise AssertionError('guest tunnel bypassed shared tenant network quota')
        check('background-network-command-killed',handle.kill())
        handle.wait();wait(lambda:closed_slow(path) and quiescent(),'command kill retained TLS upstream',seconds=2)
        check('command-kill-reclaims-network-and-keeps-session',execute(value,'cat /workspace/network-check').succeeded)
        handle,path=start_slow(value,'daemon-stop')
        subprocess.run(['systemctl','stop',egress],check=True)
        wait(lambda:closed_slow(path),'egress shutdown retained guest TLS',seconds=2)
        check('daemon-stop-terminates-inflight-guest-network-command',not handle.wait().succeeded)
        check('daemon-stop-withdraws-guest-proxy',not a.capabilities()['features']['network_egress'])
        check('daemon-stop-preserves-VM-workspace',output(execute(value,'cat /workspace/network-check'))=='workspace-retained')
        try:a._exchange('POST','/v2/sessions',{'backend':'firecracker-linux','artifact_manifest_sha256':manifest_digest(release),'network':'proxy'})
        except sdk.APIError as error:check('daemon-down-rejects-new-proxy-VM-before-admission',error.status==503)
        else:raise AssertionError('proxy VM admitted without egress')
        subprocess.run(['systemctl','start',egress],check=True)
        wait(lambda:a.capabilities()['features']['network_egress'],'guest proxy did not recover')
        result=execute(value,'/usr/bin/osv-http -cacert /input/fixture-ca.crt '+https+'/data | /bin/busybox base64')
        check('existing-VM-proxy-recovers-after-egress-restart',result.succeeded and output(result)==expected)
        value.close();wait(quiescent,'session close retained network')
        expiring=session(ttl=1500);handle,path=start_slow(expiring,'ttl')
        wait(lambda:session_gone(expiring),'proxy session did not expire')
        wait(lambda:closed_slow(path) and quiescent(),'proxy TTL retained upstream',seconds=2)
        check('TTL-destroys-VM-proxy-and-TLS-connection',True)
        wait(lambda:a.doctor()['vm_capacity']['active']==0,'expired proxy VM physical capacity not released',seconds=5)
        check('expired-proxy-VM-physical-capacity-released',True)
        renewed=session(ttl=1500,after_expiry=True);renewed.set_timeout(4000);time.sleep(1.7)
        result=execute(renewed,'/usr/bin/osv-http '+http+'/data | /bin/busybox base64')
        check('renewed-session-proxy-survives-original-soft-TTL',result.succeeded and output(result)==expected)
        renewed.close();wait(quiescent,'renewed proxy retained network')
        # Installed Node SDK must use the same actual guest path.
        module=(release/'sdk/node/index.js').as_uri()
        node_config={'url':endpoint,'token':str(root/'secrets/token'),'ca':str(root/'tls/ca.crt'),'cert':str(root/'tls/client.crt'),'key':str(root/'tls/client.key')}
        credentials=root/'guest-proxy-node.json';credentials.write_text(json.dumps(node_config));credentials.chmod(0o600)
        code="import{Client}from "+json.dumps(module)+";import fs from'node:fs';const c=JSON.parse(fs.readFileSync(process.argv[1]));const sdk=new Client(c.url,{token:fs.readFileSync(c.token,'utf8'),caFile:c.ca,certFile:c.cert,keyFile:c.key});const r=await sdk.run({entrypoint:'/bin/sh',args:['-c','/usr/bin/osv-http -method POST -data node-guest http://localhost:44445/echo'],network:'proxy',memoryMiB:128,timeoutMs:10000});if(!r.succeeded||r.guestResult.stdout!=='node-guest')throw Error('actual Node guest proxy failed');"
        ready();subprocess.run(['node','--input-type=module','-e',code,str(credentials)],check=True,capture_output=True)
        wait(quiescent,'Node guest retained network');check('installed-Node-SDK-actual-guest-proxy',True)
        spec=importlib.util.spec_from_file_location('guest_proxy_mcp',Path(__file__).with_name('e2e-mcp.py'));module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        mcp_config=root/'guest-proxy-mcp.json';mcp_config.write_text(json.dumps({'api_url':endpoint,'ca_file':str(root/'tls/ca.crt'),'cert_file':str(root/'tls/client.crt'),'key_file':str(root/'tls/client.key'),'token_file':str(root/'secrets/token')}));mcp_config.chmod(0o600)
        mcp=module.MCP(release/'bin/osv-sandbox-mcp',mcp_config)
        ready();result=mcp.call('sandbox.exec',entrypoint='/bin/sh',args=['-c','/usr/bin/osv-http -method POST -data mcp-guest http://localhost:44445/echo'],network='proxy',memory_mib=128,timeout_ms=10000)
        check('MCP-exec-uses-authorized-guest-proxy',result['state']=='succeeded' and result['guest_result']['stdout']=='mcp-guest')
        wait(quiescent,'MCP guest retained network')
        ready();created=mcp.call('sandbox.session.create',network='proxy',memory_mib=128,vcpus=1,ttl_ms=60000)
        try:
            check('MCP-creates-proxy-session-with-startup-metadata',created['network']=='proxy' and created['startup_mode']==args.expected_mode)
            result=mcp.call('sandbox.exec',session_id=created['id'],entrypoint='/bin/sh',args=['-c','/usr/bin/osv-http -method POST -data mcp-session http://localhost:44445/echo'],timeout_ms=10000)
            check('MCP-session-exec-inherits-authorized-proxy',result['result']['state']=='succeeded' and result['result']['guest_result']['stdout']=='mcp-session')
            denied=mcp.call('sandbox.exec',expected_error=True,session_id=created['id'],entrypoint='/bin/sh',network='proxy')
            check('MCP-session-exec-rejects-network-mutation','error' in denied)
        finally:
            mcp.call('sandbox.session.close',session_id=created['id'])
        wait(quiescent,'MCP proxy session retained network')
        wait(lambda:not list(run_root.rglob('agent.vsock_5001')),'consumed VM proxy socket remained')
        check('no-proxy-listener-in-idle-pristine-pool',True)
        rows=records(root/'egress-audit/network.jsonl');guest=[row for row in rows if row.get('vm_id')]
        check('durable-real-VM-tenant-lease-audit',len(guest)>10 and all(row['tenant']=='validation-a' and len(row['vm_id'])==24 and len(row['lease_id'])==24 for row in guest))
        report['passed']=True
    finally:
        if mcp is not None:mcp.stop()
        for value in sessions:
            try:value.close()
            except sdk.APIError as error:
                if error.status!=404:raise
        if subprocess.run(['systemctl','is-active','--quiet',egress]).returncode:subprocess.run(['systemctl','start',egress],check=True)
        (root/'results'/('guest-proxy-'+args.expected_mode+'.json')).write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))


def manifest_digest(release):
    return hashlib.sha256((release/'artifacts/manifest.json').read_bytes()).hexdigest()


if __name__=='__main__':main()
