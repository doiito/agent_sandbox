#!/usr/bin/env python3
"""Real egress/API/MCP processes against local TLS; no guest/Internet claims."""
import argparse
import base64
import hashlib
import http.server
import importlib.util
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('mcp_protocol_probe', ROOT / 'scripts/test-mcp-stdio.py')
mcp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mcp)

def wait_for(predicate, message, seconds=5):
    deadline = time.monotonic() + seconds
    while not predicate():
        assert time.monotonic() < deadline, message
        time.sleep(.02)

def build(path, package):
    subprocess.run(['go','build','-buildvcs=false','-trimpath','-o',str(path),package],cwd=ROOT,
                   env=os.environ|{'CGO_ENABLED':'0','GOCACHE':os.environ.get('GOCACHE','/tmp/osv-sandbox-go-cache')},check=True)

def suite(work, egress_binary, mcp_binary, api_binary):
    tls_dir = work / 'tls'
    config = mcp.fixtures(tls_dir)
    token = (tls_dir / 'token').read_text()
    marker = secrets.token_hex(16)
    entered = threading.Event()
    released = threading.Event()
    observations = []
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'
        def log_message(self, *_): pass
        def do_GET(self): self.handle_request()
        def do_POST(self): self.handle_request()
        def handle_request(self):
            body = self.rfile.read(int(self.headers.get('Content-Length','0')))
            observations.append({'path':self.path,'method':self.command,'headers':dict(self.headers),'body':body})
            status, data = 200, b'\0\xff'+marker.encode()
            if self.path.startswith('/redirect'):
                self.send_response(302);self.send_header('Location',f'https://127.0.0.1:{upstream.server_port}/final');self.send_header('Content-Length','0');self.end_headers();return
            if self.path == '/denied-redirect':
                self.send_response(302);self.send_header('Location','https://unlisted.invalid/data');self.send_header('Content-Length','0');self.end_headers();return
            if self.path == '/slow':
                self.send_response(200);self.send_header('Content-Length','100');self.end_headers();self.wfile.flush();entered.set()
                self.connection.settimeout(5)
                try:
                    if self.connection.recv(1) == b'': released.set()
                except (ssl.SSLError,ConnectionResetError): released.set()
                return
            if self.path == '/large': data = b'x' * 4097
            if self.path == '/not-found': status, data = 404, b'missing'
            if self.path == '/echo': data = body
            self.send_response(status);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
    upstream = http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(tls_dir/'server.crt',tls_dir/'server.key')
    upstream.socket = context.wrap_socket(upstream.socket,server_side=True)
    thread = threading.Thread(target=upstream.serve_forever,daemon=True);thread.start()
    class IPv6Server(http.server.ThreadingHTTPServer): address_family = socket.AF_INET6
    ipv6 = IPv6Server(('::1',0),Handler);ipv6.socket = context.wrap_socket(ipv6.socket,server_side=True)
    ipv6_thread = threading.Thread(target=ipv6.serve_forever,daemon=True);ipv6_thread.start()
    origins=[f'https://localhost:{upstream.server_port}',f'https://127.0.0.1:{upstream.server_port}',f'https://[::1]:{ipv6.server_port}']
    policy={'allowed_origins':origins,'allowed_cidrs':['127.0.0.1/32','::1/128'],'max_concurrent':1,'max_request_bytes':4096,'max_response_bytes':4096,'timeout_ms':2000,'max_redirects':2}
    auth={'protocol':'osv-sandbox-auth/v1','tenants':[{'id':'network-a','token_sha256':hashlib.sha256(token.encode()).hexdigest(),'allowed_entrypoints':['/bin/sh'],'requests_per_second':100,'burst':100,'max_concurrent':1,'egress':policy},
            {'id':'network-b','token_sha256':hashlib.sha256(b'disabled-test-token').hexdigest(),'allowed_entrypoints':['/bin/sh'],'requests_per_second':100,'burst':100,'max_concurrent':1}]}
    auth_path=work/'auth.json';auth_path.write_text(json.dumps(auth));auth_path.chmod(0o600)
    private=work/'egress';private.mkdir(mode=0o700)
    daemon_config=work/'egress.json';daemon_config.write_text(json.dumps({'production':False,'socket_path':str(private/'e.sock'),'auth_policy_path':str(auth_path),'audit_log_path':str(private/'audit.jsonl'),'ca_file':str(tls_dir/'ca.crt'),'max_concurrent':2}));daemon_config.chmod(0o600)
    env=os.environ|{'HTTP_PROXY':'http://127.0.0.1:1','HTTPS_PROXY':'http://127.0.0.1:1','NO_PROXY':''}
    daemon_log=(work/'daemon.log').open('w+');api_log=(work/'api.log').open('w+')
    daemon=subprocess.Popen([str(egress_binary),'-require-production=false','-config',str(daemon_config)],stderr=daemon_log,stdout=daemon_log,env=env)
    api=None;children=[];checks=[];transcripts=[]
    schemas=mcp.check_schemas()
    try:
        wait_for(lambda:(private/'e.sock').exists(),'egress service did not create socket')
        ready=work/'api-ready.json'
        api=subprocess.Popen([str(api_binary),'-auth',str(auth_path),'-socket',str(private/'e.sock'),'-tls',str(tls_dir),'-ready',str(ready)],stderr=api_log,stdout=api_log,env=env)
        wait_for(ready.exists,'API fixture did not start')
        address=json.loads(ready.read_text())['address'];config['api_url']='https://'+address;config_path=work/'mcp.json';config_path.write_text(json.dumps(config));config_path.chmod(0o600)
        p=mcp.Process(mcp_binary,config_path);children.append(p)
        def call(name,args=None,error=False):
            response=p.receive(p.request('tools/call',{'name':name,'arguments':args or {}}))
            assert 'error' not in response,response
            result=response['result'];mcp.validate(schemas,mcp.MODERN,'CallToolResult',result)
            assert result['isError']==error,result
            assert json.loads(result['content'][0]['text'])==result['structuredContent']
            transcripts.append(response)
            return result['structuredContent']
        caps=call('sandbox.capabilities');assert caps['features']['network_fetch'] and not caps['features']['network_egress']
        checks.append('actual-process-policy-and-distinct-network-capabilities')
        tools=p.receive(p.request('tools/list'))['result'];assert 'sandbox.net.fetch' in [x['name'] for x in tools['tools']]
        mcp.validate(schemas,mcp.MODERN,'ListToolsResult',tools)
        checks.append('MCP-network-tool-official-schema')
        result=call('sandbox.net.fetch',{'url':origins[0]+'/data?secret-query='+marker})
        assert base64.b64decode(result['body_base64'])==b'\0\xff'+marker.encode()
        checks.append('actual-TLS-DNS-loopback-binary-response')
        result=call('sandbox.net.fetch',{'url':origins[2]+'/data'})
        assert result['status']==200
        checks.append('actual-IPv6-TLS-response')
        result=call('sandbox.net.fetch',{'url':origins[0]+'/echo','method':'POST','body_base64':'AP8='})
        assert base64.b64decode(result['body_base64'])==b'\0\xff'
        checks.append('actual-binary-POST')
        result=call('sandbox.net.fetch',{'url':origins[0]+'/redirect','headers':{'Authorization':'remote-secret','X-Key':'remote-custom'},'follow_redirects':True})
        assert result['redirects']==1 and not any(k.lower() in ('authorization','x-key') for k in observations[-1]['headers'])
        checks.append('cross-origin-redirect-strips-all-caller-secrets')
        for path,code in [('/denied-redirect','egress_origin_denied'),('/large','egress_response_limit')]:
            result=call('sandbox.net.fetch',{'url':origins[0]+path,'follow_redirects':True},True);assert result['error']['code']==code
        result=call('sandbox.net.fetch',{'url':origins[0]+'/not-found'},True);assert result['status']==404
        checks.append('denied-redirect-body-limit-and-upstream-isError')
        rid=p.request('tools/call',{'name':'sandbox.net.fetch','arguments':{'url':origins[0]+'/slow'}});assert entered.wait(3)
        busy=call('sandbox.net.fetch',{'url':origins[0]+'/data'},True);assert busy['error']['status']==429
        p.send({'jsonrpc':'2.0','method':'notifications/cancelled','params':{'requestId':rid}});assert released.wait(3)
        p.receive(p.request('server/discover'))
        def cancelled_count():
            lines=(private/'audit.jsonl').read_text().splitlines()
            try:return sum(json.loads(line).get('code')=='egress_cancelled' for line in lines)
            except json.JSONDecodeError:return 0
        wait_for(lambda:cancelled_count()==1,'cancelled operation did not finish audit/slot release')
        checks.append('in-flight-quota-cancel-closes-upstream-no-cancelled-response')
        result=call('sandbox.net.fetch',{'url':origins[0]+'/data'});assert result['status']==200
        checks.append('network-slot-reusable-after-cancel')
        entered.clear();released.clear()
        p.request('tools/call',{'name':'sandbox.net.fetch','arguments':{'url':origins[0]+'/slow'}});assert entered.wait(3)
        p.stop();children.remove(p);assert released.wait(3)
        wait_for(lambda:cancelled_count()==2,'EOF operation did not release network slot')
        p=mcp.Process(mcp_binary,config_path);children.append(p)
        result=call('sandbox.net.fetch',{'url':origins[0]+'/data'});assert result['status']==200
        checks.append('MCP-EOF-cancels-upstream-and-releases-network-slot')
        # Native SDKs use the same real API; neither process reaches the origin directly.
        sys.path.insert(0,str(ROOT/'sdk/python'))
        import osv_sandbox_client as sdk
        client=sdk.Client(config['api_url'],token=token,ca_file=config['ca_file'],cert_file=config['cert_file'],key_file=config['key_file'])
        value=client.fetch_network(origins[0]+'/echo',method='POST',body=b'\0\xff')
        assert value.body==b'\0\xff'
        checks.append('native-Python-SDK-real-API-fetch')
        module=(ROOT/'sdk/node/index.js').as_uri()
        script="import{Client}from "+json.dumps(module)+";import fs from'node:fs';const c=JSON.parse(fs.readFileSync(process.argv[1]));const sdk=new Client(c.api_url,{token:fs.readFileSync(c.token_file,'utf8'),caFile:c.ca_file,certFile:c.cert_file,keyFile:c.key_file});const r=await sdk.fetchNetwork(process.argv[2],{method:'POST',body:new Uint8Array([0,255])});if(r.body.length!==2||r.body[1]!==255)throw Error('body mismatch');"
        subprocess.run(['node','--input-type=module','-e',script,str(config_path),origins[0]+'/echo'],check=True,env=env,capture_output=True)
        checks.append('native-Node-SDK-real-API-fetch')
        p.stop();children.remove(p)
        audit=(private/'audit.jsonl').read_text()
        assert 'secret-query' not in audit and marker not in audit and 'remote-secret' not in audit and token not in audit
        assert all(any(x['event']==event for x in map(json.loads,audit.splitlines())) for event in ['net.allow','net.deny','net.complete'])
        checks.append('persistent-policy-audit-without-query-body-credentials')
        daemon.send_signal(signal.SIGTERM);assert daemon.wait(timeout=6)==0
        p=mcp.Process(mcp_binary,config_path);children.append(p)
        caps=call('sandbox.capabilities');assert not caps['features']['network_fetch']
        tools=p.receive(p.request('tools/list'))['result'];assert 'sandbox.net.fetch' not in [x['name'] for x in tools['tools']]
        p.stop();children.remove(p);checks.append('daemon-stop-withdraws-capability-no-direct-fallback')
    finally:
        for p in children:
            if p.child.poll() is None:p.child.kill();p.child.wait()
        for proc in [api,daemon]:
            if proc is not None and proc.poll() is None:
                proc.send_signal(signal.SIGTERM)
                try:proc.wait(timeout=6)
                except subprocess.TimeoutExpired:proc.kill();proc.wait()
        upstream.shutdown();upstream.server_close();ipv6.shutdown();ipv6.server_close();thread.join(timeout=2);ipv6_thread.join(timeout=2)
        daemon_log.close();api_log.close()
    return {'suite':'egress-real-process-functional/v1','passed':True,'environment':'local-real-HTTP-TLS-and-Unix-no-guest','checks':checks,'transcripts':transcripts,
            'egress_binary_sha256':hashlib.sha256(egress_binary.read_bytes()).hexdigest(),'mcp_binary_sha256':hashlib.sha256(mcp_binary.read_bytes()).hexdigest()}

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path);args=parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='egress-process-') as directory:
        work=Path(directory)
        binaries={name:work/name for name in ['osv-sandbox-egress','osv-sandbox-mcp','egress-api-fixture']}
        for name,path in binaries.items():build(path,('./tests/' if name=='egress-api-fixture' else './cmd/')+name)
        report=suite(work,binaries['osv-sandbox-egress'],binaries['osv-sandbox-mcp'],binaries['egress-api-fixture'])
    if args.output:args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k!='transcripts'}))
if __name__=='__main__':main()
