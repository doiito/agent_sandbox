"""ARM SDK fixed-loopback functions; server is a fixture, not host accounting."""
import copy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import subprocess
import sys
import threading

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'guest-sdk/python'))
import remote_infer as sdk

fixture=json.loads((ROOT/'tests/fixtures/inference-sdk.json').read_text())
bill=copy.deepcopy(fixture['bill'])
bill.update(closed=False,invocations=[],settled_units='0',held_units='0')
policy=fixture['capabilities']['remote_inference_policy']
calls=[]

class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def do_GET(self):
        assert self.path in ['http://inference.osv.invalid/v1/bill','http://inference.osv.invalid/v1/policy']
        self.reply(bill if self.path.endswith('/bill') else policy)
    def do_POST(self):
        assert self.path=='http://inference.osv.invalid/v1/invoke'
        request=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        assert request['endpoint']=='model' and set(request)=={'id','endpoint','payload','timeout_ms'}
        calls.append(request['id'])
        result=copy.deepcopy(fixture['result'])
        receipt=result['invocation']
        receipt['id']=request['id']
        receipt['input_bytes']=len(json.dumps(request['payload'],ensure_ascii=False,separators=(',',':')).encode())
        receipt['reserved_units']=str(9007199254740993+2*receipt['input_bytes']+3*receipt['max_output_bytes'])
        receipt['settled_units']=str(9007199254740993+2*receipt['input_bytes']+3*receipt['output_bytes'])
        bill['invocations'].append(receipt)
        bill['settled_units']=str(sum(int(item['settled_units']) for item in bill['invocations']))
        self.reply(result)
    def reply(self,value):
        data=json.dumps(value,ensure_ascii=False,separators=(',',':')).encode()
        self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)));self.end_headers()
        self.wfile.write(data)

server=ThreadingHTTPServer(('127.0.0.1',3128),Handler)
thread=threading.Thread(target=server.serve_forever);thread.start()
try:
    result=sdk.invoke('model',{'query':'ARM Python'},invocation_id='d'*24)
    assert result.task_id==bill['task_id'] and result.invocation_id=='d'*24 and int(result.invocation['settled_units'])>2**53
    print('PASS ARM64-guest-SDK-python-fixed-loopback',flush=True)
    script="""const sdk=require(process.argv[1]);
(async()=>{const result=await sdk.invoke('model',{query:'ARM Node'},{invocationId:'e'.repeat(24)});
if(result.invocationId!=='e'.repeat(24)||BigInt(result.invocation.settled_units)<=2n**53n)throw new Error('ARM Node result');
console.log('PASS ARM64-guest-SDK-node-fixed-loopback');})().catch(error=>{console.error(error);process.exitCode=1;});"""
    subprocess.run(['/opt/node/bin/node','-e',script,str(ROOT/'guest-sdk/node/remote-infer.cjs')],check=True,timeout=30)
    assert calls==['d'*24,'e'*24]
    assert len(sdk.bill()['invocations'])==2
finally:
    server.shutdown();server.server_close();thread.join()
