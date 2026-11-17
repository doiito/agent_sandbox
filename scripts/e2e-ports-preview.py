#!/usr/bin/env python3
"""Same installed candidate: real VM loopback TCP, browser preview and SIGTERM.

Requires a dedicated --port-preview code fixture. Stops its API at the end.
No latency/performance or ARM KVM acceptance is inferred from this test.
"""
import argparse
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import runpy
import signal
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
from urllib.parse import urlsplit


GUEST = r'''
import base64,hashlib,http.server,socketserver,struct,threading
MARKER = __MARKER__
def exact(stream, n):
 data = bytearray()
 while len(data) < n:
  part = stream.read(n-len(data))
  if not part: raise EOFError()
  data.extend(part)
 return bytes(data)
class Echo(socketserver.StreamRequestHandler):
 def handle(self):
  while True:
   data=self.request.recv(16384)
   if not data:return
   self.request.sendall(data)
class TCP(socketserver.ThreadingTCPServer):
 allow_reuse_address=True
 daemon_threads=True
class HTTP(http.server.BaseHTTPRequestHandler):
 protocol_version='HTTP/1.1'
 def log_message(self,*args):pass
 def do_POST(self):
  data=self.rfile.read(int(self.headers.get('Content-Length','0')))
  self.send_response(200);self.send_header('Content-Length',str(len(data)));self.end_headers()
  self.wfile.write(data);self.wfile.flush()
 def do_GET(self):
  if self.path=='/ws':
   key=self.headers['Sec-WebSocket-Key']
   accept=base64.b64encode(hashlib.sha1((key+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
   self.send_response(101);self.send_header('Upgrade','websocket');self.send_header('Connection','Upgrade')
   self.send_header('Sec-WebSocket-Accept',accept);self.end_headers();self.wfile.flush()
   try:
    while True:
     header=exact(self.rfile,2);size=header[1]&127
     if size==126:size=struct.unpack('>H',exact(self.rfile,2))[0]
     if size==127:size=struct.unpack('>Q',exact(self.rfile,8))[0]
     if not header[1]&128 or size>1048576:raise ValueError()
     mask=exact(self.rfile,4);data=exact(self.rfile,size)
     data=bytes(c^mask[i%4] for i,c in enumerate(data))
     if header[0]&15==8:return
     prefix=bytes([0x82,len(data)]) if len(data)<126 else (b'\x82\x7e'+struct.pack('>H',len(data)) if len(data)<65536 else b'\x82\x7f'+struct.pack('>Q',len(data)))
     self.wfile.write(prefix+data);self.wfile.flush()
   except (EOFError,OSError,ValueError):pass
   return
  body=(MARKER+(' credential-leak' if self.headers.get('Cookie') or self.headers.get('Authorization') else '')).encode()
  self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
tcp=TCP(('127.0.0.1',8081),Echo)
http=http.server.ThreadingHTTPServer(('127.0.0.1',8080),HTTP)
threading.Thread(target=tcp.serve_forever,daemon=True).start()
print('READY',flush=True)
http.serve_forever()
'''

NODE = r'''
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
const [root,release,sid]=process.argv.slice(1);
const {Client}=await import(pathToFileURL(release+'/sdk/node/index.js').href);
const config=JSON.parse(readFileSync(root+'/config.production.json','utf8'));
const client=new Client('https://localhost:'+config.listen.split(':').at(-1),{
 token:readFileSync(root+'/secrets/token','utf8'),certFile:root+'/tls/client.crt',keyFile:root+'/tls/client.key',caFile:root+'/tls/ca.crt'});
const session=await client.connectSession(sid),tunnel=await session.ports.open(8081,{timeoutMs:10000});
const data=Buffer.alloc(32768,0xa5),chunks=[];
const writer=(async()=>{await tunnel.write(data.subarray(0,16384));await tunnel.write(data.subarray(16384));await tunnel.closeWrite();})();
for(;;){const frame=await tunnel.readFrame();if(frame.kind==='data')chunks.push(frame.data);if(frame.kind==='finished'){assert.equal(frame.info.status,'completed');break;}}
await writer;assert.deepEqual(Buffer.concat(chunks),data);
const grant=await session.ports.createPreview(8080,{ttlMs:10000});assert(grant.bootstrapURL);
assert(!Object.hasOwn(await grant.info(),'bootstrap_url'));assert.equal((await grant.revoke()).status,'revoked');
console.log(JSON.stringify({passed:true,checks:3}));
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--package', type=Path, required=True)
    parser.add_argument('--expected-mode', choices=['cold', 'warm'], required=True)
    parser.add_argument('--in-netns', action='store_true')
    args = parser.parse_args()
    root = args.root.resolve()
    api_unit = root.name + '-api.service'
    pid = int(subprocess.check_output(['systemctl', 'show', '-p', 'MainPID', '--value', api_unit], text=True).strip())
    assert pid > 1
    if not args.in_netns:
        raise SystemExit(subprocess.run(['nsenter', '-t', str(pid), '-n', sys.executable, __file__, '--root', str(root),
            '--package', str(args.package), '--expected-mode', args.expected_mode, '--in-netns']).returncode)
    release = next((root / 'releases').iterdir())
    sys.path.insert(0, str(release / 'sdk/python'))
    import osv_sandbox_client as sdk
    config = json.loads((root / 'config.production.json').read_text())
    url = 'https://localhost:' + config['listen'].rsplit(':', 1)[1]
    options = dict(ca_file=str(root / 'tls/ca.crt'), cert_file=str(root / 'tls/client.crt'), key_file=str(root / 'tls/client.key'))
    a = sdk.Client(url, token=(root / 'secrets/token').read_text(), **options)
    b = sdk.Client(url, token=(root / 'secrets/token-b').read_text(), **options)
    browser_context = ssl.create_default_context(cafile=root / 'tls/ca.crt')
    cases, sessions, local = [], [], []
    stopped = False

    def check(name, condition):
        assert condition, name
        cases.append(name)
        print('PASS vm-ports-' + name, flush=True)

    def wait(action, seconds=30):
        deadline = time.monotonic() + seconds
        while not action():
            assert time.monotonic() < deadline, 'observation timeout'
            time.sleep(.025)

    class BrowserConnection(http.client.HTTPSConnection):
        def connect(self):
            raw = socket.create_connection(('127.0.0.1', self.port), self.timeout)
            try:
                self.sock = browser_context.wrap_socket(raw, server_hostname=self.host)
            except BaseException:
                raw.close()
                raise

    def browser(target, cookie=None, body=None, token=None):
        parsed = urlsplit(target)
        conn = BrowserConnection(parsed.hostname, parsed.port, timeout=4)
        headers = {}
        if cookie: headers['Cookie'] = cookie
        if token: headers['Authorization'] = 'Bearer ' + token
        conn.request('POST' if body is not None else 'GET', parsed.path + ('?' + parsed.query if parsed.query else ''), body, headers)
        response = conn.getresponse()
        result = response.status, response.read(), response.getheader('Set-Cookie')
        conn.close()
        return result

    def authorize(grant):
        status, _, cookie = browser(grant['bootstrap_url'])
        assert status == 303 and cookie and cookie.startswith('__Host-osv-preview=')
        return cookie.split(';', 1)[0]

    def websocket(origin, cookie):
        parsed = urlsplit(origin)
        conn = BrowserConnection(parsed.hostname, parsed.port, timeout=4)
        conn.connect()
        conn.request('GET', '/ws', headers={'Cookie': cookie, 'Origin': origin, 'Connection': 'Upgrade', 'Upgrade': 'websocket',
            'Sec-WebSocket-Version': '13', 'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ=='})
        response = conn.getresponse()
        assert response.status == 101 and response.getheader('Sec-WebSocket-Accept') == 's3pPLMBiTxaQ9kYGzzhZRbK+xOo='
        local.append(conn)
        return conn, response.fp

    def exact(stream, size):
        data = bytearray()
        while len(data) < size:
            block = stream.read(size-len(data))
            assert block, 'unexpected websocket EOF'
            data.extend(block)
        return bytes(data)

    def binary_echo(session):
        tunnel = session.ports.open(8081, timeout_ms=10000)
        local.append(tunnel)
        data = bytes(range(256)) * 800
        errors = []
        def write():
            try:
                for offset in range(0, len(data), 16384): tunnel.write(data[offset:offset+16384])
                tunnel.close_write()
            except BaseException as error: errors.append(error)
        writer = threading.Thread(target=write, daemon=True)
        writer.start()
        chunks, eof = [], False
        while True:
            frame = tunnel.read_frame()
            if frame.kind == 'data': chunks.append(frame.data)
            elif frame.kind == 'eof': eof = True
            else:
                assert frame.info['status'] == 'completed' and frame.info['sent_bytes'] == frame.info['received_bytes'] == len(data)
                break
        writer.join(2)
        assert not writer.is_alive() and not errors and eof and b''.join(chunks) == data
        return tunnel

    report = dict(suite='same-candidate-port-preview-kvm/v1', passed=False, mode=args.expected_mode, cases=cases,
        actual_vsock=True, performance_gate_evidence=False, formal_release=False)
    try:
        cap = a.capabilities()
        check('signed-v6-native-and-preview', cap['artifact_manifest_protocol'] in ('osv-sandbox-artifacts/v6', 'osv-sandbox-artifacts/v7', 'osv-sandbox-artifacts/v8') and
              cap['features']['port_forward'] and cap['features']['port_preview'])
        for client in (a, b):
            if args.expected_mode == 'warm':
                wait(lambda: any(row['name'] == 'code' and row['ready'] >= 1 for row in client.doctor()['warm_pool']['profiles']))
            session = client.create_session(sdk.SessionRequest(memory_mib=1024, ttl_ms=180000))
            sessions.append(session)
            check('session-mode-' + str(len(sessions)), session.created.startup_mode == args.expected_mode)
            source = GUEST.replace('__MARKER__', repr(session.id))
            compile(source, '<guest-server>', 'exec')
            session.write_file('/workspace/preview-server.py', source.encode())
            command = session.start_command(sdk.SessionCommand('/opt/python/bin/python3.12', ('-u', '/workspace/preview-server.py'), timeout_ms=170000))
            startup = dict(session_id=session.id, stdout='', stderr='', output_frames=0)
            report.setdefault('guest_startup', []).append(startup)
            events = command.events(timeout_ms=10000)
            try:
                for event in events:
                    if event.stream in ('stdout', 'stderr'):
                        startup[event.stream] += event.data.decode('utf-8', errors='replace')
                        startup['output_frames'] += 1
                        assert len(startup['stdout']) + len(startup['stderr']) <= 4096
                    if startup['stdout'] == 'READY\n' or event.result is not None:
                        break
            finally:
                events.close()
            check('guest-loopback-ready-' + str(len(sessions)), startup['stdout'] == 'READY\n' and not startup['stderr'])
        sa, sb = sessions
        tunnel = binary_echo(sa)
        check('python-binary-duplex-halfclose-finished', tunnel.info()['status'] == 'completed')
        denied = False
        try: sa.ports.open(3128)
        except sdk.APIError as error: denied = error.status == 403
        check('port-policy-deny', denied)
        denied = False
        try: b.connect_session(sa.id)
        except sdk.APIError as error: denied = error.status == 404
        check('cross-tenant-owner-deny', denied)
        ga = sa.ports.create_preview(8080, ttl_ms=30000)
        gb = sb.ports.create_preview(8080, ttl_ms=30000)
        ca, cb = authorize(ga.created), authorize(gb.created)
        check('preview-origin-per-vm', ga.created['origin'] != gb.created['origin'])
        check('bootstrap-no-replay', browser(ga.bootstrap_url)[0] == 401)
        check('browser-to-owner-vm', browser(ga.created['origin']+'/', ca, token=a._token)[:2] == (200, sa.id.encode()))
        check('browser-to-other-vm', browser(gb.created['origin']+'/', cb)[:2] == (200, sb.id.encode()))
        check('cookie-cannot-cross-vm', browser(gb.created['origin']+'/', ca)[0] == 401)
        data = bytes(range(256))*800
        check('preview-binary-http', browser(ga.created['origin']+'/echo', ca, data)[:2] == (200, data))
        ws, stream = websocket(ga.created['origin'], ca)
        mask = b'\x01\x02\x03\x04'
        ws.sock.sendall(b'\x82\xff'+struct.pack('>Q',len(data))+mask+bytes(c^mask[i%4] for i,c in enumerate(data)))
        header = exact(stream,2); size = header[1]&127
        if size == 126: size = struct.unpack('>H',exact(stream,2))[0]
        if size == 127: size = struct.unpack('>Q',exact(stream,8))[0]
        check('preview-binary-websocket', header[0] == 0x82 and not header[1]&128 and exact(stream,size) == data)
        check('revoke-authority', ga.revoke()['status'] == 'revoked')
        check('revoke-closes-websocket', stream.read(1) == b'')
        check('other-vm-survives-revoke', browser(gb.created['origin']+'/', cb)[0] == 200)
        check('get-does-not-reissue-secret', 'bootstrap_url' not in gb.info())
        node = subprocess.run(['node', '--input-type=module', '-e', NODE, str(root), str(release), sa.id], text=True, capture_output=True, check=True, timeout=30)
        check('installed-node-native-and-preview', json.loads(node.stdout)['passed'])
        MCP = runpy.run_path(str(Path(__file__).with_name('e2e-mcp.py')))['MCP']
        mcp_config = root / 'mcp-preview.json'
        mcp_config.write_text(json.dumps(dict(api_url=url, ca_file=options['ca_file'], cert_file=options['cert_file'], key_file=options['key_file'], token_file=str(root/'secrets/token'), max_in_flight=1)))
        mcp_config.chmod(0o600)
        child = MCP(release/'bin/osv-sandbox-mcp', mcp_config)
        mid = 'd'*24
        native_args = dict(session_id=sa.id, connection_id='e'*24, port=8081)
        try:
            assert child.call('sandbox.ports.open', **native_args, max_bytes=1024, timeout_ms=10000)['transport_open']
            payload = b'\x00\xffmcp'
            assert child.call('sandbox.ports.write', **native_args, data_base64=base64.b64encode(payload).decode())['written_bytes'] == len(payload)
            assert child.call('sandbox.ports.close_write', **native_args)['write_closed']
            received = bytearray()
            while True:
                packet = child.call('sandbox.ports.read', **native_args)
                if packet['kind'] == 'data': received.extend(base64.b64decode(packet['data_base64'], validate=True))
                elif packet['kind'] == 'finished':
                    check('mcp-native-binary-halfclose-finished', received == payload and packet['connection']['status'] == 'completed')
                    break
            value = child.call('sandbox.preview.create', session_id=sa.id, preview_id=mid, port=8080, ttl_ms=10000)
        finally: child.stop()
        mcookie = authorize(value)
        check('mcp-exit-keeps-browser-grant', browser(value['origin']+'/',mcookie)[0] == 200)
        child = MCP(release/'bin/osv-sandbox-mcp', mcp_config, True)
        try:
            check('mcp-legacy-known-port-info', child.call('sandbox.ports.info', **native_args)['connection']['status'] == 'completed')
            observed = child.call('sandbox.preview.info', session_id=sa.id, preview_id=mid, port=8080)
            revoked = child.call('sandbox.preview.revoke', session_id=sa.id, preview_id=mid, port=8080)
            check('mcp-legacy-known-id-cleanup', observed['status']=='active' and 'bootstrap_url' not in observed and revoked['status']=='revoked')
        finally: child.stop()
        sb.close()
        check('session-close-revokes-preview', browser(gb.created['origin']+'/',cb)[0] == 404)
        final_grant = sa.ports.create_preview(8080, ttl_ms=30000)
        final_cookie = authorize(final_grant.created)
        final_ws, final_stream = websocket(final_grant.created['origin'], final_cookie)
        pending = sa.ports.open(8081, timeout_ms=30000)
        local.append(pending)
        os.kill(pid, signal.SIGTERM)
        stopped = True
        wait(lambda: subprocess.check_output(['systemctl','show','-p','MainPID','--value',api_unit],text=True).strip()=='0',10)
        check('sigterm-api-exits', True)
        check('sigterm-closes-preview-websocket', final_stream.read(1)==b'')
        closed = False
        try:
            frame = pending.read_frame()
            closed = frame.kind == 'finished' and frame.info['status'] in ('cancelled', 'failed')
        except sdk.TransportError: closed = True
        check('sigterm-closes-native-transport', closed)
        report['passed'] = True
    finally:
        for handle in local:
            try: handle.close()
            except BaseException: pass
        if not stopped:
            for session in reversed(sessions):
                try: session.close()
                except BaseException: pass
        with args.package.open('rb') as package:
            report['candidate_sha256'] = hashlib.file_digest(package,'sha256').hexdigest()
        (root/'results'/('ports-preview-'+args.expected_mode+'.json')).write_text(json.dumps(report,indent=2)+'\n')


if __name__ == '__main__': main()
