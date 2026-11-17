#!/usr/bin/env python3
"""Disposable local TLS upstream inside the validation-only network namespace."""
import argparse
import hashlib
import http.server
import hmac
import json
from pathlib import Path
import signal
import socket
import ssl
import threading

p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);args=p.parse_args();root=args.root
lock=threading.Lock();events=root/'results/upstream-events.jsonl'
def record(value):
 with lock:
  with events.open('a') as stream:stream.write(json.dumps(value)+'\n');stream.flush()
class Handler(http.server.BaseHTTPRequestHandler):
 protocol_version='HTTP/1.1'
 def log_message(self,*_):pass
 def do_GET(self):self.respond()
 def do_POST(self):self.respond()
 def respond(self):
  body=self.rfile.read(int(self.headers.get('Content-Length','0')))
  record({'event':'request','path':self.path,'method':self.command,'header_names':[key.lower() for key in self.headers],'body_bytes':len(body),'body_sha256':hashlib.sha256(body).hexdigest()})
  if self.path=='/infer':
   credential=root/'egress-state/provider-credential'
   authorized=credential.is_file() and hmac.compare_digest(self.headers.get('Authorization',''),'Bearer '+credential.read_text())
   record({'event':'model-request','authorized':authorized,'body_bytes':len(body),'body_sha256':hashlib.sha256(body).hexdigest()})
   payload=json.loads(body)
   if not authorized:
    self.send_response(401);self.send_header('Content-Length','0');self.end_headers();return
   if payload.get('mode')=='pending':
    self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length','100');self.end_headers();self.wfile.flush();record({'event':'model-pending'});self.connection.settimeout(15)
    try:
     if self.connection.recv(1)==b'':record({'event':'model-pending-closed'})
    except (ssl.SSLError,ConnectionResetError):record({'event':'model-pending-closed'})
    return
   value={'text':'\u2028'*140000} if payload.get('mode')=='unicode' else {'answer':'ok'}
   data=json.dumps(value,ensure_ascii=False,separators=(',',':')).encode()
   self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data);return
  if self.path.startswith('/redirect'):
   self.send_response(302);self.send_header('Location','https://127.0.0.1:44443/final');self.send_header('Content-Length','0');self.end_headers();return
  if self.path=='/denied-redirect':
   self.send_response(302);self.send_header('Location','https://unlisted.invalid/data');self.send_header('Content-Length','0');self.end_headers();return
  if self.path.startswith('/slow'):
   self.send_response(200);self.send_header('Content-Length','100');self.end_headers();self.wfile.flush();record({'event':'slow-entered','path':self.path});self.connection.settimeout(10)
   try:
    if self.connection.recv(1)==b'':record({'event':'slow-closed','path':self.path})
   except (ssl.SSLError,ConnectionResetError):record({'event':'slow-closed','path':self.path})
   return
  status,data=200,b'\0\xff'+b'egress-real-KVM-fixture'
  if self.path=='/echo':data=body
  if self.path=='/large':data=b'x'*4097
  if self.path=='/not-found':status,data=404,b'missing'
  self.send_response(status);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
class IPv6(http.server.ThreadingHTTPServer):address_family=socket.AF_INET6
tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);tls.load_cert_chain(root/'tls/server.crt',root/'tls/server.key')
servers=[http.server.ThreadingHTTPServer(('127.0.0.1',44443),Handler),IPv6(('::1',44444),Handler)]
for server in servers:
 server.socket=tls.wrap_socket(server.socket,server_side=True)
 threading.Thread(target=server.serve_forever,daemon=True).start()
plain=http.server.ThreadingHTTPServer(('127.0.0.1',44445),Handler)
threading.Thread(target=plain.serve_forever,daemon=True).start()
servers.append(plain)
(root/'upstream-ready.json').write_text(json.dumps({'IPv4':44443,'IPv6':44444}))
stop=threading.Event()
for sig in (signal.SIGINT,signal.SIGTERM):signal.signal(sig,lambda *_:stop.set())
stop.wait()
for server in servers:server.shutdown();server.server_close()
