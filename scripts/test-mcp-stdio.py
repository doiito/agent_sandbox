#!/usr/bin/env python3
"""Real stdio process + mTLS mock API, validated with pinned official schemas.

All generated certificates are disposable test credentials. This is a protocol
test; real VM execution is checked separately by e2e-mcp.py.
"""
import argparse
import base64
import fcntl
import hashlib
import http.server
import json
import os
from pathlib import Path
import queue
import secrets
import signal
import ssl
import subprocess
import tempfile
import threading
import time
import termios
from urllib.parse import urlsplit, parse_qs

import jsonschema

WORKSPACE = Path(__file__).resolve().parents[1]
MODERN = '2026-07-28'
LEGACY = '2025-11-25'
VERSION_KEY = 'io.modelcontextprotocol/protocolVersion'
CAPABILITIES_KEY = 'io.modelcontextprotocol/clientCapabilities'


def fixtures(root):
    root.mkdir(parents=True, exist_ok=True)
    def openssl(*args):
        subprocess.run(['openssl', *map(str, args)], check=True, capture_output=True)
    openssl('req', '-x509', '-newkey', 'ed25519', '-nodes', '-days', '1',
            '-subj', '/CN=MCP disposable validation CA', '-keyout', root / 'ca.key', '-out', root / 'ca.crt')
    for name, purpose in [('server', 'serverAuth'), ('client', 'clientAuth')]:
        openssl('req', '-newkey', 'ed25519', '-nodes', '-subj', '/CN=' + name,
                '-keyout', root / (name + '.key'), '-out', root / (name + '.csr'))
        extension = root / (name + '.ext')
        extension.write_text('extendedKeyUsage=' + purpose + '\n' +
                             ('subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1\n' if name == 'server' else ''))
        openssl('x509', '-req', '-days', '1', '-in', root / (name + '.csr'),
                '-CA', root / 'ca.crt', '-CAkey', root / 'ca.key', '-CAcreateserial',
                '-extfile', extension, '-out', root / (name + '.crt'))
    for key in root.glob('*.key'):
        key.chmod(0o600)
    (root / 'token').write_text(secrets.token_hex(32))
    (root / 'token').chmod(0o600)
    return {'api_url': 'https://127.0.0.1:1', 'ca_file': str(root / 'ca.crt'),
            'cert_file': str(root / 'client.crt'), 'key_file': str(root / 'client.key'),
            'token_file': str(root / 'token'), 'max_in_flight': 2, 'request_timeout_ms': 10000}


class Process:
    def __init__(self, binary, config):
        env = os.environ | {'HTTPS_PROXY': 'http://127.0.0.1:1', 'NO_PROXY': ''}
        self.child = subprocess.Popen([str(binary), '-config', str(config)], stdin=subprocess.PIPE,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        self.lines = queue.Queue()
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()
        self.sequence = 0

    def _read(self):
        for line in self.child.stdout:
            self.lines.put(json.loads(line))
        self.lines.put(None)

    def send(self, value):
        self.child.stdin.write(json.dumps(value).encode() + b'\n')
        self.child.stdin.flush()

    def request(self, method, params=None, modern=True):
        self.sequence += 1
        params = dict(params or {})
        if modern:
            params['_meta'] = {VERSION_KEY: MODERN, CAPABILITIES_KEY: {}}
        self.send({'jsonrpc': '2.0', 'id': self.sequence, 'method': method, 'params': params})
        return self.sequence

    def receive(self, expected=None):
        response = self.lines.get(timeout=8)
        assert response is not None, 'MCP stdout ended unexpectedly'
        if expected is not None:
            assert response['id'] == expected, response
        return response

    def stop(self, terminate=False, expected=0):
        if terminate:
            self.child.send_signal(signal.SIGTERM)
        else:
            self.child.stdin.close()
        try:
            code = self.child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.child.kill()
            self.child.wait()
            raise AssertionError('MCP child failed to exit with blocked or idle stdio')
        stderr = self.child.stderr.read().decode()
        self.reader.join(timeout=2)
        assert code == expected, (code, stderr)
        assert 'Bearer' not in stderr and 'BEGIN PRIVATE' not in stderr, 'credential diagnostic'
        return stderr


def check_schemas():
    root = WORKSPACE / 'assets/contracts/mcp-2026-07-28'
    lock = json.loads((root / 'source-lock.json').read_text())
    for entry in lock['source_sha256'].values():
        assert hashlib.sha256((root / entry['file']).read_bytes()).hexdigest() == entry['sha256']
    return {version: json.loads((root / f'schema__{version}__schema.json').read_text())
            for version in [MODERN, LEGACY]}


def validate(schemas, version, definition, value):
    schema = schemas[version] | {'$ref': '#/$defs/' + definition}
    jsonschema.validators.validator_for(schema)(schema).validate(value)


def suite(binary, root):
    schemas = check_schemas()
    config = fixtures(root)
    token = (root / 'token').read_text()
    entered, cancelled = threading.Event(), threading.Event()
    code_entered, code_cancelled = threading.Event(), threading.Event()
    code_sid, code_cid, code_eid = '1' * 24, '2' * 24, '3' * 24
    code_records = {}
    requests = []
    cap = {'protocol': 'osv-sandbox-capabilities/v1', 'backend': 'firecracker-linux',
           'artifact_authenticated': True, 'artifact_manifest_sha256': 'a' * 64,
           'allowed_entrypoints': ['/bin/sh'],
           'features': dict.fromkeys(['one_shot_job', 'sessions', 'session_files', 'session_listing',
                                     'background_commands', 'interactive_stdin', 'environment',
                                     'working_directory', 'session_environment', 'session_working_directory',
                                     'input_files', 'stdin', 'session_timeout_update'], True),
           'limits': {'min_memory_mib': 64, 'max_memory_mib': 512, 'max_vcpus': 2,
                      'max_timeout_ms': 300000, 'max_concurrent': 4, 'max_output_bytes': 65536,
                      'session_max_ttl_ms': 300000, 'session_max_lifetime_ms': 600000}}
    cap.update(artifact_manifest_protocol='osv-sandbox-artifacts/v5', code_languages=['python', 'javascript', 'typescript'],
               methods=['GET /v1/capabilities', 'GET /v2/sessions/{id}/capabilities'],
               code_runtime={'architecture':'amd64', 'kernel_protocol':'osv-code-kernel/v2', 'python_version':'3.12.16',
                             'node_version':'22.23.4', 'typescript_version':'5.9.3', 'prewarm_language':'python',
                             'runtime_inventory_sha256':'a'*64, 'kernel_scripts_sha256':{'python.py':'b'*64,'node.cjs':'c'*64},
                             'minimum_cpu_features':['sse4_1']})
    cap['features']['code_contexts'] = True
    cap['limits'].update(code_contexts=4, code_execution_ids=256, code_source_bytes=65536, code_output_bytes=65536, code_event_page=64)

    def code_context(language='python'):
        return {'session_id':code_sid,'id':code_cid,'generation':1,'language':language,'cwd':'/workspace','state':'idle',
                'pid':42,'failure':None,'discarded_late_events':0,'discarded_late_bytes':0}

    def code_page(execution_id, after):
        row = code_records[execution_id]
        events = [{'sequence':index+1,'event':event} for index,event in enumerate(row['events'])][after:after+64]
        return {'session_id':code_sid,'id':execution_id,'context_id':code_cid,'generation':1,'language':'python','status':row['status'],
                'events':events,'last_sequence':len(row['events']),'next_sequence':after+len(events),'events_evicted':False,'failure':row.get('failure')}

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def log_message(self, *_):
            pass

        def do_GET(self):
            self.handle_api()

        def do_POST(self):
            self.handle_api()

        def do_DELETE(self):
            self.handle_api()

        def handle_api(self):
            assert self.headers.get('Authorization') == 'Bearer ' + token
            body = json.loads(self.rfile.read(int(self.headers.get('Content-Length', '0'))) or b'{}')
            requests.append((self.command, self.path, body))
            status = 200
            parsed = urlsplit(self.path)
            query = parse_qs(parsed.query)
            if self.path == '/v1/capabilities':
                value = cap
            elif parsed.path == '/v2/sessions/'+code_sid+'/capabilities':
                value = dict(cap, session_id=code_sid)
            elif parsed.path == '/v2/sessions/'+code_sid+'/contexts':
                assert 'session_id' not in body and 'operation' not in body
                value = {'session_id':code_sid,'contexts':[code_context()]} if self.command == 'GET' else code_context(body['language'])
            elif parsed.path == '/v2/sessions/'+code_sid+'/contexts/default':
                value = code_context(body['language'])
            elif parsed.path in ['/v2/sessions/'+code_sid+'/contexts/'+code_cid, '/v2/sessions/'+code_sid+'/contexts/'+code_cid+'/restart']:
                if self.command == 'DELETE':
                    assert query['generation'] == ['1']
                    value = {'session_id':code_sid,'context_id':code_cid,'removed':True}
                else:
                    value = code_context()
                    if self.command == 'POST':
                        assert body == {'generation':1}
                        value['state'] = 'stopping'
            elif parsed.path == '/v2/sessions/'+code_sid+'/code-executions':
                execution_id = body['execution_id']
                assert 'session_id' not in body and 'operation' not in body and body['context_id'] == code_cid and body['generation'] == 1
                assert execution_id not in code_records, 'source was replayed'
                code_records[execution_id] = {'status':'running','events':[{'type':'started'}]}
                if body['code'] == 'block-submit':
                    code_entered.set()
                    self.connection.settimeout(6)
                    try:
                        assert self.connection.recv(1) == b''
                        code_cancelled.set()
                    except (ssl.SSLError, ConnectionResetError):
                        code_cancelled.set()
                    return
                code_records[execution_id] = {'status':'completed','events':[{'type':'started'},
                    {'type':'result','data':{'application/json':{'integer':9007199254740993},'text/plain':'42'},'is_main_result':True},
                    {'type':'finished','status':'completed','context_usable':True}]}
                value = {'session_id':code_sid,'execution_id':execution_id,'accepted':True}
            elif parsed.path.startswith('/v2/sessions/'+code_sid+'/code-executions/'):
                execution_id = parsed.path.rsplit('/',1)[1]
                if self.command == 'DELETE':
                    assert query['context_id'] == [code_cid] and query['generation'] == ['1']
                    row = code_records[execution_id]
                    if row['status'] == 'running':
                        row['status'] = 'cancelled'
                        row['events'].append({'type':'finished','status':'cancelled','context_usable':True})
                    value = {'session_id':code_sid,'execution_id':execution_id,'accepted':True}
                else:
                    value = code_page(execution_id,int(query['after'][0]))
            elif self.path == '/v2/jobs':
                if body.get('args') == ['block']:
                    entered.set()
                    self.connection.settimeout(6)
                    try:
                        assert self.connection.recv(1) == b'', 'unexpected data after cancelled request'
                        cancelled.set()
                    except (ssl.SSLError, ConnectionResetError):
                        cancelled.set()
                    return
                assert body['artifact_manifest_sha256'] == 'a' * 64
                if body.get('args') == ['redirect']:
                    self.send_response(302)
                    self.send_header('Location', 'https://127.0.0.1:1/credential-leak')
                    self.send_header('Content-Length', '0')
                    self.end_headers()
                    return
                if body.get('args') == ['denied']:
                    status, value = 403, {'code': 'forbidden', 'message': token}
                else:
                    value = {'state': 'succeeded', 'protocol_ok': True, 'stdout': body.get('stdin', '')}
            else:
                status, value = 404, {'code': 'not_found'}
            data = json.dumps(value).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    server.daemon_threads = True
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_3
    tls.load_cert_chain(root / 'server.crt', root / 'server.key')
    tls.load_verify_locations(root / 'ca.crt')
    tls.verify_mode = ssl.CERT_REQUIRED
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    config['api_url'] = f'https://127.0.0.1:{server.server_port}'
    config_path = root / 'mcp.json'
    config_path.write_text(json.dumps(config))
    config_path.chmod(0o600)
    checks, transcripts = [], []

    def response(p, request_id, version, definition):
        value = p.receive(request_id)
        validate(schemas, version, 'JSONRPCResultResponse', value)
        validate(schemas, version, definition, value['result'])
        transcripts.append({'version': version, 'definition': definition, 'response': value})
        return value['result']

    children = []
    try:
        p = Process(binary, config_path)
        children.append(p)
        response(p, p.request('server/discover'), MODERN, 'DiscoverResult')
        checks.append('modern-discovery-official-schema')
        listed = response(p, p.request('tools/list'), MODERN, 'ListToolsResult')
        names = [t['name'] for t in listed['tools']]
        assert names == sorted(set(names)) and len(names) >= 20 and not any('.net.' in n for n in names)
        assert len([name for name in names if name.startswith('sandbox.code.')]) == 9
        assert listed['ttlMs'] == 0 and listed['cacheScope'] == 'private'
        for tool in listed['tools']:
            jsonschema.Draft202012Validator.check_schema(tool['inputSchema'])
        checks.append('authenticated-tools-official-schema-and-input-schemas')
        binary_input = base64.b64encode(b'\0\xffstdio\n').decode()
        args = {'entrypoint': '/bin/sh', 'stdin': binary_input}
        value = response(p, p.request('tools/call', {'name': 'sandbox.exec', 'arguments': args}), MODERN, 'CallToolResult')
        assert not value['isError'] and value['structuredContent']['stdout'] == binary_input
        assert json.loads(value['content'][0]['text']) == value['structuredContent']
        assert requests[-1][2]['stdin'] == binary_input
        checks.append('real-process-mtls-bearer-binary-exec-proxy-disabled')
        code_binding = {'session_id':code_sid,'context_id':code_cid,'generation':1,'execution_id':code_eid}
        for name, arguments in [
            ('sandbox.code.context.create',{'session_id':code_sid,'context_id':code_cid,'language':'python'}),
            ('sandbox.code.context.default',{'session_id':code_sid,'language':'python'}),
            ('sandbox.code.context.list',{'session_id':code_sid}),
            ('sandbox.code.context.info',{'session_id':code_sid,'context_id':code_cid}),
            ('sandbox.code.context.restart',{'session_id':code_sid,'context_id':code_cid,'generation':1}),
            ('sandbox.code.execute',dict(code_binding,code='40+2',timeout_ms=0)),
            ('sandbox.code.poll',code_binding),
            ('sandbox.code.cancel',code_binding),
            ('sandbox.code.context.remove',{'session_id':code_sid,'context_id':code_cid,'generation':1})]:
            definition = next(item for item in listed['tools'] if item['name'] == name)
            jsonschema.Draft202012Validator(definition['inputSchema']).validate(arguments)
            value = response(p,p.request('tools/call',{'name':name,'arguments':arguments}),MODERN,'CallToolResult')
            assert not value['isError'], value
            assert json.loads(value['content'][0]['text']) == value['structuredContent']
            if name == 'sandbox.code.poll':
                assert value['structuredContent']['events'][1]['event']['data']['application/json']['integer'] == 9007199254740993
        checks.append('nine-code-tools-real-mtls-schema-mapping-zero-timeout-and-exact-json-integer')
        value = response(p,p.request('tools/call',{'name':'sandbox.capabilities','arguments':{'session_id':code_sid}}),MODERN,'CallToolResult')
        assert value['structuredContent']['session_id'] == code_sid and value['structuredContent']['code_runtime']['kernel_protocol'] == 'osv-code-kernel/v2'
        checks.append('bound-owner-capabilities-through-real-stdio')
        for mode, code in [('redirect', 'redirect_rejected'), ('denied', 'forbidden')]:
            value = response(p, p.request('tools/call', {'name': 'sandbox.exec', 'arguments': {'entrypoint': '/bin/sh', 'args': [mode]}}), MODERN, 'CallToolResult')
            assert value['isError'] and value['structuredContent']['error']['code'] == code
            assert token not in json.dumps(value)
        checks.append('redirect-rejected-api-error-isError-no-credential-echo')
        p.request('tools/list', {'_meta': {VERSION_KEY: '2099-01-01'}}, modern=False)
        error = p.receive()
        validate(schemas, MODERN, 'JSONRPCErrorResponse', error)
        assert error['error']['code'] == -32022 and MODERN in error['error']['data']['supported']
        transcripts.append({'version': MODERN, 'definition': 'JSONRPCErrorResponse', 'response': error})
        checks.append('unsupported-version-error-schema')
        call = p.request('tools/call', {'name': 'sandbox.exec', 'arguments': {'entrypoint': '/bin/sh', 'args': ['block']}})
        assert entered.wait(3)
        p.send({'jsonrpc': '2.0', 'method': 'notifications/cancelled', 'params': {'requestId': call}})
        assert cancelled.wait(3), 'cancel did not close in-flight API request'
        response(p, p.request('server/discover'), MODERN, 'DiscoverResult')
        checks.append('cancel-interrupts-http-no-cancelled-response-reader-live')
        delayed_binding = dict(code_binding, execution_id='4'*24)
        code_call = p.request('tools/call',{'name':'sandbox.code.execute','arguments':dict(delayed_binding,code='block-submit')})
        assert code_entered.wait(3)
        p.send({'jsonrpc':'2.0','method':'notifications/cancelled','params':{'requestId':code_call}})
        assert code_cancelled.wait(3)
        value=response(p,p.request('tools/call',{'name':'sandbox.code.poll','arguments':delayed_binding}),MODERN,'CallToolResult')
        assert value['structuredContent']['status'] == 'running'
        assert len([row for row in requests if row[0]=='POST' and row[1].endswith('/code-executions') and row[2].get('execution_id')=='4'*24]) == 1
        assert not any(row[0]=='DELETE' and '/code-executions/'+'4'*24 in row[1] for row in requests)
        checks.append('cancelled-code-submit-http-preserves-known-id-without-replay-or-rollback')
        p.stop()
        children.remove(p)
        checks.append('EOF-process-exits')

        p = Process(binary, config_path)
        children.append(p)
        init = p.request('initialize', {'protocolVersion': LEGACY, 'capabilities': {}, 'clientInfo': {'name': 'test', 'version': '1'}}, modern=False)
        initialized = response(p, init, LEGACY, 'InitializeResult')
        assert initialized['protocolVersion'] == LEGACY
        p.send({'jsonrpc': '2.0', 'method': 'notifications/initialized'})
        legacy_tools = response(p, p.request('tools/list', modern=False), LEGACY, 'ListToolsResult')
        assert [x['name'] for x in legacy_tools['tools']] == names
        response(p, p.request('tools/call', {'name': 'sandbox.templates', 'arguments': {}}, modern=False), LEGACY, 'CallToolResult')
        value=response(p,p.request('tools/call',{'name':'sandbox.code.poll','arguments':delayed_binding},modern=False),LEGACY,'CallToolResult')
        assert value['structuredContent']['status'] == 'running'
        response(p,p.request('tools/call',{'name':'sandbox.code.cancel','arguments':delayed_binding},modern=False),LEGACY,'CallToolResult')
        value=response(p,p.request('tools/call',{'name':'sandbox.code.poll','arguments':delayed_binding},modern=False),LEGACY,'CallToolResult')
        assert value['isError'] and value['structuredContent']['status'] == 'cancelled'
        checks.append('legacy-code-handle-survives-process-restart-and-explicit-cancel-is-terminal')
        response(p, p.request('server/discover'), MODERN, 'DiscoverResult')
        p.stop(terminate=True)
        children.remove(p)
        checks.append('legacy-handshake-tools-templates-official-schema-mixed-eras')
        checks.append('SIGTERM-interrupts-idle-stdio')

        # Fill the real stdout pipe without reading it, then cancel the process.
        raw = subprocess.Popen([str(binary), '-config', str(config_path)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            capacity = fcntl.fcntl(raw.stdout.fileno(), fcntl.F_SETPIPE_SZ, 4096)
            payload = {'jsonrpc': '2.0', 'id': 'large', 'method': 'tools/list', 'params': {'_meta': {VERSION_KEY: MODERN, CAPABILITIES_KEY: {}}}}
            raw.stdin.write(json.dumps(payload).encode() + b'\n')
            raw.stdin.flush()
            deadline = time.monotonic() + 3
            while True:
                unread = int.from_bytes(fcntl.ioctl(raw.stdout.fileno(), termios.FIONREAD, b'\0' * 4), 'little')
                if unread == capacity:
                    break
                assert time.monotonic() < deadline, 'stdout pipe did not actually fill'
                time.sleep(0.01)
            raw.send_signal(signal.SIGTERM)
            assert raw.wait(timeout=5) == 0, raw.stderr.read().decode()
        finally:
            if raw.poll() is None:
                raw.kill()
                raw.wait()
            raw.stdin.close()
            raw.stdout.close()
            raw.stderr.close()
        checks.append('SIGTERM-interrupts-unread-real-stdout-pipe')
    finally:
        for p in children:
            p.child.kill()
            p.child.wait()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
    return {'suite': 'mcp-stdio-protocol/v1', 'passed': True, 'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
            'upstream_schema_commit': '3c4d91b7e832d9b74338d56eed03403ccc662123',
            'checks': checks, 'transcripts': transcripts, 'api_kind': 'disposable-mtls-mock-not-VM'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--fixtures-only', type=Path)
    args = parser.parse_args()
    if args.fixtures_only:
        config = fixtures(args.fixtures_only.resolve())
        (args.fixtures_only / 'mcp.json').write_text(json.dumps(config))
        return
    with tempfile.TemporaryDirectory(prefix='osv-mcp-stdio-') as work:
        root = Path(work)
        binary = args.binary.resolve() if args.binary else root / 'osv-sandbox-mcp'
        if not args.binary:
            subprocess.run(['go', 'build', '-buildvcs=false', '-trimpath', '-o', str(binary), './cmd/osv-sandbox-mcp'],
                           cwd=WORKSPACE, env=os.environ | {'CGO_ENABLED': '0', 'GOCACHE': os.environ.get('GOCACHE', '/tmp/osv-sandbox-go-cache')}, check=True)
        result = suite(binary, root / 'tls')
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: v for k, v in result.items() if k != 'transcripts'}))


if __name__ == '__main__':
    main()
