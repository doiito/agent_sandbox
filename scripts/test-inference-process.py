#!/usr/bin/env python3
"""Actual non-root production egress inference process; no VM/guest SDK claim."""
import argparse
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
TOKEN = 'disposable-inference-process-token'
SECRET = 'disposable-provider-fixture-key'
BINDING = {'tenant': 'model-a', 'task_id': '1' * 24, 'vm_id': '2' * 24, 'lease_id': '3' * 24}
PROTOCOL = 'osv-sandbox-inference-root/v1'


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def unix_request(path, route, value=None, token=None):
    data = b'' if value is None else json.dumps(value, separators=(',', ':')).encode()
    connection = socket.socket(socket.AF_UNIX)
    connection.settimeout(10)
    try:
        connection.connect(str(path))
        headers = [f'{"GET" if value is None else "POST"} {route} HTTP/1.1', 'Host: egress.invalid',
                   'Connection: close', 'Content-Type: application/json', f'Content-Length: {len(data)}']
        if token:
            headers.append('Authorization: Bearer ' + token)
        connection.sendall(('\r\n'.join(headers) + '\r\n\r\n').encode() + data)
        response = http.client.HTTPResponse(connection)
        response.begin()
        body = response.read((1 << 20) + (64 << 10) + 1)
        assert len(body) <= (1 << 20) + (64 << 10), 'unbounded inference response'
        status = response.status
        response.close()
        return status, json.loads(body)
    finally:
        connection.close()


def peer_probe(main, control):
    status, policy = unix_request(main, '/v1/inference/policy', token=TOKEN)
    assert status == 200 and policy['endpoints'][0]['name'] == 'model'
    status, result = unix_request(main, '/v1/inference/root/bind', {'protocol': PROTOCOL, 'binding': BINDING}, token=TOKEN)
    assert status == 403 and result['error']['code'] == 'inference_root_required'
    connection = socket.socket(socket.AF_UNIX)
    connection.settimeout(3)
    try:
        connection.connect(str(control))
        connection.sendall(b'POST /v1/inference/root/bind HTTP/1.1\r\nHost: egress.invalid\r\nContent-Length: 0\r\n\r\n')
        try:
            assert connection.recv(1) == b'', 'non-root peer entered the dedicated control server'
        except ConnectionResetError:
            pass
    finally:
        connection.close()
    print(json.dumps({'passed': True, 'kernel_uid': os.geteuid(), 'bearer_cannot_grant': True, 'control_rejects_same_service_uid': True}))


def suite(binary, report):
    assert os.geteuid() == 0, 'Process fixture needs root to launch a non-root production daemon'
    base = ROOT / 'build/validation/inference-service'
    base.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix='process-', dir=base))
    work.chmod(0o755)
    service = work / 'service'
    service.mkdir(mode=0o700)
    os.chown(service, 65534, 65534)
    checks, observations, clients = [], [], []
    slow_events = {name: (threading.Event(), threading.Event()) for name in ['close', 'kill', 'stop']}
    child = None
    provider = None
    completed = False
    log = (report / 'daemon.log').open('a')
    try:
        key, cert = work / 'provider.key', work / 'provider.crt'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ed25519', '-nodes', '-days', '1',
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
                        '-keyout', str(key), '-out', str(cert)], capture_output=True, check=True)
        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'
            def log_message(self, *_):
                pass
            def do_POST(self):
                body = self.rfile.read(int(self.headers.get('Content-Length', 0)))
                valid = self.headers.get('Authorization') == 'Bearer ' + SECRET
                observations.append({'path': self.path, 'input_bytes': len(body), 'input_sha256': hashlib.sha256(body).hexdigest(),
                                     'credential_matched': valid, 'tls_version': self.connection.version()})
                if not valid:
                    self.send_error(401)
                    return
                payload = json.loads(body)
                slow = payload.get('slow')
                data = b'{"result":"fixture-answer"}'
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(128 if slow else len(data)))
                self.send_header('Connection', 'close')
                self.end_headers()
                if slow:
                    self.wfile.flush()
                    entered, ended = slow_events[slow]
                    entered.set()
                    self.connection.settimeout(10)
                    try:
                        self.connection.recv(1)
                    except OSError:
                        pass
                    ended.set()
                else:
                    self.wfile.write(data)
        provider = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cert, key)
        provider.socket = tls.wrap_socket(provider.socket, server_side=True)
        threading.Thread(target=provider.serve_forever, daemon=True).start()
        secret = service / 'provider.token'
        secret.write_text(SECRET + '\n')
        secret.chmod(0o600)
        os.chown(secret, 65534, 65534)
        endpoint = f'https://localhost:{provider.server_port}/invoke'
        tenant = {'id': 'model-a', 'token_sha256': hashlib.sha256(TOKEN.encode()).hexdigest(), 'allowed_entrypoints': ['/bin/sh'],
                  'requests_per_second': 100, 'burst': 100, 'max_concurrent': 1,
                  'egress': {'allowed_origins': [f'https://localhost:{provider.server_port}'], 'allowed_cidrs': ['127.0.0.1/32', '::1/128'],
                             'max_concurrent': 1, 'max_request_bytes': 4096, 'max_response_bytes': 4096, 'timeout_ms': 30000},
                  'inference': {'endpoints': [{'name': 'model', 'url': endpoint, 'credential': {'file': str(secret), 'header': 'Authorization', 'prefix': 'Bearer '},
                                               'price': {'request_units': '5', 'input_byte_units': '2', 'output_byte_units': '3'}}],
                                'max_invocations': 16, 'budget_units': '100000'}}
        auth = {'protocol': 'osv-sandbox-auth/v1', 'tenants': [tenant, {'id': 'model-b', 'token_sha256': hashlib.sha256(b'disabled-inference-fixture').hexdigest(),
                'allowed_entrypoints': ['/bin/sh'], 'requests_per_second': 100, 'burst': 100, 'max_concurrent': 1}]}
        auth_path = work / 'auth.json'
        auth_path.write_text(json.dumps(auth)); auth_path.chmod(0o644)
        original_auth_sha256 = sha(auth_path)
        main, control = service / 'e.sock', service / 'inference.sock'
        ledger = service / 'ledger'
        config = work / 'egress.json'
        config.write_text(json.dumps({'production': True, 'guest_proxy': True, 'socket_path': str(main), 'auth_policy_path': str(auth_path),
                          'audit_log_path': str(service / 'audit.jsonl'), 'ca_file': str(cert), 'max_concurrent': 2,
                          'inference': {'ledger_directory': str(ledger), 'max_tasks': 16}}))
        config.chmod(0o644)
        def start():
            process = subprocess.Popen([str(binary), '-config', str(config)], stdout=log, stderr=log, user=65534, group=65534,
                                       extra_groups=[], start_new_session=True, umask=0o077,
                                       env=os.environ | {'HTTP_PROXY': 'http://127.0.0.1:1', 'HTTPS_PROXY': 'http://127.0.0.1:1', 'NO_PROXY': ''})
            deadline = time.monotonic() + 5
            while True:
                assert process.poll() is None, 'production daemon exited; inspect daemon.log'
                if main.exists() and control.exists():
                    try:
                        probe = socket.socket(socket.AF_UNIX); probe.settimeout(.2); probe.connect(str(control)); probe.close()
                        break
                    except OSError:
                        pass
                assert time.monotonic() < deadline, 'production inference sockets not ready'
                time.sleep(.01)
            return process
        def rpc(operation, binding=BINDING, invocation=None, digest=None):
            value = {'protocol': PROTOCOL, 'binding': binding}
            if invocation is not None:
                value['invocation'] = invocation
            if digest is not None:
                value['exported_sha256'] = digest
            return unix_request(main if operation == 'invoke' else control, '/v1/inference/root/' + operation, value)
        def invoke(number, payload):
            return {'id': f'{number:024x}', 'endpoint': 'model', 'payload': payload}
        child = start()
        assert main.stat().st_uid == control.stat().st_uid == ledger.stat().st_uid == 65534
        checks.append('actual-nonroot-production-command-and-persistent-owned-ledger')
        probe = subprocess.run(['/usr/bin/python3', str(Path(__file__).resolve()), '--peer-probe', str(main), str(control)],
                               user=65534, group=65534, extra_groups=[], capture_output=True, text=True, check=True)
        peer = json.loads(probe.stdout)
        assert peer['passed'] and peer['kernel_uid'] == 65534
        checks.append('actual-kernel-service-uid-cannot-grant-or-enter-root-control')
        status, policy = unix_request(main, '/v1/inference/policy', token=TOKEN)
        assert status == 200 and policy['endpoints'][0]['name'] == 'model'
        assert SECRET not in json.dumps(policy) and str(secret) not in json.dumps(policy) and endpoint not in json.dumps(policy)
        checks.append('tenant-discovery-redacts-credential-and-provider-location')
        assert rpc('bind')[0] == 200
        request = invoke(1, {'prompt': 'fixture-private-prompt'})
        status, answer = rpc('invoke', invocation=request)
        assert status == 200 and answer['data'] == {'result': 'fixture-answer'} and answer['invocation']['state'] == 'succeeded'
        assert rpc('invoke', invocation=request)[0] == 409 and len(observations) == 1
        checks.append('real-provider-TLS-private-credential-known-id-no-replay')
        status, state = unix_request(main, '/v1/inference/state', token=TOKEN)
        assert status == 200 and len(state['policy_sha256']) == 64
        # Synthetic root fixture only. The actual launcher keeps its own
        # startup snapshot rather than fetching a new digest on reconnect.
        policy_digest = state['policy_sha256']
        connection = socket.socket(socket.AF_UNIX); connection.settimeout(5); connection.connect(str(main))
        connection.sendall((f'POST /v1/guest-proxy HTTP/1.1\r\nHost: egress.invalid\r\nConnection: Upgrade\r\nUpgrade: osv-guest-proxy/1\r\n'
                            f'X-OSV-Tenant: {BINDING["tenant"]}\r\nX-OSV-Task: {BINDING["task_id"]}\r\nX-OSV-VM: {BINDING["vm_id"]}\r\n'
                            f'X-OSV-Lease: {BINDING["lease_id"]}\r\nX-OSV-Inference: remote-infer-v1\r\n'
                            f'X-OSV-Inference-Policy: {policy_digest}\r\nContent-Length: 0\r\n\r\n').encode())
        response = http.client.HTTPResponse(connection); response.begin(); assert response.status == 101; response.close()
        guest_request = json.dumps(invoke(2, {'prompt': 'fixture-private-guest-prompt'})).encode()
        connection.sendall((f'POST http://inference.osv.invalid/v1/invoke HTTP/1.1\r\nHost: inference.osv.invalid\r\n'
                            f'X-OSV-Task: {"f" * 24}\r\nX-OSV-Tenant: model-b\r\nContent-Length: {len(guest_request)}\r\n\r\n').encode() + guest_request)
        response = http.client.HTTPResponse(connection); response.begin(); assert response.status == 200
        guest_reply = json.loads(response.read()); response.close(); connection.close()
        assert guest_reply['invocation']['id'] == invoke(2, {})['id']
        status, bill = unix_request(main, '/v1/inference/bills/' + BINDING['task_id'], token=TOKEN)
        assert status == 200 and bill['task_id'] == BINDING['task_id'] and bill['vm_id'] != bill['task_id'] and len(bill['invocations']) == 2
        checks.append('real-upgraded-guest-protocol-uses-outer-logical-task-not-inner-spoof')
        status, _ = unix_request(main, '/v1/inference/bills/' + BINDING['task_id'], token='disabled-inference-fixture')
        assert status == 404
        checks.append('cross-tenant-history-hidden-with-404')
        slow_results = {}
        def pending(name, binding, number):
            try:
                slow_results[name] = rpc('invoke', binding, invoke(number, {'slow': name}))
            except (OSError, http.client.HTTPException):
                slow_results[name] = 'transport-closed'
        thread = threading.Thread(target=pending, args=('close', BINDING, 3), daemon=True); clients.append(thread); thread.start()
        assert slow_events['close'][0].wait(3)
        status, pending_bill = unix_request(main, '/v1/inference/bills/' + BINDING['task_id'], token=TOKEN)
        assert status == 200 and pending_bill['invocations'][-1]['state'] == 'reserved'
        status, closed = rpc('close')
        thread.join(3)
        assert status == 200 and closed['bill']['closed'] and closed['bill']['invocations'][-1]['state'] == 'uncertain'
        assert not thread.is_alive() and slow_results['close'][0] == 499 and slow_events['close'][1].wait(3)
        assert rpc('bind')[0] == 409
        checks.append('independent-history-and-control-close-join-full-model-slot')
        second = BINDING | {'task_id': '4' * 24, 'vm_id': '5' * 24, 'lease_id': '6' * 24}
        assert rpc('bind', second)[0] == 200
        thread = threading.Thread(target=pending, args=('kill', second, 4), daemon=True); clients.append(thread); thread.start()
        assert slow_events['kill'][0].wait(3)
        child.kill(); assert child.wait(timeout=3) == -signal.SIGKILL
        thread.join(3); assert not thread.is_alive() and slow_results['kill'] == 'transport-closed'
        assert slow_events['kill'][1].wait(3)
        child = start()
        status, recovered = unix_request(main, '/v1/inference/bills/' + second['task_id'], token=TOKEN)
        assert status == 200 and recovered['invocations'][0]['state'] == 'uncertain' and recovered['invocations'][0]['code'] == 'inference_restarted'
        assert int(recovered['held_units']) > 0 and recovered['settled_units'] == '0'
        assert rpc('invoke', second, invoke(4, {'slow': 'kill'}))[0] == 409 and len(observations) == 4
        assert rpc('close', second)[0] == 200
        checks.append('actual-daemon-SIGKILL-restart-keeps-budget-and-never-replays')
        status, exported = rpc('export')
        assert status == 200
        archive = json.dumps(exported['record'], ensure_ascii=False, separators=(',', ':')).encode()
        assert hashlib.sha256(archive).hexdigest() == exported['sha256']
        exported_path = report / 'closed-task-export.json'
        with exported_path.open('wb') as stream:
            stream.write(archive); stream.flush(); os.fsync(stream.fileno())
        descriptor = os.open(report, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        assert sha(exported_path) == exported['sha256']
        # Exercise the commands shipped in this exact static service ELF. The
        # live ledger remains owned by the non-root daemon throughout.
        admin_archive = report / 'bill-archives/closed-task.json'
        def admin(operation, *arguments, offline=False, expected=0):
            config_path = work / 'missing-offline-config.json' if offline else config
            command = [str(binary), '-config', str(config_path), operation, *map(str, arguments)]
            result = subprocess.run(command, capture_output=True, text=True, timeout=20)
            assert result.returncode == expected, f'{operation}: unexpected exit {result.returncode}: {result.stderr}'
            if expected == 0:
                value = json.loads(result.stdout)
                assert value['protocol'] == 'osv-sandbox-inference-admin/v1' and value['verified'] is True
                assert value['tenant'] == BINDING['tenant'] and value['task_id'] == BINDING['task_id']
                assert value['sha256'] == exported['sha256']
                return value
            assert not result.stdout
            return None
        assert not admin('bill-export', '-tenant', BINDING['tenant'], '-task', BINDING['task_id'], '-output', admin_archive)['retired']
        assert admin_archive.stat().st_mode & 0o777 == 0o600
        assert admin_archive.parent.stat().st_mode & 0o777 == 0o700
        admin_digest = sha(admin_archive)
        admin('bill-export', '-tenant', BINDING['tenant'], '-task', BINDING['task_id'], '-output', admin_archive, expected=1)
        assert sha(admin_archive) == admin_digest and len(observations) == 4
        assert not admin('bill-verify', '-archive', admin_archive, offline=True)['retired']
        checks.append('shipped-static-CLI-private-export-no-overwrite-and-config-independent-offline-verify')
        assert rpc('retire', digest='0' * 64)[0] == 409
        assert admin('bill-retire', '-archive', admin_archive)['retired']
        assert unix_request(main, '/v1/inference/bills/' + BINDING['task_id'], token=TOKEN)[0] == 404
        assert sha(admin_archive) == admin_digest
        checks.append('closed-bill-durable-export-exact-digest-before-explicit-retirement')
        third = BINDING | {'task_id': '7' * 24, 'vm_id': '8' * 24, 'lease_id': '9' * 24}
        assert rpc('bind', third)[0] == 200
        thread = threading.Thread(target=pending, args=('stop', third, 5), daemon=True); clients.append(thread); thread.start()
        assert slow_events['stop'][0].wait(3)
        child.send_signal(signal.SIGTERM); assert child.wait(timeout=3) == 0
        thread.join(3)
        assert not thread.is_alive() and slow_events['stop'][1].wait(3)
        assert slow_results['stop'] == 'transport-closed' or slow_results['stop'][0] == 499
        checks.append('actual-daemon-SIGTERM-cancels-joins-and-persists-pending-model')
        del tenant['inference']; del tenant['egress']
        auth_path.write_text(json.dumps(auth)); auth_path.chmod(0o644)
        child = start()
        status, closed = rpc('close', third)
        assert status == 200 and closed['bill']['closed'] and closed['bill']['invocations'][0]['state'] == 'uncertain' and int(closed['bill']['held_units']) > 0
        assert unix_request(main, '/v1/inference/bills/' + third['task_id'], token=TOKEN)[0] == 200
        assert unix_request(main, '/v1/inference/policy', token=TOKEN)[0] == 403
        checks.append('revoked-egress-policy-still-allows-root-close-and-owned-history')
        child.send_signal(signal.SIGTERM); assert child.wait(timeout=3) == 0
        assert not main.exists() and not control.exists()
        assert not admin('bill-verify', '-archive', admin_archive, offline=True)['retired']
        assert len(observations) == 5
        checks.append('shipped-CLI-offline-verify-after-daemon-stop-preserves-archive-and-never-replays')
        events = (service / 'audit.jsonl').read_bytes()
        assert all(marker not in events for marker in [SECRET.encode(), TOKEN.encode(), b'fixture-private-prompt', b'fixture-private-guest-prompt', b'fixture-answer'])
        records = [json.loads(line) for line in events.splitlines()]
        assert any(item['event'] == 'infer.close' for item in records) and any(item['event'] == 'infer.allow' for item in records)
        (report / 'audit.jsonl').write_bytes(events)
        (report / 'provider-observations.json').write_text(json.dumps(observations, indent=2) + '\n')
        shutil.copyfile(cert, report / 'provider-ca.crt')
        assert all(item['credential_matched'] for item in observations) and len(observations) == 5
        checks.append('both-sockets-removed-final-audit-redacted-and-no-late-provider-call')
        completed = True
        return {'protocol': 'osv-inference-production-process/v1', 'passed': True, 'checks': checks, 'daemon_binary_sha256': sha(binary),
                'service_uid': 65534, 'production_configuration': True, 'real_tls_provider_requests': len(observations),
                'production_config_sha256': sha(config), 'original_auth_sha256': original_auth_sha256, 'revoked_auth_sha256': sha(auth_path),
                'provider_ca_sha256': sha(cert), 'openssl_version': subprocess.check_output(['openssl', 'version'], text=True).strip(),
                'host_kernel': os.uname().release, 'host_machine': os.uname().machine,
                'guest_vm_involved': False, 'guest_sdk_accepted': False, 'public_api_inference_enabled': False,
                'verification_workdir_removed': True, 'scope': 'actual production egress CLI, root/internal RPC and synthetic guest HTTP protocol; no KVM or public API/MCP/SDK acceptance'}
    finally:
        if child is not None and child.poll() is None:
            child.kill(); child.wait(timeout=3)
        for thread in clients:
            thread.join(timeout=3)
        if provider is not None:
            provider.shutdown(); provider.server_close()
        log.close()
        if completed:
            shutil.rmtree(work)
        else:
            (report / 'failed-workdir.txt').write_text(str(work) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--peer-probe', nargs=2)
    args = parser.parse_args()
    if args.peer_probe:
        peer_probe(*map(Path, args.peer_probe))
        return
    assert args.binary is not None and args.output is not None
    args.output.mkdir(parents=True, exist_ok=True)
    report = suite(args.binary.resolve(), args.output.resolve())
    (args.output / 'process-receipt.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
