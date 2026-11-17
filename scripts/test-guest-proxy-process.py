#!/usr/bin/env python3
"""Real non-root production egress + root launcher protocol, without a guest VM."""
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
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
VM = '0123456789abcdef01234567'
LEASE = 'abcdef0123456789abcdef01'


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def upgrade(path, tenant='proxy-a'):
    connection = socket.socket(socket.AF_UNIX)
    connection.settimeout(5)
    connection.connect(str(path))
    connection.sendall((f'POST /v1/guest-proxy HTTP/1.1\r\nHost: egress.invalid\r\n'
                        f'Connection: Upgrade\r\nUpgrade: osv-guest-proxy/1\r\n'
                        f'X-OSV-Tenant: {tenant}\r\nX-OSV-VM: {VM}\r\nX-OSV-Lease: {LEASE}\r\n'
                        'Content-Length: 0\r\n\r\n').encode())
    response = http.client.HTTPResponse(connection)
    response.begin()
    status = response.status
    response.close()
    return connection, status


def suite(binary, report_dir):
    if os.geteuid() != 0:
        raise SystemExit('Process fixture requires root to spawn a non-root egress worker')
    work = Path(tempfile.mkdtemp(prefix='process-', dir=ROOT / 'build/validation/guest-proxy-core'))
    work.chmod(0o755)
    child = None
    servers = []
    checks = []
    requests = []
    try:
        key, certificate = work / 'upstream.key', work / 'upstream.crt'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ed25519', '-nodes', '-days', '1',
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
                        '-keyout', str(key), '-out', str(certificate)], capture_output=True, check=True)
        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'
            def log_message(self, *_):
                pass
            def do_GET(self):
                self.respond()
            def do_POST(self):
                self.respond()
            def respond(self):
                body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
                requests.append((self.command, body))
                data = b'\x00\xffproxy-functional' + body
                self.send_response(200)
                self.send_header('Content-Length', str(len(data)))
                self.send_header('Connection', 'close')
                self.end_headers()
                self.wfile.write(data)
        for tls in (False, True):
            server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
            if tls:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(certificate, key)
                server.socket = context.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            servers.append((server, thread))
        http_port, https_port = (server.server_port for server, _ in servers)
        policy = {'allowed_origins': [f'http://127.0.0.1:{http_port}', f'https://localhost:{https_port}'],
                  'allowed_cidrs': ['127.0.0.1/32', '::1/128'], 'max_concurrent': 1, 'timeout_ms': 30000}
        token = 'disposable-process-fixture-token'
        auth = {'protocol': 'osv-sandbox-auth/v1', 'tenants': [
            {'id': 'proxy-a', 'token_sha256': hashlib.sha256(token.encode()).hexdigest(),
             'allowed_entrypoints': ['/bin/sh'], 'requests_per_second': 100, 'burst': 100,
             'max_concurrent': 1, 'egress': policy},
            {'id': 'proxy-b', 'token_sha256': hashlib.sha256(b'disabled-fixture').hexdigest(),
             'allowed_entrypoints': ['/bin/sh'], 'requests_per_second': 100, 'burst': 100,
             'max_concurrent': 1}]}
        auth_path = work / 'auth.json'
        auth_path.write_text(json.dumps(auth)); auth_path.chmod(0o644)
        service_dir = work / 'service'; service_dir.mkdir(mode=0o700)
        os.chown(service_dir, 65534, 65534)
        socket_path = service_dir / 'e.sock'
        config = work / 'egress.json'
        config.write_text(json.dumps({'production': True, 'guest_proxy': True, 'socket_path': str(socket_path),
                                      'auth_policy_path': str(auth_path), 'audit_log_path': str(service_dir / 'audit.jsonl'),
                                      'max_concurrent': 2}))
        config.chmod(0o644)
        log_path = report_dir / 'nonroot-process.log'
        with log_path.open('w') as log:
            child = subprocess.Popen([str(binary), '-config', str(config)], stdout=log, stderr=log,
                                     user=65534, group=65534, extra_groups=[], start_new_session=True, umask=0o077,
                                     env=os.environ | {'HTTP_PROXY': 'http://127.0.0.1:1', 'HTTPS_PROXY': 'http://127.0.0.1:1'})
            deadline = time.monotonic() + 5
            while not socket_path.exists():
                assert child.poll() is None, f'egress process exited: {log_path}'
                assert time.monotonic() < deadline, 'egress did not create socket'
                time.sleep(.01)
            assert socket_path.stat().st_uid == 65534
            checks.append('nonroot-production-worker-root-owned-config')
            connection, status = upgrade(socket_path, 'proxy-b')
            connection.close(); assert status == 403
            checks.append('kernel-root-launcher-still-obeys-tenant-policy')
            connection, status = upgrade(socket_path)
            assert status == 101
            connection.sendall((f'POST http://127.0.0.1:{http_port}/private?not-audited HTTP/1.1\r\n'
                                'Host: ignored.invalid\r\nContent-Length: 4\r\n\r\n').encode() + b'\0\xffok')
            response = http.client.HTTPResponse(connection); response.begin()
            assert response.status == 200 and response.read() == b'\x00\xffproxy-functional\0\xffok'
            response.close(); connection.close()
            checks.append('real-http-post-binary')
            connection, status = upgrade(socket_path); assert status == 101
            authority = f'localhost:{https_port}'
            connection.sendall(f'CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n'.encode())
            response = http.client.HTTPResponse(connection); response.begin(); assert response.status == 200; response.close()
            tls_client = ssl.create_default_context(cafile=str(certificate)).wrap_socket(connection, server_hostname='localhost')
            tls_client.sendall(b'GET /encrypted HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n')
            response = http.client.HTTPResponse(tls_client); response.begin()
            assert response.status == 200 and response.read() == b'\x00\xffproxy-functional'
            response.close(); tls_client.close()
            checks.append('real-https-connect-client-verifies-certificate-and-sni')
            connection, status = upgrade(socket_path); assert status == 101
            connection.sendall(f'CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n'.encode())
            response = http.client.HTTPResponse(connection); response.begin(); assert response.status == 200; response.close()
            try:
                ssl.create_default_context(cafile=str(certificate)).wrap_socket(connection, server_hostname='unlisted.invalid')
                raise AssertionError('mismatched SNI accepted')
            except (ssl.SSLError, OSError):
                pass
            finally:
                connection.close()
            checks.append('actual-clienthello-sni-denied-without-upstream-request')
            # Wait for slot reclamation without retrying a business request.
            deadline = time.monotonic() + 3
            while True:
                audit_path = service_dir / 'audit.jsonl'
                events = [json.loads(line) for line in audit_path.read_text().splitlines()]
                if any(e.get('code') == 'egress_sni_denied' for e in events):
                    break
                assert time.monotonic() < deadline, 'SNI denial not persisted'
                time.sleep(.01)
            assert len(requests) == 2
            connection, status = upgrade(socket_path); assert status == 101
            blocked, status = upgrade(socket_path); blocked.close(); assert status == 429
            checks.append('network-concurrency-bound-while-reading-guest-headers')
            started = time.monotonic()
            child.send_signal(signal.SIGTERM); assert child.wait(timeout=3) == 0
            assert time.monotonic() - started < 3
            try:
                assert connection.recv(1) == b''
            except ConnectionResetError:
                pass
            connection.close()
            checks.append('sigterm-reclaims-hijack-and-network-slots')
            events = [json.loads(line) for line in audit_path.read_text().splitlines()]
            assert any(e['event'] == 'net.complete' for e in events)
            assert all(e.get('vm_id') == VM and e.get('lease_id') == LEASE for e in events)
            assert not any('private' in e.get('origin', '') or 'not-audited' in json.dumps(e) or token in json.dumps(e) for e in events)
            (report_dir / 'nonroot-network-audit.jsonl').write_bytes(audit_path.read_bytes())
            checks.append('durable-tenant-vm-lease-audit-without-secrets-or-path')
        return {'suite': 'guest-proxy-nonroot-production-process/v1', 'passed': True, 'checks': checks,
                'binary_sha256': sha(binary), 'guest_vm_involved': False, 'network_egress_capability_enabled': False}
    finally:
        if child is not None and child.poll() is None:
            child.kill(); child.wait()
        for server, thread in servers:
            server.shutdown(); server.server_close(); thread.join(timeout=3)
        shutil.rmtree(work)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    report = suite(args.binary.resolve(), args.output.resolve())
    (args.output / 'nonroot-process-receipt.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
