#!/usr/bin/env python3
"""Exercise the public session API against an isolated, test-signed KVM fixture."""

import argparse
import json
from pathlib import Path
import socket
import ssl
import time
import urllib.error
import urllib.request


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve()
    config = json.loads((root / 'config.production.json').read_text())
    url = 'https://localhost:' + config['listen'].rsplit(':', 1)[1]
    context = ssl.create_default_context(cafile=root / 'tls/ca.crt')
    context.load_cert_chain(root / 'tls/client.crt', root / 'tls/client.key')
    tokens = {name: (root / 'secrets' / name).read_text() for name in ('token', 'token-b')}
    cases = []
    active = []

    def call(token, method, path, body=None):
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(url + path, data=data, method=method,
                                         headers={'Authorization': 'Bearer ' + tokens[token],
                                                  'Content-Type': 'application/json'})
        try:
            response = urllib.request.urlopen(request, context=context, timeout=20)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            payload = response.read()
            return response.status, json.loads(payload) if payload else None

    def check(name, condition, detail=None):
        cases.append({'name': name, 'passed': bool(condition), 'detail': detail})
        if not condition:
            raise AssertionError(f'{name}: {detail}')

    def create(token, ttl_ms=60000, retry_busy=False, retry_seconds=10):
        deadline = time.monotonic() + retry_seconds
        while True:
            status, body = call(token, 'POST', '/v2/sessions', {
                'backend': 'firecracker-linux', 'artifact_manifest_sha256': digest,
                'network': 'none', 'ttl_ms': ttl_ms})
            if not retry_busy or status != 429 or time.monotonic() >= deadline:
                break
            time.sleep(0.1)
        check('create-' + token + '-' + str(len(cases)), status == 201 and body['state'] == 'running', body)
        active.append((token, body['id']))
        return body['id']

    def command(token, session_id, shell):
        return call(token, 'POST', '/v2/sessions/' + session_id + '/commands',
                    {'entrypoint': '/bin/sh', 'args': ['-c', shell], 'timeout_ms': 10000})

    report = {'suite': 'offline-session-api-kvm/v1', 'cases': cases, 'passed': False}
    try:
        status, capability = call('token', 'GET', '/v1/capabilities')
        digest = capability['artifact_manifest_sha256']
        check('capability-template', status == 200 and len(digest) == 64)
        a = create('token')
        path = '/v2/sessions/' + a
        check('owner-get', call('token', 'GET', path)[0] == 200)
        check('cross-tenant-get', call('token-b', 'GET', path)[0] == 404)
        check('cross-tenant-run', command('token-b', a, 'true')[0] == 404)
        check('cross-tenant-delete', call('token-b', 'DELETE', path)[0] == 404)
        check('held-tenant-quota', call('token', 'POST', '/v2/sessions', {
            'backend': 'firecracker-linux', 'artifact_manifest_sha256': digest})[0] == 429)

        status, result = command('token', a, 'printf session-ok > /workspace/session-marker')
        check('same-vm-write', status == 200 and result['result']['state'] == 'succeeded', result)
        status, result = command('token', a, 'cat /workspace/session-marker')
        check('same-vm-read', status == 200 and result['result']['guest_result']['stdout'] == 'session-ok', result)
        status, result = command('token', a, 'exit 7')
        check('guest-exit-status', status == 200 and result['result']['exit_code'] == 7 and
              result['result']['state'] == 'guest_error', result)
        check('entrypoint-policy', call('token', 'POST', path + '/commands',
              {'entrypoint': '/bin/false'})[0] == 403)
        check('owner-delete', call('token', 'DELETE', path)[0] == 204)
        active.remove(('token', a))
        check('deleted-invisible', call('token', 'GET', path)[0] == 404)

        b = create('token-b')
        status, result = command('token-b', b, 'printf tenant-b')
        check('second-tenant-run', status == 200 and result['result']['guest_result']['stdout'] == 'tenant-b', result)
        check('second-tenant-delete', call('token-b', 'DELETE', '/v2/sessions/' + b)[0] == 204)
        active.remove(('token-b', b))

        short = create('token', 3000)
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline and call('token', 'GET', '/v2/sessions/' + short)[0] != 404:
            time.sleep(0.1)
        check('ttl-expires', call('token', 'GET', '/v2/sessions/' + short)[0] == 404)
        active.remove(('token', short))
        final = create('token', retry_busy=True)
        check('quota-released-after-ttl', call('token', 'DELETE', '/v2/sessions/' + final)[0] == 204)
        active.remove(('token', final))

        canceled = create('token', retry_busy=True)
        payload = json.dumps({'entrypoint': '/bin/sh', 'args': ['-c', 'sleep 10'],
                              'timeout_ms': 20000}).encode()
        raw = socket.create_connection(('127.0.0.1', int(config['listen'].rsplit(':', 1)[1])), timeout=5)
        try:
            with context.wrap_socket(raw, server_hostname='localhost') as connection:
                connection.sendall((f'POST /v2/sessions/{canceled}/commands HTTP/1.1\r\n'
                                    f'Host: localhost\r\nAuthorization: Bearer {tokens["token"]}\r\n'
                                    f'Content-Type: application/json\r\nContent-Length: {len(payload)}\r\n'
                                    'Connection: close\r\n\r\n').encode() + payload)
                time.sleep(0.5)
        finally:
            raw.close()
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and call('token', 'GET', '/v2/sessions/' + canceled)[0] != 404:
            time.sleep(0.1)
        check('client-disconnect-closes-session',
              call('token', 'GET', '/v2/sessions/' + canceled)[0] == 404)
        active.remove(('token', canceled))
        check('disconnect-quarantines-quota', call('token', 'POST', '/v2/sessions', {
            'backend': 'firecracker-linux', 'artifact_manifest_sha256': digest})[0] == 429)
        after_cancel = create('token', retry_busy=True, retry_seconds=20)
        check('quota-released-after-disconnect',
              call('token', 'DELETE', '/v2/sessions/' + after_cancel)[0] == 204)
        active.remove(('token', after_cancel))

        parent = Path('/sys/fs/cgroup') / config['jailer']['parent_cgroup']
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and (list((root / 'run').glob('job-*')) or
                                                  list(parent.glob('job-*'))):
            time.sleep(0.1)
        remaining_dirs = [path.name for path in (root / 'run').glob('job-*')]
        remaining_cgroups = [path.name for path in parent.glob('job-*')]
        remaining_processes = []
        for process in Path('/proc').iterdir():
            if not process.name.isdigit():
                continue
            try:
                if config['jailer']['parent_cgroup'] + '/' in (process / 'cgroup').read_text():
                    remaining_processes.append(process.name)
            except OSError:
                pass
        check('no-session-residue', not any((remaining_dirs, remaining_cgroups,
                                            remaining_processes)),
              {'dirs': remaining_dirs, 'cgroups': remaining_cgroups,
               'processes': remaining_processes})
        report['passed'] = True
    except Exception as error:
        report['error'] = str(error)
    finally:
        for token, session_id in active:
            try:
                call(token, 'DELETE', '/v2/sessions/' + session_id)
            except Exception:
                pass
        (root / 'results/session-api.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps({'passed': report['passed'], 'cases': len(cases), 'error': report.get('error')}))
    raise SystemExit(0 if report['passed'] else 1)


if __name__ == '__main__':
    main()
