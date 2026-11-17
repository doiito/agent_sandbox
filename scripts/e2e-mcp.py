#!/usr/bin/env python3
"""Installed MCP -> authenticated API -> launcher -> real KVM functional probe."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import queue
import subprocess
import sys
import threading
import time


class MCP:
    def __init__(self, binary, config, legacy=False):
        self.process = subprocess.Popen([str(binary), '-config', str(config)], stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.messages = queue.Queue()
        self.sequence = 0
        self.legacy = legacy
        self.reader = threading.Thread(target=self.read, daemon=True)
        self.reader.start()
        if legacy:
            self.receive(self.request('initialize', {'protocolVersion': '2025-11-25', 'capabilities': {},
                                                     'clientInfo': {'name': 'kvm-acceptance', 'version': '1'}}))
            self.send({'jsonrpc': '2.0', 'method': 'notifications/initialized'})

    def read(self):
        for line in self.process.stdout:
            self.messages.put(json.loads(line))
        self.messages.put(None)

    def send(self, value):
        self.process.stdin.write(json.dumps(value).encode() + b'\n')
        self.process.stdin.flush()

    def request(self, method, params):
        self.sequence += 1
        if not self.legacy:
            params = params | {'_meta': {'io.modelcontextprotocol/protocolVersion': '2026-07-28',
                                       'io.modelcontextprotocol/clientCapabilities': {}}}
        self.send({'jsonrpc': '2.0', 'id': self.sequence, 'method': method, 'params': params})
        return self.sequence

    def receive(self, request_id):
        value = self.messages.get(timeout=45)
        assert value and value['id'] == request_id, value
        assert 'error' not in value, value
        if not self.legacy:
            assert value['result']['resultType'] == 'complete'
        return value['result']

    def call(self, name, expected_error=False, **arguments):
        value = self.receive(self.request('tools/call', {'name': name, 'arguments': arguments}))
        assert value['isError'] == expected_error, (name, value)
        assert value['structuredContent'] == json.loads(value['content'][0]['text'])
        return value['structuredContent']

    def stop(self):
        self.process.stdin.close()
        assert self.process.wait(timeout=5) == 0, self.process.stderr.read().decode()
        self.reader.join(timeout=2)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--package', type=Path, required=True)
    parser.add_argument('--expected-mode', choices=['cold', 'warm'], required=True)
    parser.add_argument('--in-netns', action='store_true')
    args = parser.parse_args()
    root = args.root.resolve()
    if not args.in_netns:
        pid = subprocess.check_output(['systemctl', 'show', '-p', 'MainPID', '--value', root.name + '-api.service'], text=True).strip()
        assert int(pid) > 1
        raise SystemExit(subprocess.run(['nsenter', '-t', pid, '-n', sys.executable, __file__,
                                        '--root', str(root), '--package', str(args.package),
                                        '--expected-mode', args.expected_mode, '--in-netns']).returncode)
    release = next((root / 'releases').iterdir())
    sys.path.insert(0, str(release / 'sdk/python'))
    from osv_sandbox_client import Client
    service = json.loads((root / 'config.production.json').read_text())
    url = 'https://localhost:' + service['listen'].rsplit(':', 1)[1]
    api = Client(url, token=(root / 'secrets/token').read_text(), ca_file=str(root / 'tls/ca.crt'),
                 cert_file=str(root / 'tls/client.crt'), key_file=str(root / 'tls/client.key'), request_timeout_seconds=10)
    config = {'api_url': url, 'ca_file': str(root / 'tls/ca.crt'), 'cert_file': str(root / 'tls/client.crt'),
              'key_file': str(root / 'tls/client.key'), 'token_file': str(root / 'secrets/token'), 'max_in_flight': 4}
    paths = []
    for suffix in ['', '-b']:
        path = root / ('mcp' + suffix + '.json')
        path.write_text(json.dumps(config | {'token_file': str(root / ('secrets/token' + suffix))}))
        path.chmod(0o600)
        paths.append(path)
    binary = release / 'bin/osv-sandbox-mcp'
    children, sessions = [], []
    report = {'suite': 'mcp-real-kvm/v1', 'passed': False, 'mode': args.expected_mode,
              'cases': [], 'job_ids': [], 'performance_gate_evidence': False, 'production_validated': False}

    def check(name, condition):
        assert condition, name
        report['cases'].append(name)

    def wait_for(predicate, label, seconds=20):
        deadline = time.monotonic() + seconds
        while not predicate():
            assert time.monotonic() < deadline, label
            time.sleep(0.05)

    def ready():
        if args.expected_mode == 'warm':
            wait_for(lambda: any(row['name'] == 'small' and row['ready'] >= 1 for row in api.doctor()['warm_pool']['profiles']), 'pool not ready')

    def spawn(tenant=0, legacy=False):
        p = MCP(binary, paths[tenant], legacy)
        children.append(p)
        return p

    def stop(p):
        p.stop()
        children.remove(p)

    try:
        p, b = spawn(), spawn(1)
        caps = p.call('sandbox.capabilities')
        templates = p.call('sandbox.templates')['templates']
        check('authenticated-template-and-capabilities', len(templates) == 1 and templates[0]['artifact_manifest_sha256'] == caps['artifact_manifest_sha256'])
        listed = p.receive(p.request('tools/list', {}))
        names = [row['name'] for row in listed['tools']]
        check('real-capability-filtered-tool-list', names == sorted(set(names)) and len(names) >= 20 and
              (('sandbox.net.fetch' in names) if caps['features'].get('network_fetch') else not any('.net.' in name for name in names)))
        data = b'\0\xffMCP\n'
        ready()
        result = p.call('sandbox.exec', entrypoint='/bin/sh', args=['-c', 'printf "%s|%s|" "$MCP_VALUE" "$PWD"; /bin/busybox sha256sum'],
                        memory_mib=128, vcpus=1, environment={'MCP_VALUE': 'mcp-value'}, cwd='/workspace', stdin=base64.b64encode(data).decode())
        report['job_ids'].append(result['id'])
        check('real-guest-env-cwd-binary-stdin', result['protocol_ok'] and result['guest_result']['stdout'] == 'mcp-value|/workspace|' + hashlib.sha256(data).hexdigest() + '  -\n')
        report['first_job_startup_mode'] = result.get('startup_mode')
        # The API omits mode for a non-pooled cold job. Preserve that absence;
        # only a real pool checkout may satisfy the warm assertion.
        check('actual-startup-mode', result.get('startup_mode') == 'warm' if args.expected_mode == 'warm' else
              result.get('startup_mode') in (None, 'cold') and not service.get('warm_pool', {}).get('enabled'))
        invalid = p.call('sandbox.exec', expected_error=True, entrypoint='/bin/sh', artifact_manifest_sha256='b' * 64)
        check('template-mismatch-does-not-fallback', 'error' in invalid)
        check('entrypoint-policy', 'error' in p.call('sandbox.exec', expected_error=True, entrypoint='/bin/false'))
        ready()
        failed = p.call('sandbox.exec', expected_error=True, entrypoint='/bin/sh', args=['-c', 'exit 7'], memory_mib=128)
        report['job_ids'].append(failed['id'])
        check('guest-exit-propagates-isError', failed['state'] == 'guest_error' and failed['exit_code'] == 7 and failed['protocol_ok'])
        ready()
        session = p.call('sandbox.session.create', ttl_ms=60000, memory_mib=128, vcpus=1)
        sid = session['id']
        sessions.append(sid)
        check('explicit-session-created', session['state'] == 'running')
        if caps['features'].get('file_watch'):
            check('watch-tools-follow-signed-capability', all('sandbox.watch.'+op in names for op in ('start','list','poll','stop')))
            watched = p.call('sandbox.watch.start', session_id=sid, path='/workspace', include_entry=True)
            wid = watched['id']
            p.call('sandbox.fs.write', session_id=sid, path='/workspace/mcp-watch', data_base64=base64.b64encode(b'watch').decode())
            wait_for(lambda:any(event['name']=='mcp-watch' for event in p.call('sandbox.watch.poll',session_id=sid,watch_id=wid)['events']), 'MCP inotify event missing')
            check('real-mcp-watch-event', any(row['id']==wid for row in p.call('sandbox.watch.list',session_id=sid)['watches']))
            check('cross-tenant-watch-hidden', b.call('sandbox.watch.poll',expected_error=True,session_id=sid,watch_id=wid)['error']['status']==404)
            check('mcp-watch-stop-releases-stream', p.call('sandbox.watch.stop',session_id=sid,watch_id=wid)['stopped'])
        listed = p.call('sandbox.session.list', limit=10)
        check('owner-session-list', any(row['id'] == sid for row in listed['sessions']))
        check('held-tenant-quota', p.call('sandbox.session.create', expected_error=True)['error']['status'] == 429)
        for tool, extra in [('sandbox.session.get', {}), ('sandbox.session.close', {}), ('sandbox.fs.read', {'path': '/workspace/x'}), ('sandbox.commands.list', {})]:
            check('cross-tenant-' + tool, b.call(tool, expected_error=True, session_id=sid, **extra)['error']['status'] == 404)
        check('workspace-confined', 'error' in p.call('sandbox.fs.read', expected_error=True, session_id=sid, path='/etc/passwd'))
        p.call('sandbox.fs.mkdir', session_id=sid, path='/workspace/dir')
        p.call('sandbox.fs.write', session_id=sid, path='/workspace/dir/a', data_base64=base64.b64encode(data).decode(), metadata={'source': 'mcp'})
        read = p.call('sandbox.fs.read', session_id=sid, path='/workspace/dir/a')
        check('workspace-binary-roundtrip', base64.b64decode(read['data_base64']) == data)
        info = p.call('sandbox.fs.info', session_id=sid, path='/workspace/dir/a')
        check('workspace-info-metadata', info['info']['metadata'] == {'source': 'mcp'})
        p.call('sandbox.fs.rename', session_id=sid, path='/workspace/dir/a', destination='/workspace/dir/b')
        check('workspace-rename-list', p.call('sandbox.fs.list', session_id=sid, path='/workspace/dir')['entries'] == ['b'])
        p.call('sandbox.fs.remove', session_id=sid, path='/workspace/dir/b')
        p.call('sandbox.fs.remove', session_id=sid, path='/workspace/dir')
        changed = p.call('sandbox.session.set_timeout', session_id=sid, ttl_ms=60000)
        check('session-timeout-update', changed['lease_revision'] > session['lease_revision'])
        command = p.call('sandbox.commands.start', session_id=sid, entrypoint='/bin/sh', args=['-c', 'printf ready; /bin/busybox sha256sum; printf stderr >&2'], interactive_stdin=True, timeout_ms=30000)
        cid = command['id']
        stop(p)
        p = spawn(legacy=True)
        check('session-survives-MCP-EOF', p.call('sandbox.session.get', session_id=sid)['state'] == 'running')
        check('command-survives-MCP-restart', any(row['id'] == cid for row in p.call('sandbox.commands.list', session_id=sid)['commands']))
        receipt = p.call('sandbox.commands.stdin', session_id=sid, command_id=cid, data_base64=base64.b64encode(data).decode())
        def delivered():
            status = p.call('sandbox.commands.stdin_status', session_id=sid, command_id=cid, sequence=receipt['sequence'])
            return status['state'] == 'delivered' and status['written_bytes'] == len(data)
        wait_for(delivered, 'input not delivered')
        p.call('sandbox.commands.stdin', session_id=sid, command_id=cid, data_base64='', close=True)
        finished = p.call('sandbox.commands.wait', session_id=sid, command_id=cid)
        check('interactive-stdin-EOF-after-reconnect', finished['info']['state'] == 'succeeded' and finished['result']['result']['guest_result']['stdout'] == 'ready' + hashlib.sha256(data).hexdigest() + '  -\n' and finished['result']['result']['guest_result']['stderr'] == 'stderr')
        command = p.call('sandbox.commands.start', session_id=sid, entrypoint='/bin/sh', args=['-c', 'sleep 20'], timeout_ms=30000)
        check('background-cancel-confirmed', p.call('sandbox.commands.cancel', session_id=sid, command_id=command['id'])['killed'])
        check('background-cancel-isError', p.call('sandbox.commands.wait', expected_error=True, session_id=sid, command_id=command['id'])['info']['state'] == 'cancelled')
        result = p.call('sandbox.exec', session_id=sid, entrypoint='/bin/sh', args=['-c', 'printf session-kept'])
        check('session-reusable-after-background-cancel', result['result']['guest_result']['stdout'] == 'session-kept')
        check('session-close-204-is-success', p.call('sandbox.session.close', session_id=sid)['status'] == 204)
        sessions.remove(sid)
        stop(p)
        p = spawn()
        for mode in ['notification', 'EOF']:
            wait_for(lambda: api.doctor()['vm_capacity']['active'] == 0, 'active VM not released')
            ready()
            rid = p.request('tools/call', {'name': 'sandbox.exec', 'arguments': {'entrypoint': '/bin/sh', 'args': ['-c', 'sleep 20'], 'memory_mib': 128, 'timeout_ms': 30000}})
            wait_for(lambda: api.doctor()['vm_capacity']['active'] == 1, 'execution did not start')
            if mode == 'notification':
                p.send({'jsonrpc': '2.0', 'method': 'notifications/cancelled', 'params': {'requestId': rid}})
                p.receive(p.request('server/discover', {}))
            else:
                stop(p)
                p = spawn()
            wait_for(lambda: api.doctor()['vm_capacity']['active'] == 0, 'cancel did not release VM')
            check('one-shot-' + mode + '-reclaims-VM', True)
        inspection = subprocess.run([sys.executable, str(Path(__file__).with_name('check-job-input-pool-state.py')), '--root', str(root), '--expected-mode', args.expected_mode], text=True, capture_output=True)
        if inspection.returncode:
            report['cleanup_inspection_failure'] = {'stdout': inspection.stdout, 'stderr': inspection.stderr}
            raise AssertionError('host resource inspection failed: ' + inspection.stderr)
        report['cleanup_inspection'] = json.loads(inspection.stdout)
        check('host-no-active-workdirs-cgroups-and-idle-pool-accounted', report['cleanup_inspection']['passed'])
        report['passed'] = True
    finally:
        for child in children:
            if child.process.poll() is None:
                child.stop()
        for sid in sessions:
            try:
                api._exchange('DELETE', '/v2/sessions/' + sid)
            except Exception:
                pass
        for path in paths:
            path.unlink(missing_ok=True)
        with args.package.open('rb') as stream:
            report['candidate_sha256'] = hashlib.file_digest(stream, 'sha256').hexdigest()
        report['installed_mcp_sha256'] = hashlib.sha256(binary.read_bytes()).hexdigest()
        report['case_count'] = len(report['cases'])
        (root / 'results/mcp.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps({'passed': report['passed'], 'cases': report['case_count'], 'mode': args.expected_mode}), flush=True)


if __name__ == '__main__':
    main()
