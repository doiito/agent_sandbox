#!/usr/bin/env python3
"""Installed MCP code tools through the authenticated API and actual KVM vsock."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import runpy
import secrets
import subprocess
import sys
import time


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
        raise SystemExit(subprocess.run(['nsenter', '-t', pid, '-n', sys.executable, __file__, '--root', str(root),
            '--package', str(args.package), '--expected-mode', args.expected_mode, '--in-netns']).returncode)
    MCP = runpy.run_path(str(Path(__file__).with_name('e2e-mcp.py')))['MCP']
    release = next((root / 'releases').iterdir())
    sys.path.insert(0, str(release / 'sdk/python'))
    import osv_sandbox_client as sdk
    config = json.loads((root / 'config.production.json').read_text())
    url = 'https://localhost:' + config['listen'].rsplit(':', 1)[1]
    client = sdk.Client(url, token=(root / 'secrets/token').read_text(), ca_file=str(root / 'tls/ca.crt'),
        cert_file=str(root / 'tls/client.crt'), key_file=str(root / 'tls/client.key'), request_timeout_seconds=60)
    paths = []
    for suffix in ['', '-b']:
        path = root / ('code-mcp' + suffix + '.json')
        path.write_text(json.dumps({'api_url': url, 'ca_file': str(root / 'tls/ca.crt'),
            'cert_file': str(root / 'tls/client.crt'), 'key_file': str(root / 'tls/client.key'),
            'token_file': str(root / ('secrets/token' + suffix)), 'max_in_flight': 4}))
        path.chmod(0o600)
        paths.append(path)
    cases, children, sessions = [], [], []
    report = {'suite': 'mcp-code-real-kvm/v1', 'passed': False, 'mode': args.expected_mode,
        'actual_code_vsock': True, 'cases': cases, 'performance_gate_evidence': False,
        'candidate_sha256': hashlib.file_digest(args.package.open('rb'), 'sha256').hexdigest()}

    def check(name, value):
        assert value, name
        cases.append(name)
        print('PASS mcp-code-' + name, flush=True)

    def wait(action, seconds=45):
        end = time.monotonic() + seconds
        while True:
            value = action()
            if value:
                return value
            assert time.monotonic() < end, 'MCP code state observation timed out'
            time.sleep(.025)

    def spawn(legacy=False, tenant=0):
        child = MCP(release / 'bin/osv-sandbox-mcp', paths[tenant], legacy)
        children.append(child)
        return child

    def stop(child):
        child.stop()
        children.remove(child)

    def context_ready(child, sid, cid):
        def observe():
            value = child.call('sandbox.code.context.info', session_id=sid, context_id=cid)
            return value if value['state'] == 'idle' else None
        return wait(observe)

    def poll(child, sid, context, eid, after=0):
        value = child.receive(child.request('tools/call', {'name': 'sandbox.code.poll', 'arguments': {
            'session_id': sid, 'context_id': context['id'], 'generation': context['generation'],
            'execution_id': eid, 'after': after}}))
        page = value['structuredContent']
        assert page == json.loads(value['content'][0]['text'])
        assert page['id'] == eid and page['context_id'] == context['id'] and page['generation'] == context['generation']
        expected_error = page['status'] in ['failed', 'cancelled', 'timed_out', 'evicted'] or any(row['event']['type'] == 'error' for row in page['events'])
        assert value['isError'] == expected_error
        return page

    def finish(child, sid, context, eid):
        events, cursor, end = [], 0, time.monotonic() + 20
        while True:
            page = poll(child, sid, context, eid, cursor)
            events.extend(row['event'] for row in page['events'])
            cursor = page['next_sequence']
            if page['status'] != 'running' and cursor == page['last_sequence']:
                return page, events
            assert time.monotonic() < end, 'MCP journal did not terminate'
            time.sleep(.025)

    try:
        for legacy in [False, True]:
            protocol = 'legacy' if legacy else 'modern'
            if args.expected_mode == 'warm':
                wait(lambda: any(row['name'] == 'code' and row['ready'] >= 1 for row in client.doctor()['warm_pool']['profiles']))
            session = client.create_session(sdk.SessionRequest(ttl_ms=180000))
            sessions.append(session)
            sid = session.id
            check(protocol + '-actual-startup', session.created.startup_mode == args.expected_mode)
            child, foreign = spawn(legacy), spawn(legacy, 1)
            names = {entry['name'] for entry in child.receive(child.request('tools/list', {}))['tools']}
            expected = {'sandbox.code.context.' + op for op in ['create', 'default', 'list', 'info', 'restart', 'remove']} | {'sandbox.code.' + op for op in ['execute', 'poll', 'cancel']}
            check(protocol + '-nine-tools', expected <= names)
            cap = child.call('sandbox.capabilities', session_id=sid)
            check(protocol + '-owner-profile', cap['session_id'] == sid and cap['code_runtime']['kernel_protocol'] == 'osv-code-kernel/v2')
            default = child.call('sandbox.code.context.default', session_id=sid, language='python')
            context_ready(child, sid, default['id'])
            cid = secrets.token_hex(12)
            child.call('sandbox.code.context.create', session_id=sid, context_id=cid, language='python')
            context = context_ready(child, sid, cid)
            rows = child.call('sandbox.code.context.list', session_id=sid)['contexts']
            check(protocol + '-list-create', cid in {entry['id'] for entry in rows})
            foreign.call('sandbox.code.context.info', expected_error=True, session_id=sid, context_id=cid)
            cases.append(protocol + '-foreign-owner-hidden')
            eid = secrets.token_hex(12)
            child.call('sandbox.code.execute', session_id=sid, context_id=cid, generation=context['generation'], execution_id=eid,
                code="print('mcp-中文')\nvalue=41\nvalue+1", timeout_ms=0, environment={})
            page, events = finish(child, sid, context, eid)
            output = b''.join(base64.b64decode(event['data']) for event in events if event['type'] == 'stdout').decode()
            check(protocol + '-execute-poll', page['status'] == 'completed' and 'mcp-中文' in output and
                  any(event['type'] == 'result' and event['data'].get('text/plain') == '42' for event in events))
            child.call('sandbox.code.context.restart', session_id=sid, context_id=cid, generation=context['generation'])
            restarted = context_ready(child, sid, cid)
            check(protocol + '-restart-generation', restarted['generation'] == context['generation'] + 1)
            context = restarted
            eid = secrets.token_hex(12)
            child.call('sandbox.code.execute', session_id=sid, context_id=cid, generation=context['generation'], execution_id=eid,
                code='import time\nwhile True: time.sleep(.01)', timeout_ms=0)
            check(protocol + '-running-before-eof', poll(child, sid, context, eid)['status'] == 'running')
            stop(child)
            child = spawn(not legacy)
            check(protocol + '-reconnect-keeps-known-execution', poll(child, sid, context, eid)['status'] == 'running')
            child.call('sandbox.code.cancel', session_id=sid, context_id=cid, generation=context['generation'], execution_id=eid)
            page, events = finish(child, sid, context, eid)
            check(protocol + '-explicit-cancel-confirmed', page['status'] == 'cancelled' and events[-1]['type'] == 'finished')
            child.call('sandbox.code.context.remove', session_id=sid, context_id=cid, generation=context['generation'])
            def removed():
                try:
                    session.code.get(cid)
                except sdk.APIError as error:
                    assert error.status == 404 and error.code == 'code_not_found'
                    return True
                return False
            wait(removed)
            child.call('sandbox.code.context.info', expected_error=True, session_id=sid, context_id=cid)
            cases.append(protocol + '-remove-observed')
            # Journals remain readable after their context has been removed.
            check(protocol + '-removed-context-journal-readable', poll(child, sid, context, eid)['status'] == 'cancelled')
            stop(child)
            stop(foreign)
            session.close()
        check('active-capacity-returned', client.doctor()['vm_capacity']['active'] == 0)
        report['passed'] = True
    finally:
        for child in children:
            child.stop()
        for session in sessions:
            try:
                session.close()
            except sdk.APIError as error:
                if error.status != 404:
                    raise
        (root / 'results' / ('mcp-code-' + args.expected_mode + '.json')).write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
