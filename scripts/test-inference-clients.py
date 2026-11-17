#!/usr/bin/env python3
"""Actual SDK/MCP mTLS -> API/root Unix RPC -> TLS model; constructed VM owner."""
import json
from pathlib import Path
import runpy
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'sdk/python'))
from osv_sandbox_client import APIError, Client, InferenceError, Session, SessionInfo


def main():
    config = json.loads(Path(sys.argv[1]).read_text())
    mode = sys.argv[2]
    def client(token='inference-test-token'):
        return Client(config['url'], token=token, cert_file=config['cert'], key_file=config['key'], ca_file=config['ca'])
    api = client()
    session = Session(api, SessionInfo.from_payload(config['session']))
    sid = session.id
    identity = lambda n: f'{n:024x}'
    def check(name, value):
        assert value, name
        print('PASS ' + mode + ' ' + name, flush=True)
    def wait(action):
        deadline = time.monotonic() + 5
        while True:
            result = action()
            if result:
                return result
            assert time.monotonic() < deadline, 'state observation timed out'
            time.sleep(.02)
    def entry(bill, number):
        return next((x for x in bill['invocations'] if x['id'] == identity(number)), {})
    children = []
    try:
        if mode == 'mcp':
            MCP = runpy.run_path(str(ROOT / 'scripts/e2e-mcp.py'))['MCP']
            child = MCP(config['binary'], config['mcp_config']); children.append(child)
            tools = child.receive(child.request('tools/list', {}))['tools']
            check('dynamic-tool-discovery', {'sandbox.ml.invoke', 'sandbox.ml.bill'} <= {x['name'] for x in tools})
            def invoke(number, payload, expected_error=False, endpoint='model'):
                return child.call('sandbox.ml.invoke', expected_error=expected_error, session_id=sid,
                                  invocation_id=identity(number), endpoint=endpoint, payload=payload)
            def bill():
                return child.call('sandbox.ml.bill', task_id=sid)
            result = invoke(1, {'query': 'hi'})
            check('known-id-exact-money', result['task_id'] == sid and result['invocation']['id'] == identity(1) and
                  result['data'] == {'answer': 'ok'} and isinstance(result['invocation']['settled_units'], str) and
                  int(result['invocation']['settled_units']) > 2**53)
            rejected = invoke(1, {'query': 'hi'}, expected_error=True)
            check('duplicate-no-replay', rejected['invocation_id'] == identity(1) and rejected['delivery_unknown'] and
                  rejected['error']['code'] == 'inference_replay')
            denied = invoke(4, {}, expected_error=True, endpoint='other')
            check('alias-denied-before-submit', not denied['delivery_unknown'])
            other = MCP(config['binary'], config['mcp_config-other']); children.append(other)
            denied = other.call('sandbox.ml.bill', expected_error=True, task_id=sid)
            check('other-tenant-history-hidden', denied['error']['code'] == 'inference_not_found')
            pending = child.request('tools/call', {'name': 'sandbox.ml.invoke', 'arguments': {
                'session_id': sid, 'invocation_id': identity(2), 'endpoint': 'model', 'payload': {'mode': 'pending'}}})
            wait(lambda: Path(config['pending_marker']).exists())
            check('bill-observable-with-full-work-slot', entry(bill(), 2).get('state') == 'reserved')
            child.send({'jsonrpc': '2.0', 'method': 'notifications/cancelled', 'params': {'requestId': pending}})
            terminal = wait(lambda: value if (value := entry(bill(), 2)).get('state') == 'uncertain' else None)
            check('MCP-cancel-preserves-held-budget', terminal['settled_units'] == '0' and int(terminal['reserved_units']) > 0)
            large = invoke(3, {'mode': 'unicode'})
            check('expanded-JSON-response', large['data']['text'] == '\u2028' * 140000 and large['invocation']['output_bytes'] < 512 << 10)
        else:
            result = session.ml.invoke('model', {'query': 'hi'}, invocation_id=identity(1))
            check('known-id-exact-money', result.task_id == sid and result.invocation_id == identity(1) and
                  result.data == {'answer': 'ok'} and isinstance(result.invocation['settled_units'], str) and
                  int(result.invocation['settled_units']) > 2**53)
            try:
                session.ml.invoke('model', {'query': 'hi'}, invocation_id=identity(1))
            except InferenceError as failure:
                check('duplicate-no-replay', failure.invocation_id == identity(1) and failure.code == 'inference_replay' and failure.delivery_unknown)
            else:
                raise AssertionError('duplicate invocation succeeded')
            try:
                session.ml.invoke('other', {}, invocation_id=identity(4))
            except InferenceError as failure:
                check('alias-denied-before-submit', not failure.delivery_unknown)
            else:
                raise AssertionError('unknown alias invoked')
            try:
                client('inference-other-token').get_inference_bill(sid)
            except APIError as failure:
                check('other-tenant-history-hidden', failure.status == 404)
            else:
                raise AssertionError('cross-tenant history disclosed')
            failures = []
            def pending():
                try:
                    session.ml.invoke('model', {'mode': 'pending'}, invocation_id=identity(2), request_timeout=.6)
                except InferenceError as failure:
                    failures.append(failure)
            thread = threading.Thread(target=pending)
            thread.start()
            wait(lambda: Path(config['pending_marker']).exists())
            check('bill-observable-with-pending-model', entry(session.ml.bill(), 2).get('state') == 'reserved')
            thread.join(3)
            assert not thread.is_alive() and len(failures) == 1
            terminal = wait(lambda: value if (value := entry(session.ml.bill(), 2)).get('state') == 'uncertain' else None)
            check('request-timeout-preserves-held-budget', failures[0].invocation_id == identity(2) and failures[0].delivery_unknown and terminal['settled_units'] == '0')
            large = session.ml.invoke('model', {'mode': 'unicode'}, invocation_id=identity(3))
            check('expanded-JSON-response', large.data['text'] == '\u2028' * 140000 and large.invocation['output_bytes'] < 512 << 10)
            bill = session.ml.bill
        session.close()
        try:
            api.capabilities()
        except APIError as failure:
            assert failure.status == 503
        else:
            raise AssertionError('fixture did not disable new admission')
        closed = bill()
        check('history-after-session-and-discovery-end', closed['closed'] and len(closed['invocations']) == 3 and int(closed['held_units']) > 0)
        fresh = client().get_inference_bill(sid)
        assert fresh['settled_units'] == closed['settled_units']
    finally:
        for child in children:
            child.stop()


if __name__ == '__main__':
    main()
