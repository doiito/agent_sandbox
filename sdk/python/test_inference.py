"""Known-ID inference and exact billing contracts, shared with the Node tests."""
import copy
import io
import json
from pathlib import Path
import unittest
from urllib.error import HTTPError, URLError
from unittest.mock import patch

from osv_sandbox_client import (APIError, ConfigurationError, InferenceError, ProtocolError,
                                Session, SessionInfo, TransportError, UnsupportedCapability)
from test_client import FakeOpener, Reply, make_client

FIXTURE = json.loads((Path(__file__).resolve().parents[2] / 'tests/fixtures/inference-sdk.json').read_text())
SID, IID = FIXTURE['session']['id'], FIXTURE['result']['invocation']['id']


def setup(replies, network='proxy'):
    opener = FakeOpener(replies)
    client = make_client(opener)
    info = dict(FIXTURE['session'], network=network)
    return Session(client, SessionInfo.from_payload(info)), opener


def responses(result=None, cap=None):
    return [Reply(200, copy.deepcopy(FIXTURE['capabilities'] if cap is None else cap)),
            Reply(200, copy.deepcopy(FIXTURE['result'] if result is None else result))]


class InferenceSDKTest(unittest.TestCase):
    def test_linux_v8_keeps_signed_inference_capability(self):
        cap = copy.deepcopy(FIXTURE['capabilities'])
        cap['artifact_manifest_protocol'] = 'osv-sandbox-artifacts/v8'
        session, _ = setup(responses(cap=cap))
        result = session.ml.invoke('model', {'query': 'hi'}, invocation_id=IID, timeout_ms=1000)
        self.assertEqual(result.data, {'answer': 'ok'})

    def test_authenticated_invoke_and_history_without_session_discovery(self):
        session, opener = setup(responses() + [Reply(200, FIXTURE['bill']), Reply(200, FIXTURE['bill'])])
        result = session.ml.invoke('model', {'query': 'hi'}, invocation_id=IID, timeout_ms=1000)
        self.assertEqual((result.task_id, result.invocation_id, result.data), (SID, IID, {'answer': 'ok'}))
        self.assertEqual(result.invocation['settled_units'], '9007199254741066')
        post = opener.requests[1][0]
        self.assertEqual(post.full_url, 'https://sandbox.example/v2/sessions/' + SID + '/ml/invocations')
        self.assertEqual(post.get_header('Authorization'), 'Bearer test-token')
        self.assertEqual(json.loads(post.data), {'id': IID, 'endpoint': 'model', 'payload': {'query': 'hi'}, 'timeout_ms': 1000})
        self.assertEqual(session.ml.bill()['settled_units'], '9007199254741066')
        self.assertEqual(session._client.get_inference_bill(SID)['closed'], True)
        self.assertTrue(all(req.full_url.endswith('/v2/ml/bills/' + SID) for req, _ in opener.requests[2:]))

    def test_generated_id_is_known_after_transport_or_http_failure_without_replay(self):
        for failure in (URLError('connection lost'), HTTPError('https://sandbox.example', 409, 'Conflict', {},
                        io.BytesIO(b'{"code":"inference_replay","error":"already known"}'))):
            session, opener = setup([Reply(200, FIXTURE['capabilities'])])
            normal = opener.open
            def exchange(req, timeout):
                if req.method == 'POST':
                    opener.requests.append((req, timeout))
                    raise failure
                return normal(req, timeout)
            opener.open = exchange
            with patch('osv_sandbox_client.secrets.token_hex', return_value=IID), self.assertRaises(InferenceError) as caught:
                session.ml.invoke('model', {'query': 'hi'})
            self.assertEqual((caught.exception.task_id, caught.exception.invocation_id), (SID, IID))
            self.assertTrue(caught.exception.delivery_unknown)
            self.assertIsInstance(caught.exception.cause, APIError if isinstance(failure, HTTPError) else TransportError)
            self.assertEqual(len(opener.requests), 2)
            self.assertEqual(json.loads(opener.requests[-1][0].data)['id'], IID)

    def test_payload_is_copied_before_capability_io(self):
        session, opener = setup(responses())
        payload = {'query': 'hi'}
        normal = opener.open
        def exchange(req, timeout):
            if req.method == 'GET':
                payload['query'] = 'changed while waiting'
            return normal(req, timeout)
        opener.open = exchange
        session.ml.invoke('model', payload, invocation_id=IID)
        self.assertEqual(json.loads(opener.requests[1][0].data)['payload'], {'query': 'hi'})

    def test_invalid_plain_json_and_options_never_open_a_connection(self):
        cycle = []; cycle.append(cycle)
        bad_payloads = [float('nan'), float('inf'), 1 << 54, {'bad': object()}, {3: 'key'}, '\ud800', cycle, {'x': 'a' * (256 << 10)}]
        for payload in bad_payloads:
            with self.subTest(type=type(payload).__name__):
                session, opener = setup([])
                with self.assertRaises(InferenceError) as caught:
                    session.ml.invoke('model', payload, invocation_id=IID)
                self.assertIsInstance(caught.exception.cause, ConfigurationError)
                self.assertFalse(caught.exception.delivery_unknown)
                self.assertEqual(opener.requests, [])
        for options in ({'timeout_ms': True}, {'request_timeout': 0}):
            session, opener = setup([])
            with self.assertRaises(InferenceError):
                session.ml.invoke('model', {}, invocation_id=IID, **options)
            self.assertEqual(opener.requests, [])
        session, opener = setup([])
        with self.assertRaises(ConfigurationError):
            session.ml.invoke('model', {}, invocation_id='bad')
        with self.assertRaises(InferenceError):
            session.ml.invoke('https://provider.invalid', {}, invocation_id=IID)
        self.assertEqual(opener.requests, [])

    def test_owner_policy_and_limits_are_checked_before_post(self):
        for name in ('old-profile', 'other-session', 'wrong-template', 'disabled', 'unknown-alias', 'size', 'timeout', 'network'):
            with self.subTest(name=name):
                cap = copy.deepcopy(FIXTURE['capabilities'])
                alias, payload, timeout = 'model', {'query': 'hi'}, 0
                if name == 'old-profile': cap['artifact_manifest_protocol'] = 'osv-sandbox-artifacts/v6'
                if name == 'other-session': cap['session_id'] = 'e' * 24
                if name == 'wrong-template': cap['artifact_manifest_sha256'] = 'e' * 64
                if name == 'disabled': cap['features']['remote_inference'] = False
                if name == 'unknown-alias': alias = 'other'
                if name == 'size': payload = {'query': 'a' * 200}
                if name == 'timeout': timeout = 1001
                session, opener = setup([Reply(200, cap)], network='none' if name == 'network' else 'proxy')
                with self.assertRaises(InferenceError) as caught:
                    session.ml.invoke(alias, payload, invocation_id=IID, timeout_ms=timeout)
                self.assertFalse(caught.exception.delivery_unknown)
                self.assertTrue(all(req.method == 'GET' for req, _ in opener.requests))

    def test_result_binding_and_accounting_errors_preserve_known_id(self):
        for name in ('task', 'id', 'endpoint', 'price-number', 'settled', 'unfinished', 'unstarted', 'duration', 'zero-start', 'nonfinite-output'):
            with self.subTest(name=name):
                result = copy.deepcopy(FIXTURE['result'])
                invoice = result['invocation']
                if name == 'task': result['task_id'] = 'e' * 24
                if name == 'id': invoice['id'] = 'e' * 24
                if name == 'endpoint': invoice['endpoint'] = 'other'
                if name == 'price-number': invoice['price']['request_units'] = 9007199254740993
                if name == 'settled': invoice['settled_units'] = '0'
                if name == 'unfinished': del invoice['finished_at']
                if name == 'unstarted': invoice['dispatched'] = False
                if name == 'duration': invoice['duration_ms'] = -1
                if name == 'zero-start': invoice['started_at'] = '0001-01-01T00:00:00Z'
                if name == 'nonfinite-output': result['data'] = float('inf')
                session, opener = setup(responses(result))
                with self.assertRaises(InferenceError) as caught:
                    session.ml.invoke('model', {'query': 'hi'}, invocation_id=IID)
                self.assertEqual(caught.exception.invocation_id, IID)
                self.assertTrue(caught.exception.delivery_unknown)
                self.assertIsInstance(caught.exception.cause, ProtocolError)
                self.assertEqual(len(opener.requests), 2)

    def test_bill_handles_pending_uncertain_and_rejects_corrupt_totals(self):
        bill = copy.deepcopy(FIXTURE['bill'])
        invoice = bill['invocations'][0]
        invoice.update(state='reserved', dispatched=False, http_status=0, output_bytes=0, settled_units='0')
        del invoice['finished_at']
        bill.update(closed=False, settled_units='0', held_units=invoice['reserved_units'])
        session, _ = setup([Reply(200, bill)])
        self.assertEqual(session.ml.bill()['held_units'], '9007199254741405')
        invoice.update(state='uncertain', code='inference_restarted', finished_at='2026-11-07T00:00:01Z')
        bill['closed'] = True
        session, _ = setup([Reply(200, bill)])
        self.assertEqual(session.ml.bill()['invocations'][0]['state'], 'uncertain')
        for edit in (lambda b: b.update(held_units='0'), lambda b: b.update(budget_units='1'),
                     lambda b: b.update(task_id='e' * 24), lambda b: b['invocations'].append(b['invocations'][0]),
                     lambda b: b['invocations'][0].update(reserved_units='09007199254741405'),
                     lambda b: b['invocations'][0].update(reserved_units='18446744073709551616')):
            broken = copy.deepcopy(bill); edit(broken)
            session, _ = setup([Reply(200, broken)])
            with self.assertRaises(ProtocolError): session.ml.bill()
        oversized = copy.deepcopy(FIXTURE['bill'])
        entry = oversized['invocations'][0]
        entry.update(output_bytes=entry['max_output_bytes'] + 1, settled_units=entry['reserved_units'])
        oversized['settled_units'] = entry['reserved_units']
        session, _ = setup([Reply(200, oversized)])
        with self.assertRaises(ProtocolError): session.ml.bill()


if __name__ == '__main__':
    unittest.main()
