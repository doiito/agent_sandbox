"""E2B adapter contracts over the real native client, with a stateful API fixture."""
import base64
import copy
import json
import threading
import unittest
from unittest.mock import patch
import osv_sandbox_client as sdk_module

from osv_sandbox_client import (APIError, CodeCleanupError, CodeExecutionFailed, ConfigurationError,
    Context, ExecutionError, OutputMessage, ProtocolError, Sandbox, TimeoutException, TransportError,
    UnsupportedCapability)
from test_code import CID, code_caps, context, session


class CodeGateway:
    def __init__(self):
        native, _ = session([])
        native._client._exchange = self.exchange
        self.sandbox = Sandbox(native)
        self.calls, self.contexts, self.records = [], {CID: context()}, {}
        self.transitions, self.removing = {}, {}
        self.events, self.page_size, self.running, self.failure = [], 64, False, None
        self.terminal_status, self.evicted, self.create_loss = 'completed', False, False
        self.submit_loss, self.cancel_loss, self.forged_after_cancel = None, False, False
        self.cancelled = threading.Event()
        self.owner_missing = False
        self.lock = threading.Lock()

    def exchange(self, method, path, payload=None, **options):
        with self.lock:
            self.calls.append((method, path, copy.deepcopy(payload), options))
            if path.endswith('/capabilities'):
                return code_caps()
            if path.endswith('/contexts/default'):
                language = payload['language']
                value = next((c for c in self.contexts.values() if c['language'] == language), None)
                if value is None:
                    value = context(id=('d' if language == 'javascript' else 'f') * 24, language=language)
                    self.contexts[value['id']] = value
                return copy.deepcopy(value)
            if path.endswith('/contexts'):
                if method == 'GET':
                    return {'session_id': self.sandbox.sandbox_id, 'contexts': copy.deepcopy(list(self.contexts.values()))}
                value = context(id=payload['context_id'], language=payload['language'], cwd=payload['cwd'], state='starting', pid=None)
                self.contexts[value['id']] = value
                self.transitions[value['id']] = [('starting', 1), ('idle', 1)]
                if self.create_loss:
                    self.create_loss = False
                    raise TransportError('created context reply lost')
                return copy.deepcopy(value)
            if '/contexts/' in path:
                cid = path.split('/contexts/')[1].split('?')[0].split('/')[0]
                if method == 'GET':
                    if cid in self.removing:
                        self.removing[cid] -= 1
                        if not self.removing[cid]: self.contexts.pop(cid, None)
                    if cid not in self.contexts:
                        raise APIError(404, 'not_found' if self.owner_missing else 'code_not_found', 'missing')
                    value = self.contexts[cid]
                    if self.transitions.get(cid):
                        value['state'], value['generation'] = self.transitions[cid].pop(0)
                        value['pid'] = 42 if value['state'] == 'idle' else None
                    return copy.deepcopy(value)
                value = self.contexts[cid]
                if method == 'POST':
                    self.transitions[cid] = [('stopping', value['generation']), ('starting', value['generation'] + 1), ('idle', value['generation'] + 1)]
                    value['state'], value['pid'] = 'stopping', None
                    return copy.deepcopy(value)
                self.removing[cid] = 2
                value['state'] = 'stopping'
                return {'session_id': value['session_id'], 'context_id': cid, 'removed': True}
            if path.endswith('/code-executions'):
                eid = payload['execution_id']
                if eid in self.records:
                    raise APIError(409, 'conflict', 'execution already exists')
                if self.submit_loss == 'reject':
                    raise APIError(409, 'stale_context', 'generation changed')
                if self.submit_loss == 'before':
                    raise TransportError('submit response lost before delayed admission')
                events = [{'type': 'started'}] + copy.deepcopy(self.events)
                status = 'running' if self.running else self.terminal_status
                if not self.running: events += [{'type': 'finished', 'status': status, 'context_usable': True}]
                self.records[eid] = dict(context_id=payload['context_id'], generation=payload['generation'], status=status, events=events, failure=self.failure)
                if self.submit_loss == 'accepted': raise TransportError('accepted reply lost')
                return {'session_id': self.sandbox.sandbox_id, 'execution_id': eid, 'accepted': True}
            if '/code-executions/' in path:
                eid = path.split('/code-executions/')[1].split('?')[0]
                if method == 'DELETE':
                    from urllib.parse import parse_qs
                    query = parse_qs(path.split('?')[1])
                    if eid not in self.records:
                        self.records[eid] = dict(context_id=query['context_id'][0], generation=int(query['generation'][0]), status='cancelled',
                            events=[{'type': 'finished', 'status': 'cancelled', 'context_usable': True}], failure='cancelled_before_submit')
                    row = self.records[eid]
                    if row['status'] == 'running':
                        row['status'] = 'cancelled'
                        row['events'].append({'type': 'finished', 'status': 'cancelled', 'context_usable': True})
                    self.cancelled.set()
                    if self.cancel_loss:
                        self.cancel_loss = False
                        raise TransportError('cancel acknowledgment lost')
                    return {'session_id': self.sandbox.sandbox_id, 'execution_id': eid, 'accepted': True}
                row = self.records[eid]
                after = int(path.split('after=')[1])
                events = [] if self.evicted else [{'sequence': n + 1, 'event': event} for n, event in enumerate(row['events'])][after:after+self.page_size]
                return copy.deepcopy(dict(session_id=('a' * 24 if self.forged_after_cancel and self.cancelled.is_set() else self.sandbox.sandbox_id), id=eid,
                    language=self.contexts[row['context_id']]['language'], context_id=row['context_id'], generation=row['generation'], status=row['status'],
                    events=events, last_sequence=len(row['events']), next_sequence=after+len(events), events_evicted=self.evicted, failure=row['failure']))
            if method == 'DELETE' and path.endswith(self.sandbox.sandbox_id):
                return {}
            raise AssertionError((method, path))

    def submitted(self):
        return [call for call in self.calls if call[0] == 'POST' and call[1].endswith('/code-executions')]


class E2BCodeTests(unittest.TestCase):
    def _transport_at_execution_deadline(self, expired, phase):
        gateway = CodeGateway()
        gateway.running = True
        original = TransportError('HTTPS exchange failed (URLError)')
        clock, injected = [0.0], [False]
        exchange = gateway.exchange

        def failing_exchange(method, path, payload=None, **options):
            submit = method == 'POST' and path.endswith('/code-executions')
            poll = method == 'GET' and '/code-executions/' in path
            if (submit if phase == 'submit' else poll) and not injected[0]:
                if submit:
                    exchange(method, path, payload, **options)
                injected[0] = True
                clock[0] = .04 if expired else .01
                raise original
            if method == 'DELETE':
                clock[0] = .04  # Cleanup crossing the deadline must not reclassify.
            return exchange(method, path, payload, **options)

        gateway.sandbox._session._client._exchange = failing_exchange
        with patch.object(sdk_module.time, 'monotonic', lambda: clock[0]), \
                patch.object(sdk_module.threading, 'Timer'):
            expected = TimeoutException if expired else TransportError
            with self.assertRaises(expected) as caught:
                gateway.sandbox.run_code('while True: pass', timeout=.03)
        self.assertTrue(injected[0])
        self.assertTrue(gateway.cancelled.is_set())
        self.assertEqual(len(gateway.submitted()), 1)
        execution = caught.exception.execution
        self.assertEqual(gateway.records[execution.id]['status'], 'cancelled')
        if expired:
            self.assertIs(caught.exception.__cause__, original)
        else:
            self.assertIs(caught.exception, original)

    def test_transport_failure_after_execution_deadline_is_timeout(self):
        for phase in ('submit', 'poll'):
            with self.subTest(phase=phase):
                self._transport_at_execution_deadline(True, phase)

    def test_transport_failure_before_execution_deadline_is_preserved(self):
        for phase in ('submit', 'poll'):
            with self.subTest(phase=phase):
                self._transport_at_execution_deadline(False, phase)

    def test_callback_transport_error_after_deadline_is_preserved(self):
        gateway = CodeGateway()
        gateway.running = True
        gateway.events = [{'type': 'stdout', 'data': 'eA=='}]
        original = TransportError('callback request failed')
        clock = [0.0]

        def callback(_):
            clock[0] = .04
            raise original

        with patch.object(sdk_module.time, 'monotonic', lambda: clock[0]), \
                patch.object(sdk_module.threading, 'Timer'):
            with self.assertRaises(TransportError) as caught:
                gateway.sandbox.run_code('print(1)', timeout=.03, on_stdout=callback)
        self.assertIs(caught.exception, original)
        self.assertTrue(gateway.cancelled.is_set())
        self.assertEqual(len(gateway.submitted()), 1)

    def test_rich_output_utf8_paging_empty_fields_and_callback_models(self):
        gateway = CodeGateway()
        gateway.page_size = 2
        gateway.events = [
            {'type': 'stdout', 'data': base64.b64encode(b'x\xe2').decode()},
            {'type': 'stdout', 'data': base64.b64encode(b'\x82\xac').decode()},
            {'type': 'stderr', 'data': base64.b64encode(b'warning').decode()},
            {'type': 'result', 'data': {'text/plain': '', 'text/html': '', 'application/json': {'n': 9007199254740993}}, 'is_main_result': True}]
        seen = []
        result = gateway.sandbox.run_code('value = 42\nvalue', envs={'V': '中文'}, timeout=0,
            on_stdout=lambda value: seen.append(value), on_stderr=lambda value: seen.append(value), on_result=lambda value: seen.append(value))
        self.assertEqual(''.join(result.logs.stdout), 'x€')
        self.assertEqual(result.logs.stderr, ['warning'])
        self.assertEqual(result.text, '')
        self.assertEqual(result.results[0].json['n'], 9007199254740993)
        self.assertEqual(result.results[0]._repr_html_(), '')
        self.assertEqual(result.results[0].raw['json']['n'], 9007199254740993)
        self.assertIsNone(result.execution_count)
        self.assertIsInstance(seen[0], OutputMessage)
        self.assertFalse(seen[0].error)
        self.assertTrue(seen[2].error)
        self.assertEqual(json.loads(result.to_json())['results'][0]['html'], '')
        self.assertEqual(json.loads(result.logs.to_json())['stderr'], ['warning'])
        self.assertEqual(gateway.submitted()[0][2]['timeout_ms'], 0)
        self.assertFalse(gateway.cancelled.is_set())

    def test_user_error_is_execution_data_and_error_callback_is_typed(self):
        gateway = CodeGateway()
        gateway.events = [{'type': 'error', 'name': 'ValueError', 'value': '', 'traceback': ''}]
        seen = []
        result = gateway.sandbox.run_code('raise ValueError()', on_error=seen.append)
        self.assertIsInstance(result.error, ExecutionError)
        self.assertEqual(result.error.value, '')
        self.assertEqual(seen, [result.error])
        self.assertFalse(gateway.cancelled.is_set())

    def test_callback_failure_confirms_stop_and_preserves_original_exception(self):
        gateway = CodeGateway()
        gateway.running = True
        gateway.events = [{'type': 'stdout', 'data': 'eA=='}]
        original = RuntimeError('callback failed')
        def callback(_): raise original
        with self.assertRaises(RuntimeError) as caught:
            gateway.sandbox.run_code('while True: pass', on_stdout=callback)
        self.assertIs(caught.exception, original)
        self.assertTrue(gateway.cancelled.is_set())
        self.assertEqual(len(gateway.submitted()), 1)
        self.assertTrue(all(row['status'] == 'cancelled' for row in gateway.records.values()))

    def test_unknown_submit_delivery_is_cancelled_by_known_id_without_replay(self):
        for mode in ('accepted', 'before'):
            gateway = CodeGateway()
            gateway.running, gateway.submit_loss, gateway.cancel_loss = True, mode, True
            with self.assertRaises(TransportError):
                gateway.sandbox.run_code('side_effect()')
            self.assertEqual(len(gateway.submitted()), 1)
            eid = gateway.submitted()[0][2]['execution_id']
            self.assertEqual(gateway.records[eid]['status'], 'cancelled')
            if mode == 'before':
                self.assertEqual(gateway.records[eid]['failure'], 'cancelled_before_submit')
                with self.assertRaises(APIError):
                    gateway.exchange('POST', gateway.submitted()[0][1], gateway.submitted()[0][2])

    def test_deadline_cancels_guest_while_synchronous_callback_is_blocked(self):
        gateway = CodeGateway()
        gateway.running = True
        gateway.events = [{'type': 'stdout', 'data': 'eA=='}]
        def callback(_):
            self.assertTrue(gateway.cancelled.wait(2), 'watchdog could not cancel during callback')
        with self.assertRaises(TimeoutException):
            gateway.sandbox.run_code('while True: pass', on_stdout=callback, timeout=0.03)
        self.assertEqual(gateway.submitted()[0][2]['timeout_ms'], 30)

    def test_unconfirmed_stop_requests_owner_close_and_reports_uncertainty(self):
        gateway = CodeGateway()
        gateway.running, gateway.forged_after_cancel = True, True
        gateway.events = [{'type': 'stdout', 'data': 'eA=='}]
        original = RuntimeError('callback failed')
        def callback(_): raise original
        with self.assertRaises(CodeCleanupError) as caught:
            gateway.sandbox.run_code('while True: pass', on_stdout=callback)
        self.assertIs(caught.exception.original_error, original)
        self.assertIsInstance(caught.exception.cleanup_error, ProtocolError)
        self.assertTrue(caught.exception.owner_close_requested)
        self.assertEqual(gateway.calls[-1][0], 'DELETE')
        self.assertTrue(gateway.calls[-1][1].endswith(gateway.sandbox.sandbox_id))

    def test_all_context_methods_wait_for_real_ready_next_generation_and_removal(self):
        gateway = CodeGateway()
        value = gateway.sandbox.create_code_context(language='javascript', request_timeout=2)
        self.assertIsInstance(value, Context)
        self.assertEqual(gateway.contexts[value.id]['state'], 'idle')
        self.assertEqual(len(gateway.sandbox.list_code_contexts()), 2)
        gateway.sandbox.restart_code_context(value)
        self.assertEqual(gateway.contexts[value.id]['generation'], 2)
        self.assertEqual(gateway.contexts[value.id]['state'], 'idle')
        gateway.sandbox.run_code('40+2', context=value)
        self.assertEqual(gateway.submitted()[0][2]['generation'], 2)
        gateway.sandbox.remove_code_context(value.id)
        self.assertNotIn(value.id, gateway.contexts)
        self.assertIn(CID, gateway.contexts)

    def test_owner_missing_is_not_context_removal_confirmation(self):
        gateway = CodeGateway()
        gateway.owner_missing = True
        with self.assertRaises(APIError) as caught:
            gateway.sandbox.remove_code_context(CID)
        self.assertEqual(caught.exception.code, 'not_found')

    def test_invalid_inputs_callbacks_and_cross_owner_context_are_rejected(self):
        gateway = CodeGateway()
        async def callback(_): pass
        for source, options in [('', {'language':'python', 'context':Context(CID, 'python', '/workspace')}),
            ('', {'on_stdout':callback}), ('', {'timeout':True}), ('x' * 65537, {}), ('', {'envs':{'BAD=KEY':'x'}}),
            ('', {'context':Context(CID, 'python', '/workspace', session_id='a'*24)})]:
            with self.assertRaises(ConfigurationError): gateway.sandbox.run_code(source, **options)
        self.assertFalse(gateway.calls)

    def test_definitive_submit_rejection_does_not_cancel_another_cell(self):
        gateway = CodeGateway()
        gateway.submit_loss = 'reject'
        with self.assertRaises(APIError): gateway.sandbox.run_code('40+2')
        self.assertFalse(gateway.cancelled.is_set())

    def test_old_template_still_rejects_code(self):
        gateway = CodeGateway()
        report = code_caps()
        report['features']['code_contexts'] = False
        original = gateway.exchange
        gateway.sandbox._session._client._exchange = lambda method, path, payload=None, **options: report if path.endswith('/capabilities') else original(method, path, payload, **options)
        with self.assertRaises(UnsupportedCapability): gateway.sandbox.run_code('40+2')

    def test_runtime_failure_timeout_and_eviction_are_not_empty_success(self):
        for status, evicted, expected in [('failed', False, CodeExecutionFailed), ('timed_out', False, TimeoutException),
                                          ('completed', True, ProtocolError)]:
            gateway = CodeGateway()
            gateway.terminal_status, gateway.evicted, gateway.failure = status, evicted, 'kernel_exited' if status == 'failed' else None
            with self.assertRaises(expected): gateway.sandbox.run_code('40+2')
            self.assertTrue(gateway.cancelled.is_set())

    def test_cancel_ack_and_transient_missing_journal_do_not_prove_stop(self):
        gateway = CodeGateway()
        gateway.running = True
        gateway.events = [{'type': 'stdout', 'data': 'eA=='}]
        original_exchange = gateway.exchange
        checked = []
        def exchange(method, path, payload=None, **options):
            if method == 'GET' and '/code-executions/' in path and gateway.cancelled.is_set():
                checked.append(path)
                if len(checked) < 3: raise APIError(404, 'code_not_found', 'not yet admitted')
            return original_exchange(method, path, payload, **options)
        gateway.sandbox._session._client._exchange = exchange
        original = RuntimeError('callback failed')
        def callback(_): raise original
        with self.assertRaises(RuntimeError) as caught: gateway.sandbox.run_code('while True: pass', on_stdout=callback)
        self.assertIs(caught.exception, original)
        self.assertEqual(len(checked), 3)

    def test_creation_ack_loss_observes_existing_id_without_recreating(self):
        gateway = CodeGateway()
        gateway.create_loss = True
        value = gateway.sandbox.create_code_context(language='typescript')
        self.assertEqual(gateway.contexts[value.id]['state'], 'idle')
        self.assertEqual(len([call for call in gateway.calls if call[0]=='POST' and call[1].endswith('/contexts')]), 1)

    def test_busy_or_failed_context_does_not_submit_or_cancel_another_cell(self):
        for state, expected in [('running', APIError), ('failed', CodeExecutionFailed)]:
            gateway = CodeGateway()
            gateway.contexts[CID]['state'] = state
            with self.assertRaises(expected): gateway.sandbox.run_code('40+2')
            self.assertEqual(gateway.submitted(), [])
            self.assertFalse(gateway.cancelled.is_set())

    def test_synchronous_callback_can_query_contexts_without_a_client_lock(self):
        gateway = CodeGateway()
        gateway.events = [{'type':'stdout', 'data':'eA=='}]
        seen = []
        gateway.sandbox.run_code('print(42)', on_stdout=lambda _: seen.extend(gateway.sandbox.list_code_contexts()))
        self.assertEqual(seen[0].id, CID)


if __name__ == '__main__': unittest.main()
