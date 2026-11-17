import io
import json
import unittest
from osv_sandbox_client import Session, SessionInfo, SessionCommand, ProtocolError, TransportError
from test_client import SESSION_ID, FakeOpener, Reply, make_client, result, session_info

COMMAND_ID = 'c' * 24

def info():
    return {'id': COMMAND_ID, 'session_id': SESSION_ID, 'state': 'running'}

def terminal(sequence=1):
    value = result(); value['id'] = COMMAND_ID
    return {'info': dict(info(), state='succeeded'), 'events': [], 'next_sequence': sequence,
            'complete': True, 'result': {'session_id': SESSION_ID, 'result': value}}

class SSE(io.BytesIO):
    headers = {'Content-Type': 'text/event-stream'}
    status = 200
    def __init__(self, frames):
        super().__init__(b': keepalive\n\n' + b''.join(
            b'event: '+kind.encode()+b'\ndata: '+json.dumps(value).encode()+b'\n\n'
            for kind, value in frames))

class CommandTests(unittest.TestCase):
    def test_handle_reconnect_and_sse_bytes_terminal_and_idempotent_kill(self):
        output = {'session_id': SESSION_ID, 'command_id': COMMAND_ID,
                  'sequence': 1, 'stream': 'stdout', 'data_base64': 'AP8='}
        opener = FakeOpener([Reply(202, info()), Reply(200, {'session_id': SESSION_ID, 'commands': [info()]}),
                             Reply(200, {'info': info()}), Reply(200, {'killed': True}),
                             Reply(200, {'killed': False}), SSE([('output', output), ('result', terminal())])])
        session = Session(make_client(opener), SessionInfo.from_payload(session_info()))
        handle = session.start_command(SessionCommand('/bin/sh', ('-c', 'printf data')))
        self.assertEqual(session.list_commands()[0]['id'], handle.id)
        connected = session.connect_command(handle.id)
        self.assertTrue(connected.kill())
        self.assertFalse(connected.kill())
        events = list(connected.events())
        self.assertEqual(events[0].data, b'\x00\xff')
        self.assertTrue(events[-1].result.succeeded)
        self.assertEqual(events[-1].result.id, COMMAND_ID)
        self.assertIn('/events?after=0', opener.requests[-1][0].full_url)

    def test_corrupt_sequence_foreign_binding_and_missing_terminal_are_refused(self):
        base = {'session_id': SESSION_ID, 'command_id': COMMAND_ID,
                'sequence': 1, 'stream': 'stdout', 'data_base64': 'eA=='}
        for bad in (dict(base, sequence=2), dict(base, command_id='d'*24),
                    dict(base, data_base64='eA==\n')):
            session = Session(make_client(FakeOpener([Reply(202, info()), SSE([('output', bad)])])),
                              SessionInfo.from_payload(session_info()))
            handle = session.start_command(SessionCommand('/bin/sh'))
            with self.assertRaises(ProtocolError): list(handle.events())
        session = Session(make_client(FakeOpener([Reply(202, info()), SSE([])])),
                          SessionInfo.from_payload(session_info()))
        handle = session.start_command(SessionCommand('/bin/sh'))
        with self.assertRaises(TransportError): handle.wait()

    def test_resume_cursor_does_not_reexecute(self):
        session = Session(make_client(FakeOpener([Reply(202, info()), SSE([('result', terminal())])])),
                          SessionInfo.from_payload(session_info()))
        handle = session.start_command(SessionCommand('/bin/sh'))
        events = list(handle.events(after=1))
        self.assertEqual(len(events), 1)
        self.assertTrue(events[0].result.succeeded)

if __name__ == '__main__':
    unittest.main()
