import base64
from types import SimpleNamespace
import unittest
from osv_sandbox_client import (APIError, CommandHandle, ConfigurationError, ProtocolError,
                                Sandbox, TimeoutException)

class InputClient:
    _timeout = 0.2
    def __init__(self):
        self.calls=[];self.receipts={};self.pending=False;self.foreign=False;self.failed=False
    def _exchange(self,method,path,payload=None,accepted=(200,),timeout_seconds=None):
        self.calls.append((method,path,payload))
        if method=='POST':
            sequence=len(self.receipts)+1
            self.receipts[sequence]={'session_id':'b'*24,'command_id':'c'*24,'sequence':sequence,
                'state':'pending','written_bytes':0,'closed':False}
            self.last=payload
        else:
            sequence=int(path.rsplit('/',1)[1])
            if not self.pending:
                self.receipts[sequence].update(state='closed' if self.last['close'] else 'delivered',
                    written_bytes=len(base64.b64decode(self.last['data_base64'])),closed=self.last['close'])
                if self.failed:self.receipts[sequence].update(state='failed',error_code='stdin_closed')
        value=dict(self.receipts[sequence])
        if self.foreign:value['command_id']='d'*24
        return value

def fixture():
    client=InputClient()
    info={'session_id':'b'*24,'id':'c'*24,'state':'running','pid':42,'entrypoint':'/bin/bash','args':[]}
    session=SimpleNamespace(id='b'*24,_client=client,list_commands=lambda:[info])
    return client,CommandHandle(session,info),Sandbox(session)

class InputTests(unittest.TestCase):
    def test_native_and_pid_facade_preserve_binary_text_and_eof(self):
        client,native,facade=fixture()
        self.assertIsNone(native.send_stdin(b'\0\xff'))
        self.assertEqual(client.calls[0][2]['data_base64'],'AP8=')
        self.assertIsNone(facade.commands.send_stdin(42,'环境'))
        self.assertEqual(base64.b64decode(client.last['data_base64']),'环境'.encode())
        self.assertIsNone(facade.commands.close_stdin(42))
        self.assertTrue(client.last['close'])
        self.assertEqual(len([call for call in client.calls if call[0]=='POST']),3)

    def test_timeout_preserves_ticket_and_does_not_retry(self):
        client,native,_=fixture();client.pending=True
        with self.assertRaises(TimeoutException):native.send_stdin(b'once',request_timeout=0.02)
        self.assertEqual(len([call for call in client.calls if call[0]=='POST']),1)
        self.assertEqual(native.poll_stdin(1)['state'],'pending')
        client.pending=False
        self.assertEqual(native.poll_stdin(1)['written_bytes'],4)

    def test_invalid_receipt_input_and_pipe_failure_are_explicit(self):
        client,native,facade=fixture()
        for data in ('text',b'x'*16385):
            with self.assertRaises(ConfigurationError):native.send_stdin(data)
        self.assertEqual(client.calls,[])
        client.foreign=True
        with self.assertRaises(ProtocolError):native.submit_stdin(b'x')
        client.foreign=False;client.failed=True
        with self.assertRaises(APIError) as caught:native.send_stdin(b'x')
        self.assertEqual(caught.exception.code,'stdin_closed')
        with self.assertRaises(APIError) as caught:facade.commands.close_stdin(99)
        self.assertEqual(caught.exception.status,404)
