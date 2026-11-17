"""Guest SDK contract and partial-I/O checks; not actual OSv VM acceptance."""
import copy
import ctypes
import json
from pathlib import Path
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'guest-sdk/python'))
import remote_infer as sdk
from remote_infer import _transport as transport

FIXTURE = json.loads((ROOT / 'tests/fixtures/inference-sdk.json').read_text())
ID = FIXTURE['result']['invocation']['id']


class BytesConnection:
    def __init__(self, data, step=3):
        self.data, self.step, self.written, self.closed = data, step, b'', 0

    def read(self, maximum, deadline):
        transport.remaining(deadline)
        count = min(maximum, self.step)
        result, self.data = self.data[:count], self.data[count:]
        return result

    def write(self, data, deadline):
        transport.remaining(deadline)
        self.written += data

    def close(self):
        self.closed += 1


def framed(body=b'{}', headers=None, status='200 OK'):
    fields = headers or [b'Content-Length: ' + str(len(body)).encode(), b'Content-Type: application/json']
    return ('HTTP/1.1 ' + status + '\r\n').encode() + b'\r\n'.join(fields) + b'\r\n\r\n' + body


class GuestInference(unittest.TestCase):
    def setUp(self):
        sdk._task_id = None

    def test_import_opens_no_network_and_probes_no_c_abi(self):
        code = '''import ctypes,socket,sys
def forbidden(*a,**k): raise AssertionError('import performed network/C ABI I/O')
ctypes.CDLL=forbidden
socket.socket=forbidden
sys.path.insert(0,sys.argv[1])
import remote_infer,sandbox
assert sandbox.ml is remote_infer.ml
'''
        subprocess.run([sys.executable, '-c', code, str(ROOT / 'guest-sdk/python')], check=True)

    def test_fixed_proxy_request_and_partial_response_ignore_environment(self):
        connection = BytesConnection(framed(b'{"value":"hello"}'))
        with patch.object(transport, '_connect', return_value=connection), patch.dict('os.environ', {'HTTP_PROXY':'http://forbidden.invalid:1'}):
            self.assertEqual(transport.exchange('GET', '/v1/bill', None, transport.deadline(1)), {'value':'hello'})
        self.assertTrue(connection.written.startswith(b'GET http://inference.osv.invalid/v1/bill HTTP/1.1\r\n'))
        self.assertEqual(connection.closed, 1)
        self.assertNotIn(b'forbidden', connection.written)

    def test_malformed_framing_json_and_eof_are_bounded(self):
        for label, wire in {
            'duplicate-length': framed(headers=[b'Content-Length: 2',b'Content-Length: 2',b'Content-Type: application/json']),
            'transfer-encoding': framed(headers=[b'Transfer-Encoding: chunked',b'Content-Length: 2',b'Content-Type: application/json']),
            'too-large': framed(headers=[b'Content-Length: 99999999',b'Content-Type: application/json']),
            'bad-utf8': framed(b'"\xff"'),
            'duplicate-json': framed(b'{"id":1,"id":2}'),
            'NaN': framed(b'NaN'),
            'partial-header': b'HTTP/1.1 200 OK\r\n',
            'partial-body': framed(b'{}')[:-1],
            'overlong-header': b'HTTP/1.1 200 OK\r\nX: '+b'a'*16384+b'\r\n\r\n{}',
            'redirect': framed(b'{}',status='302 Found'),
        }.items():
            with self.subTest(label):
                connection = BytesConnection(wire, 4096)
                with patch.object(transport, '_connect', return_value=connection):
                    with self.assertRaises(sdk.ProtocolError):
                        transport.exchange('GET', '/v1/bill', None, transport.deadline(1))
                self.assertEqual(connection.closed, 1)

    def test_one_absolute_deadline_includes_slow_headers(self):
        connection = BytesConnection(framed())
        original = connection.read
        def slow(maximum, bound):
            time.sleep(.01)
            return original(maximum, bound)
        connection.read = slow
        with patch.object(transport, '_connect', return_value=connection):
            with self.assertRaises(sdk.TransportError):
                transport.exchange('GET','/v1/bill',None,transport.deadline(.025))
        self.assertEqual(connection.closed, 1)

    def test_osv_partial_send_recv_negative_errno_and_close(self):
        class ABI:
            def __init__(self):
                self.input, self.output, self.closed, self.interrupted = b'', framed(b'{"ok":true}'), 0, False
            def osv_vsock_connect(self,cid,port,timeout):
                self.address=(cid,port)
                assert 0 < timeout <= 300000
                return 8
            def osv_vsock_send(self,handle,pointer,size,timeout):
                if not self.interrupted:
                    self.interrupted=True
                    return -4
                count=min(size,7)
                self.input+=ctypes.string_at(pointer,count)
                return count
            def osv_vsock_recv(self,handle,pointer,size,timeout):
                data,self.output=self.output[:min(size,5)],self.output[min(size,5):]
                ctypes.memmove(pointer,data,len(data))
                return len(data)
            def osv_vsock_close(self,handle):
                self.closed+=1
                return 0
        api=ABI()
        with patch.object(transport,'_osv_api',return_value=api):
            self.assertEqual(transport.exchange('GET','/v1/policy',None,transport.deadline(1)), {'ok':True})
        self.assertEqual(api.address,(2,5001))
        self.assertEqual(api.closed,1)
        self.assertTrue(api.input.endswith(b'Connection: close\r\n\r\n'))
        for operation, result in [('osv_vsock_connect',-110),('osv_vsock_send',-32),('osv_vsock_send',0),('osv_vsock_recv',-104),('osv_vsock_recv',0)]:
            with self.subTest(operation=operation,result=result):
                api=ABI()
                setattr(api,operation,lambda *args:result)
                with patch.object(transport,'_osv_api',return_value=api):
                    with self.assertRaises((sdk.TransportError,sdk.ProtocolError)):
                        transport.exchange('GET','/v1/policy',None,transport.deadline(1))
                self.assertEqual(api.closed,0 if operation=='osv_vsock_connect' else 1)

    def exchange(self,method,path,value,bound):
        self.calls.append((method,path,value))
        if path == '/v1/bill':
            return copy.deepcopy(FIXTURE['bill'])
        if path == '/v1/policy':
            return copy.deepcopy(FIXTURE['capabilities']['remote_inference_policy'])
        return copy.deepcopy(FIXTURE['result'])

    def test_shared_contract_and_result_keep_exact_units(self):
        self.calls=[]
        with patch.object(transport,'exchange',side_effect=self.exchange):
            result=sdk.ml.invoke('model',{'query':'hi'},invocation_id=ID)
        self.assertEqual(result.invocation_id,ID)
        self.assertEqual(result.invocation['settled_units'],'9007199254741066')
        self.assertEqual([row[1] for row in self.calls],['/v1/bill','/v1/policy','/v1/invoke'])

    def test_invalid_payload_or_explicit_identity_causes_no_io(self):
        cycle=[];cycle.append(cycle)
        for value in [float('nan'),2**53,cycle,{'bad':object()}]:
            with self.subTest(kind=type(value).__name__),patch.object(transport,'exchange') as exchange:
                with self.assertRaises(sdk.InferenceError) as error:
                    sdk.invoke('model',value,invocation_id=ID)
                self.assertFalse(error.exception.delivery_unknown)
                self.assertEqual(error.exception.invocation_id,ID)
                exchange.assert_not_called()
        with patch.object(transport,'exchange') as exchange:
            with self.assertRaises(sdk.ConfigurationError):
                sdk.invoke('model',{},invocation_id='invalid')
            exchange.assert_not_called()

    def test_lost_result_retains_known_id_without_replay(self):
        self.calls=[]
        def lost(*args):
            if args[1]=='/v1/invoke':
                self.calls.append(args)
                raise sdk.TransportError('lost response')
            return self.exchange(*args)
        with patch.object(transport,'exchange',side_effect=lost):
            with self.assertRaises(sdk.InferenceError) as error:
                sdk.invoke('model',{},invocation_id=ID)
        self.assertTrue(error.exception.delivery_unknown)
        self.assertEqual(error.exception.task_id,FIXTURE['result']['task_id'])
        self.assertEqual(sum(row[1]=='/v1/invoke' for row in self.calls),1)

    def test_task_identity_is_pinned_and_receipt_corruption_rejected(self):
        self.calls=[]
        with patch.object(transport,'exchange',side_effect=self.exchange):
            sdk.bill()
        other=copy.deepcopy(FIXTURE['bill']);other['task_id']='f'*24
        with patch.object(transport,'exchange',return_value=other):
            with self.assertRaises(sdk.ProtocolError):sdk.bill()
        def corrupt(*args):
            value=self.exchange(*args)
            if args[1]=='/v1/invoke':value['invocation']['settled_units']='1'
            return value
        with patch.object(transport,'exchange',side_effect=corrupt):
            with self.assertRaises(sdk.InferenceError) as error:sdk.invoke('model',{},invocation_id=ID)
        self.assertTrue(error.exception.delivery_unknown)
        self.assertEqual(error.exception.invocation_id,ID)


if __name__=='__main__':unittest.main()
