"""Network fetch stays on the authenticated API and validates binary results."""
import copy
import json
import unittest
from osv_sandbox_client import ConfigurationError, NetworkFetchResult, ProtocolError, UnsupportedCapability
from test_client import FakeOpener, Reply, capabilities, make_client

def network_capabilities():
    value = capabilities()
    value['methods'].append('POST /v2/net/fetch')
    value['features']['network_fetch'] = True
    value['network_fetch_policy'] = {'max_request_bytes': 262144, 'max_response_bytes': 524288, 'timeout_ms': 1000}
    return value

def network_response():
    return {'protocol': 'osv-sandbox-network-fetch/v1', 'request_id': 'a' * 24,
            'url': 'https://allowed.test/data', 'status': 404, 'headers': {'Content-Type': ['application/octet-stream']},
            'body_base64': 'AP8=', 'body_bytes': 2, 'redirects': 0, 'duration_ms': 1, 'request_bytes': 2, 'response_bytes': 2}

class NetworkFetchTest(unittest.TestCase):
    def test_authenticated_route_and_binary_body(self):
        opener = FakeOpener([Reply(200, network_capabilities()), Reply(200, network_response())])
        client = make_client(opener)
        result = client.fetch_network('https://allowed.test/data', method='POST', body=b'\0\xff',
                                      headers={'Authorization': 'remote-key'}, timeout_ms=1000)
        self.assertEqual((result.status, result.body), (404, b'\0\xff'))
        req = opener.requests[1][0]
        self.assertEqual(req.full_url, 'https://sandbox.example/v2/net/fetch')
        payload = json.loads(req.data)
        self.assertEqual(payload['body_base64'], 'AP8=')
        self.assertEqual(payload['headers'], {'Authorization': 'remote-key'})
        self.assertEqual(req.get_header('Authorization'), 'Bearer test-token')

    def test_disabled_feature_and_bad_options(self):
        client = make_client(FakeOpener([Reply(200, capabilities())]))
        with self.assertRaises(UnsupportedCapability):
            client.fetch_network('https://allowed.test')
        client = make_client(FakeOpener([]))
        for options in [{'body': 'text'}, {'method': 'CONNECT'}, {'timeout_ms': True}, {'follow_redirects': 'yes'}]:
            with self.assertRaises(ConfigurationError):
                client.fetch_network('https://allowed.test', **options)
        for options in [{'body': b'x' * 262145, 'method': 'POST'}, {'timeout_ms': 1001}]:
            client = make_client(FakeOpener([Reply(200, network_capabilities())]))
            with self.assertRaises(ConfigurationError):
                client.fetch_network('https://allowed.test', **options)

    def test_response_integrity(self):
        for patch in [{'body_base64': '???'}, {'body_bytes': 3}, {'redirects': 6}, {'request_id': 'other'},
                      {'headers': {'X': 'not-list'}}, {'status': True}, {'response_bytes': 1}]:
            value = copy.deepcopy(network_response())
            value.update(patch)
            with self.assertRaises(ProtocolError):
                NetworkFetchResult.from_payload(value)

if __name__ == '__main__':
    unittest.main()
