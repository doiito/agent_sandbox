"""Guest proxy must remain an explicit, live tenant capability."""
import json
import unittest
from osv_sandbox_client import JobRequest, SessionRequest, TemplateSelector, UnsupportedCapability, ProtocolError
from test_client import DIGEST, FakeOpener, Reply, capabilities, make_client, result, session_info

def proxy_capabilities():
    value=capabilities()
    value['features'].update(network_egress=True,sessions=True)
    value['methods'].append('POST /v2/sessions')
    return value

class GuestProxyContractTest(unittest.TestCase):
    def test_explicit_proxy_job_and_session_use_the_advertised_template(self):
        for session in (False,True):
            opener=FakeOpener([Reply(200,proxy_capabilities()),Reply(201 if session else 200,session_info() if session else result())])
            client=make_client(opener)
            if session:
                client.create_session(SessionRequest(network='proxy'))
            else:
                client.run(JobRequest('/bin/sh',network='proxy'))
            payload=json.loads(opener.requests[-1][0].data)
            self.assertEqual(payload['network'],'proxy')
            self.assertEqual(payload['artifact_manifest_sha256'],DIGEST)
            self.assertEqual(len(opener.requests),2)

    def test_missing_live_permission_or_different_template_never_posts(self):
        for session in (False,True):
            for wrong_template in (False,True):
                opener=FakeOpener([Reply(200,proxy_capabilities() if wrong_template else capabilities())])
                client=make_client(opener)
                template=TemplateSelector('firecracker-linux','c'*64 if wrong_template else DIGEST)
                with self.assertRaises(ProtocolError if wrong_template else UnsupportedCapability):
                    if session:
                        client.create_session(SessionRequest(network='proxy'),template=template)
                    else:
                        client.run(JobRequest('/bin/sh',network='proxy'),template=template)
                self.assertEqual(len(opener.requests),1)
                self.assertEqual(opener.requests[0][0].method,'GET')

    def test_none_remains_default_and_unknown_network_is_rejected(self):
        self.assertEqual(JobRequest('/bin/sh').payload()['network'],'none')
        self.assertEqual(SessionRequest().payload()['network'],'none')
        for request in (JobRequest('/bin/sh',network='all'),SessionRequest(network='all')):
            with self.assertRaises(UnsupportedCapability):request.payload()
