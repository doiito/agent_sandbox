import unittest
from osv_sandbox_client import (Client, ConfigurationError, ProtocolError, Sandbox, SandboxError, Session,
                                SessionInfo, UnsupportedCapability)
from test_client import FakeOpener, Reply, make_client, session_info, SESSION_ID

def detailed():
    value=session_info()
    value.update(memory_mib=128,vcpus=1,guest_protocol='fc-agent/v2',max_expires_at='2026-10-30T00:10:00Z')
    return value

class LifecycleTests(unittest.TestCase):
    def test_real_metadata_pagination_shape_and_timeout_units(self):
        value=detailed();other=dict(value,id='c'*24)
        opener=FakeOpener([Reply(200,{'sessions':[value],'next_cursor':'cursor1'}),Reply(200,{'sessions':[other]}),Reply(200,value),Reply(200,value)])
        client=make_client(opener);paginator=Sandbox.list(client=client,limit=1,order='asc')
        self.assertTrue(paginator.has_next)
        first=paginator.next_items()[0]
        self.assertEqual((first.sandbox_id,first.template_id,first.memory_mb,first.cpu_count,first.envd_version),(SESSION_ID,'firecracker-linux',128,1,'fc-agent/v2'))
        self.assertEqual(first.lifecycle,{'on_timeout':'kill','auto_resume':False})
        self.assertEqual(paginator.next_token,'cursor1')
        self.assertEqual(paginator.next_items()[0].sandbox_id,'c'*24)
        self.assertFalse(paginator.has_next)
        with self.assertRaises(SandboxError):paginator.next_items()
        sandbox=Sandbox(Session(client,SessionInfo.from_payload(value)))
        self.assertEqual(sandbox.get_info(),first)
        self.assertIsNone(sandbox.set_timeout(3))
        import json
        self.assertEqual(json.loads(opener.requests[-1][0].data),{'ttl_ms':3000})
        self.assertIn('cursor=cursor1',opener.requests[1][0].full_url)

    def test_invalid_metadata_and_options_fail_without_silent_fallback(self):
        client=make_client(FakeOpener([]))
        for kwargs in ({'limit':0},{'limit':101},{'order':'random'},{'next_token':'!'}):
            with self.assertRaises(ConfigurationError):Sandbox.list(client=client,**kwargs)
        with self.assertRaises(UnsupportedCapability):Sandbox.list(client=client,query={'metadata':{'x':'y'}})
        sandbox=Sandbox(Session(client,SessionInfo.from_payload(session_info())))
        for timeout in (0,301,True):
            with self.assertRaises(ConfigurationError):sandbox.set_timeout(timeout)
        incomplete=detailed();incomplete.pop('memory_mib')
        opener=FakeOpener([Reply(200,{'sessions':[incomplete]})])
        with self.assertRaises(ProtocolError):Sandbox.list(client=make_client(opener)).next_items()
