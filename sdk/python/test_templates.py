import copy
import json
import unittest
from urllib.parse import parse_qs, urlparse

from osv_sandbox_client import JobRequest, ProtocolError, SessionRequest, TemplateSelector
from test_client import DIGEST, FakeOpener, Reply, capabilities, make_client, result, session_info


class TemplateCatalogTest(unittest.TestCase):
    def test_discovery_and_selected_capabilities_do_not_require_visible_default(self):
        cap = capabilities()
        cap['artifact_authenticated'] = True
        cap['artifact_manifest_sha256'] = 'c' * 64
        catalog = {'protocol': 'osv-sandbox-template-catalog/v1', 'default_template_id': '',
                   'templates': [{'id': 'secondary', 'available': True, 'capabilities': cap}]}
        opener = FakeOpener([Reply(200, catalog), Reply(200, cap)])
        client = make_client(opener)
        self.assertEqual(client.templates()['templates'][0]['id'], 'secondary')
        selected = TemplateSelector('firecracker-linux', 'c' * 64)
        self.assertEqual(client.capabilities(template=selected)['artifact_manifest_sha256'], 'c' * 64)
        self.assertEqual(urlparse(opener.requests[0][0].full_url).path, '/v2/templates')
        self.assertEqual(parse_qs(urlparse(opener.requests[1][0].full_url).query),
                         {'backend': ['firecracker-linux'], 'artifact_manifest_sha256': ['c' * 64]})

    def test_proxy_job_and_session_use_selected_live_capability(self):
        for session in (False, True):
            cap = capabilities()
            cap.update(artifact_manifest_sha256='c' * 64)
            cap['features']['network_egress'] = True
            response = session_info() if session else result()
            response.update(artifact_manifest_sha256='c' * 64, template_id='secondary')
            opener = FakeOpener([Reply(200, cap), Reply(201 if session else 200, response)])
            client = make_client(opener)
            selected = TemplateSelector('firecracker-linux', 'c' * 64)
            value = client.create_session(SessionRequest(network='proxy'), template=selected) if session else client.run(
                JobRequest('/bin/sh', network='proxy'), template=selected)
            self.assertEqual(len(opener.requests), 2)
            self.assertIn('artifact_manifest_sha256=' + 'c' * 64, opener.requests[0][0].full_url)
            self.assertEqual(json.loads(opener.requests[1][0].data)['artifact_manifest_sha256'], 'c' * 64)
            if not session:
                self.assertEqual((value.template_id, value.artifact_manifest_sha256), ('secondary', 'c' * 64))

    def test_malformed_catalog_and_mismatched_execution_are_protocol_errors(self):
        cap = capabilities()
        cap['artifact_authenticated'] = True
        base = {'protocol': 'osv-sandbox-template-catalog/v1', 'default_template_id': 'main',
                'templates': [{'id': 'main', 'available': True, 'capabilities': cap}]}
        values = []
        for change in ('duplicate-id', 'duplicate-selector', 'hidden-default', 'unsigned'):
            value = copy.deepcopy(base)
            if change.startswith('duplicate'):
                value['templates'].append(copy.deepcopy(value['templates'][0]))
                if change == 'duplicate-selector':
                    value['templates'][1]['id'] = 'another'
            elif change == 'hidden-default':
                value['default_template_id'] = 'hidden'
            else:
                value['templates'][0]['capabilities']['artifact_authenticated'] = False
            values.append(value)
        for value in values:
            with self.assertRaises(ProtocolError):
                make_client(FakeOpener([Reply(200, value)])).templates()
        response = result()
        response['artifact_manifest_sha256'] = 'c' * 64
        with self.assertRaises(ProtocolError):
            make_client(FakeOpener([Reply(200, response)])).run(JobRequest('/bin/sh'),
                template=TemplateSelector('firecracker-linux', DIGEST))
