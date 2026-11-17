"""Contract checks for the standard-library Python client."""

import io
import json
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

from osv_sandbox_client import (APIError, Client, ConfigurationError, InputFile, JobRequest,
                                JobResult, ProtocolError, Sandbox, Session, SessionCommand, SessionInfo, SessionRequest, TemplateMismatch,
                                TemplateSelector, UnsupportedCapability)


DIGEST = 'a' * 64
SESSION_ID = 'b' * 24


class Reply:
    def __init__(self, status, payload):
        self.status = status
        self._data = io.BytesIO(b'' if payload is None else json.dumps(payload).encode())

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self._data.close()

    def read(self, count):
        return self._data.read(count)


class FakeOpener:
    def __init__(self, replies):
        self.replies = list(replies)
        self.requests = []

    def open(self, req, timeout):
        self.requests.append((req, timeout))
        return self.replies.pop(0)


def make_client(opener):
    with patch('osv_sandbox_client.ssl.create_default_context') as context, \
            patch('osv_sandbox_client.request.build_opener', return_value=opener):
        return Client('https://sandbox.example', token='test-token',
                      cert_file='/cert', key_file='/key', ca_file='/ca')


def capabilities():
    return {'protocol': 'osv-sandbox-capabilities/v1',
            'backend': 'firecracker-linux', 'artifact_authenticated': True,
            'artifact_manifest_sha256': DIGEST,
            'allowed_entrypoints': ['/bin/sh'],
            'methods': ['GET /v1/capabilities', 'POST /v2/jobs'],
            'features': {'input_files': True}}


def result(state='succeeded', protocol_ok=True):
    return {'id': 'job-1', 'state': state, 'backend': 'firecracker-linux',
            'exit_code': 0, 'timed_out': False, 'duration_ms': 3,
            'output': '', 'output_truncated': False, 'protocol_ok': protocol_ok,
            'guest_result': {'ok': protocol_ok}}


def session_info(session_id=SESSION_ID):
    return {'id': session_id, 'state': 'running', 'backend': 'firecracker-linux',
            'artifact_manifest_sha256': DIGEST,
            'created_at': '2026-10-30T00:00:00Z', 'expires_at': '2026-10-30T00:05:00Z'}


class ClientContractTest(unittest.TestCase):
    def test_rename_and_remove_bind_destination_and_preserve_metadata(self):
        info={'name':'new','path':'/workspace/new','type':'file','size':3,'mode':0o100600,
              'permissions':'rw-------','owner':'agent','group':'agent','modified_time_ms':1800000000000,
              'metadata':{'label':'kept'}}
        reply={'session_id':SESSION_ID,'action':'rename','path':'/workspace/old','destination':'/workspace/new',
               'size':3,'kind':'file','info':info}
        opener=FakeOpener([Reply(200,reply),Reply(200,{'session_id':SESSION_ID,'action':'remove','path':'/workspace/tree','size':0}),
                           Reply(200,dict(reply,destination='/workspace/wrong'))])
        sandbox=Sandbox(Session(make_client(opener),SessionInfo.from_payload(session_info())))
        moved=sandbox.files.rename('/workspace/old','/workspace/new')
        self.assertEqual((moved.name,moved.path,moved.size),('new','/workspace/new',3))
        self.assertEqual(moved.metadata,{'label':'kept'})
        sandbox.files.remove('/workspace/tree')
        self.assertEqual(json.loads(opener.requests[0][0].data)['destination'],'/workspace/new')
        with self.assertRaises(ConfigurationError):sandbox.files.rename('/workspace/old','/etc/out')
        with self.assertRaises(ConfigurationError):sandbox.files.remove('/workspace')
        with self.assertRaises(ProtocolError):sandbox.files.rename('/workspace/old','/workspace/new')
        self.assertEqual(len(opener.requests),3)

    def test_e2b_facade_lifecycle_and_file_semantics(self):
        report = capabilities()
        report['methods'].append('POST /v2/sessions')
        report['features']['sessions'] = True
        missing = HTTPError('https://sandbox.example/files', 404, 'Not Found', {},
                            io.BytesIO(b'{"code":"file_not_found","error":"missing"}'))
        def closed():
            return HTTPError('https://sandbox.example/session', 404, 'Not Found', {},
                             io.BytesIO(b'{"code":"not_found","error":"closed"}'))
        opener = FakeOpener([Reply(200, report), Reply(201, session_info()),
                             Reply(200, session_info()),
                             Reply(200, {'session_id': SESSION_ID, 'action': 'read',
                                         'path': '/workspace/text', 'size': 2,
                                         'data_base64': 'aGk='}),
                             Reply(200, {'session_id': SESSION_ID, 'action': 'stat',
                                         'path': '/workspace/text', 'size': 2,
                                         'kind': 'file'}), missing,
                             Reply(204, None), closed(), closed()])
        client = make_client(opener)
        sandbox = Sandbox.create('firecracker-linux', client=client, timeout=30)
        self.assertEqual(sandbox.sandbox_id, SESSION_ID)
        self.assertTrue(sandbox.is_running())
        self.assertEqual(sandbox.files.read('/workspace/text'), 'hi')
        self.assertTrue(sandbox.files.exists('/workspace/text'))
        self.assertFalse(sandbox.files.exists('/workspace/missing'))
        self.assertTrue(sandbox.kill())
        self.assertFalse(sandbox.is_running())
        self.assertFalse(sandbox.kill())
        self.assertEqual(json.loads(opener.requests[1][0].data)['ttl_ms'], 30000)

    def test_e2b_facade_does_not_hide_unsupported_or_permission_errors(self):
        denied = HTTPError('https://sandbox.example/files', 403, 'Forbidden', {},
                           io.BytesIO(b'{"code":"file_denied","error":"denied"}'))
        opener = FakeOpener([denied])
        client = make_client(opener)
        sandbox = Sandbox(Session(client, SessionInfo.from_payload(session_info())))
        with self.assertRaises(APIError) as caught:
            sandbox.files.exists('/workspace/linked')
        self.assertEqual(caught.exception.status, 403)
        with self.assertRaises(UnsupportedCapability):
            sandbox.files.write('/workspace/new', io.BytesIO(b'x'))
        with self.assertRaises(UnsupportedCapability):
            sandbox.commands.run('forbidden',user='root')
        with self.assertRaises(UnsupportedCapability):
            Sandbox.create('base', client=client)
        self.assertEqual(len(opener.requests), 1)

    def test_e2b_write_creates_parent_and_validates_batch_before_side_effects(self):
        replies = [
            Reply(200, {'session_id': SESSION_ID, 'action': 'mkdir', 'path': '/workspace/deep',
                        'size': 0, 'created': True}),
            Reply(200, {'session_id': SESSION_ID, 'action': 'write', 'path': '/workspace/deep/a',
                        'size': 2}),
            Reply(200, {'session_id': SESSION_ID, 'action': 'mkdir', 'path': '/workspace/deep',
                        'size': 0, 'created': False}),
            Reply(200, {'session_id': SESSION_ID, 'action': 'write', 'path': '/workspace/deep/b',
                        'size': 1}),
            Reply(200, {'session_id': SESSION_ID, 'action': 'write', 'path': '/workspace/labelled',
                        'size': 2}),
        ]
        opener = FakeOpener(replies)
        sandbox = Sandbox(Session(make_client(opener), SessionInfo.from_payload(session_info())))
        with self.assertRaises(ConfigurationError):
            sandbox.files.write_files([{'path': '/workspace/deep/a', 'data': 'ok'},
                                       {'path': '/workspace/../escape', 'data': 'x'}])
        with self.assertRaises(ConfigurationError):
            sandbox.files.write_files([{'path': '/workspace/huge', 'data': b'x' * (512 * 1024 + 1)}])
        with self.assertRaises(ConfigurationError):
            sandbox.files.write('/workspace/labelled', 'ok', metadata={'bad key': 'x'})
        self.assertEqual(len(opener.requests), 0)
        results = sandbox.files.write_files([{'path': '/workspace/deep/a', 'data': 'ok'},
                                             {'path': '/workspace/deep/b', 'data': b'!'}])
        self.assertEqual([(item.name, item.path, item.type) for item in results],
                         [('a', '/workspace/deep/a', 'file'), ('b', '/workspace/deep/b', 'file')])
        self.assertEqual([json.loads(req[0].data)['action'] for req in opener.requests],
                         ['mkdir', 'write', 'mkdir', 'write'])
        labelled = sandbox.files.write('/workspace/labelled', 'ok', metadata={'label': 'proof'})
        self.assertEqual(labelled.metadata, {'label': 'proof'})
        self.assertEqual(json.loads(opener.requests[-1][0].data)['metadata'], {'label': 'proof'})

    def test_e2b_file_info_uses_guest_metadata_and_rejects_old_guest(self):
        file_info = {'name': 'a', 'path': '/workspace/a', 'type': 'file',
                     'size': 3, 'mode': 0o100600, 'permissions': 'rw-------',
                     'owner': 'agent', 'group': 'agent', 'modified_time_ms': 1800000000000,
                     'metadata': {'label': 'proof'}}
        link = {'name': 'link', 'path': '/workspace/link', 'type': 'symlink',
                'size': 11, 'mode': 0o120777, 'permissions': 'rwxrwxrwx',
                'owner': 'agent', 'group': 'agent', 'modified_time_ms': 1800000000000,
                'symlink_target': '/etc/passwd'}
        directory = {'name': 'sub', 'path': '/workspace/sub', 'type': 'directory',
                     'size': 4096, 'mode': 0o40700, 'permissions': 'rwx------',
                     'owner': 'agent', 'group': 'agent', 'modified_time_ms': 1800000000000}
        opener = FakeOpener([
            Reply(200, {'session_id': SESSION_ID, 'action': 'list', 'path': '/workspace',
                        'size': 3, 'entries': ['a', 'link', 'sub'],
                        'entry_infos': [file_info, link, directory]}),
            Reply(200, {'session_id': SESSION_ID, 'action': 'info', 'path': '/workspace/a',
                        'kind': 'file', 'size': 3, 'info': file_info}),
            Reply(200, {'session_id': SESSION_ID, 'action': 'info', 'path': '/workspace/link',
                        'kind': 'symlink', 'size': 0, 'info': link}),
            Reply(200, {'session_id': SESSION_ID, 'action': 'info', 'path': '/workspace/a',
                        'kind': 'file', 'size': 3}),
            Reply(200, {'session_id': SESSION_ID, 'action': 'info', 'path': '/workspace/a',
                        'kind': 'file', 'size': 3, 'info': dict(file_info, path='/etc/passwd')}),
        ])
        sandbox = Sandbox(Session(make_client(opener), SessionInfo.from_payload(session_info())))
        listed = sandbox.files.list('/workspace')
        self.assertEqual([(entry.name, entry.type) for entry in listed],
                         [('a', 'file'), ('link', 'symlink'), ('sub', 'dir')])
        self.assertEqual(listed[0].metadata, {'label': 'proof'})
        self.assertEqual(listed[1].symlink_target, '/etc/passwd')
        self.assertEqual(listed[2].owner, 'agent')
        self.assertEqual(listed[2].permissions, 'rwx------')
        self.assertEqual(sandbox.files.get_info('/workspace/a').size, 3)
        self.assertEqual(sandbox.files.get_info('/workspace/link').symlink_target, '/etc/passwd')
        with self.assertRaises(UnsupportedCapability):
            sandbox.files.get_info('/workspace/a')
        with self.assertRaises(ProtocolError):
            sandbox.files.get_info('/workspace/a')
        with self.assertRaises(UnsupportedCapability):
            sandbox.files.list('/workspace', depth=2)

    def test_session_lifecycle_binds_template_and_command(self):
        report = capabilities()
        report['methods'].append('POST /v2/sessions')
        report['features']['sessions'] = True
        opener = FakeOpener([Reply(200, report), Reply(201, session_info()),
                             Reply(200, session_info()),
                             Reply(200, {'session_id': SESSION_ID, 'result': result()}),
                             Reply(204, None)])
        client = make_client(opener)
        session = client.create_session(SessionRequest(ttl_ms=5000,
                                     input_files=(InputFile('x', b'ok'),)))
        self.assertEqual(session.info().id, SESSION_ID)
        self.assertTrue(session.run(SessionCommand('/bin/sh', ('-c', 'true'))).succeeded)
        session.close()
        self.assertEqual([r.full_url.rsplit('/', 1)[-1] for r, _ in opener.requests][1],
                         'sessions')
        self.assertEqual(json.loads(opener.requests[1][0].data)['ttl_ms'], 5000)
        self.assertEqual(opener.requests[-1][0].get_method(), 'DELETE')

    def test_session_rejects_unadvertised_and_mismatched_responses(self):
        client = make_client(FakeOpener([Reply(200, capabilities())]))
        with self.assertRaises(UnsupportedCapability):
            client.create_session()
        with self.assertRaises(ConfigurationError):
            client.connect_session('../wrong')
        wrong = session_info('c' * 24)
        client = make_client(FakeOpener([Reply(200, wrong)]))
        with self.assertRaises(ProtocolError):
            client.connect_session(SESSION_ID)
        client = make_client(FakeOpener([Reply(201, session_info()),
                                         Reply(200, {'session_id': 'c' * 24, 'result': result()})]))
        session = client.create_session(template=TemplateSelector('firecracker-linux', DIGEST))
        with self.assertRaises(ProtocolError):
            session.run(SessionCommand('/bin/sh'))

    def test_session_file_roundtrip_and_response_binding(self):
        opener = FakeOpener([Reply(201, session_info()),
                             Reply(200, {'session_id': SESSION_ID, 'action': 'write',
                                         'path': '/workspace/x', 'size': 3}),
                             Reply(200, {'session_id': SESSION_ID, 'action': 'read',
                                         'path': '/workspace/x', 'size': 3,
                                         'data_base64': 'AP8K'})])
        client = make_client(opener)
        session = client.create_session(template=TemplateSelector('firecracker-linux', DIGEST))
        self.assertEqual(session.write_file('/workspace/x', b'\x00\xff\n'), 3)
        self.assertEqual(session.read_file('/workspace/x'), b'\x00\xff\n')
        self.assertEqual(json.loads(opener.requests[1][0].data)['data_base64'], 'AP8K')
        with self.assertRaises(ConfigurationError):
            session.read_file('/workspace/../secret')
        self.assertEqual(len(opener.requests), 3)

    def test_session_file_rejects_malformed_read_and_other_tenant(self):
        not_found = HTTPError('https://sandbox.example/v2/sessions/' + SESSION_ID + '/files',
                              404, 'Not Found', {},
                              io.BytesIO(b'{"code":"not_found","error":"session not found"}'))
        opener = FakeOpener([Reply(201, session_info()),
                             Reply(200, {'session_id': SESSION_ID, 'action': 'read',
                                         'path': '/workspace/x', 'size': 2,
                                         'data_base64': 'AA=='}), not_found])
        session = make_client(opener).create_session(
            template=TemplateSelector('firecracker-linux', DIGEST))
        with self.assertRaises(ProtocolError):
            session.read_file('/workspace/x')
        with self.assertRaises(APIError) as denied:
            session.read_file('/workspace/x')
        self.assertEqual(denied.exception.status, 404)

    def test_session_file_list_stat_delete_bind_results(self):
        opener = FakeOpener([Reply(201, session_info()),
                             Reply(200, {'session_id': SESSION_ID, 'action': 'list',
                                         'path': '/workspace', 'size': 2,
                                         'entries': ['a', 'sub']}),
                             Reply(200, {'session_id': SESSION_ID, 'action': 'stat',
                                         'path': '/workspace/a', 'size': 3,
                                         'kind': 'file'}),
                             Reply(200, {'session_id': SESSION_ID, 'action': 'delete',
                                         'path': '/workspace/a', 'size': 0})])
        session = make_client(opener).create_session(
            template=TemplateSelector('firecracker-linux', DIGEST))
        self.assertEqual(session.list_files(), ['a', 'sub'])
        self.assertEqual(session.stat_file('/workspace/a'), {'kind': 'file', 'size': 3})
        self.assertIsNone(session.delete_file('/workspace/a'))
        with self.assertRaises(ConfigurationError):
            session.delete_file('/workspace')
        self.assertEqual(len(opener.requests), 4)

    def test_session_file_list_rejects_unsorted_or_oversized_result(self):
        opener = FakeOpener([Reply(201, session_info()),
                             Reply(200, {'session_id': SESSION_ID, 'action': 'list',
                                         'path': '/workspace', 'size': 2,
                                         'entries': ['z', 'a']}),
                             Reply(200, {'session_id': SESSION_ID, 'action': 'stat',
                                         'path': '/workspace', 'size': -1,
                                         'kind': 'directory'})])
        session = make_client(opener).create_session(
            template=TemplateSelector('firecracker-linux', DIGEST))
        with self.assertRaises(ProtocolError):
            session.list_files()
        with self.assertRaises(ProtocolError):
            session.stat_file('/workspace')

    def test_run_binds_signed_template_and_encodes_bytes(self):
        opener = FakeOpener([Reply(200, capabilities()), Reply(200, result())])
        client = make_client(opener)
        job = JobRequest('/bin/sh', args=('-c', 'cat /input/a'),
                         input_files=(InputFile('a', b'hi\n'),))
        received = client.run(job)
        self.assertTrue(received.succeeded)
        self.assertEqual([req.full_url for req, _ in opener.requests],
                         ['https://sandbox.example/v1/capabilities',
                          'https://sandbox.example/v2/jobs'])
        payload = json.loads(opener.requests[1][0].data)
        self.assertEqual(payload['artifact_manifest_sha256'], DIGEST)
        self.assertEqual(payload['backend'], 'firecracker-linux')
        self.assertEqual(payload['input_files'],
                         [{'path': 'a', 'data': 'aGkK', 'mode': 292}])

    def test_osv_signed_environment_and_binary_stdin(self):
        report = capabilities()
        report['backend'] = 'firecracker-osv'
        report['allowed_entrypoints'] = ['/task-probe.so']
        report['features'] = {'environment': True, 'stdin': True}
        opener = FakeOpener([Reply(200, report), Reply(200, result())])
        job = JobRequest('/task-probe.so', environment={'SANDBOX_TEST_MARKER': 'ok'},
                         stdin=b'A\x00B\xff\n')
        make_client(opener).run(job)
        payload = json.loads(opener.requests[1][0].data)
        self.assertEqual(payload['environment'], {'SANDBOX_TEST_MARKER': 'ok'})
        self.assertEqual(payload['stdin'], 'QQBC/wo=')
        self.assertEqual(JobRequest('/task-probe.so', stdin=b'').payload()['stdin'], '')
        for invalid in (b'x' * 16385, 'text'):
            with self.assertRaises(ConfigurationError):
                JobRequest('/task-probe.so', stdin=invalid).payload()
        with self.assertRaises(ConfigurationError):
            make_client(FakeOpener([Reply(200, report)])).run(JobRequest('/task-probe.so', environment={'LD_PRELOAD': 'bad'}))
        report['features']['stdin'] = False
        opener = FakeOpener([Reply(200, report)])
        with self.assertRaises(UnsupportedCapability):
            make_client(opener).run(JobRequest('/task-probe.so', stdin=b''))

    def test_linux_job_inputs_and_capability_rejection(self):
        report = capabilities()
        report['features'] = {'environment': True, 'stdin': True, 'working_directory': True}
        warm_result = dict(result(), startup_mode='warm')
        opener = FakeOpener([Reply(200, report), Reply(200, warm_result)])
        job = JobRequest('/bin/sh', environment={'LD_LIBRARY_PATH': '/workspace/lib', 'KEY': '中文'},
                         cwd='/input/nested', stdin=b'\x00\xff')
        self.assertEqual(make_client(opener).run(job).startup_mode, 'warm')
        with self.assertRaises(ProtocolError):
            JobResult.from_payload(dict(result(), startup_mode='invented'))
        payload = json.loads(opener.requests[1][0].data)
        self.assertEqual(payload['cwd'], '/input/nested')
        self.assertEqual(payload['stdin'], 'AP8=')
        self.assertEqual(payload['environment']['KEY'], '中文')
        for invalid in ('relative', '/workspace/\x00bad', '/workspace/\n', '/'+('中'*342)):
            with self.assertRaises(ConfigurationError):
                JobRequest('/bin/sh', cwd=invalid).payload()
        report['features']['working_directory'] = False
        opener = FakeOpener([Reply(200, report)])
        with self.assertRaises(UnsupportedCapability):
            make_client(opener).run(job)
        self.assertEqual(len(opener.requests), 1)
        with self.assertRaises(ConfigurationError):
            make_client(FakeOpener([])).run(job, template=TemplateSelector('firecracker-osv', DIGEST))
        with self.assertRaises(UnsupportedCapability):
            make_client(FakeOpener([])).run(JobRequest('/bin/sh', cwd='/input'), template=TemplateSelector('firecracker-osv', DIGEST))

    def test_template_mismatch_is_not_retried_or_downgraded(self):
        body = io.BytesIO(b'{"code":"template_mismatch","error":"stale template"}')
        conflict = HTTPError('https://sandbox.example/v2/jobs', 409,
                             'Conflict', {}, body)
        opener = FakeOpener([conflict])
        client = make_client(opener)
        with self.assertRaises(TemplateMismatch) as caught:
            client.run(JobRequest('/bin/sh'),
                       template=TemplateSelector('firecracker-linux', DIGEST))
        self.assertEqual(caught.exception.code, 'template_mismatch')
        self.assertEqual(len(opener.requests), 1)
        self.assertTrue(opener.requests[0][0].full_url.endswith('/v2/jobs'))

    def test_unsigned_server_requires_explicit_legacy(self):
        report = capabilities()
        report['artifact_authenticated'] = False
        report['methods'] = ['POST /v1/jobs']
        opener = FakeOpener([Reply(200, report), Reply(200, result())])
        client = make_client(opener)
        with self.assertRaises(UnsupportedCapability):
            client.run(JobRequest('/bin/sh'))
        self.assertEqual(len(opener.requests), 1)
        self.assertTrue(client.run_legacy(JobRequest('/bin/sh')).succeeded)
        self.assertTrue(opener.requests[1][0].full_url.endswith('/v1/jobs'))

    def test_doctor_preserves_not_ready_report(self):
        body = io.BytesIO(b'{"ready":false,"checks":[]}')
        unavailable = HTTPError('https://sandbox.example/v1/doctor', 503,
                                'Service Unavailable', {}, body)
        client = make_client(FakeOpener([unavailable]))
        self.assertEqual(client.doctor(), {'ready': False, 'checks': []})

    def test_redirect_is_rejected_without_forwarding_bearer(self):
        redirect = HTTPError('https://sandbox.example/v1/capabilities', 302,
                             'Found', {'Location': 'https://other.example/'},
                             io.BytesIO(b''))
        opener = FakeOpener([redirect])
        with self.assertRaises(ProtocolError):
            make_client(opener).capabilities()
        self.assertEqual(len(opener.requests), 1)

    def test_server_error_redacts_bearer(self):
        bad = HTTPError('https://sandbox.example/v1/capabilities', 400,
                        'Bad Request', {},
                        io.BytesIO(b'{"code":"invalid_request","error":"test-token"}'))
        with self.assertRaises(APIError) as caught:
            make_client(FakeOpener([bad])).capabilities()
        self.assertNotIn('test-token', str(caught.exception))

    def test_failed_job_is_not_success(self):
        self.assertFalse(JobResult.from_payload(result('failed', False)).succeeded)
        with self.assertRaises(ProtocolError):
            JobResult.from_payload({**result(), 'protocol_ok': 'true'})

    def test_rejects_insecure_origin_and_unsafe_input(self):
        with self.assertRaises(ConfigurationError):
            Client('http://sandbox.example', token='test-token',
                   cert_file='/cert', key_file='/key')
        with self.assertRaises(ConfigurationError):
            JobRequest('/bin/sh', input_files=(InputFile('../secret', b'x'),)).payload()
        with self.assertRaises(ConfigurationError):
            JobRequest('/bin/sh', input_files=(InputFile('x', b'x' * (512 * 1024 + 1)),)).payload()


if __name__ == '__main__':
    unittest.main()
