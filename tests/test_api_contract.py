"""Independent positive/negative validation of the complete offline wire contract."""
import copy
import importlib.util
import json
from pathlib import Path
import socket
import unittest
from unittest.mock import patch

from jsonschema import ValidationError

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('api_contract', ROOT / 'scripts/check-api-contract.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class APIContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = json.loads((ROOT / 'api/contracts/openapi.json').read_text())
        with patch.object(socket, 'create_connection', side_effect=AssertionError('network forbidden')):
            cls.contract = module.Contract(cls.document)

    def assertInvalid(self, name, value):
        with self.assertRaises(ValidationError):
            self.contract.component(name, value)

    def test_all_routes_named_types_and_special_transports(self):
        self.assertEqual(len(self.contract.operations), 48)
        for name in ('createSessionArtifact', 'readSessionArtifact', 'deleteSessionArtifact'):
            self.assertIn(name, self.contract.operations)
        self.assertGreaterEqual(len(self.contract.schemas), 70)
        stream = self.contract.operations['streamSessionCommand']
        self.assertEqual(set(stream['x-sse-events']), {'output', 'result', 'timeout'})
        self.assertEqual(set(stream['responses']['200']['content']), {'text/event-stream'})
        port = self.contract.operations['openPortTunnel']
        self.assertIn('101', port['responses'])
        self.assertNotIn('content', port['responses']['101'])
        self.assertEqual(port['x-port-tunnel']['frames']['1']['max_bytes'], 16384)
        self.assertEqual(port['x-max-request-bytes'], 4096)

    def test_inference_extension_is_explicit_without_weakening_generic_errors(self):
        generic = {'code': 'future_code', 'error': 'failed'}
        extended = dict(generic, invocation_id='a'*24)
        self.contract.component('APIErrorResponseOutput', generic)
        self.assertInvalid('APIErrorResponseOutput', extended)
        self.contract.component('InferenceAPIErrorResponseOutput', extended)
        self.contract.component('InferenceAPIErrorResponseOutput', generic)
        for value in (generic, extended):
            self.contract.exchange({'operation_id': 'invokeInference', 'status': 502, 'response': value})
        self.assertInvalid('InferenceAPIErrorResponseOutput', dict(extended, invocation_id='bad'))
        self.assertInvalid('InferenceAPIErrorResponseOutput', dict(extended, credential='private'))

    def test_required_fields_defaults_null_and_unknown_fields(self):
        request = {'entrypoint': '/bin/echo', 'backend': 'firecracker-linux', 'artifact_manifest_sha256': 'b'*64}
        self.contract.component('RunRequestV2Input', request)
        self.contract.component('RunRequestV2Input', dict(request, timeout_ms=None, memory_mib=0, stdin=None))
        self.assertInvalid('RunRequestV2Input', {'entrypoint': '/bin/echo'})
        self.assertInvalid('RunRequestV2Input', dict(request, arbitrary='unknown'))
        self.assertInvalid('RunRequestV2Input', dict(request, artifact_manifest_sha256='B'*64))
        execution = {'context_id': 'a'*24, 'execution_id': 'b'*24, 'generation': 1}
        for timeout in (0, None, 60000):
            self.contract.component('CodeExecutionRequestInput', dict(execution, timeout_ms=timeout))
        self.assertInvalid('CodeExecutionRequestInput', dict(execution, timeout_ms=-1))
        self.assertInvalid('CodeExecutionRequestInput', dict(execution, generation=2**53))
        self.assertInvalid('CodeExecutionRequestInput', dict(execution, code='界'*22000))

    def test_decimal_units_stay_strings_above_javascript_integer_precision(self):
        schema = self.contract.schemas['InferenceBillOutput']['properties']['held_units']
        for value in ('0', str(2**53+1), str(2**64-1)):
            self.contract.validate(schema, value)
        for value in (2**53+1, '01', '-1', str(2**64), '1.0'):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                self.contract.validate(schema, value)

    def test_base64_and_cross_field_file_and_stdin_constraints(self):
        self.contract.component('SessionCommandInputRequestInput', {'data_base64': 'AP8=', 'close': False})
        self.contract.component('SessionCommandInputRequestInput', {'close': True})
        for value in ({'data_base64': 'AP8=', 'close': True}, {'data_base64': 'AB=='}, {'data_base64': 'not base64!'}, {'data_base64': 'A' * 21852}):
            self.assertInvalid('SessionCommandInputRequestInput', value)
        self.contract.component('SessionFileRequestInput', {'action': 'write', 'path': '/workspace/x', 'data_base64': ''})
        self.assertInvalid('SessionFileRequestInput', {'action': 'write', 'path': '/workspace/x'})
        self.assertInvalid('SessionFileRequestInput', {'action': 'read', 'path': '/workspace/x', 'data_base64': ''})
        self.assertInvalid('SessionFileRequestInput', {'action': 'rename', 'path': '/workspace/x'})

    def test_custom_code_union_preserves_required_false_and_empty_fields(self):
        self.contract.component('CodeEventOutput', {'type': 'finished', 'status': 'completed', 'context_usable': False})
        self.contract.component('CodeEventOutput', {'type': 'error', 'name': 'Error', 'value': '', 'traceback': ''})
        for event in ({'type': 'finished', 'status': 'completed'}, {'type': 'started', 'data': 'wrong field'}, {'type': 'stdout', 'data': 'AB=='}, {'type': 'new-unknown'}):
            self.assertInvalid('CodeEventOutput', event)

    def test_document_mutations_dangling_external_refs_and_missing_paths_reject(self):
        mutations = []
        dangling = copy.deepcopy(self.document)
        dangling['components']['schemas']['RunResultOutput']['properties']['state'] = {'$ref': '#/components/schemas/Missing'}
        mutations.append(dangling)
        external = copy.deepcopy(self.document)
        external['components']['schemas']['RunResultOutput']['properties']['state'] = {'$ref': 'https://must-not-fetch.invalid/schema'}
        mutations.append(external)
        missing = copy.deepcopy(self.document)
        missing['paths']['/v2/sessions/{id}']['get']['parameters'] = []
        mutations.append(missing)
        duplicate = copy.deepcopy(self.document)
        duplicate['paths']['/v2/jobs']['post']['operationId'] = 'health'
        mutations.append(duplicate)
        weak = copy.deepcopy(self.document)
        weak['components']['schemas']['RunRequestV2Input'] = {}
        mutations.append(weak)
        for document in mutations:
            with self.subTest(), patch.object(socket, 'create_connection', side_effect=AssertionError('network forbidden')), self.assertRaises((ValueError, ValidationError)):
                module.Contract(document)

    def test_meta_source_tamper_is_rejected(self):
        original = Path.read_bytes
        def changed(path):
            data = original(path)
            return data + b' ' if path == ROOT / 'assets/build/schemas/openapi-3.1/schema.json' else data
        with patch.object(Path, 'read_bytes', changed), self.assertRaisesRegex(ValueError, 'pinned OpenAPI input changed'):
            module.Contract(self.document)


if __name__ == '__main__':
    unittest.main()
