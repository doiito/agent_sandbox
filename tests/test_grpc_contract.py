"""Versioned wire evolution checks, independent from generated Go boilerplate."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('grpc_contract_generator', ROOT / 'scripts/generate-grpc-contract.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class NativeContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = json.loads((ROOT / 'api/contracts/openapi.json').read_text())
        cls.registry = json.loads((ROOT / 'api/control/v1/field-numbers.json').read_text())

    def test_all_methods_and_real_stream_shapes_are_explicit(self):
        contract = module.Contract(self.document)
        self.assertEqual(len(contract.operations), 48)
        for name in ('CreateSessionArtifact', 'ReadSessionArtifact', 'DeleteSessionArtifact'):
            self.assertIn(name, contract.operations)
        self.assertEqual([name for name, operation in contract.operations.items() if operation['client_streaming']], ['OpenPortTunnel'])
        self.assertEqual({name for name, operation in contract.operations.items() if operation['server_streaming']}, {'OpenPortTunnel', 'StreamSessionCommand'})
        self.assertEqual(contract.messages['CodeEventOutput']['kind'], 'union')
        self.assertEqual(set(contract.messages['CodeEventOutput']['variants']), {'started', 'stdout', 'stderr', 'result', 'error', 'finished'})

    def test_read_only_check_does_not_edit_registry(self):
        before = copy.deepcopy(self.registry)
        contract = module.Contract(self.document)
        self.assertEqual(contract.bind(self.registry), self.registry)
        self.assertEqual(before, self.registry)

    def test_new_alphabetically_first_field_does_not_renumber_existing(self):
        document = copy.deepcopy(self.document)
        document['components']['schemas']['RunRequestInput']['properties']['aaa_new_flag'] = {'type': 'boolean'}
        contract = module.Contract(document)
        with self.assertRaisesRegex(ValueError, 'Unregistered field'):
            contract.bind(self.registry)
        after = contract.bind(self.registry, update=True)
        old = self.registry['messages']['RunRequestInput']['fields']
        fresh = after['messages']['RunRequestInput']['fields']
        for key in old:
            self.assertEqual(old[key], fresh[key])
        self.assertGreater(fresh['aaa_new_flag']['number'], max(field['number'] for field in old.values()))

    def test_deleted_field_is_reserved_and_cannot_be_reactivated(self):
        document = copy.deepcopy(self.document)
        del document['components']['schemas']['RunRequestInput']['properties']['stdin']
        contract = module.Contract(document)
        with self.assertRaisesRegex(ValueError, 'Removed field must be reserved'):
            contract.bind(self.registry)
        after = contract.bind(self.registry, update=True)
        retired = after['messages']['RunRequestInput']['fields']['stdin']
        self.assertTrue(retired['retired'])
        self.assertIn('reserved "stdin";', contract.proto())
        self.assertIn(f'reserved {retired["number"]};', contract.proto())
        with self.assertRaisesRegex(ValueError, 'Incompatible/reused field'):
            module.Contract(self.document).bind(after, update=True)

    def test_retyping_existing_field_is_not_an_automatic_lock_update(self):
        document = copy.deepcopy(self.document)
        document['components']['schemas']['RunRequestInput']['properties']['stdin'] = {'type': 'string'}
        with self.assertRaisesRegex(ValueError, 'Incompatible/reused field'):
            module.Contract(document).bind(self.registry, update=True)

    def test_duplicate_numbers_and_service_signature_changes_fail_closed(self):
        registry = copy.deepcopy(self.registry)
        fields = list(registry['messages']['RunRequestInput']['fields'].values())
        fields[1]['number'] = fields[0]['number']
        with self.assertRaisesRegex(ValueError, 'Invalid/duplicate field numbers'):
            module.Contract(self.document).bind(registry, update=True)
        registry = copy.deepcopy(self.registry)
        registry['methods']['RunJob']['client_streaming'] = True
        with self.assertRaisesRegex(ValueError, 'Changed RPC signature'):
            module.Contract(self.document).bind(registry, update=True)

    def test_nested_nullable_is_idempotent_without_erasing_numeric_constraints(self):
        number = {'type': 'integer', 'anyOf': [{'const': 0}, {'minimum': 1000, 'maximum': 300000}]}
        nested = {'anyOf': [{'anyOf': [number, {'type': 'null'}]}, {'type': 'null'}]}
        self.assertEqual(module.Contract.unnull(nested), (number, True))
        self.assertEqual(module.Contract.unnull(number), (number, False))


if __name__ == '__main__':
    unittest.main()
