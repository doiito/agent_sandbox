"""Schema validation must stay offline and enforce reference identity."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('sbom_schema',ROOT/'scripts/validate-sbom-schema.py')
schema=importlib.util.module_from_spec(spec)
spec.loader.exec_module(schema)


class SchemaTests(unittest.TestCase):
    def validate(self,bom):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'sbom.json'
            path.write_text(json.dumps(bom))
            with patch('socket.create_connection',side_effect=AssertionError('network forbidden')):
                return schema.validate(path)

    def test_valid_minimum_schema_is_validated_without_network(self):
        result=self.validate({'bomFormat':'CycloneDX','specVersion':'1.5','version':1})
        self.assertTrue(result['passed'])
        self.assertFalse(result['network_retrieval_enabled'])

    def test_wrong_schema_shape_duplicate_refs_and_dangling_edges_reject(self):
        base={'bomFormat':'CycloneDX','specVersion':'1.5','version':1}
        examples=[dict(base,unknown='not allowed'),dict(base,serialNumber='urn:uuid:00000000-0000-0000-0000-000000000000'),
            dict(base,components=[{'type':'library','name':'one','bom-ref':'same'},{'type':'library','name':'two','bom-ref':'same'}]),
            dict(base,dependencies=[{'ref':'absent','dependsOn':[]}])]
        for example in examples:
            with self.subTest(example=example),self.assertRaises(ValueError):
                self.validate(example)

    def test_missing_optional_format_helpers_fail_instead_of_skipping(self):
        with patch.dict(schema.FormatChecker.checkers,{},clear=True),self.assertRaisesRegex(ValueError,'missing schema format validators'):
            self.validate({'bomFormat':'CycloneDX','specVersion':'1.5','version':1})

    def test_invalid_timestamp_and_iri_are_rejected(self):
        base={'bomFormat':'CycloneDX','specVersion':'1.5','version':1}
        examples=[dict(base,metadata={'timestamp':'not-a-date'}),
            dict(base,externalReferences=[{'type':'website','url':'https://['}])]
        for example in examples:
            with self.subTest(example=example),self.assertRaises(ValueError):
                self.validate(example)


if __name__=='__main__':
    unittest.main()
