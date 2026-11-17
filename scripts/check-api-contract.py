#!/usr/bin/env python3
"""Validate the complete HTTP wire document using pinned schemas, offline."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import sys

from jsonschema import Draft202012Validator, FormatChecker, ValidationError, validators
from referencing import Registry, Resource
from referencing.exceptions import NoSuchResource

ROOT = Path(__file__).resolve().parents[1]
DOCUMENT_ID = 'urn:osv-sandbox:openapi:v2'


def no_retrieval(uri):
    raise NoSuchResource(ref=uri)


CHECKER = FormatChecker()


@CHECKER.checks('byte')
def byte_string(value):
    if not isinstance(value, str):
        return True
    try:
        base64.b64decode(value.replace('\r', '').replace('\n', ''), validate=True)
        return True
    except (ValueError, UnicodeError):
        return False


@CHECKER.checks('osv-base64')
def canonical_base64(value):
    if not isinstance(value, str):
        return True
    try:
        return base64.b64encode(base64.b64decode(value, validate=True)).decode() == value
    except (ValueError, UnicodeError):
        return False


@CHECKER.checks('osv-uint64-decimal')
def decimal_units(value):
    return not isinstance(value, str) or bool(re.fullmatch(r'0|[1-9][0-9]{0,19}', value)) and int(value) <= 2**64-1


def max_utf8_bytes(validator, limit, value, schema):
    if isinstance(value, str) and len(value.encode('utf-8')) > limit:
        yield ValidationError('string exceeds UTF-8 byte quota')


def max_decoded_bytes(validator, limit, value, schema):
    if isinstance(value, str) and byte_string(value) and len(base64.b64decode(value)) > limit:
        yield ValidationError('base64 value exceeds decoded byte quota')


WireValidator = validators.extend(Draft202012Validator, {
    'x-max-utf8-bytes': max_utf8_bytes, 'x-max-decoded-bytes': max_decoded_bytes,
})


def pinned_meta():
    lock = json.loads((ROOT / 'deploy/schemas/openapi-3.1/lock.json').read_text())
    if lock['protocol'] != 'osv-openapi-schema-sources/v1':
        raise ValueError('unsupported OpenAPI source lock')
    folder = ROOT / 'assets/build/schemas/openapi-3.1'
    for name, info in lock['files'].items():
        if hashlib.sha256((folder / name).read_bytes()).hexdigest() != info['sha256']:
            raise ValueError('pinned OpenAPI input changed: ' + name)
    schema = json.loads((folder / 'schema.json').read_text())
    if schema['$id'] != lock['schema_id']:
        raise ValueError('OpenAPI meta-schema identity changed')
    return schema


class Contract:
    def __init__(self, document):
        self.document = document
        registry = Registry(retrieve=no_retrieval)
        Draft202012Validator(pinned_meta(), registry=registry).validate(document)
        if document.get('openapi') != '3.1.1' or document.get('jsonSchemaDialect') != 'https://json-schema.org/draft/2020-12/schema':
            raise ValueError('unsupported contract version/dialect')
        self.schemas = document['components']['schemas']
        self.operations = {}
        operations = 0
        for path, methods in document['paths'].items():
            for method, operation in methods.items():
                if method not in {'get', 'post', 'delete', 'put', 'patch', 'head', 'options', 'trace'}:
                    raise ValueError('unsupported operation key')
                operations += 1
                name = operation['operationId']
                if name in self.operations:
                    raise ValueError('duplicate operationId')
                self.operations[name] = operation
                path_parameters = [p for p in operation.get('parameters', []) if p['in'] == 'path']
                names = [p['name'] for p in path_parameters]
                if set(names) != set(re.findall(r'\{([^}]+)\}', path)) or len(names) != len(set(names)) or not all(p.get('required') for p in path_parameters):
                    raise ValueError('missing/duplicate/optional path parameter')
                params = [(p['in'], p['name']) for p in operation.get('parameters', [])]
                if len(params) != len(set(params)):
                    raise ValueError('duplicate parameter')
                if 'requestBody' in operation:
                    self._concrete_root(operation['requestBody']['content']['application/json']['schema'], 'input')
                for status, response in operation['responses'].items():
                    schema = response.get('content', {}).get('application/json', {}).get('schema')
                    if schema is not None and status.isdigit() and 200 <= int(status) < 300:
                        self._concrete_root(schema, 'response')
        if operations != document['x-source-route-count']:
            raise ValueError('operation denominator does not match declared source routes')
        self._refs(document)
        for schema in self.schemas.values():
            Draft202012Validator.check_schema(schema)
        resource = Resource.from_contents({'$schema': 'https://json-schema.org/draft/2020-12/schema', '$id': DOCUMENT_ID, **document})
        self.registry = registry.with_resource(DOCUMENT_ID, resource)

    def _refs(self, value):
        if isinstance(value, dict):
            if '$ref' in value:
                ref = value['$ref']
                if not isinstance(ref, str) or not ref.startswith('#/components/schemas/'):
                    raise ValueError('external or unsupported reference forbidden')
                if ref.removeprefix('#/components/schemas/') not in self.schemas:
                    raise ValueError('dangling component reference')
            for child in value.values():
                self._refs(child)
        elif isinstance(value, list):
            for child in value:
                self._refs(child)

    def _concrete_root(self, schema, context):
        ref = schema.get('$ref', '')
        if not ref.startswith('#/components/schemas/'):
            raise ValueError(context + ' JSON root must reference a named wire object')
        target = self.schemas.get(ref.removeprefix('#/components/schemas/'), {})
        if target.get('type') != 'object' or not target.get('properties'):
            raise ValueError(context + ' JSON root is unconstrained')

    def validate(self, schema, value):
        # An explicit base URI resolves local component references without I/O.
        wrapper = {'$id': DOCUMENT_ID, 'components': {'schemas': self.schemas}, **schema}
        WireValidator(wrapper, registry=self.registry, format_checker=CHECKER).validate(value)

    def component(self, name, value):
        if name not in self.schemas:
            raise ValueError('unknown component ' + name)
        self.validate({'$ref': '#/components/schemas/' + name}, value)

    def exchange(self, sample):
        operation = self.operations[sample['operation_id']]
        if sample.get('validate_request'):
            self.validate(operation['requestBody']['content']['application/json']['schema'], sample['request'])
        status = str(sample['status'])
        response = operation['responses'].get(status, operation['responses']['default'])
        if sample.get('media_type', 'application/json') == 'application/json':
            self.validate(response['content']['application/json']['schema'], sample['response'])
        else:
            media_type = sample['media_type']
            self.validate(response['content'][media_type]['schema'], sample['response'])


def load(path):
    if path.stat().st_size > 4 << 20:
        raise ValueError('HTTP contract exceeds size limit')
    return Contract(json.loads(path.read_text()))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--document', type=Path, default=ROOT / 'api/contracts/openapi.json')
    parser.add_argument('--samples', type=Path, help='named component instances captured from actual encoders')
    parser.add_argument('--exchanges', type=Path, help='actual request/response exchange samples')
    args = parser.parse_args()
    contract = load(args.document)
    instances = exchanges = 0
    if args.samples:
        values = json.load(sys.stdin) if str(args.samples) == '-' else json.loads(args.samples.read_text())
        for sample in values:
            contract.component(sample['schema'], sample['value'])
            instances += 1
    if args.exchanges:
        values = json.load(sys.stdin) if str(args.exchanges) == '-' else json.loads(args.exchanges.read_text())
        for sample in values:
            contract.exchange(sample)
            exchanges += 1
    print(json.dumps({'passed': True, 'operations': len(contract.operations), 'schemas': len(contract.schemas),
                      'actual_encoder_samples': instances, 'actual_exchanges': exchanges,
                      'network_retrieval_enabled': False}))


if __name__ == '__main__':
    main()
