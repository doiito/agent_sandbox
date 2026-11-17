#!/usr/bin/env python3
"""Generate the typed native gRPC contract; never renumber a published field.

Only --update-lock may append field numbers or retire removed fields. --check
is read-only, including when a new field would otherwise be safe to append.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = 'sandbox.control.v1'
SCALARS = {'string', 'bytes', 'bool', 'double', 'int64', 'uint64'}


def title(value):
    return ''.join(part[0].upper() + part[1:] for part in re.findall(r'[A-Za-z0-9]+', value))


class Contract:
    def __init__(self, document):
        self.document = document
        self.schemas = document['components']['schemas']
        self.messages = {}
        self.operations = {}
        self.add('TransportEmpty', 'object', {})
        self.add('JsonArray', 'json_array', {'values': self.f('JsonValue', cardinality='repeated')})
        self.add('JsonObject', 'json_object', {'values': self.f('JsonValue', cardinality='map')})
        self.add('JsonValue', 'json', {
            'null_value': self.f('JsonNull', oneof='kind'),
            'boolean': self.f('bool', oneof='kind'),
            'number': self.f('string', oneof='kind'),
            'text': self.f('string', oneof='kind'),
            'array': self.f('JsonArray', oneof='kind'),
            'object': self.f('JsonObject', oneof='kind'),
        })
        self.add_object('ErrorDetail', {'type': 'object', 'properties': {
            'code': {'type': 'string'}, 'message': {'type': 'string'},
            'http_status': {'type': 'integer', 'minimum': 0}, 'invocation_id': {'type': 'string'},
        }})
        for name in sorted(self.schemas):
            self.component(name)
        self.add('MetricsText', 'text', {'text': self.f('string')})
        for path, methods in document['paths'].items():
            for method, operation in methods.items():
                if method in {'get', 'post', 'put', 'delete', 'patch', 'head', 'options', 'trace'}:
                    self.operation(method, path, operation)
        if len(self.operations) != 48:
            raise ValueError('Review the full operation inventory before changing its denominator')
        self.add('SessionCommandStreamEvent', 'stream_event', {
            'sequence': self.f('uint64'),
            'output': self.f('SessionOutputFrameOutput', oneof='event'),
            'result': self.f('SessionCommandPageOutput', oneof='event'),
            'timeout': self.f('SessionCommandTimeoutFrameOutput', oneof='event'),
        })
        self.add('PortOpened', 'object', {key: self.f(kind) for key, kind in
                 [('id', 'string'), ('connection', 'string'), ('port', 'uint64')]})
        self.add('PortClientFrame', 'port_client', {
            'open': self.f('OpenPortTunnelRequest', oneof='frame'),
            'data': self.f('bytes', oneof='frame'),
            'eof': self.f('TransportEmpty', oneof='frame'),
            'cancel': self.f('TransportEmpty', oneof='frame'),
        })
        self.add('PortServerFrame', 'port_server', {
            'opened': self.f('PortOpened', oneof='frame'),
            'data': self.f('bytes', oneof='frame'),
            'eof': self.f('TransportEmpty', oneof='frame'),
            'finished': self.f('SessionPortInfoOutput', oneof='frame'),
        })

    @staticmethod
    def f(type_name, **metadata):
        return {'type': type_name, 'cardinality': 'singular', **metadata}

    def add(self, name, kind, fields, **metadata):
        if not re.fullmatch(r'[A-Za-z][A-Za-z0-9]*', name) or name in self.messages:
            raise ValueError('Invalid or duplicate message ' + name)
        self.messages[name] = {'kind': kind, 'fields': fields, **metadata}
        return name

    @staticmethod
    def unnull(schema):
        nullable = False
        while 'anyOf' in schema:
            branches = [branch for branch in schema['anyOf'] if branch.get('type') != 'null']
            if len(branches) == len(schema['anyOf']):
                break  # A numeric range union is a constraint on its declared type.
            if len(branches) != 1:
                raise ValueError('Explicit handling needed for schema union ' + repr(schema))
            schema, nullable = dict(branches[0]), True
        return schema, nullable

    def component(self, name):
        if name in self.messages:
            return name
        schema = self.schemas[name]
        if 'oneOf' in schema:
            fields, variants = {}, {}
            self.add(name, 'union', fields, variants=variants)
            for variant in schema['oneOf']:
                kind = variant['properties']['type']['const']
                variant_name = name + title(kind)
                self.add_object(variant_name, variant)
                fields[kind] = self.f(variant_name, oneof='event')
                variants[kind] = variant_name
            return name
        return self.add_object(name, schema)

    def add_object(self, name, schema):
        fields, constants = {}, {}
        self.add(name, 'object', fields, constants=constants)
        for key, value in sorted(schema.get('properties', {}).items()):
            if not re.fullmatch(r'[a-zA-Z_][a-zA-Z0-9_]*', key):
                raise ValueError('Explicit proto field spelling required for ' + key)
            if 'const' in value:
                constants[key] = value['const']
                continue
            field = self.field(value, name + title(key))
            field['required'] = key in schema.get('required', [])
            fields[key] = field
        return name

    def field(self, schema, context, element=False):
        schema, nullable = self.unnull(schema)
        if element and nullable:
            field = self.field(schema, context + 'Value')
            self.add(context, 'nullable', {'null_value': self.f('JsonNull', oneof='nullable'),
                                         'value': {**field, 'oneof': 'nullable'}})
            return self.f(context, nullable=True)
        if '$ref' in schema:
            prefix = '#/components/schemas/'
            if not schema['$ref'].startswith(prefix):
                raise ValueError('Only local canonical schema refs are accepted')
            return self.f(self.component(schema['$ref'][len(prefix):]), nullable=nullable)
        kind = schema.get('type')
        if kind is None:
            if set(schema) - {'description'}:
                raise ValueError('Unsupported untyped schema ' + repr(schema))
            return self.f('JsonValue', nullable=nullable)
        if kind == 'object':
            value = schema.get('additionalProperties')
            if isinstance(value, dict):
                inner = self.field(value, context + 'Entry', element=True)
                self.add(context, 'map', {'values': {**inner, 'cardinality': 'map'}})
            elif 'properties' in schema:
                self.add_object(context, schema)
            else:
                raise ValueError('Unbounded unnamed object needs explicit review: ' + context)
            return self.f(context, nullable=nullable)
        if kind == 'array':
            inner = self.field(schema['items'], context + 'Entry', element=True)
            self.add(context, 'list', {'values': {**inner, 'cardinality': 'repeated'}})
            return self.f(context, nullable=nullable)
        result = self.f({'string': 'string', 'boolean': 'bool', 'integer': 'int64', 'number': 'double'}[kind], nullable=nullable)
        if kind == 'integer' and schema.get('minimum', -1) >= 0:
            result['type'] = 'uint64'
        if schema.get('format') in {'byte', 'osv-base64'} or schema.get('contentEncoding') == 'base64':
            result.update(type='bytes', json_encoding='base64')
        if schema.get('format') == 'osv-uint64-decimal':
            result.update(type='uint64', json_encoding='decimal_string')
        return result

    def operation(self, method, path, source):
        name = title(source['operationId'])
        if name in self.operations:
            raise ValueError('Duplicate RPC method ' + name)
        fields = {}
        for parameter in source.get('parameters', []):
            if parameter['in'] == 'header':
                if source['operationId'] != 'openPortTunnel':
                    raise ValueError('Review explicit header parameter transport')
                continue
            key = parameter['name']
            field = self.field(parameter['schema'], name + 'Request' + title(key))
            fields[key] = {**field, 'location': parameter['in'], 'required': parameter.get('required', False)}
        content = source.get('requestBody', {}).get('content', {})
        if content:
            fields['body'] = {**self.field(content['application/json']['schema'], name + 'Body'),
                              'location': 'body', 'required': source['requestBody'].get('required', False)}
        self.add(name + 'Request', 'request', fields)
        responses = [(int(status), definition) for status, definition in source['responses'].items()
                     if status.isdigit() and 200 <= int(status) < 300]
        stream_input = stream_output = False
        if source['operationId'] == 'openPortTunnel':
            request, response, status = 'PortClientFrame', 'PortServerFrame', 101
            stream_input = stream_output = True
        else:
            if len(responses) != 1:
                raise ValueError('Review success response choices: ' + name)
            status, response_definition = responses[0]
            media = response_definition.get('content', {})
            if 'application/json' in media:
                response = self.field(media['application/json']['schema'], name + 'Result')['type']
            elif 'text/plain' in media:
                response = 'MetricsText'
            elif 'text/event-stream' in media:
                response, stream_output = 'SessionCommandStreamEvent', True
            elif not media and status == 204:
                response = self.add(name + 'Response', 'object', {})
            else:
                raise ValueError('Review non-JSON success media: ' + name)
            request = name + 'Request'
        self.operations[name] = {'operation_id': source['operationId'], 'method': method.upper(), 'path': path,
                                 'request': request, 'response': response, 'open_request': name + 'Request',
                                 'client_streaming': stream_input, 'server_streaming': stream_output,
                                 'http_status': status}

    def bind(self, existing, update=False):
        registry = copy.deepcopy(existing)
        if registry.get('protocol') != 'osv-grpc-field-registry/v1' or registry.get('package') != PACKAGE:
            raise ValueError('Unknown protobuf registry protocol/package')
        entries = registry.setdefault('messages', {})
        for name in sorted(self.messages):
            message = self.messages[name]
            prior = entries.setdefault(name, {}) if update else entries.get(name)
            if prior is None:
                raise ValueError('Unregistered message: ' + name)
            if prior.get('retired'):
                raise ValueError('Cannot reactivate retired message ' + name)
            if 'kind' in prior and prior['kind'] != message['kind']:
                raise ValueError('Message shape changed: ' + name)
            if update:
                prior['kind'] = message['kind']
            used = prior.setdefault('fields', {}) if update else prior.get('fields', {})
            numbers = [field['number'] for field in used.values()]
            if len(numbers) != len(set(numbers)) or any(number <= 0 or number >= 1 << 29 or 19000 <= number <= 19999 for number in numbers):
                raise ValueError('Invalid/duplicate field numbers in ' + name)
            next_number = max(numbers, default=0) + 1
            for key, field in sorted(message['fields'].items()):
                identity = {label: field[label] for label in ['type', 'cardinality']}
                identity['oneof'] = field.get('oneof')
                if key in used:
                    old = used[key]
                    if old.get('retired') or any(old.get(label) != value for label, value in identity.items()):
                        raise ValueError('Incompatible/reused field: ' + name + '.' + key)
                elif update:
                    if 19000 <= next_number <= 19999:
                        next_number = 20000
                    used[key] = dict(identity, number=next_number)
                    next_number += 1
                else:
                    raise ValueError('Unregistered field: ' + name + '.' + key)
                field['number'] = used[key]['number']
            for key, old in used.items():
                if key not in message['fields'] and not old.get('retired'):
                    if not update:
                        raise ValueError('Removed field must be reserved: ' + name + '.' + key)
                    old['retired'] = True
        for name, old in entries.items():
            if name not in self.messages and not old.get('retired'):
                if not update:
                    raise ValueError('Removed message must be retired: ' + name)
                old['retired'] = True
        service = registry.setdefault('methods', {})
        for name, operation in sorted(self.operations.items()):
            identity = {key: operation[key] for key in ['request', 'response', 'client_streaming', 'server_streaming']}
            if name in service:
                if service[name] != identity:
                    raise ValueError('Changed RPC signature: ' + name)
            elif update:
                service[name] = identity
            else:
                raise ValueError('Unregistered RPC method: ' + name)
        if set(service) != set(self.operations):
            raise ValueError('Removed/reused RPC method requires a new versioned contract')
        self.registry = registry
        return registry

    def proto(self):
        lines = ['// Generated from the canonical HTTP wire contract. DO NOT EDIT.', 'syntax = "proto3";',
                 'package ' + PACKAGE + ';', 'option go_package = "github.com/doiito/agent_sandbox/api/control/v1;controlv1";',
                 '', 'enum JsonNull { JSON_NULL = 0; }', '']
        for name, message in sorted(self.messages.items()):
            lines.append('message ' + name + ' {')
            retired = [(key, field['number']) for key, field in self.registry['messages'][name]['fields'].items() if field.get('retired')]
            if retired:
                lines.append('  reserved ' + ', '.join(str(number) for _, number in sorted(retired)) + ';')
                lines.append('  reserved ' + ', '.join(json.dumps(key) for key, _ in sorted(retired)) + ';')
            groups = {}
            for key, field in sorted(message['fields'].items(), key=lambda pair: pair[1]['number']):
                if field.get('oneof'):
                    groups.setdefault(field['oneof'], []).append((key, field))
                else:
                    lines.append('  ' + self.proto_field(key, field))
            for group, fields in sorted(groups.items()):
                lines.append('  oneof ' + group + ' {')
                for key, field in fields:
                    lines.append('    ' + self.proto_field(key, field))
                lines.append('  }')
            lines += ['}', '']
        lines.append('service Control {')
        for name, operation in sorted(self.operations.items()):
            prefix = 'stream ' if operation['client_streaming'] else ''
            suffix = 'stream ' if operation['server_streaming'] else ''
            lines.append('  // ' + operation['method'] + ' ' + operation['path'])
            lines.append(f'  rpc {name} ({prefix}{operation["request"]}) returns ({suffix}{operation["response"]});')
        lines += ['}', '']
        return '\n'.join(lines)

    @staticmethod
    def proto_field(key, field):
        kind, cardinality = field['type'], field['cardinality']
        if cardinality == 'map':
            kind = 'map<string, ' + kind + '>'
        elif cardinality == 'repeated':
            kind = 'repeated ' + kind
        elif not field.get('oneof') and kind in SCALARS:
            kind = 'optional ' + kind
        return f'{kind} {key} = {field["number"]} [json_name = "{key}"];'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    action = parser.add_mutually_exclusive_group()
    action.add_argument('--check', action='store_true')
    action.add_argument('--update-lock', action='store_true')
    args = parser.parse_args()
    root = args.root.resolve()
    canonical = root / 'api/contracts/openapi.json'
    document = json.loads(canonical.read_text())
    contract = Contract(document)
    lock = root / 'api/control/v1/field-numbers.json'
    existing = json.loads(lock.read_text()) if lock.exists() else {'protocol': 'osv-grpc-field-registry/v1', 'package': PACKAGE}
    registry = contract.bind(existing, args.update_lock)
    metadata = {'protocol': 'osv-grpc-wire-mapping/v1', 'package': PACKAGE,
                'canonical_HTTP_contract_sha256': hashlib.sha256(canonical.read_bytes()).hexdigest(),
                'messages': contract.messages, 'operations': contract.operations}
    outputs = {'api/control/v1/control.proto': contract.proto(),
               'api/control/v1/wire-mapping.json': json.dumps(metadata, sort_keys=True, indent=2) + '\n'}
    if args.update_lock:
        outputs['api/control/v1/field-numbers.json'] = json.dumps(registry, sort_keys=True, indent=2) + '\n'
    for name, data in outputs.items():
        path = root / name
        if args.check:
            if not path.is_file() or path.read_text() != data:
                raise SystemExit('Stale native gRPC contract: ' + name)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(data)
    print(json.dumps({'operations': len(contract.operations), 'messages': len(contract.messages),
                      'check': args.check, 'registry_updated': args.update_lock}))


if __name__ == '__main__':
    main()
