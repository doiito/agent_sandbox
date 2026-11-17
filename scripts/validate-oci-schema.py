#!/usr/bin/env python3
"""Offline format checks using the original hash-pinned OCI Image 1.1.0 schemas.

This build-time checker is not a template signature/admission verifier.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re

from jsonschema import Draft4Validator, FormatChecker
from referencing import Registry, Resource
from referencing.exceptions import NoSuchResource
from referencing.jsonschema import DRAFT4

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / 'assets/build/schemas/oci-image-1.1.0'

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def reject_retrieval(uri):
    raise NoSuchResource(ref=uri)

def validate(layout):
    lock = json.loads((SCHEMAS / 'source-lock.json').read_text())
    if lock['protocol'] != 'osv-oci-image-schemas/v1' or lock['commit'] != 'e7f7c0ca69b21688c3cea7c87a04e4503e6099e2':
        raise ValueError('unexpected OCI schema lock')
    registry = Registry(retrieve=reject_retrieval)
    documents = {}
    for name, expected in lock['files_sha256'].items():
        if sha(SCHEMAS / name) != expected:
            raise ValueError('schema differs from pinned upstream: ' + name)
        if not name.endswith('.json'):
            continue
        document = json.loads((SCHEMAS / name).read_text())
        # Upstream definition-only fragments omit $schema and id. Keep their
        # original bytes and supply the parent schemas' Draft 4 explicitly.
        resource = Resource.from_contents(document, default_specification=DRAFT4)
        if 'id' in document:
            registry = registry.with_resource(document['id'], resource)
        for base in ('https://opencontainers.org/schema/', 'https://opencontainers.org/schema/image/',
                     'https://raw.githubusercontent.com/opencontainers/image-spec/' + lock['commit'] + '/schema/'):
            registry = registry.with_resource(base + name, resource)
        documents[name] = document
    checked = []
    def check(data, schema, name):
        document = json.loads(data)
        Draft4Validator(documents[schema], registry=registry, format_checker=FormatChecker()).validate(document)
        checked.append({'object': name, 'schema': schema, 'sha256': hashlib.sha256(data).hexdigest()})
        return document
    def read_small(path):
        if path.stat().st_size > 1 << 20:
            raise ValueError('OCI JSON exceeds 1MiB')
        return path.read_bytes()
    check(read_small(layout / 'oci-layout'), 'image-layout-schema.json', 'oci-layout')
    index = check(read_small(layout / 'index.json'), 'image-index-schema.json', 'index.json')
    if len(index['manifests']) != 1:
        raise ValueError('this checker expects one template per layout')
    descriptor = index['manifests'][0]
    check(json.dumps(descriptor).encode(), 'content-descriptor.json', 'index descriptor')
    if not re.fullmatch(r'sha256:[a-f0-9]{64}', descriptor['digest']):
        raise ValueError('expected SHA256 manifest digest')
    data = read_small(layout / 'blobs/sha256' / descriptor['digest'][7:])
    if len(data) != descriptor['size'] or hashlib.sha256(data).hexdigest() != descriptor['digest'][7:]:
        raise ValueError('manifest differs from index descriptor')
    manifest = check(data, 'image-manifest-schema.json', 'image manifest')
    for position, layer in enumerate([manifest['config'], *manifest['layers']]):
        check(json.dumps(layer).encode(), 'content-descriptor.json', 'descriptor-' + str(position))
    return {'protocol': 'osv-oci-offline-schema-validation/v1', 'passed': True,
        'upstream_commit': lock['commit'], 'schema_lock_sha256': sha(SCHEMAS / 'source-lock.json'),
        'network_retrieval_enabled': False, 'signature_admission_verified': False,
        'oci_manifest_digest': descriptor['digest'], 'checks': checked}

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('layout', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    report = validate(args.layout)
    if args.output:
        args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report), flush=True)
