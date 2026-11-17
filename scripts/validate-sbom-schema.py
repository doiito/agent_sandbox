#!/usr/bin/env python3
"""Validate CycloneDX 1.5 using hash-pinned schemas without network retrieval."""
import argparse
import hashlib
import importlib.metadata
import json
import uuid
from pathlib import Path

from jsonschema import Draft7Validator, FormatChecker
from referencing import Registry, Resource
from referencing.exceptions import NoSuchResource

ROOT=Path(__file__).resolve().parents[1]
LOCK=ROOT/'deploy/schemas/cyclonedx-1.5/lock.json'
SCHEMAS=ROOT/'assets/build/schemas/cyclonedx-1.5'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def reject_retrieval(uri):
    raise NoSuchResource(ref=uri)


def validate(path):
    lock=json.loads(LOCK.read_text())
    names={'bom-1.5.schema.json','spdx.schema.json','jsf-0.82.schema.json'}
    if lock['protocol']!='osv-cyclonedx-schema-sources/v1' or set(lock['files_sha256'])!=names:
        raise ValueError('unsupported schema source lock')
    registry=Registry(retrieve=reject_retrieval)
    documents={}
    for name,digest in lock['files_sha256'].items():
        schema_path=SCHEMAS/name
        if sha(schema_path)!=digest:
            raise ValueError('schema differs from pinned source: '+name)
        document=json.loads(schema_path.read_text())
        resource=Resource.from_contents(document)
        registry=registry.with_resource(document['$id'],resource)
        registry=registry.with_resource('http://cyclonedx.org/schema/'+name,resource)
        documents[name]=document
    if path.stat().st_size>16*1024*1024:
        raise ValueError('SBOM exceeds validation size limit')
    bom=json.loads(path.read_text())
    required_formats=set()
    def formats(value):
        if isinstance(value,dict):
            if isinstance(value.get('format'),str):
                required_formats.add(value['format'])
            for child in value.values():
                formats(child)
        elif isinstance(value,list):
            for child in value:
                formats(child)
    for document in documents.values():
        formats(document)
    checker=FormatChecker()
    missing=required_formats-set(checker.checkers)
    if missing:
        raise ValueError('missing schema format validators '+','.join(sorted(missing))+
            '; install deploy/requirements-validation.txt from assets/build/python-validation')
    validator=Draft7Validator(documents['bom-1.5.schema.json'],registry=registry,format_checker=checker)
    sample=next(validator.iter_errors(bom),None)
    if sample is not None:
        raise ValueError('/'.join(str(value) for value in sample.absolute_path)+': '+sample.message[:500])
    if 'serialNumber' in bom:
        serial=uuid.UUID(bom['serialNumber'])
        if serial.variant != uuid.RFC_4122 or serial.version not in (1,2,3,4,5):
            raise ValueError('SBOM serialNumber is not an RFC 4122 UUID')
    refs=set()
    components=0
    def walk(entry,depth=0):
        nonlocal components
        if depth>16:
            raise ValueError('excessive component nesting')
        components+=1
        reference=entry.get('bom-ref')
        if reference:
            if reference in refs:
                raise ValueError('duplicate component reference: '+reference)
            refs.add(reference)
        for child in entry.get('components',[]):
            walk(child,depth+1)
    metadata=bom.get('metadata',{}).get('component')
    if metadata:
        walk(metadata)
    for entry in bom.get('components',[]):
        walk(entry)
    sources=set()
    for edge in bom.get('dependencies',[]):
        if edge['ref'] not in refs or edge['ref'] in sources or any(target not in refs for target in edge.get('dependsOn',[])):
            raise ValueError('dangling or duplicate dependency reference')
        sources.add(edge['ref'])
    return {'protocol':'osv-cyclonedx-schema-validation/v1','spec_version':'1.5','passed':True,
        'sbom_sha256':sha(path),'schema_lock_sha256':sha(LOCK),'schema_sha256':lock['files_sha256'],
        'component_count':components,'dependency_nodes':len(sources),'network_retrieval_enabled':False,
        'jsonschema_version':importlib.metadata.version('jsonschema'),'validated_formats':sorted(required_formats)}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('sbom',type=Path)
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    result=validate(args.sbom)
    if args.output:
        args.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result),flush=True)


if __name__=='__main__':
    main()
