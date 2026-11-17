#!/usr/bin/env python3
"""Export a sealed science tree as hash-bound CycloneDX component input."""
import argparse
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('science_closure',ROOT/'scripts/python_science_closure.py')
closure = importlib.util.module_from_spec(spec)
spec.loader.exec_module(closure)
rofs_spec = importlib.util.spec_from_file_location('science_rofs',ROOT/'scripts/rofs_inventory.py')
rofs = importlib.util.module_from_spec(rofs_spec)
rofs_spec.loader.exec_module(rofs)
ROOTFS_REF = 'urn:osv:artifact:osv-rootfs'
KERNEL_REF = 'urn:osv:artifact:osv-kernel'
METADATA = {'/runtime-components.json','/runtime-inventory.json','/bytecode-provenance.json','/bytecode-verification.json'}


def sha(path):
    return closure.sources.digest(path)


def file_ref(path):
    return 'runtime:file:'+quote(path,safe='/')


def export(rootfs,inventory,image):
    document = json.loads(inventory.read_text())
    if (rootfs/'runtime-inventory.json').read_bytes() != inventory.read_bytes():
        raise ValueError('embedded inventory differs from build inventory')
    closure.verify(rootfs,document)
    provenance = json.loads((rootfs/'runtime-components.json').read_text())
    if provenance['protocol'] != 'osv-runtime-component-provenance/v1' or set(provenance['generated_metadata_paths']) != METADATA:
        raise ValueError('invalid component provenance')
    rows = document['files']+[{'path':'/runtime-inventory.json','size':inventory.stat().st_size,'sha256':sha(inventory)}]
    files = {row['path']:row for row in rows}
    image_files = {row['path']:row for row in rofs.inspect(image)['files']}
    if any(image_files.get(path) != row for path,row in files.items()):
        raise ValueError('ROFS image contents differ from the sealed source inventory')
    expected_base = {
        '/etc/fstab':ROOT/'osv-upstream/build/release.x64/fstab',
        '/etc/hosts':ROOT/'osv-upstream/static/etc/hosts',
        '/libenviron.so':ROOT/'osv-upstream/build/release.x64/libenviron-stripped.so',
        '/osv-job-agent.so':ROOT/'osv-upstream/apps/job-agent/osv-job-agent-stripped.so'}
    extras = set(image_files)-set(files)
    if extras != set(expected_base)|{'/etc/mnttab'}:
        raise ValueError('unexpected or missing image base files (diagnostic modules are not allowed)')
    for path,source in expected_base.items():
        if image_files[path].get('sha256') != sha(source) or image_files[path].get('size') != source.stat().st_size:
            raise ValueError('image support file differs from its build artifact: '+path)
    if image_files['/etc/mnttab'] != {'path':'/etc/mnttab','symlink':'/proc/mounts'}:
        raise ValueError('unexpected image mount table link')
    owners = dict(provenance['file_owners'])
    for path in METADATA:
        if path in owners or path not in files:
            raise ValueError('generated metadata ownership mismatch')
        owners[path] = 'runtime:build-metadata'
    bytecode = json.loads((rootfs/'bytecode-provenance.json').read_text())
    verified = json.loads((rootfs/'bytecode-verification.json').read_text())
    if (verified['protocol'] != 'osv-python-checked-bytecode-verification/v1' or
            not verified['source_compilation_equal'] or not verified['optimized_code_rejected'] or
            verified['provenance_sha256'] != sha(rootfs/'bytecode-provenance.json') or
            verified['bytecode_files'] != len(bytecode['files'])):
        raise ValueError('missing or stale bytecode semantic verification')
    derived = {}
    for row in bytecode['files']:
        if row['source'] not in owners or row['bytecode'] in owners or row['bytecode'] in derived:
            raise ValueError('invalid derived bytecode owner')
        owners[row['bytecode']] = owners[row['source']]
        derived[row['bytecode']] = row['source']
    if set(files) != set(owners):
        raise ValueError('runtime file ownership is incomplete or contains extra paths')
    for path in extras:
        owners[path] = 'runtime:project-agent' if path == '/osv-job-agent.so' else 'runtime:image-base'
        files[path] = image_files[path]
    components = {}
    dependencies = {}
    upstream = subprocess.check_output(['git','-C',str(ROOT/'osv-upstream'),'rev-parse','HEAD'],text=True).strip()
    if not re.fullmatch('[0-9a-f]{40}',upstream):
        raise ValueError('invalid image base source revision')
    base_component = {'ref':'runtime:image-base','type':'library','name':'OSv image support files',
        'version':upstream,'purl':'pkg:github/cloudius-systems/osv@'+upstream,
        'version_status':'image-bytes-and-build-artifacts-verified','licenses':[],
        'origin':{'support_files':{path:sha(source) for path,source in expected_base.items() if path != '/osv-job-agent.so'}}}
    agent_component = {'ref':'runtime:project-agent','type':'file','name':'osv-job-agent embedded in ROFS',
        'version_status':'project-build-stripped-artifact','licenses':[],
        'origin':{'unstripped_sha256':sha(ROOT/'osv-upstream/apps/job-agent/osv-job-agent.so'),
            'stripped_sha256':sha(ROOT/'osv-upstream/apps/job-agent/osv-job-agent-stripped.so'),
            'source_sha256':sha(ROOT/'osv-native/apps/job-agent/main.c')}}
    component_rows = provenance['components']+[base_component,agent_component]
    for item in component_rows:
        reference = item['ref']
        if not reference or reference in components:
            raise ValueError('duplicate component reference')
        value = {'type':item['type'],'bom-ref':reference,'name':item['name'],'components':[],
            'properties':[{'name':'osv:version-status','value':item['version_status']},
                {'name':'osv:origin','value':json.dumps(item.get('origin',{}),sort_keys=True)}]}
        for key in ('version','purl'):
            if item.get(key):
                value[key] = item[key]
        notices=[]
        for path in item['licenses']:
            closure.guest_path(path)
            if path not in files:
                raise ValueError('license is not present in the sealed tree')
            data = (rootfs/path.lstrip('/')).read_bytes()
            if hashlib.sha256(data).hexdigest() != files[path].get('sha256'):
                raise ValueError('license text differs from sealed file')
            notices.append({'license':{'name':'Packaged notices: '+path,
                'text':{'contentType':'text/plain','encoding':'base64','content':base64.b64encode(data).decode()}}})
        if notices:
            value['licenses'] = notices
        components[reference] = value
        dependencies[reference] = set()
    if set(owners.values())-set(components):
        raise ValueError('file owner references an absent component')
    for path,row in sorted(files.items()):
        closure.guest_path(path)
        value = {'type':'file','bom-ref':file_ref(path),'name':path}
        if row.get('sha256'):
            value['hashes'] = [{'alg':'SHA-256','content':row['sha256']}]
        else:
            value['properties'] = [{'name':'osv:symlink-target','value':row['symlink']}]
        if path in derived:
            value.setdefault('properties',[]).append({'name':'osv:derived-from','value':derived[path]})
        components[owners[path]]['components'].append(value)
        dependencies[value['bom-ref']] = {file_ref(derived[path])} if path in derived else set()
    for edge in provenance['native_dependencies']:
        if edge['from'] not in files:
            raise ValueError('native dependency source missing')
        target = KERNEL_REF if edge['provider'] == 'OSv' else file_ref(edge['provider'])
        if edge['provider'] != 'OSv' and edge['provider'] not in owners:
            raise ValueError('native dependency target missing')
        dependencies[file_ref(edge['from'])].add(target)
        if edge['provider'] != 'OSv' and owners[edge['from']] != owners[edge['provider']]:
            dependencies[owners[edge['from']]].add(owners[edge['provider']])
    pypi = {re.sub('[-_.]+','-',item['name']).lower():item['ref'] for item in component_rows if item.get('purl','').startswith('pkg:pypi/')}
    for item in component_rows:
        reference = item['ref']
        if item.get('embedded_in'):
            if item['embedded_in'] not in dependencies:
                raise ValueError('embedded component parent missing')
            dependencies[item['embedded_in']].add(reference)
        if item.get('purl','').startswith('pkg:pypi/'):
            dependencies[reference].add('runtime:cpython')
            for requirement in item.get('origin',{}).get('requires_dist',[]):
                name = re.match(r'[A-Za-z0-9][A-Za-z0-9._-]*',requirement)
                if name:
                    dependency = pypi.get(re.sub('[-_.]+','-',name[0]).lower())
                    if dependency and dependency != reference:
                        dependencies[reference].add(dependency)
    dependencies[ROOTFS_REF] = set(components)|{KERNEL_REF}
    unresolved = sorted(item['ref'] for item in provenance['components'] if item['version_status'].startswith('unresolved'))
    if unresolved != sorted(provenance['unresolved_versions']):
        raise ValueError('component version coverage mismatch')
    return {'protocol':'osv-runtime-sbom-input/v1','rootfs_sha256':sha(image),
        'inventory_sha256':sha(inventory),'provenance_sha256':sha(rootfs/'runtime-components.json'),
        'files_count':len(files),'components':sorted(components.values(),key=lambda item:item['bom-ref']),
        'image_base_files':[files[path] for path in sorted(extras)],
        'dependencies':[{'ref':ref,'dependsOn':sorted(values)} for ref,values in sorted(dependencies.items())],
        'unresolved_versions':unresolved,'file_coverage_complete':True,'version_coverage_complete':False,
        'static_component_audit':provenance['static_component_audit'],'vulnerability_scan_complete':False,
        'python_dependency_scope':'Installed declared package-name relationships; raw environment markers retained in origin metadata',
        'producer_sha256':sha(Path(__file__))}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rootfs',type=Path,required=True)
    parser.add_argument('--inventory',type=Path,required=True)
    parser.add_argument('--image',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists():
        raise ValueError('requires a fresh SBOM input output')
    document=export(args.rootfs.resolve(strict=True),args.inventory,args.image)
    args.output.write_text(json.dumps(document,indent=2)+'\n')
    print(json.dumps({'components':len(document['components']),'files':document['files_count'],
        'unresolved_versions':document['unresolved_versions'],'vulnerability_scan_complete':False}),flush=True)


if __name__ == '__main__':
    main()
