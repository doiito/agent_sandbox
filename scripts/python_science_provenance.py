#!/usr/bin/env python3
"""Collect verified package/file origins and package license texts offline."""
import argparse
from email.parser import BytesParser
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
from urllib.parse import quote
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('science_closure',ROOT/'scripts/python_science_closure.py')
closure = importlib.util.module_from_spec(spec)
spec.loader.exec_module(closure)


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(1048576),b''):
            digest.update(block)
    return digest.hexdigest()


def owner_of(path, original):
    candidates = [str(path),str(original)]
    if str(path).startswith('/usr/lib/'):
        candidates.append(str(path)[4:])
    for candidate in candidates:
        lookup = subprocess.run(['dpkg-query','-S',candidate],capture_output=True,text=True)
        if lookup.returncode == 0:
            matches = {line.split(': ',1)[0] for line in lookup.stdout.splitlines() if ': /' in line}
            if len(matches) != 1:
                raise ValueError('ambiguous installed package owner: '+str(path))
            return matches.pop()
    raise ValueError('no installed package owner: '+str(path))


def collect_system(rootfs, provenance, image_id):
    if image_id != provenance['builder_image_id']:
        raise ValueError('builder image differs from original runtime build')
    expected = dict(item.split('=',1) for item in provenance['packages'])
    providers = closure.system_libraries()
    components, owners, licenses, copies = {}, {}, {}, {}
    for library in sorted((rootfs/'usr/lib').iterdir()):
        if library.is_symlink() or not library.is_file():
            raise ValueError('unsupported runtime library inode')
        installed = providers.get(library.name)
        if installed is None or sha(installed) != sha(library):
            raise ValueError('runtime library differs from builder: '+library.name)
        owner = owner_of(installed, installed)
        fields = subprocess.check_output(['dpkg-query','-W',
            '-f=${binary:Package}\t${Version}\t${source:Package}\t${source:Version}\t${Architecture}\n',owner],text=True).strip().split('\t')
        if len(fields) != 5 or expected.get(fields[0]) != fields[1]:
            raise ValueError('package version differs from build provenance: '+owner)
        package,version,source,source_version,architecture = fields
        name = package.split(':')[0]
        reference = 'pkg:deb/ubuntu/'+name+'@'+quote(version,safe='')+'?arch='+architecture+'&distro=ubuntu-22.04'
        copyright = Path('/usr/share/doc')/name/'copyright'
        guest_copyright = '/usr/share/licenses/osv-runtime/packages/'+name+'/copyright'
        text = copyright.read_text()
        copies[guest_copyright] = copyright.read_bytes()
        component_licenses = [guest_copyright]
        for value in sorted(set(re.findall(r'/usr/share/common-licenses/[A-Za-z0-9.+_-]+',text))):
            path = Path(value.rstrip('.'))
            if not path.is_file():
                raise ValueError('missing referenced common license: '+value)
            guest = '/usr/share/licenses/osv-runtime/common/'+path.name
            copies[guest] = path.read_bytes()
            component_licenses.append(guest)
            licenses[guest] = 'runtime:license-texts'
        guest = '/usr/lib/'+library.name
        owners[guest] = reference
        owners[guest_copyright] = reference
        if reference not in components:
            components[reference] = {'ref':reference,'type':'library','name':name,'version':version,'purl':reference,
                'version_status':'builder-package-and-file-verified','licenses':component_licenses,
                'origin':{'binary_package':package,'source_package':source,'source_version':source_version,
                    'architecture':architecture,'builder_image_id':image_id},'files':[]}
        components[reference]['files'].append({'path':guest,'sha256':sha(library),'builder_path':str(installed)})
    owners.update(licenses)
    return list(components.values()),owners,copies


def collect_wheels(rootfs, lock):
    components,owners = [],{}
    site = rootfs/'opt/python/lib/python3.12/site-packages'
    for item in lock['files']:
        if item['kind'] != 'wheel':
            continue
        wheel = closure.sources.SOURCES/item['filename']
        closure.sources.verify(wheel,item['sha256'])
        reference = 'pkg:pypi/'+re.sub('[-_.]+','-',item['project']).lower()+'@'+item['version']
        member_names=[]
        with zipfile.ZipFile(wheel) as archive:
            for member in archive.infolist():
                name = member.filename.rstrip('/')
                path = PurePosixPath(name)
                if (path.is_absolute() or str(path) != name or '..' in path.parts or '\\' in name or
                        any(part.endswith('.data') for part in path.parts)):
                    raise ValueError('unsafe wheel origin path')
                if member.is_dir() or closure.EXCLUDED_PARTS.intersection(path.parts) or name.endswith(('.pyc','.pyo')):
                    continue
                installed = site/name
                if installed.is_symlink() or not installed.is_file() or sha(installed) != hashlib.sha256(archive.read(member)).hexdigest():
                    raise ValueError('installed wheel file differs from locked source: '+name)
                guest = '/'+str(installed.relative_to(rootfs))
                if guest in owners:
                    raise ValueError('overlapping wheel file owner: '+guest)
                owners[guest] = reference
                member_names.append(name)
        metadata_names = [name for name in member_names if name.endswith('.dist-info/METADATA')]
        if len(metadata_names) != 1:
            raise ValueError('ambiguous wheel metadata')
        metadata = BytesParser().parsebytes((site/metadata_names[0]).read_bytes())
        if re.sub('[-_.]+','-',metadata['Name']).lower() != re.sub('[-_.]+','-',item['project']).lower() or metadata['Version'] != item['version']:
            raise ValueError('wheel metadata differs from source lock')
        dist = metadata_names[0].rsplit('/',1)[0]
        license_paths = sorted('/opt/python/lib/python3.12/site-packages/'+name for name in member_names
            if name.startswith(dist+'/') and any(part.lower().startswith(('license','copying','copyright')) for part in PurePosixPath(name).parts[1:]))
        if not license_paths:
            raise ValueError('wheel license missing: '+item['project'])
        components.append({'ref':reference,'type':'library','name':item['project'],'version':item['version'],
            'purl':reference,'version_status':'locked-wheel-metadata-and-files-verified','licenses':license_paths,
            'origin':{'source':item,'metadata_path':'/opt/python/lib/python3.12/site-packages/'+metadata_names[0],
                'requires_dist':metadata.get_all('Requires-Dist',[])},'files':[]})
    return components,owners


def source_notices(rootfs, lock, facts):
    item = next(item for item in lock['files'] if item['project'] == 'CPython')
    archive = closure.sources.SOURCES/item['filename']
    closure.sources.verify(archive,item['sha256'])
    prefix = 'Python-'+item['version']+'/'
    selected = {'expat':'Modules/expat/COPYING', 'mpdecimal':'Modules/_decimal/libmpdec/mpdecimal.h'}
    copies,components = {},[]
    with tarfile.open(archive,'r:xz') as source:
        header = source.extractfile(prefix+'Modules/expat/expat.h').read().decode()
        version = '.'.join(re.search(r'#\s*define XML_'+name+'_VERSION\s+(\d+)',header)[1] for name in ('MAJOR','MINOR','MICRO'))
        decimal_header = source.extractfile(prefix+selected['mpdecimal']).read()
        decimal_version = re.search(rb'#define MPD_VERSION "([^"]+)"',decimal_header)[1].decode()
        for name,actual in (('expat',version),('mpdecimal',decimal_version)):
            if facts[name] != actual:
                raise ValueError('bundled source version differs from actual runtime export: '+name)
            relative = selected[name]
            data = source.extractfile(prefix+relative).read()
            if name == 'mpdecimal':
                data = data[:data.index(b'*/')+2]+b'\n'
            guest = '/usr/share/licenses/osv-runtime/cpython/'+name+'.txt'
            copies[guest] = data
            components.append({'ref':'runtime:bundled:'+name,'type':'library','name':name,'version':actual,
                'purl':'pkg:generic/'+name+'@'+actual,'version_status':'locked-source-and-runtime-export-verified',
                'licenses':[guest],'origin':{'source_archive':item,'notice_source_path':relative},'files':[],
                'embedded_in':'runtime:cpython'})
        refresh = source.extractfile(prefix+'Modules/_hacl/refresh.sh').read()
        revision = re.search(rb'expected_hacl_star_rev=([0-9a-f]{40})',refresh)[1].decode()
        hacl = source.extractfile(prefix+'Modules/_hacl/Hacl_Hash_SHA2.c').read()
        guest = '/usr/share/licenses/osv-runtime/cpython/hacl-star.txt'
        copies[guest] = hacl[:hacl.index(b'*/')+2]+b'\n'
        components.append({'ref':'runtime:bundled:hacl-star','type':'library','name':'HACL*','version':revision,
            'purl':'pkg:github/hacl-star/hacl-star@'+revision,'version_status':'locked-source-upstream-revision',
            'licenses':[guest],'origin':{'source_archive':item,'revision_source':'Modules/_hacl/refresh.sh'},
            'files':[],'embedded_in':'runtime:cpython'})
    return components,copies


def collect(rootfs, image_id, facts, cpython_origins):
    if (rootfs/'runtime-inventory.json').exists() or (rootfs/'runtime-components.json').exists():
        raise ValueError('collection requires an unsealed, fresh runtime component record')
    provenance = json.loads((rootfs/'build-provenance.json').read_text())
    closure.inventory(rootfs)  # Reject unsupported inodes and symlink escapes before any writes.
    if cpython_origins['protocol'] != 'osv-cpython-install-origins/v1' or cpython_origins['source_lock_sha256'] != sha(closure.sources.LOCK):
        raise ValueError('invalid CPython install origins')
    cpython_files = {item['path']:item for item in cpython_origins['files']}
    if len(cpython_files) != len(cpython_origins['files']):
        raise ValueError('duplicate CPython install origin')
    if facts['protocol'] != 'osv-runtime-version-facts/v1' or not facts['linux_build_reference_only']:
        raise ValueError('invalid runtime version facts')
    for guest,digest in facts['files_sha256'].items():
        closure.guest_path(guest)
        if sha(rootfs/guest.lstrip('/')) != digest:
            raise ValueError('version facts refer to changed runtime bytes')
    lock = closure.sources.read_lock()
    for name in ('numpy','pandas'):
        expected = next(item['version'] for item in lock['files'] if item['project'] == name)
        if facts[name] != expected:
            raise ValueError('runtime package version differs from lock: '+name)
    system,owners,copies = collect_system(rootfs,provenance,image_id)
    wheels,wheel_owners = collect_wheels(rootfs,lock)
    if set(owners).intersection(wheel_owners):
        raise ValueError('overlapping system and wheel owners')
    owners.update(wheel_owners)
    bundled,source_copies = source_notices(rootfs,lock,facts)
    copies.update(source_copies)
    for path in source_copies:
        owners[path] = 'runtime:license-texts'
    cpython = next(item for item in lock['files'] if item['project'] == 'CPython')
    components = system+wheels+bundled+[
        {'ref':'runtime:cpython','type':'library','name':'CPython','version':cpython['version'],
         'purl':'pkg:generic/cpython@'+cpython['version'],'version_status':'locked-source-and-build-verified',
         'licenses':['/opt/python/LICENSE'],'origin':{'source':cpython},'files':[]},
        {'ref':'runtime:project-entry','type':'file','name':'osv-python-entry','version_status':'project-build',
         'licenses':[],'origin':{'source_sha256':provenance['inputs_sha256'].get('osv-native/apps/python-science/main.c')},'files':[]},
        {'ref':'runtime:build-metadata','type':'data','name':'runtime-build-metadata','version_status':'project-generated',
         'licenses':[],'files':[]},
        {'ref':'runtime:license-texts','type':'data','name':'runtime-license-texts','version_status':'source-notices',
         'licenses':[],'files':[]}]
    site = '/opt/python/lib/python3.12/site-packages/numpy.libs/'
    numpy_ref = next(item['ref'] for item in wheels if item['name'] == 'numpy')
    native = [('OpenBLAS','openblas','libscipy_openblas64_-f48b354e.so'),
        ('libgfortran',None,'libgfortran-83c28eba-468e71e5.so.5.0.0'),
        ('libquadmath',None,'libquadmath-2284e583-a9307bba.so.0.0.0')]
    numpy_licenses = next(item['licenses'] for item in wheels if item['ref'] == numpy_ref)
    for name,key,filename in native:
        guest = site+filename
        if owners.get(guest) != numpy_ref:
            raise ValueError('vendored binary is not in pinned NumPy wheel')
        reference = 'runtime:bundled:'+name.lower()
        owners[guest] = reference
        component = {'ref':reference,'type':'library','name':name,'licenses':numpy_licenses,
            'version_status':'runtime-export-verified' if key else 'unresolved-exact-source-version',
            'origin':{'wheel_component':numpy_ref,'binary_sha256':sha(rootfs/guest.lstrip('/'))},'files':[]}
        if key:
            component['version'] = facts[key]
            component['purl'] = 'pkg:generic/openblas@'+quote(facts[key],safe='')
        components.append(component)
    components.append({'ref':'runtime:bundled:lapack','type':'library','name':'LAPACK','version':facts['lapack'],
        'purl':'pkg:generic/lapack@'+facts['lapack'],'version_status':'runtime-export-verified',
        'licenses':numpy_licenses,'embedded_in':'runtime:bundled:openblas','files':[],
        'origin':{'wheel_component':numpy_ref}})
    if (rootfs/'opt/osv/guest-inference.json').exists():
        # The SDK is project source, not part of CPython or a scientific wheel.
        import guest_inference_image as guest_sdk
        profile=json.loads((rootfs/'opt/osv/guest-inference.json').read_text())
        guest_sdk.validate(rootfs,profile,'firecracker-osv','amd64')
        sdk_files=sorted([*profile['files_sha256'],guest_sdk.META])
        if any(path in owners for path in sdk_files):raise ValueError('SDK file overlaps an existing package owner')
        owners.update({path:'runtime:guest-inference-sdk' for path in sdk_files})
        components.append({'ref':'runtime:guest-inference-sdk','type':'library','name':'osv-sandbox-guest-inference-sdk','version':'remote-infer-v1',
            'version_status':'project-source-and-files-verified','licenses':[],
            'origin':{'inputs_sha256':{name:sha(ROOT/name) for name in guest_sdk.input_names('firecracker-osv')},
                      'profile_sha256':sha(rootfs/guest_sdk.META.lstrip('/'))},
            'files':[{'path':path,'sha256':sha(rootfs/path.lstrip('/'))} for path in sdk_files]})
    for path in sorted(rootfs.rglob('*')):
        if path.is_file() or path.is_symlink():
            guest = '/'+str(path.relative_to(rootfs))
            if guest in owners:
                continue
            if guest.startswith('/opt/python/'):
                expected = cpython_files.get(guest)
                if expected is None or (path.is_symlink() and expected.get('symlink') != path.readlink().as_posix()) or (
                        not path.is_symlink() and expected.get('sha256') != sha(path)):
                    raise ValueError('unverified CPython file origin: '+guest)
                owners[guest] = 'runtime:cpython'
            elif guest == '/python3.12.so':
                owners[guest] = 'runtime:project-entry'
            elif guest in ('/build-provenance.json','/runtime-version-facts.json'):
                owners[guest] = 'runtime:build-metadata'
            else:
                raise ValueError('unattributed runtime file: '+guest)
    # Resolve again without access to builder libraries: this may not add files.
    edges = closure.resolve_closure(rootfs,{})
    for guest,data in copies.items():
        closure.guest_path(guest)
        output = rootfs/guest.lstrip('/')
        if not output.resolve().is_relative_to(rootfs) or any(parent.is_symlink() for parent in output.parents if parent.is_relative_to(rootfs)):
            raise ValueError('license destination traverses a symlink: '+guest)
        if output.exists() or output.is_symlink():
            raise ValueError('license destination already exists: '+guest)
        output.parent.mkdir(parents=True,exist_ok=True)
        with output.open('xb') as sink:
            sink.write(data)
    by_ref = {item['ref']:item for item in components}
    if len(by_ref) != len(components):
        raise ValueError('duplicate runtime component reference')
    for item in components:
        for guest in item['licenses']:
            if not (rootfs/guest.lstrip('/')).is_file():
                raise ValueError('component license missing: '+guest)
    document = {'protocol':'osv-runtime-component-provenance/v1','builder_image_id':image_id,
        'source_lock_sha256':sha(closure.sources.LOCK),'collector_sha256':sha(Path(__file__)),
        'cpython_install_origins_sha256':hashlib.sha256(json.dumps(cpython_origins,sort_keys=True).encode()).hexdigest(),
        'components':sorted(components,key=lambda item:item['ref']),'file_owners':dict(sorted(owners.items())),
        'native_dependencies':edges,'generated_metadata_paths':['/runtime-components.json','/runtime-inventory.json',
            '/bytecode-provenance.json','/bytecode-verification.json'],
        'unresolved_versions':[item['ref'] for item in components if item['version_status'].startswith('unresolved')],
        'static_component_audit':'partial; additional code-copy notices require source audit',
        'vulnerability_scan_complete':False,'production_validated':False}
    (rootfs/'runtime-components.json').write_text(json.dumps(document,indent=2)+'\n')
    return document


def capture_cpython(rootfs):
    files = closure.inventory(rootfs/'opt/python')
    for item in files:
        item['path'] = '/opt/python'+item['path']
    return {'protocol':'osv-cpython-install-origins/v1','source_lock_sha256':sha(closure.sources.LOCK),
        'files':files}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rootfs',type=Path,required=True)
    parser.add_argument('--builder-image-id')
    parser.add_argument('--cpython-origins',type=Path)
    parser.add_argument('--capture-cpython',action='store_true')
    parser.add_argument('--output',type=Path)
    args = parser.parse_args()
    rootfs = args.rootfs.resolve(strict=True)
    if args.capture_cpython:
        if args.output is None or args.output.exists():
            raise ValueError('capture requires a fresh output file')
        document = capture_cpython(rootfs)
        args.output.write_text(json.dumps(document,indent=2)+'\n')
        print('captured CPython install origins: '+str(len(document['files'])),flush=True)
        return
    if not args.builder_image_id or args.cpython_origins is None:
        raise ValueError('collection requires builder identity and CPython install origins')
    facts = json.loads((rootfs/'runtime-version-facts.json').read_text())
    origins = json.loads(args.cpython_origins.read_text())
    document = collect(rootfs,args.builder_image_id,facts,origins)
    print(json.dumps({'components':len(document['components']),'owned_files':len(document['file_owners']),
        'unresolved_versions':document['unresolved_versions'],'vulnerability_scan_complete':False}),flush=True)


if __name__ == '__main__':
    main()
