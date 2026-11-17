#!/usr/bin/env python3
"""Build and verify project-owned offline Linux code images without mounting them."""
import argparse
from collections import defaultdict
import json
import math
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from urllib.parse import quote

from linux_code_runtime_closure import elf_machine, inventory, MACHINES, resolve, sha
import guest_inference_image as inference_sdk

ROOT = Path(__file__).resolve().parents[1]
RUNTIMES = ROOT / 'assets/runtimes/linux-code'
CA = '/etc/ssl/certs/ca-certificates.crt'
INPUTS = ['scripts/linux_code_image.py', 'scripts/linux_code_runtime_closure.py',
          'linux-guest/code-kernels/python.py', 'linux-guest/code-kernels/node.cjs']


def dump(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def run(argv, **kwargs):
    return subprocess.run(list(map(str, argv)), check=True, **kwargs)


def project_path(path):
    path = path.resolve()
    if not path.is_relative_to(ROOT):
        raise ValueError('real image inputs and outputs must be within the project')
    # debugfs commands do not have a general shell quoting mechanism.
    if any(c.isspace() or c in '\"\\\0' for c in str(path)):
        raise ValueError('image paths must not contain debugfs command delimiters')
    return path


def extract(image, root):
    root.mkdir()
    result = run(['debugfs', '-R', f'rdump / {root}', image], capture_output=True, text=True)
    if not (root / 'sbin/agent-init').is_file() or 'error' in result.stderr.lower():
        raise ValueError('cannot extract actual guest image: ' + result.stderr[-1000:])


def profile_for(architecture, inventory_path):
    return {'architecture': architecture, 'kernel_protocol': 'osv-code-kernel/v2',
            'python_version': '3.12.16', 'node_version': '22.23.4', 'typescript_version': '5.9.3',
            'prewarm_language': 'python', 'runtime_inventory_sha256': sha(inventory_path),
            'kernel_scripts_sha256': {name: sha(ROOT / 'linux-guest/code-kernels' / name)
                                      for name in ['python.py', 'node.cjs']},
            'minimum_cpu_features': ['sse4_1'] if architecture == 'amd64' else ['asimd']}


def check_runtime(architecture):
    asset = RUNTIMES / ('linux-' + architecture)
    data = json.loads((asset / 'runtime-inventory.json').read_text())
    if (data['protocol'] != 'osv-linux-code-runtime/v1' or data['architecture'] != architecture
            or data['source_lock_sha256'] != sha(RUNTIMES / 'source-lock.json')
            or data['files'] != inventory(asset / 'rootfs')):
        raise ValueError('sealed runtime differs from its inventory or source lock')
    if resolve(asset / 'rootfs', architecture)['edges'] != data['closure']['edges']:
        raise ValueError('sealed runtime ELF closure changed')
    return asset, data


def overlay(root, runtime, data):
    before = inventory(root)
    conflicts = sorted(set(before) & set(data['files']))
    if conflicts != [CA]:
        raise ValueError('unexpected base/runtime file overlap: ' + repr(conflicts))
    shutil.copytree(runtime / 'rootfs', root, symlinks=True, dirs_exist_ok=True)
    actual = inventory(root)
    for name, wanted in data['files'].items():
        if actual.get(name) != wanted:
            raise ValueError('runtime overlay changed a sealed file: ' + name)
    for name, wanted in before.items():
        if name != CA and actual.get(name) != wanted:
            raise ValueError('runtime overlay changed base file: ' + name)
    return {CA: {'base_sha256': before[CA]['sha256'],
                 'runtime_sha256': data['files'][CA]['sha256']}}


def build(args):
    architecture = args.architecture
    output, base, musl = map(project_path, [args.output, args.base_rootfs, args.musl_assets])
    if not output.is_relative_to(RUNTIMES / 'images') or output.exists():
        raise ValueError('output must be fresh inside assets/runtimes/linux-code/images')
    run(['python3', ROOT / 'scripts/check-musl-allocator.py', '--architecture', architecture,
         '--artifacts', musl], stdout=subprocess.DEVNULL)
    runtime, data = check_runtime(architecture)
    output.mkdir(parents=True)
    # Work trees are disposable copies; the sealed runtime stays at its project path.
    work_parent = ROOT / 'build/linux-code-images'
    work_parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=architecture + '-', dir=work_parent) as temporary:
        root = Path(temporary) / 'rootfs'
        extract(base, root)
        if sha(root / 'sbin/agent-init') != sha(musl / 'agent-init'):
            raise ValueError('base image agent differs from selected current musl build')
        if sha(root / 'sbin/osv-workload-supervisor') != sha(musl / 'osv-workload-supervisor'):
            raise ValueError('base image supervisor differs from selected current musl build')
        replacements = overlay(root, runtime, data)
        meta = root / 'opt/osv'
        meta.mkdir(parents=True, exist_ok=True)
        kernels = meta / 'code-kernels'
        shutil.copytree(ROOT / 'linux-guest/code-kernels', kernels,
                        ignore=shutil.ignore_patterns('__pycache__', '*.pyc', '*.pyo'))
        shutil.copyfile(runtime / 'runtime-inventory.json', meta / 'runtime-inventory.json')
        profile = profile_for(architecture, runtime / 'runtime-inventory.json')
        dump(meta / 'code-runtime.json', profile)
        sdk_profile = inference_sdk.install(root, 'firecracker-linux', architecture) if args.inference else None
        files = inventory(root)
        closure = resolve(root, architecture)
        for name in ['bin/busybox', 'bin/bash', 'sbin/agent-init', 'sbin/osv-workload-supervisor', 'usr/bin/osv-http']:
            if elf_machine(root / name) != MACHINES[architecture]:
                raise ValueError('wrong base ELF architecture: ' + name)
        # 50% headroom covers ext4 metadata and future small runtime additions.
        image_mib = max(640, math.ceil(sum(f.get('size', 0) for f in files.values()) * 1.5 / 2**20 / 64) * 64)
        image = output / 'rootfs.ext4'
        with image.open('xb') as stream:
            stream.truncate(image_mib * 2**20)
        run(['mkfs.ext4', '-q', '-F', '-O', '^has_journal,^metadata_csum_seed', '-L', 'linux-code',
             '-d', root, image])
        run(['e2fsck', '-fn', image])
        shutil.copyfile(runtime / 'runtime-inventory.json', output / 'runtime-inventory.json')
        shutil.copyfile(RUNTIMES / 'source-lock.json', output / 'source-lock.json')
        dump(output / 'code-runtime.json', profile)
        if sdk_profile:
            shutil.copyfile(root / inference_sdk.META.lstrip('/'), output / 'guest-inference.json')
        dump(output / 'image-inventory.json', {'protocol': 'osv-linux-code-image-files/v1',
                                              'architecture': architecture, 'files': files})
        provenance = {'protocol': 'osv-linux-code-image/v2', 'architecture': architecture,
                      'base_rootfs_sha256': sha(base), 'rootfs_sha256': sha(image),
                      'image_size_mib': image_mib, 'runtime_inventory_sha256': sha(output / 'runtime-inventory.json'),
                      'source_lock_sha256': sha(output / 'source-lock.json'),
                      'image_inventory_sha256': sha(output / 'image-inventory.json'),
                      'code_runtime_sha256': sha(output / 'code-runtime.json'),
                      'musl_provenance_sha256': sha(musl / 'build-provenance.json'),
                      'agent_sha256': sha(musl / 'agent-init'),
                      'supervisor_sha256': sha(musl / 'osv-workload-supervisor'), 'allowed_replacements': replacements,
                      'inputs_sha256': {name: sha(ROOT / name) for name in sorted(set(INPUTS) | (set(inference_sdk.input_names('firecracker-linux')) if sdk_profile else set()))},
                      'closure': closure, 'full_image_file_count': len(files),
                      'runtime_file_count': len(data['files']), 'performance_acceptance': False,
                      'minimal_64mib_acceptance': False, 'actual_vsock_acceptance': False}
        if sdk_profile:
            provenance['guest_inference_sha256'] = sha(output / 'guest-inference.json')
        dump(output / 'image-build-provenance.json', provenance)
    verify(output, architecture)
    names = ['rootfs.ext4', 'runtime-inventory.json', 'source-lock.json', 'code-runtime.json',
             'image-inventory.json', 'image-build-provenance.json']
    if sdk_profile: names.append('guest-inference.json')
    (output / 'SHA256SUMS').write_text(''.join(sha(output / name) + '  ' + name + '\n' for name in names))
    print(f'Built and extracted verified {architecture} offline image: {output}', flush=True)


def validate_records(asset, architecture):
    build = json.loads((asset / 'image-build-provenance.json').read_text())
    runtime = json.loads((asset / 'runtime-inventory.json').read_text())
    sealed = json.loads((asset / 'image-inventory.json').read_text())
    profile = json.loads((asset / 'code-runtime.json').read_text())
    lock = json.loads((asset / 'source-lock.json').read_text())
    if (build['protocol'] != 'osv-linux-code-image/v2' or build['architecture'] != architecture
            or runtime['protocol'] != 'osv-linux-code-runtime/v1' or runtime['architecture'] != architecture
            or sealed['protocol'] != 'osv-linux-code-image-files/v1' or sealed['architecture'] != architecture
            or lock['protocol'] != 'osv-linux-code-runtime-sources/v1'):
        raise ValueError('image metadata protocol/architecture mismatch')
    for filename, key in [('rootfs.ext4', 'rootfs_sha256'), ('runtime-inventory.json', 'runtime_inventory_sha256'),
                          ('source-lock.json', 'source_lock_sha256'), ('image-inventory.json', 'image_inventory_sha256'),
                          ('code-runtime.json', 'code_runtime_sha256')]:
        if build[key] != sha(asset / filename):
            raise ValueError('image build metadata digest mismatch: ' + filename)
    if (runtime['source_lock_sha256'] != build['source_lock_sha256']
            or profile != profile_for(architecture, asset / 'runtime-inventory.json')
            or build['inputs_sha256'] != {name: sha(ROOT / name) for name in sorted(set(INPUTS) | (set(inference_sdk.input_names('firecracker-linux')) if build.get('guest_inference_sha256') else set()))}
            or build['full_image_file_count'] != len(sealed['files'])
            or build['runtime_file_count'] != len(runtime['files'])):
        raise ValueError('image profile/source/file counts are inconsistent')
    for name, entry in runtime['files'].items():
        if sealed['files'].get(name) != entry:
            raise ValueError('sealed image omits or changes runtime file: ' + name)
    for name, digest in profile['kernel_scripts_sha256'].items():
        if sealed['files'].get('/opt/osv/code-kernels/' + name, {}).get('sha256') != digest:
            raise ValueError('image kernel script differs from signed profile')
    for filename in ['code-runtime.json', 'runtime-inventory.json']:
        if sealed['files'].get('/opt/osv/' + filename, {}).get('sha256') != sha(asset / filename):
            raise ValueError('image metadata differs from external signed input')
    if sealed['files'].get('/sbin/agent-init', {}).get('sha256') != build['agent_sha256']:
        raise ValueError('image agent binding mismatch')
    if sealed['files'].get('/sbin/osv-workload-supervisor', {}).get('sha256') != build['supervisor_sha256']:
        raise ValueError('image supervisor binding mismatch')
    if (asset / 'guest-inference.json').exists() != bool(build.get('guest_inference_sha256')):
        raise ValueError('guest SDK metadata presence differs from build record')
    if build.get('guest_inference_sha256'):
        path = asset / 'guest-inference.json'
        if sha(path) != build['guest_inference_sha256'] or sealed['files'].get(inference_sdk.META, {}).get('sha256') != sha(path):
            raise ValueError('guest SDK metadata differs from actual image inventory')
        inference_sdk.validate_inventory(sealed['files'], json.loads(path.read_text()), 'firecracker-linux', architecture)
    return build, runtime, sealed, profile, lock


def verify(asset, architecture):
    asset = project_path(asset)
    build, runtime, sealed, _, _ = validate_records(asset, architecture)
    work_parent = ROOT / 'build/linux-code-images'
    work_parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='verify-' + architecture + '-', dir=work_parent) as temporary:
        root = Path(temporary) / 'rootfs'
        extract(asset / 'rootfs.ext4', root)
        if inventory(root) != sealed['files']:
            raise ValueError('actual ext4 files/modes/links differ from sealed image inventory')
        if resolve(root, architecture)['edges'] != build['closure']['edges']:
            raise ValueError('actual image ELF closure differs from sealed build')
        # Each runtime origin must be attached to an actual sealed file.
        if set(runtime['origins']) != {p for p, f in runtime['files'].items() if f['kind'] == 'file'}:
            raise ValueError('runtime file provenance coverage mismatch')
    print('Verified actual ext4 and complete ELF closure: ' + architecture, flush=True)


def add_sbom(asset, architecture, path):
    build, runtime, sealed, _, lock = validate_records(asset, architecture)
    document = json.loads(path.read_text())
    roots = [c for c in document['components'] if c['name'] == 'linux-agent-rootfs']
    if len(roots) != 1 or roots[0]['hashes'] != [{'alg': 'SHA-256', 'content': build['rootfs_sha256']}]:
        raise ValueError('base BOM does not describe the selected code image')
    source_by_sha = {r['sha256']: r for r in lock['files'] if architecture in r['architectures']}
    packages = dict(p.split('=', 1) for p in runtime['build_packages'])
    groups = defaultdict(list)
    for name, entry in sealed['files'].items():
        origin = runtime['origins'].get(name)
        if origin and 'package' in origin:
            key = ('debian', origin['package'])
        elif origin and 'source_sha256' in origin:
            key = ('source', origin['project'], origin['source_sha256'])
        elif name in runtime['files']:
            key = ('runtime', origin['project'] if origin else 'runtime-links')
        else:
            key = ('base', 'guest-base-and-code-protocol')
        leaf = {'type': 'file', 'bom-ref': 'urn:osv:linux-code:file:' + quote(name, safe=''), 'name': name}
        if entry['kind'] == 'file':
            leaf['hashes'] = [{'alg': 'SHA-256', 'content': entry['sha256']}]
            leaf['properties'] = [{'name': 'osv:file-mode', 'value': oct(entry['mode'])}]
        else:
            leaf['properties'] = [{'name': 'osv:symlink-target', 'value': entry['target']}]
        groups[key].append(leaf)
    components = []
    for key, files in sorted(groups.items()):
        c = {'type': 'library' if key[0] != 'base' else 'application',
             'bom-ref': 'urn:osv:linux-code:origin:' + quote(':'.join(key), safe=''),
             'name': key[1], 'components': files}
        if key[0] == 'debian':
            if key[1] not in packages:
                raise ValueError('runtime package lacks a pinned version: ' + key[1])
            c['version'] = packages[key[1]]
            package, _, arch = key[1].partition(':')
            c['purl'] = 'pkg:deb/debian/' + package + '@' + quote(c['version'], safe='') + ('?arch=' + arch if arch else '')
        elif key[0] == 'source':
            if key[2] not in source_by_sha:
                raise ValueError('runtime origin is absent from the architecture source lock')
            source = source_by_sha[key[2]]
            c['version'] = source['version'] if source['project'] == key[1] else 'bundled-with-' + source['project'] + '-' + source['version']
            c['properties'] = [{'name': 'source:sha256', 'value': key[2]},
                               {'name': 'source:url', 'value': source['url']}]
        components.append(c)
    roots[0]['bom-ref'] = 'urn:osv:artifact:linux-code-rootfs'
    roots[0]['components'] = components
    roots[0]['properties'] = [{'name': 'osv:full-image-inventory-sha256', 'value': build['image_inventory_sha256']},
                              {'name': 'osv:runtime-inventory-sha256', 'value': build['runtime_inventory_sha256']},
                              {'name': 'osv:glibc-interpreters-allocator', 'value': 'upstream defaults; Rust agent alone uses mimalloc'}]
    document['metadata'].setdefault('properties', []).extend([
        {'name': 'osv:image-file-coverage', 'value': 'complete; actual ext4 independently extracted and compared'},
        {'name': 'osv:runtime-version-coverage', 'value': 'incomplete: bundled upstream subcomponents not individually audited'},
        {'name': 'osv:vulnerability-scan', 'value': 'not-run; ordinary baseline'}])
    dump(path, document)
    print('Added ' + str(len(sealed['files'])) + ' actual image files and ' + str(len(components)) + ' origins to code BOM', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['build', 'verify', 'sbom'])
    parser.add_argument('--architecture', choices=MACHINES, required=True)
    parser.add_argument('--output', type=Path, required=True, help='project image asset directory')
    parser.add_argument('--base-rootfs', type=Path)
    parser.add_argument('--musl-assets', type=Path)
    parser.add_argument('--sbom', type=Path)
    parser.add_argument('--inference', action='store_true', help='embed the source-bound fixed guest SDK and v7 profile')
    args = parser.parse_args()
    if args.action == 'build':
        if not args.base_rootfs or not args.musl_assets:
            parser.error('build requires base-rootfs and musl-assets')
        build(args)
    elif args.action == 'verify':
        verify(args.output, args.architecture)
    else:
        if not args.sbom:
            parser.error('sbom action requires --sbom')
        add_sbom(args.output, args.architecture, args.sbom)


if __name__ == '__main__':
    main()
