"""Select a hash-bound allocator reference in an isolated validation fixture."""
import base64
import hashlib
import json
from pathlib import Path
import shutil

FILES = {'kernel', 'rootfs.ext4', 'agent-init', 'comparison-provenance.json',
         'manifest.json', 'manifest.json.sig', 'sbom.cdx.json', 'artifact.public'}


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def prepare(source, root, config):
    source, root = Path(source).resolve(), Path(root)
    descriptor = source / 'reference.json'
    if descriptor.is_symlink() or descriptor.stat().st_size > 65536:
        raise ValueError('invalid allocator reference descriptor')
    reference = json.loads(descriptor.read_text())
    code_read_comparison = reference.get('protocol') == 'osv-allocator-api-reference/v3'
    supervisor_comparison = reference.get('protocol') in ('osv-allocator-api-reference/v2', 'osv-allocator-api-reference/v3')
    expected_files = FILES | {'osv-workload-supervisor'} if supervisor_comparison else FILES
    if (reference.get('protocol') not in ('osv-allocator-api-reference/v1', 'osv-allocator-api-reference/v2',
                                        'osv-allocator-api-reference/v3') or
            reference.get('diagnostic') is not True or reference.get('release_eligible') is not False or
            reference.get('allocator') not in ('system', 'mimalloc') or
            set(reference.get('files', {})) != expected_files or config['backend'] != 'firecracker-linux'):
        raise ValueError('invalid allocator reference identity or file inventory')
    if supervisor_comparison:
        variant = reference.get('variant')
        expected_allocator = 'mimalloc' if variant == 'combined' and not code_read_comparison else 'system'
        expected_path = '/sbin/agent-init' if variant == 'combined' and not code_read_comparison else '/sbin/osv-workload-supervisor'
        comparison = 'supervisor-code-preparation' if code_read_comparison else 'workload-supervisor-layout'
        variants = ('baseline', 'primed') if code_read_comparison else ('combined', 'standalone')
        if (reference.get('comparison') != comparison or
                variant not in variants or reference['allocator'] != 'mimalloc' or
                reference.get('mimalloc_secure_level') != 4 or
                reference.get('supervisor_allocator') != expected_allocator or
                reference.get('supervisor_path') != expected_path or
                reference.get('helper_sha256') != reference['files']['osv-workload-supervisor']):
            raise ValueError('invalid workload supervisor comparison identity')
        if code_read_comparison and reference.get('helper_code_primed') is not (variant == 'primed'):
            raise ValueError('invalid supervisor code preparation state')
    for name, digest in reference['files'].items():
        path = source / name
        if path.is_symlink() or not path.is_file() or sha(path) != digest:
            raise ValueError('allocator reference file differs from descriptor: ' + name)
    original = json.loads((Path(config['artifact_root']) / config['artifact_manifest']['path']).read_text())
    manifest = json.loads((source / 'manifest.json').read_text())
    for key in ('protocol', 'backend', 'agent_features', 'kernel', 'kernel_size', 'image_size',
                'firecracker_sha256', 'jailer_sha256'):
        if manifest.get(key) != original.get(key):
            raise ValueError('allocator reference changed a control variable: ' + key)
    if (manifest['kernel']['path'] != 'kernel' or manifest['image']['path'] != 'rootfs.ext4' or
            manifest['image'].get('format') != 'raw' or
            manifest['kernel']['sha256'] != reference['files']['kernel'] or
            manifest['image']['sha256'] != reference['files']['rootfs.ext4'] or
            manifest['sbom_sha256'] != reference['files']['sbom.cdx.json'] or
            manifest['image_size'] != (source / 'rootfs.ext4').stat().st_size or
            manifest['kernel_size'] != (source / 'kernel').stat().st_size or
            manifest['sbom_size'] != (source / 'sbom.cdx.json').stat().st_size or
            reference.get('agent_sha256') != reference['files']['agent-init']):
        raise ValueError('allocator reference manifest and payload differ')
    provenance = json.loads((source / 'comparison-provenance.json').read_text())
    if provenance.get('allocator') != reference['allocator'] or provenance.get('agent_sha256') != reference['agent_sha256']:
        raise ValueError('allocator reference provenance differs')
    if supervisor_comparison and any(provenance.get(key) != reference[key] for key in (
            'comparison', 'variant', 'mimalloc_secure_level', 'supervisor_allocator', 'supervisor_path', 'helper_sha256')):
        raise ValueError('supervisor reference provenance differs')
    if code_read_comparison and provenance.get('helper_code_primed') is not reference['helper_code_primed']:
        raise ValueError('supervisor code preparation provenance differs')
    if len(base64.b64decode((source / 'artifact.public').read_text().strip(), validate=True)) != 32:
        raise ValueError('invalid allocator reference public key')
    if len(base64.b64decode((source / 'manifest.json.sig').read_text().strip(), validate=True)) != 64:
        raise ValueError('invalid allocator reference signature')
    target = root / 'allocator-reference'
    target.mkdir(mode=0o755)
    for name in expected_files:
        shutil.copyfile(source / name, target / name)
        (target / name).chmod(0o444)
        if sha(target / name) != reference['files'][name]:
            raise ValueError('allocator reference changed during copy: ' + name)
    config['artifact_root'] = str(target)
    config['kernel'], config['image'] = manifest['kernel'], manifest['image']
    config['artifact_manifest'] = {**config['artifact_manifest'], 'public_key_path': str(target / 'artifact.public')}
    receipt = {'diagnostic': True, 'release_eligible': False, 'allocator': reference['allocator'],
               'source_descriptor_sha256': sha(descriptor), 'files': reference['files'],
               'base_package_sha256': reference['base_package_sha256']}
    if supervisor_comparison:
        receipt.update({key: reference[key] for key in (
            'comparison', 'variant', 'mimalloc_secure_level', 'supervisor_allocator', 'supervisor_path', 'helper_sha256')})
    if code_read_comparison:
        receipt['helper_code_primed'] = reference['helper_code_primed']
    (root / 'results/allocator-reference.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return receipt
