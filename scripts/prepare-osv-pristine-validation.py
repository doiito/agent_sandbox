#!/usr/bin/env python3
"""Prepare an isolated root-owned OSv protocol fixture, without API or services."""
import argparse
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess


def sha(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--template', type=Path, required=True)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--verifier', type=Path, required=True)
    parser.add_argument('--manifest-sha256', required=True)
    args = parser.parse_args()
    root = args.root
    if os.geteuid() != 0 or root.exists() or not root.is_absolute() or root.parent != Path('/var/lib') or not root.name.startswith('osv-offline-validation-20261030-osvpristine'):
        raise SystemExit('requires root and a new isolated absolute fixture')
    source = args.template.resolve()
    if sha(source / 'artifacts/manifest.test.json') != args.manifest_sha256:
        raise SystemExit('source manifest differs from trusted expected digest')
    for lookup in (pwd.getpwuid, grp.getgrgid):
        try:
            lookup(232000)
        except KeyError:
            pass
        else:
            raise SystemExit('validation identity 232000 is already assigned')
    root.mkdir(mode=0o755)
    for name in ('run', 'results'):
        (root / name).mkdir(mode=0o700)
    template = root / 'template'
    shutil.copytree(source, template)
    for item in template.rglob('*'):
        if item.is_symlink():
            raise SystemExit('template contains a symlink')
        item.chmod(0o755 if item.is_dir() or item.parent == template / 'bin' else 0o644)
    manifest = json.loads((template / 'artifacts/manifest.test.json').read_text())
    if 'pristine-v1' not in manifest.get('agent_features', []):
        raise SystemExit('template has no signed pristine feature')
    command = [str(args.verifier.resolve()), '-artifact-root', str(template / 'artifacts'),
               '-kernel', manifest['kernel']['path'], '-kernel-sha256', manifest['kernel']['sha256'],
               '-image', manifest['image']['path'], '-image-sha256', manifest['image']['sha256'],
               '-backend', 'firecracker-osv', '-firecracker', str(template / 'bin/firecracker'),
               '-jailer', str(template / 'bin/jailer'), '-manifest', 'manifest.test.json',
               '-signature', 'manifest.test.json.sig', '-sbom', 'sbom.cdx.json',
               '-public-key', str(template / 'artifact-test.public'), '-entrypoint', '/task-probe.so']
    verified = subprocess.run(command, check=True, text=True, capture_output=True)
    (root / 'results/artifact-verify.log').write_text(verified.stdout)
    config = {'listen': '127.0.0.1:18548', 'artifact_root': str(template / 'artifacts'),
              'run_root': str(root / 'run'), 'backend': 'firecracker-osv',
              'hypervisor_path': str(template / 'bin/firecracker'),
              'jailer': {'path': str(template / 'bin/jailer'), 'uid': 232000, 'gid': 232000,
                         'identity_pool_size': 1, 'cgroup_version': 2, 'parent_cgroup': root.name},
              'kernel': manifest['kernel'], 'image': manifest['image'],
              'allowed_entrypoints': ['/task-probe.so'],
              'limits': {'max_concurrent': 1, 'max_output_bytes': 16384, 'max_timeout_ms': 30000},
              'artifact_manifest': {'path': 'manifest.test.json', 'signature_path': 'manifest.test.json.sig',
                                    'public_key_path': str(template / 'artifact-test.public'), 'sbom_path': 'sbom.cdx.json'}}
    path = root / 'config.diagnostic.json'
    path.write_text(json.dumps(config, indent=2) + '\n')
    path.chmod(0o600)
    provenance = {'suite': 'osv-pristine-protocol-fixture/v1', 'production_validated': False,
                  'configuration_sha256': sha(path), 'manifest_sha256': args.manifest_sha256,
                  'verifier_sha256': sha(args.verifier.resolve()),
                  'template_files': {str(item.relative_to(template)): sha(item) for item in template.rglob('*') if item.is_file()}}
    (root / 'results/fixture.json').write_text(json.dumps(provenance, indent=2) + '\n')
    print(json.dumps({'root': str(root), 'configuration': str(path), 'manifest_sha256': args.manifest_sha256}))


if __name__ == '__main__':
    main()
