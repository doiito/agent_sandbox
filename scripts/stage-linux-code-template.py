#!/usr/bin/env python3
"""Stage a verified Linux v5-v8 code template into a multi-template offline release."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import tarfile

from linux_code_image import ROOT, RUNTIMES, run, sha, verify, add_sbom, validate_records
from reproducible_license_archive import write_license_archive


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage', type=Path, required=True)
    parser.add_argument('--assets', type=Path, required=True)
    parser.add_argument('--architecture', choices=['amd64', 'arm64'], required=True)
    parser.add_argument('--kernel', type=Path, required=True)
    parser.add_argument('--musl-assets', type=Path, required=True)
    parser.add_argument('--bash-assets', type=Path, required=True)
    parser.add_argument('--private-key', type=Path, required=True)
    parser.add_argument('--valid-for', default='8760h')
    parser.add_argument('--ports', action='store_true', help='explicitly sign source-bound port-forward-v1 with v6')
    parser.add_argument('--inference', action='store_true', help='explicitly sign the embedded guest SDK and v7 profile')
    parser.add_argument('--artifacts', action='store_true', help='explicitly sign the source-bound workspace artifact service with v8')
    args = parser.parse_args()
    stage, asset = args.stage.resolve(), args.assets.resolve()
    musl, bash = args.musl_assets.resolve(), args.bash_assets.resolve()
    if not asset.is_relative_to(RUNTIMES / 'images'):
        parser.error('code images must be project-owned sealed assets')
    verify(asset, args.architecture)
    run(['sha256sum', '--quiet', '-c', 'SHA256SUMS'], cwd=asset)
    build, runtime, sealed, _, _ = validate_records(asset, args.architecture)
    if bool(build.get('guest_inference_sha256')) != args.inference:
        raise ValueError('explicit inference signing must match the actual image SDK')
    if build['agent_sha256'] != sha(musl / 'agent-init') or build['musl_provenance_sha256'] != sha(musl / 'build-provenance.json'):
        raise ValueError('code image uses a different agent/allocator build')
    if build['supervisor_sha256'] != sha(musl / 'osv-workload-supervisor'):
        raise ValueError('code image uses a different supervisor build')
    if args.artifacts:
        sources = json.loads((musl / 'build-provenance.json').read_text())['source_sha256']
        modules = sorted((ROOT / 'linux-guest/src/artifacts').glob('*.rs')) + [ROOT / 'linux-guest/src/main.rs']
        if len(modules) < 5 or any(sources.get(str(path.relative_to(ROOT))) != sha(path) for path in modules):
            raise ValueError('workspace artifacts require the current source-bound guest')
    template = stage / 'templates/linux-code'
    artifacts, docs = template / 'artifacts', template / 'docs'
    artifacts.mkdir(parents=True, exist_ok=False)
    docs.mkdir()
    run(['cp', '--sparse=always', asset / 'rootfs.ext4', artifacts / 'rootfs.ext4'])
    shutil.copyfile(args.kernel, artifacts / 'kernel')
    for name in ['runtime-inventory.json', 'image-inventory.json', 'image-build-provenance.json',
                 'source-lock.json', 'code-runtime.json']:
        shutil.copyfile(asset / name, docs / name)
    if args.inference:
        shutil.copyfile(asset / 'guest-inference.json', docs / 'guest-inference.json')
    license_names = sorted(name for name, entry in runtime['files'].items()
                           if entry['kind'] == 'file' and
                           (any(part.lower() == 'licenses' for part in Path(name).parts)
                            or Path(name).name.lower().startswith(('license', 'copyright', 'copying', 'notice'))))
    runtime_root = RUNTIMES / ('linux-' + args.architecture) / 'rootfs'
    entries=[]
    for name in license_names:
        source = runtime_root / name.lstrip('/')
        if source.is_symlink() or sha(source) != sealed['files'][name]['sha256']:
            raise ValueError('license differs from sealed image: ' + name)
        entries.append((source,name.lstrip('/')))
    write_license_archive(docs / 'runtime-licenses.tar.gz',entries)
    (docs / 'runtime-license-paths.json').write_text(json.dumps(license_names, indent=2) + '\n')
    command = ['go', 'run', './cmd/osv-sbom', '-profile', 'linux',
               '-kernel', artifacts / 'kernel', '-rootfs', artifacts / 'rootfs.ext4',
               '-agent', musl / 'agent-init', '-api', stage / 'bin/osv-sandboxd',
               '-workload-supervisor', musl / 'osv-workload-supervisor',
               '-launcher', stage / 'bin/osv-sandbox-launcher', '-mcp', stage / 'bin/osv-sandbox-mcp',
               '-firecracker', stage / 'bin/firecracker', '-jailer', stage / 'bin/jailer',
               '-allocator-policy', musl / 'allocator-policy.json',
               '-allocator-archive', musl / 'build-libraries/libmimalloc.a',
               '-allocator-provenance', musl / 'build-provenance.json',
               '-bash', bash / 'bash', '-bash-source-lock', bash / 'source-lock.json',
               '-output', artifacts / 'sbom.cdx.json']
    run(command, cwd=ROOT)
    add_sbom(asset, args.architecture, artifacts / 'sbom.cdx.json')
    # Source-bound agent implements all three features; code images include the
    # same guest HTTP client as the base and the sealed runtime's own CA data.
    port_features = ['-agent-feature', 'port-forward-v1'] if args.ports else []
    inference_features = ['-agent-feature', 'remote-infer-v1', '-guest-inference', docs / 'guest-inference.json'] if args.inference else []
    artifact_features = ['-agent-feature', 'workspace-artifacts-v1'] if args.artifacts else []
    run(['go', 'run', './cmd/osv-artifact-manifest', *port_features, *inference_features, *artifact_features, '-backend', 'firecracker-linux',
         '-agent-feature', 'code-contexts-v1', '-agent-feature', 'workspace-watch-v1',
         '-agent-feature', 'vsock-proxy-v1', '-code-runtime', docs / 'code-runtime.json',
         '-artifact-root', artifacts, '-kernel', 'kernel', '-image', 'rootfs.ext4',
         '-firecracker', stage / 'bin/firecracker', '-jailer', stage / 'bin/jailer',
         '-sbom', 'sbom.cdx.json', '-private-key', args.private_key,
         '-output', artifacts / 'manifest.json', '-valid-for', args.valid_for], cwd=ROOT)
    config = json.loads((ROOT / 'examples/config.production.json').read_text())
    value = {'id': 'linux-code', 'backend': 'firecracker-linux',
             'artifact_root': '/opt/osv-sandbox/current/templates/linux-code/artifacts',
             'kernel': {'path': 'kernel', 'sha256': sha(artifacts / 'kernel')},
             'image': {'path': 'rootfs.ext4', 'sha256': sha(artifacts / 'rootfs.ext4'), 'format': 'raw'},
             'artifact_manifest': {'path': 'manifest.json', 'signature_path': 'manifest.json.sig',
                                   'public_key_path': config['artifact_manifest']['public_key_path'],
                                   'sbom_path': 'sbom.cdx.json'},
             'allowed_entrypoints': config['allowed_entrypoints'] + ['/opt/python/bin/python3.12', '/opt/node/bin/node'],
             'defaults': {'memory_mib': 1024, 'vcpus': 1, 'timeout_ms': 30000}}
    (template / 'template.json').write_text(json.dumps(value, indent=2) + '\n')
    version = 'v8' if args.artifacts else 'v7' if args.inference else 'v6' if args.ports else 'v5'
    print(f'Staged signed {args.architecture} Linux {version} code template with {len(license_names)} license files', flush=True)


if __name__ == '__main__':
    main()
