#!/usr/bin/env python3
"""Compare payload hashes from two independently verified offline archives."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile


def archive_report(path, verifier, public_key, arch):
    subprocess.run([str(verifier), 'verify', '-archive', str(path),
                    '-public-key', str(public_key), '-arch', arch],
                   check=True, capture_output=True, text=True)
    with path.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    with tarfile.open(path) as archive:
        manifest = json.load(archive.extractfile('manifest.json'))
        sbom = json.load(archive.extractfile('artifacts/sbom.cdx.json'))
    return digest, {item['path']: item['sha256'] for item in manifest['files']}, sbom


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--old', type=Path, required=True)
    parser.add_argument('--new', type=Path, required=True)
    parser.add_argument('--verifier', type=Path, required=True)
    parser.add_argument('--public-key', type=Path, required=True)
    parser.add_argument('--old-public-key', type=Path,
                        help='old release key when test-signing keys rotated')
    parser.add_argument('--arch', choices=('amd64', 'arm64'), required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    old_digest, old, old_sbom = archive_report(args.old, args.verifier,
                                               args.old_public_key or args.public_key, args.arch)
    new_digest, new, new_sbom = archive_report(args.new, args.verifier, args.public_key, args.arch)
    unchanged = sorted(path for path in old.keys() & new.keys() if old[path] == new[path])
    changed = sorted(path for path in old.keys() & new.keys() if old[path] != new[path])
    running_paths = sorted(path for path in new if path.startswith(('bin/', 'lib/', 'systemd/'))
                           or path in ('artifacts/kernel', 'artifacts/rootfs.ext4',
                                       'config/config.production.json.template'))
    running_paths.remove('bin/osv-offline-release')
    report = {'suite': 'offline-payload-comparison/v1',
              'old_archive_sha256': old_digest, 'new_archive_sha256': new_digest,
              'old_files': len(old), 'new_files': len(new),
              'added': sorted(new.keys() - old.keys()), 'removed': sorted(old.keys() - new.keys()),
              'changed': changed, 'unchanged': unchanged,
              'running_payload_identical': all(path in unchanged for path in running_paths),
              'running_paths': running_paths,
              'sbom_components_identical': old_sbom.get('components') == new_sbom.get('components'),
              'sbom_metadata_component_identical': old_sbom.get('metadata', {}).get('component') ==
                                                  new_sbom.get('metadata', {}).get('component'),
              'sbom_changed_top_level': sorted(key for key in old_sbom.keys() | new_sbom.keys()
                                               if old_sbom.get(key) != new_sbom.get(key))}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'changed': changed, 'running_payload_identical': report['running_payload_identical']}))


if __name__ == '__main__':
    main()
