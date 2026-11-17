#!/usr/bin/env python3
"""Verify a signed release binds the Python client to its file list and SBOM."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile


SDK_PATH = 'sdk/python/osv_sandbox_client.py'


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--verifier', type=Path, required=True)
    parser.add_argument('--public-key', type=Path, required=True)
    parser.add_argument('--arch', choices=('amd64', 'arm64'), required=True)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    subprocess.run([str(args.verifier), 'verify', '-archive', str(args.archive),
                    '-public-key', str(args.public_key), '-arch', args.arch],
                   check=True, capture_output=True, text=True)
    with tarfile.open(args.archive) as archive:
        manifest = json.load(archive.extractfile('manifest.json'))
        sbom = json.load(archive.extractfile('artifacts/sbom.cdx.json'))
        sdk_bytes = archive.extractfile(SDK_PATH).read()
    sdk_hash = hashlib.sha256(sdk_bytes).hexdigest()
    source_hash = hashlib.sha256(args.source.read_bytes()).hexdigest()
    files = {entry['path']: entry for entry in manifest['files']}
    require(SDK_PATH in files and 'docs/PYTHON-SDK.md' in files,
            'signed release omits the client or its usage guide')
    require(files[SDK_PATH]['sha256'] == sdk_hash == source_hash,
            'release client differs from signed file list or project source')
    components = {item['name']: item for item in sbom['components']}
    sdk_component = components.get('osv-python-client', {})
    require(sdk_component.get('hashes') == [{'alg': 'SHA-256', 'content': sdk_hash}],
            'Linux SBOM omits or mismatches client source hash')
    with args.archive.open('rb') as stream:
        archive_hash = hashlib.file_digest(stream, 'sha256').hexdigest()
    report = {'suite': 'signed-python-sdk-release/v1', 'arch': args.arch,
              'version': manifest['version'], 'archive_sha256': archive_hash,
              'sdk_sha256': sdk_hash, 'sdk_file_mode': files[SDK_PATH]['mode'],
              'sbom_component': 'osv-python-client', 'passed': True}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
