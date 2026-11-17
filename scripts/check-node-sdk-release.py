#!/usr/bin/env python3
"""Verify signed offline Node client payload against project source and Linux SBOM."""
import argparse
import hashlib
import json
from pathlib import Path
import posixpath
import re
import subprocess
import tarfile


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--verifier', type=Path, required=True)
    parser.add_argument('--public-key', type=Path, required=True)
    parser.add_argument('--arch', choices=('amd64', 'arm64'), required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    subprocess.run([str(args.verifier), 'verify', '-archive', str(args.archive),
                    '-public-key', str(args.public_key), '-arch', args.arch],
                   check=True, capture_output=True, text=True)
    source = Path(__file__).resolve().parents[1]
    with tarfile.open(args.archive) as tar:
        manifest = json.load(tar.extractfile('manifest.json'))
        sbom = json.load(tar.extractfile('artifacts/sbom.cdx.json'))
        files = {item['path']: item for item in manifest['files']}
        components = {item['name']: item for item in sbom['components']}
        hashes = {}
        for name, component in [('sdk/node/index.js', 'osv-node-client'),
                                ('sdk/node/index.d.ts', 'osv-node-client-types')]:
            data = tar.extractfile(name).read()
            value = digest(data)
            assert files[name]['sha256'] == value == digest((source / name).read_bytes()), name
            assert components[component]['hashes'] == [{'alg': 'SHA-256', 'content': value}], component
            hashes[name] = value
        for name in ('sdk/node/package.json', 'docs/NODE-SDK.md'):
            data = tar.extractfile(name).read()
            source_name = 'sdk/node/README.md' if name.startswith('docs/') else name
            expected = (source / source_name).read_bytes()
            if name.startswith('docs/'):
                # The release builder retains links to bundled files and turns
                # unavailable source-tree links into plain labels. Verify that
                # exact transformation, while still checking the signed bytes.
                def bundled_link(match):
                    label, target = match.groups()
                    if target.startswith(('https://', 'http://', '#')):
                        return match.group()
                    path = posixpath.normpath(posixpath.join('docs', target.split('#', 1)[0]))
                    if not path.startswith(('/', '../')) and path in files:
                        return match.group()
                    return label
                expected = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', bundled_link, expected.decode()).encode()
            assert files[name]['sha256'] == digest(data) == digest(expected), name
    report = {'suite': 'signed-node-sdk-release/v1', 'arch': args.arch,
              'version': manifest['version'], 'archive_sha256': digest(args.archive.read_bytes()),
              'files': hashes, 'bundled_document_links_verified': True, 'passed': True}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
