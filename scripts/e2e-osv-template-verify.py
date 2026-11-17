#!/usr/bin/env python3
"""Verify a test-signed OSv template with an independent static verifier."""

import argparse
import json
from pathlib import Path
import subprocess

KERNEL_SHA256 = '78e4993ce81d93f06fa4f692e18a28f5a2840cd200f64a2f426287fed3db38d8'
IMAGE_SHA256 = 'ccca9ce56451a6e112c516350e7a3db08c9b6a79b2f0721feb0bf5b01058ac55'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    verifier = root / 'osv-artifact-verify-linux-amd64'
    artifact = root / 'artifacts'
    base = [str(verifier), '-artifact-root', str(artifact),
            '-kernel', 'kernel.elf', '-kernel-sha256', KERNEL_SHA256,
            '-image', 'rootfs.raw', '-image-sha256', IMAGE_SHA256,
            '-backend', 'firecracker-osv',
            '-firecracker', '/usr/local/bin/firecracker',
            '-jailer', '/usr/local/bin/jailer',
            '-manifest', 'manifest.test.json',
            '-signature', 'manifest.test.json.sig',
            '-sbom', 'sbom.cdx.json',
            '-public-key', str(root / 'artifact.public'),
            '-entrypoint', '/task-probe.so']
    routes = subprocess.run(['/sbin/ip', 'route', 'show'], capture_output=True, text=True, check=True)
    if routes.stdout.strip():
        raise SystemExit('network namespace has outbound routes')
    tampered = artifact / 'sbom-tampered.cdx.json'
    tampered.write_bytes((artifact / 'sbom.cdx.json').read_bytes() + b' ')
    cases = [
        ('valid', [], True),
        ('unsigned-entrypoint', ['-entrypoint', '/unsigned.so'], False),
        ('wrong-backend', ['-backend', 'firecracker-linux'], False),
        ('wrong-kernel-hash', ['-kernel-sha256', '0' * 64], False),
        ('tampered-sbom', ['-sbom', tampered.name], False),
        ('duplicate-entrypoint', ['-entrypoint', '/task-probe.so'], False),
    ]
    results = []
    try:
        for name, extra, should_pass in cases:
            command = base + extra
            completed = subprocess.run(command, capture_output=True, text=True, timeout=30)
            accepted = completed.returncode == 0
            item = {'name': name, 'passed': accepted == should_pass,
                    'exit_code': completed.returncode,
                    'message': (completed.stdout + completed.stderr).strip()[:500]}
            results.append(item)
            if not item['passed']:
                break
    finally:
        tampered.unlink(missing_ok=True)
    result = {'suite': 'osv-template-verification/v1', 'no_routes': True,
              'cases': results, 'passed': len(results) == len(cases) and all(x['passed'] for x in results)}
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'passed': result['passed'], 'cases': len(results)}))
    raise SystemExit(0 if result['passed'] else 1)


if __name__ == '__main__':
    main()
